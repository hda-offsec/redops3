const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function createClassList(initial = []) {
    const classes = new Set(initial);
    return {
        add(...tokens) {
            tokens.forEach((token) => classes.add(token));
        },
        remove(...tokens) {
            tokens.forEach((token) => classes.delete(token));
        },
        toggle(token, force) {
            if (force === undefined) {
                if (classes.has(token)) {
                    classes.delete(token);
                    return false;
                }
                classes.add(token);
                return true;
            }
            if (force) classes.add(token);
            else classes.delete(token);
            return force;
        },
        contains(token) {
            return classes.has(token);
        },
        toArray() {
            return Array.from(classes).sort();
        },
    };
}

function createNode() {
    return {
        innerText: "",
        innerHTML: "",
        className: "",
        style: {},
        children: [],
        querySelector() { return null; },
        prepend(child) {
            this.children.unshift(child);
        },
        classList: createClassList(),
    };
}

function createSandbox(overrides = {}) {
    const window = {};
    const document = {
        getElementById() { return null; },
        querySelectorAll() { return []; },
        querySelector() { return null; },
        addEventListener() {},
        createElement() { return createNode(); },
    };

    const sandbox = {
        console,
        window,
        document,
        navigator: { clipboard: { writeText() {} } },
        io() { return { on() {}, emit() {} }; },
        bootstrap: { Tab: { getOrCreateInstance() { return { show() {} }; } } },
        setTimeout,
        clearTimeout,
        fetch: async () => ({ ok: true, json: async () => ({ items: [], total: 0 }) }),
        ...overrides,
    };
    sandbox.window.document = sandbox.document;
    sandbox.globalThis = sandbox;
    return sandbox;
}

function loadScanDashboardClass(overrides = {}) {
    const source = fs.readFileSync(
        path.join(__dirname, "../ui/web/static/js/scan_dashboard.js"),
        "utf8"
    );
    const sandbox = createSandbox(overrides);
    vm.runInNewContext(`${source}\nthis.__ScanDashboard = ScanDashboard;`, sandbox, {
        filename: "scan_dashboard.js",
    });
    return { ScanDashboard: sandbox.__ScanDashboard, sandbox };
}


function createCortexDocumentHarness() {
    const headerBadges = createNode();
    let microscopePresent = false;
    headerBadges.querySelector = (selector) => {
        if (selector === '.fa-microscope' && microscopePresent) return { className: 'fa-microscope' };
        return null;
    };
    headerBadges.prepend = (child) => {
        microscopePresent = /fa-microscope/.test(child.innerHTML || '');
        headerBadges.children.unshift(child);
    };

    const nodes = {
        'cortex-recs-container': createNode(),
        'surface-expansion-container': createNode(),
        'service-intel-container': createNode(),
        'cortex-dynamic-status': createNode(),
    };

    return {
        document: {
            getElementById(id) {
                return nodes[id] || null;
            },
            querySelector(selector) {
                if (selector === '#cortex-intel-card .card-header .d-flex.gap-2') return headerBadges;
                return null;
            },
            querySelectorAll() { return []; },
            addEventListener() {},
            createElement() { return createNode(); },
        },
        headerBadges,
        nodes,
    };
}

test("uiRefresh syncFindingSummary keeps derived counters deterministic and additive", () => {
    const nodes = {
        "stat-findings": createNode(),
        "stat-assets": createNode(),
        "stat-endpoints": createNode(),
        "stat-high-risk": createNode(),
        "stat-critical": createNode(),
        "stat-high": createNode(),
    };

    const document = {
        getElementById(id) {
            return nodes[id] || null;
        },
        querySelectorAll() { return []; },
        querySelector() { return null; },
        addEventListener() {},
        createElement() { return createNode(); },
    };

    const { ScanDashboard } = loadScanDashboardClass({
        document,
    });

    ScanDashboard.internals.uiRefresh.syncFindingSummary(
        document,
        {
            phases: {
                recon: { open_ports: [{ port: 443 }, { port: 8443 }] },
                dns: { subdomains: ["api.example.org"] },
                osint: { cloud: ["bucket"] },
                dirbusting: { ffuf: { endpoints: [{ path: "admin" }] } },
                enum: {
                    api: { endpoints: ["/v1/users"] },
                    katana: { 443: ["https://example.org/health", "https://example.org/ready"] },
                },
            },
        },
        [
            { severity: "critical" },
            { severity: "high" },
            { severity: "low" },
        ]
    );

    assert.equal(nodes["stat-findings"].innerText, 3);
    assert.equal(nodes["stat-high-risk"].innerText, 2);
    assert.equal(nodes["stat-critical"].innerText, 1);
    assert.equal(nodes["stat-high"].innerText, 1);
    assert.equal(nodes["stat-assets"].innerText, 4);
    assert.equal(nodes["stat-endpoints"].innerText, 4);
});

test("uiRefresh syncFindingSummary resets counters when findings disappear while preserving additive asset and endpoint totals", () => {
    const nodes = {
        "stat-findings": { innerText: 9 },
        "stat-assets": { innerText: 9 },
        "stat-endpoints": { innerText: 9 },
        "stat-high-risk": { innerText: 9 },
        "stat-critical": { innerText: 9 },
        "stat-high": { innerText: 9 },
    };

    const document = {
        getElementById(id) {
            return nodes[id] || null;
        },
        querySelectorAll() { return []; },
        querySelector() { return null; },
        addEventListener() {},
        createElement() { return createNode(); },
    };

    const { ScanDashboard } = loadScanDashboardClass({ document });

    ScanDashboard.internals.uiRefresh.syncFindingSummary(
        document,
        {
            phases: {
                recon: { open_ports: [] },
                dns: { subdomains: ["api.example.org"] },
                enum: { api: { discovered_endpoints: ["/v1/users"] } },
            },
        },
        []
    );

    assert.equal(nodes["stat-findings"].innerText, 0);
    assert.equal(nodes["stat-high-risk"].innerText, 0);
    assert.equal(nodes["stat-critical"].innerText, 0);
    assert.equal(nodes["stat-high"].innerText, 0);
    assert.equal(nodes["stat-assets"].innerText, 1);
    assert.equal(nodes["stat-endpoints"].innerText, 1);
});

test("uiRefresh syncReconOverview clears stale port state and restores the empty placeholder when recon data is missing", () => {
    const portContainer = createNode();
    portContainer.innerHTML = "<div>stale ports</div>";
    portContainer.querySelector = (selector) => {
        if (selector === ".text-center") return { innerText: "placeholder" };
        return null;
    };

    const nodes = {
        "stat-open-ports": { innerText: 4 },
        "port-badges-container": portContainer,
    };

    const document = {
        getElementById(id) {
            return nodes[id] || null;
        },
        querySelectorAll() { return []; },
        querySelector() { return null; },
        addEventListener() {},
        createElement() { return createNode(); },
    };

    const { ScanDashboard } = loadScanDashboardClass({ document });

    ScanDashboard.internals.uiRefresh.syncReconOverview(document, {});

    assert.equal(nodes["stat-open-ports"].innerText, 0);
    assert.match(portContainer.innerHTML, /No open ports discovered yet/);
});

test("uiRefresh restoreDiscoveryStates preserves discovery button state mapping without changing contracts", () => {
    const { ScanDashboard } = loadScanDashboardClass();
    const calls = [];
    const dashboard = {
        activateDiscovery(id, state) {
            calls.push([id, state]);
        },
    };

    ScanDashboard.internals.uiRefresh.restoreDiscoveryStates(dashboard, {
        findings: [{ id_stable: "f-1" }],
        loot_count: 1,
        phases: {
            dns: { subdomains: ["api.example.org"] },
            recon: { open_ports: [{ port: 443 }] },
            osint: { cloud: ["s3://bucket"], historic_urls: ["https://example.org/old"] },
            enum: {
                waf: { 443: "cloudflare" },
                katana: { 443: ["https://example.org/"] },
                params: { 443: ["debug"] },
                api: { endpoints: ["/v1/users"] },
                js_secrets: { 443: ["token"] },
            },
            dirbusting: { ffuf: { endpoints: [{ path: "admin" }] } },
            vuln: {
                tls: { 443: { issuer: "ca" } },
                wordpress: { 443: { version: "6.0.0" } },
                data_leaks: [{ title: "dump" }],
                xss: [{ title: "reflected" }],
            },
            intel: { 443: [{ name: "Auth bypass" }] },
        },
        metrics: { loot_count: 1 },
    });

    const stateMap = Object.fromEntries(calls);
    assert.equal(stateMap.dns, true);
    assert.equal(stateMap.ports, true);
    assert.equal(stateMap.cloud, true);
    assert.equal(stateMap.waf, true);
    assert.equal(stateMap.crawl, true);
    assert.equal(stateMap.params, true);
    assert.equal(stateMap.fuzz, true);
    assert.equal(stateMap.api, true);
    assert.equal(stateMap.secrets, true);
    assert.equal(stateMap.vulns, true);
    assert.equal(stateMap.intel, true);
    assert.equal(stateMap.historic, true);
    assert.equal(stateMap.apps, true);
    assert.equal(stateMap.tls, true);
    assert.equal(stateMap.expert, false);
    assert.equal(stateMap.miner, true);
    assert.equal(stateMap.loot, true);
});

test("updateUI keeps the high-level orchestration order and still relies on renderJSONSection for JSON-backed panels", () => {
    const { ScanDashboard } = loadScanDashboardClass({
        setTimeout(fn) {
            fn();
            return 1;
        },
        initGraphData() {},
        updateSurfaceExplorer() {},
    });

    const order = [];
    const jsonCalls = [];
    const originalSyncReconOverview = ScanDashboard.internals.uiRefresh.syncReconOverview;
    const originalSyncFindingSummary = ScanDashboard.internals.uiRefresh.syncFindingSummary;
    const originalRestoreDiscoveryStates = ScanDashboard.internals.uiRefresh.restoreDiscoveryStates;
    const originalRenderPhaseSections = ScanDashboard.internals.uiRefresh.renderPhaseSections;
    const originalRefreshGraph = ScanDashboard.internals.uiRefresh.refreshGraph;
    const originalIngestStructuredFindings = ScanDashboard.internals.findingsFlow.ingestStructuredFindings;

    ScanDashboard.internals.uiRefresh.syncReconOverview = () => order.push("syncReconOverview");
    ScanDashboard.internals.uiRefresh.syncFindingSummary = () => order.push("syncFindingSummary");
    ScanDashboard.internals.uiRefresh.restoreDiscoveryStates = () => order.push("restoreDiscoveryStates");
    ScanDashboard.internals.uiRefresh.refreshGraph = () => order.push("refreshGraph");
    ScanDashboard.internals.findingsFlow.ingestStructuredFindings = () => order.push("ingestStructuredFindings");
    ScanDashboard.internals.uiRefresh.renderPhaseSections = (documentRef, dashboard, results) => {
        order.push("renderPhaseSections");
        return originalRenderPhaseSections.call(ScanDashboard.internals.uiRefresh, documentRef, dashboard, results);
    };

    try {
        const dashboard = {
            scanId: 7,
            updateAuditJourney() {
                order.push("updateAuditJourney");
            },
            updateCortexUI() {
                order.push("updateCortexUI");
            },
            handleProgressUpdate() {
                order.push("handleProgressUpdate");
            },
            renderTaskStatus() {
                order.push("renderTaskStatus");
            },
            renderJSONSection(parent, key, title) {
                jsonCalls.push([key, title, Boolean(parent)]);
            },
        };

        ScanDashboard.prototype.updateUI.call(dashboard, {
            findings: [{ id_stable: "finding-1", severity: "high" }],
            progress: { percent: 55, current_phase: "Validation Sweep" },
            task_status: { recon: { state: "running" } },
            phases: {
                dns: { subdomains: ["api.example.org"], records: { A: ["1.1.1.1"] } },
                osint: { cloud: ["bucket"], emails: ["ops@example.org"] },
                enum: {
                    headers: { 443: { "Strict-Transport-Security": "max-age=31536000" } },
                    whatweb: { summary: { server: "nginx" } },
                    katana: { 443: ["https://example.org/health"] },
                    api: { discovered_endpoints: ["/v1/users"] },
                },
                vuln: {
                    nuclei: { findings: [{ severity: "high", title: "nuclei hit" }] },
                    tls: { 443: { issuer: "ca" } },
                    wordpress: { 443: { wordfence_detected: true, evasion_active: false } },
                },
                recon: { open_ports: [{ port: 443, service_name: "https", priority_score: 90 }] },
                intel: { 443: [{ name: "Auth bypass", score: 90, description: "desc", action: "verify" }] },
            },
        });
    } finally {
        ScanDashboard.internals.uiRefresh.syncReconOverview = originalSyncReconOverview;
        ScanDashboard.internals.uiRefresh.syncFindingSummary = originalSyncFindingSummary;
        ScanDashboard.internals.uiRefresh.restoreDiscoveryStates = originalRestoreDiscoveryStates;
        ScanDashboard.internals.uiRefresh.renderPhaseSections = originalRenderPhaseSections;
        ScanDashboard.internals.uiRefresh.refreshGraph = originalRefreshGraph;
        ScanDashboard.internals.findingsFlow.ingestStructuredFindings = originalIngestStructuredFindings;
    }

    assert.deepEqual(order, [
        "updateAuditJourney",
        "updateCortexUI",
        "syncReconOverview",
        "ingestStructuredFindings",
        "syncFindingSummary",
        "handleProgressUpdate",
        "renderTaskStatus",
        "restoreDiscoveryStates",
        "renderPhaseSections",
        "refreshGraph",
    ]);
    assert.deepEqual(
        jsonCalls.map(([key, title]) => [key, title]),
        [
            ["cloud", "Cloud Assets"],
            ["dorks", "Google Hacking"],
            ["origin_ips", "Origin Unmasking"],
            ["emails", "Email Discovery"],
            ["github", "GitHub Leaks"],
            ["subdomains", "Discovered Subdomains"],
            ["records", "DNS Records"],
            ["headers", "Security Headers"],
            ["whatweb", "Technology Footprint"],
            ["api", "API Endpoints"],
            ["tls", "TLS/SSL Audit"],
        ]
    );
});

test("uiRefresh renderReconMatrix keeps priority sorting deterministic without mutating the source payload order", () => {
    const matrixBody = { innerHTML: "" };
    const document = {
        getElementById() { return null; },
        querySelector(selector) {
            if (selector === "#recon-matrix-body") return matrixBody;
            return null;
        },
        querySelectorAll() { return []; },
        addEventListener() {},
        createElement() { return createNode(); },
    };

    const { ScanDashboard } = loadScanDashboardClass({ document });
    const ports = [
        { port: 8080, service_name: "http", priority_score: 10 },
        { port: 443, service_name: "https", priority_score: 90 },
        { port: 8443, service_name: "https-alt", priority_score: 50 },
    ];
    const results = {
        phases: {
            recon: { open_ports: ports },
        },
    };

    ScanDashboard.internals.uiRefresh.renderReconMatrix(document, { targetIdentifier: "example.org" }, results);

    assert.deepEqual(
        ports.map((port) => port.port),
        [8080, 443, 8443]
    );
    assert.ok(matrixBody.innerHTML.indexOf("443/tcp") < matrixBody.innerHTML.indexOf("8443/tcp"));
    assert.ok(matrixBody.innerHTML.indexOf("8443/tcp") < matrixBody.innerHTML.indexOf("8080/tcp"));
});


test("cortexView renders recommendations, surface expansion, service intelligence, and active status deterministically", () => {
    const { document, headerBadges, nodes } = createCortexDocumentHarness();
    const { ScanDashboard } = loadScanDashboardClass({ document });

    ScanDashboard.internals.cortexView.render(document, {
        phases: {
            enum: {
                derived: {
                    js_expert_mining: true,
                    status: 'triaging',
                    cortex_recommendations: [
                        { title: 'Pivot to admin API', confidence: 91, reason: 'Observed API tags', port: 8443, category: 'intel' },
                        { title: 'Extend enum', confidence: 62, reason: 'Sparse headers', category: 'enum' },
                    ],
                    surface_expansion: {
                        global: {
                            derived_endpoints: ['/admin', '/debug'],
                        },
                        per_port: {
                            '8443': {
                                reasons: ['api_guess', 'admin_panel'],
                                derived_params: ['redirect_uri', 'return%3Dhttps%3A%2F%2Fexample.org'],
                            },
                        },
                    },
                    service_intelligence: [
                        { port: 8443, tags: ['api', 'auth'] },
                        { port: 8080, tags: ['webhook'] },
                    ],
                },
            },
        },
    });

    assert.equal(headerBadges.children.length, 1);
    assert.match(headerBadges.children[0].innerHTML, /JS EXPERT ACTIVE/);
    assert.match(nodes['cortex-recs-container'].innerHTML, /Pivot to admin API/);
    assert.match(nodes['cortex-recs-container'].innerHTML, /SIGNAL: 91%/);
    assert.match(nodes['cortex-recs-container'].innerHTML, /RECOMMENDATION/);
    assert.match(nodes['cortex-recs-container'].innerHTML, /PORT: 8443/);
    assert.match(nodes['surface-expansion-container'].innerHTML, /Heuristic Search Surfaces/);
    assert.match(nodes['surface-expansion-container'].innerHTML, /api guess/);
    assert.match(nodes['surface-expansion-container'].innerHTML, /return=https:\/\/example\.org/);
    assert.match(nodes['service-intel-container'].innerHTML, /API/);
    assert.match(nodes['service-intel-container'].innerHTML, /AUTH/);
    assert.match(nodes['service-intel-container'].innerHTML, /WEBHOOK/);
    assert.match(nodes['cortex-dynamic-status'].innerHTML, /TRIAGING/);
    assert.equal(nodes['cortex-dynamic-status'].classList.contains('d-none'), false);
});

test("cortexView keeps the dynamic status hidden when derived status is idle and skips empty containers", () => {
    const { document, headerBadges, nodes } = createCortexDocumentHarness();
    nodes['cortex-dynamic-status'].classList.add('d-none');
    nodes['cortex-recs-container'].innerHTML = 'existing recs';
    nodes['surface-expansion-container'].innerHTML = 'existing expansion';
    nodes['service-intel-container'].innerHTML = 'existing intel';

    const { ScanDashboard } = loadScanDashboardClass({ document });

    ScanDashboard.internals.cortexView.render(document, {
        phases: {
            enum: {
                derived: {
                    status: 'idle',
                    cortex_recommendations: [],
                    surface_expansion: {},
                    service_intelligence: [],
                },
            },
        },
    });

    assert.equal(headerBadges.children.length, 0);
    assert.equal(nodes['cortex-recs-container'].innerHTML, 'existing recs');
    assert.equal(nodes['surface-expansion-container'].innerHTML, 'existing expansion');
    assert.equal(nodes['service-intel-container'].innerHTML, 'existing intel');
    assert.equal(nodes['cortex-dynamic-status'].classList.contains('d-none'), true);
});

test("updateCortexUI delegates to the extracted cortexView helper without changing the entrypoint contract", () => {
    const { ScanDashboard } = loadScanDashboardClass();
    const originalRender = ScanDashboard.internals.cortexView.render;
    const calls = [];

    ScanDashboard.internals.cortexView.render = (documentRef, results) => {
        calls.push({ documentRef, results });
    };

    try {
        const results = { phases: { enum: { derived: { status: 'triaging' } } } };
        const dashboard = {};
        ScanDashboard.prototype.updateCortexUI.call(dashboard, results);
    } finally {
        ScanDashboard.internals.cortexView.render = originalRender;
    }

    assert.equal(calls.length, 1);
    assert.equal(typeof calls[0].documentRef.getElementById, 'function');
    assert.deepEqual(calls[0].results, { phases: { enum: { derived: { status: 'triaging' } } } });
});
