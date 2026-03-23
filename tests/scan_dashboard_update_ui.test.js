const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function createNode() {
    return {
        innerText: "",
        innerHTML: "",
        className: "",
        style: {},
        querySelector() { return null; },
        classList: {
            add() {},
            remove() {},
            toggle() {},
        },
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
