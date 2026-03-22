const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function createClassList() {
    const classes = new Set();
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
        className: "",
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

test("loadFindingsFromApi reset clears both findings containers and rendered ids before replay", async () => {
    const tableBody = { innerHTML: "<tr>legacy</tr>" };
    const resultList = { innerHTML: "<div>legacy</div>" };
    const container = {
        querySelector(selector) {
            if (selector === ".result-list") return resultList;
            return null;
        },
    };

    const { ScanDashboard } = loadScanDashboardClass({
        document: {
            getElementById(id) {
                if (id === "findings-table-body") return tableBody;
                if (id === "findings-container") return container;
                if (id === "findings-db-load-state") return { textContent: "" };
                return null;
            },
            querySelectorAll() { return []; },
            querySelector() { return null; },
            addEventListener() {},
        },
        fetch: async () => ({
            ok: true,
            json: async () => ({
                total: 1,
                items: [{ id_stable: "finding-1", title: "Only finding" }],
            }),
        }),
    });

    const seen = [];
    const renderedFindingIds = new Set(["legacy-id"]);
    const dashboard = {
        scanId: 12,
        renderedFindingIds,
        updateFindingsLoadState() {},
        handleNewFinding(item) {
            seen.push(item.id_stable);
        },
    };

    await ScanDashboard.prototype.loadFindingsFromApi.call(dashboard, { reset: true, limit: 50, offset: 0 });

    assert.equal(tableBody.innerHTML, "");
    assert.equal(resultList.innerHTML, "");
    assert.equal(renderedFindingIds.size, 0);
    assert.deepEqual(seen, ["finding-1"]);
});

test("setupSocketListeners keeps core handlers registered and results_update scoped to the active scan", () => {
    const statusEl = createNode();
    const handlers = new Map();
    const emitted = [];
    let graphRefreshes = 0;

    const { ScanDashboard, sandbox } = loadScanDashboardClass({
        document: {
            getElementById(id) {
                if (id === "socket-status") return statusEl;
                return null;
            },
            querySelectorAll() { return []; },
            querySelector() { return null; },
            addEventListener() {},
        },
        initGraphData() {
            graphRefreshes += 1;
        },
    });

    assert.deepEqual(
        Array.from(ScanDashboard.internals.socketEvents, ([eventName]) => String(eventName)),
        [
            "new_log",
            "new_finding",
            "new_suggestion",
            "new_loot",
            "progress_update",
            "module_status",
            "pipeline_event",
        ]
    );

    const dashboard = {
        scanId: 77,
        socket: {
            on(eventName, handler) {
                handlers.set(eventName, handler);
            },
            emit(eventName, payload) {
                emitted.push({ eventName, payload });
            },
        },
        updateUIResults: [],
        newLogs: [],
        newFindings: [],
        updateUI(results) {
            this.updateUIResults.push(results);
        },
        handleNewLog(data) {
            this.newLogs.push(data);
        },
        handleNewFinding(data) {
            this.newFindings.push(data);
        },
        handleNewSuggestion() {},
        handleNewLoot() {},
        handleProgressUpdate() {},
        handleModuleStatus() {},
        handlePipelineEvent() {},
    };

    ScanDashboard.prototype.setupSocketListeners.call(dashboard);

    handlers.get("connect")();
    assert.equal(statusEl.innerText, "connected");
    assert.equal(statusEl.className, "badge bg-success");
    assert.deepEqual(
        emitted.map((entry) => ({ eventName: String(entry.eventName), payload: { scan_id: Number(entry.payload.scan_id) } })),
        [{ eventName: "join_scan", payload: { scan_id: 77 } }]
    );

    handlers.get("results_update")({ scan_id: 5, results: { findings: ["skip"] } });
    handlers.get("results_update")({ scan_id: 77, results: { findings: ["keep"] } });
    assert.deepEqual(dashboard.updateUIResults, [{ findings: ["keep"] }]);

    handlers.get("new_log")({ scan_id: 77, message: "log" });
    handlers.get("new_finding")({ scan_id: 77, id_stable: "f-1" });
    assert.deepEqual(dashboard.newLogs, [{ scan_id: 77, message: "log" }]);
    assert.deepEqual(dashboard.newFindings, [{ scan_id: 77, id_stable: "f-1" }]);

    handlers.get("graph_updated")({ scan_id: 1 });
    handlers.get("graph_updated")({ scan_id: 77 });
    assert.equal(graphRefreshes, 1);

    handlers.get("connect_error")(new Error("offline"));
    assert.equal(statusEl.innerText, "offline");
    assert.equal(statusEl.className, "badge bg-danger");

    handlers.get("disconnect")();
    assert.equal(statusEl.innerText, "reconnecting...");
    assert.equal(statusEl.className, "badge bg-warning");

    assert.equal(sandbox.window.document.getElementById("socket-status"), statusEl);
});

test("updateAuditJourney keeps gate counts and alert classes synchronized with the derived summary", () => {
    const nodes = {
        "audit-stage-validation": createNode(),
        "audit-stage-correlation": createNode(),
        "audit-gate-total": createNode(),
        "audit-gate-validated": createNode(),
        "audit-gate-missing-proof": createNode(),
        "audit-gate-missing-command": createNode(),
    };

    const { ScanDashboard } = loadScanDashboardClass({
        document: {
            getElementById(id) {
                return nodes[id] || null;
            },
            querySelectorAll() { return []; },
            querySelector() { return null; },
            addEventListener() {},
        },
    });

    const dashboard = {
        deriveAuditJourney() {
            return {
                stageMap: {
                    validation: "in-progress",
                    correlation: "done",
                },
                gates: {
                    total: 4,
                    validated: 1,
                    missingProof: 2,
                    missingCommand: 0,
                },
            };
        },
        setAuditStageState: ScanDashboard.prototype.setAuditStageState,
    };

    ScanDashboard.prototype.updateAuditJourney.call(dashboard, {});

    assert.equal(nodes["audit-stage-validation"].classList.contains("in-progress"), true);
    assert.equal(nodes["audit-stage-correlation"].classList.contains("done"), true);
    assert.equal(nodes["audit-gate-total"].innerText, "4");
    assert.equal(nodes["audit-gate-validated"].innerText, "1");
    assert.equal(nodes["audit-gate-missing-proof"].innerText, "2");
    assert.equal(nodes["audit-gate-missing-proof"].classList.contains("text-danger"), true);
    assert.equal(nodes["audit-gate-missing-proof"].classList.contains("text-success"), false);
    assert.equal(nodes["audit-gate-missing-command"].innerText, "0");
    assert.equal(nodes["audit-gate-missing-command"].classList.contains("text-success"), true);
    assert.equal(nodes["audit-gate-missing-command"].classList.contains("text-danger"), false);
});
