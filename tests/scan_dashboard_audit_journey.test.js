const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function createSandbox() {
    const window = {};
    const document = {
        getElementById() { return null; },
        querySelectorAll() { return []; },
        querySelector() { return null; },
        addEventListener() {},
    };

    return {
        console,
        window,
        document,
        navigator: { clipboard: { writeText() {} } },
        io() { return { on() {}, emit() {} }; },
        bootstrap: { Tab: { getOrCreateInstance() { return { show() {} }; } } },
        setTimeout,
        clearTimeout,
        fetch: async () => ({ ok: true, json: async () => ({ items: [], total: 0 }) }),
    };
}

function loadScanDashboardClass() {
    const source = fs.readFileSync(
        path.join(__dirname, "../ui/web/static/js/scan_dashboard.js"),
        "utf8"
    );
    const sandbox = createSandbox();
    sandbox.window.document = sandbox.document;
    sandbox.globalThis = sandbox;
    vm.runInNewContext(`${source}\nthis.__ScanDashboard = ScanDashboard;`, sandbox, {
        filename: "scan_dashboard.js",
    });
    assert.equal(
        typeof sandbox.__ScanDashboard,
        "function",
        "ScanDashboard class was not exposed after evaluating scan_dashboard.js"
    );
    return sandbox.__ScanDashboard;
}

test("deriveAuditJourney keeps validation and correlation strict when scan is merely completed with findings", () => {
    const ScanDashboard = loadScanDashboardClass();
    const dashboard = {
        targetIdentifier: "example.org",
        getFindingResultState(finding) {
            return String(finding?.result_state || "").toLowerCase() || "observation";
        },
        getFindingValidationStatus(finding) {
            return String(finding?.metadata?.validation?.status || finding?.validation_status || "").toLowerCase() || "not_run";
        },
        getFindingPrimaryCommand() {
            return "";
        },
        hasMeaningfulProof(finding) {
            return Boolean(
                finding?.evidence ||
                finding?.raw_output ||
                finding?.request ||
                finding?.response ||
                finding?.metadata?.validation?.artifact ||
                finding?.metadata?.reproducibility?.response_excerpt
            );
        },
        isMeaningfulValue(value) {
            return Boolean(String(value || "").trim());
        },
    };

    const summary = ScanDashboard.prototype.deriveAuditJourney.call(dashboard, {
        status: "completed",
        target: "example.org",
        findings: [
            {
                title: "Observed surface",
                severity: "medium",
                metadata: {},
            },
        ],
        attack_plan: [],
    });

    assert.equal(summary.gates.validated, 0);
    assert.equal(summary.stageMap.validation, "in-progress");
    assert.equal(summary.stageMap.correlation, "in-progress");
    assert.notEqual(summary.stageMap.validation, "done");
    assert.notEqual(summary.stageMap.correlation, "done");
});
