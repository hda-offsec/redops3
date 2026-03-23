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

test("auditJourney inspectFinding derives validation, correlation, and gate flags without changing inputs", () => {
    const ScanDashboard = loadScanDashboardClass();
    const auditJourney = ScanDashboard.internals.auditJourney;
    const dashboard = {
        getFindingResultState(finding) {
            return String(finding?.result_state || "").toLowerCase() || "observation";
        },
        getFindingValidationStatus(finding) {
            return String(finding?.metadata?.validation?.status || finding?.validation_status || "").toLowerCase() || "not_run";
        },
        getFindingPrimaryCommand(finding) {
            return finding?.metadata?.validation?.command || "";
        },
        hasMeaningfulProof(finding) {
            return Boolean(finding?.metadata?.validation?.artifact || finding?.evidence);
        },
        isMeaningfulValue(value) {
            return Boolean(String(value || "").trim());
        },
    };
    const finding = {
        severity: "high",
        category: "attack_chain",
        metadata: {
            validation: {
                status: "success",
                command: "curl https://example.org/check",
                artifact: "proof.txt",
            },
        },
    };

    const inspected = auditJourney.inspectFinding(dashboard, finding);

    assert.equal(inspected.state, "observation");
    assert.equal(inspected.validationStatus, "success");
    assert.equal(inspected.isHighSeverity, true);
    assert.equal(inspected.hasProof, true);
    assert.equal(inspected.hasCommand, true);
    assert.equal(inspected.isValidated, true);
    assert.equal(inspected.isCorrelated, true);
});

test("auditJourney deriveJourneyInputs normalizes results before downstream stage derivation", () => {
    const ScanDashboard = loadScanDashboardClass();
    const auditJourney = ScanDashboard.internals.auditJourney;

    const inputs = auditJourney.deriveJourneyInputs({
        status: "Completed",
        progress: { current_phase: "Validation Sweep" },
        phases: {
            recon: { open_ports: [{ port: 443 }] },
            dns: { subdomains: ["api.example.org"] },
            enum: {
                katana: { "443": ["/health", "/ready"] },
                api: { discovered_endpoints: ["/v1/users"] },
            },
        },
        findings: [{ id_stable: "f-1" }],
        attack_plan: [{ id: "ap-1" }],
    }, "fallback.example.org");

    assert.equal(inputs.status, "completed");
    assert.equal(inputs.progressPhase, "validation sweep");
    assert.equal(inputs.target, "fallback.example.org");
    assert.equal(inputs.reconPorts.length, 1);
    assert.equal(inputs.dnsSubs.length, 1);
    assert.equal(inputs.enumEndpointCount, 3);
    assert.equal(inputs.findings.length, 1);
    assert.equal(inputs.attackPlan.length, 1);
});

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

test("deriveAuditJourney preserves audit gates and completed-stage transitions with extracted helpers", () => {
    const ScanDashboard = loadScanDashboardClass();
    const dashboard = {
        targetIdentifier: "example.org",
        getFindingResultState(finding) {
            return String(finding?.result_state || "").toLowerCase() || "observation";
        },
        getFindingValidationStatus(finding) {
            return String(finding?.metadata?.validation?.status || finding?.validation_status || "").toLowerCase() || "not_run";
        },
        getFindingPrimaryCommand(finding) {
            return finding?.metadata?.validation?.command || "";
        },
        hasMeaningfulProof(finding) {
            return Boolean(finding?.metadata?.validation?.artifact || finding?.evidence);
        },
        isMeaningfulValue(value) {
            return Boolean(String(value || "").trim());
        },
    };

    const summary = ScanDashboard.prototype.deriveAuditJourney.call(dashboard, {
        status: "completed",
        progress: { current_phase: "report generation" },
        phases: {
            recon: { open_ports: [{ port: 443 }] },
            enum: { api: { endpoints: ["/v1/admin"] } },
        },
        findings: [
            {
                title: "Validated finding",
                severity: "high",
                category: "attack_chain",
                metadata: {
                    validation: {
                        status: "success",
                        command: "curl https://example.org/validate",
                        artifact: "artifact.txt",
                    },
                },
            },
        ],
        attack_plan: [],
    });

    assert.equal(summary.gates.total, 1);
    assert.equal(summary.gates.validated, 1);
    assert.equal(summary.gates.missingProof, 0);
    assert.equal(summary.gates.missingCommand, 0);
    assert.equal(summary.stageMap.cadrage, "done");
    assert.equal(summary.stageMap.recon, "done");
    assert.equal(summary.stageMap.enum, "done");
    assert.equal(summary.stageMap.detection, "done");
    assert.equal(summary.stageMap.validation, "done");
    assert.equal(summary.stageMap.correlation, "done");
    assert.equal(summary.stageMap.reporting, "done");
    assert.equal(summary.stageMap.closure, "done");
});
