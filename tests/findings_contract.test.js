const test = require("node:test");
const assert = require("node:assert/strict");

const findingsContract = require("../ui/web/static/js/findings_contract.js");

function structuredFinding() {
    return {
        id: "db-1",
        id_stable: "stable-1",
        title: "GraphQL schema leak",
        severity: "high",
        confidence: "high",
        tool_source: "nuclei",
        tool: "nuclei",
        source: "nuclei",
        module: "graphql_scanner",
        category: "api",
        description: "Introspection is still reachable on the public GraphQL endpoint.",
        endpoint: "https://example.org/api/graphql",
        target: "https://example.org/api/graphql",
        parameter: "query",
        raw_output: "HTTP/1.1 200 OK\n{\"data\":{\"__schema\":{\"queryType\":{\"name\":\"Query\"}}}}",
        evidence: "Schema introspection returned the Query type.",
        reproduction: "Validate that introspection stays enabled before blocking public access.",
        remediation: "Disable introspection on public environments and restrict the endpoint.",
        request: "GET /api/graphql?query={__schema} HTTP/1.1",
        response: "HTTP/1.1 200 OK\ncontent-type: application/json",
        impact: "Public schema exposure accelerates targeted abuse and enumeration.",
        references: [
            "https://owasp.org/www-project-graphql-security-cheat-sheet/",
        ],
        screenshot_path: "loot/graphql-proof.png",
        metadata: {
            provider: "aws",
            component: "apigateway",
            version: "2024.1",
            versions: ["graphql-js 16.8.1"],
            port_state: "open",
            impact_area: "API Gateway",
            artifacts: [{ header: "x-powered-by", value: "graphql-js" }],
            references: ["https://graphql.org/learn/security/"],
            validation: {
                status: "success",
                result_state: "confirmed",
                command: "curl -isk 'https://example.org/api/graphql?query={__schema}'",
                target: "https://example.org/api/graphql",
                artifact: "HTTP/1.1 200 OK",
            },
            reproducibility: {
                command: "nuclei -u https://fallback.example.org/graphql",
                url: "https://fallback.example.org/graphql",
                request_excerpt: "GET /api/graphql HTTP/1.1",
                response_excerpt: "HTTP/1.1 200 OK\nx-powered-by: graphql-js",
            },
        },
    };
}

function makeRow() {
    return {
        attrs: {},
        style: {},
        getAttribute(name) {
            return this.attrs[name] || "";
        },
        setAttribute(name, value) {
            this.attrs[name] = String(value);
        },
    };
}

test("normalizes structured findings with canonical UI fields", () => {
    const finding = findingsContract.normalizeFindingRecord(structuredFinding());

    assert.deepEqual(findingsContract.constants.canonicalUiFields, [
        "validationStatus",
        "resultState",
        "primaryCommand",
        "primaryUrl",
        "provider",
        "component",
        "version",
        "portState",
        "hasEvidence",
        "isValidated",
        "searchText",
    ]);
    assert.deepEqual(findingsContract.constants.searchTextFieldSources, [
        "title",
        "tool_source",
        "tool",
        "source",
        "category",
        "primary_url",
        "target",
        "provider",
        "component",
        "version",
        "validation_status",
        "result_state",
        "validated_token",
        "parameter",
        "port_state",
    ]);
    assert.deepEqual(findingsContract.constants.observedVersionFieldSources, [
        "version",
        "metadata.version",
        "metadata.service_version",
        "metadata.detected_version",
        "metadata.component_version",
    ]);
    assert.deepEqual(findingsContract.constants.detailCommandBlockSources, [
        "validation.command",
        "reproducibility.command",
        "repro_command",
    ]);
    assert.deepEqual(findingsContract.constants.detailEvidenceBlockSources, [
        "validation.artifact",
        "request",
        "response",
        "raw_output",
        "evidence",
    ]);
    assert.deepEqual(findingsContract.constants.detailStateFields, [
        "summary",
        "technicalContext",
        "commandExecuted",
        "commandBlocks",
        "validationGuidance",
        "target",
        "observedVersions",
        "evidenceBlocks",
        "rawOutput",
        "interpretation",
        "severity",
        "confidence",
        "remediation",
        "references",
        "artifacts",
    ]);
    assert.equal(typeof findingsContract.contract.matchesDataset, "function");
    assert.equal(typeof findingsContract.dom.applyTableFilters, "function");
    assert.equal(finding._ui.primaryCommand, "curl -isk 'https://example.org/api/graphql?query={__schema}'");
    assert.equal(finding._ui.primaryUrl, "https://example.org/api/graphql");
    assert.equal(finding._ui.validationStatus, "success");
    assert.equal(finding._ui.resultState, "confirmed");
    assert.equal(finding._ui.hasEvidence, true);
    assert.equal(finding._ui.isValidated, true);
    assert.equal(
        finding._ui.searchText,
        "graphql schema leak nuclei api https://example.org/api/graphql aws apigateway 2024.1 success confirmed validated query open"
    );
});

test("legacy flat exports remain available and aligned with namespaced helpers", () => {
    assert.equal(findingsContract.normalizeFindingRecord, findingsContract.contract.normalizeFindingRecord);
    assert.equal(findingsContract.applyTableFilters, findingsContract.dom.applyTableFilters);
    assert.equal(findingsContract.applyRowDataset, findingsContract.dom.applyRowDataset);
    assert.deepEqual(
        Object.keys(findingsContract.buildFindingUiState(structuredFinding())),
        findingsContract.constants.canonicalUiFields
    );
});

test("builds rich detail state without dropping commands, versions, evidence, or references", () => {
    const detail = findingsContract.contract.buildFindingDetailState(structuredFinding());

    assert.equal(detail.commandExecuted, "curl -isk 'https://example.org/api/graphql?query={__schema}'");
    assert.equal(detail.target, "https://example.org/api/graphql");
    assert.deepEqual(detail.observedVersions, ["2024.1", "graphql-js 16.8.1"]);
    assert.deepEqual(Object.keys(detail), findingsContract.constants.detailStateFields);
    assert.deepEqual(
        detail.commandBlocks.map((block) => block.key),
        ["validation_command", "reproducibility_command"]
    );
    assert.deepEqual(
        detail.evidenceBlocks.map((block) => block.key),
        ["validation_artifact", "request", "response", "raw_output", "evidence"]
    );
    assert.equal(
        detail.validationGuidance,
        "Validate that introspection stays enabled before blocking public access."
    );
    assert.equal(detail.remediation, "Disable introspection on public environments and restrict the endpoint.");
    assert.deepEqual(detail.references, [
        "https://owasp.org/www-project-graphql-security-cheat-sheet/",
        "https://graphql.org/learn/security/",
    ]);
    assert.equal(detail.artifacts[0].kind, "image");
    assert.equal(detail.artifacts[1].kind, "text");
});

test("keeps command blocks when validation and reproducibility share the same command text", () => {
    const finding = structuredFinding();
    finding.metadata.reproducibility.command = finding.metadata.validation.command;

    const detail = findingsContract.contract.buildFindingDetailState(finding);

    assert.deepEqual(
        detail.commandBlocks.map((block) => block.key),
        ["validation_command", "reproducibility_command"]
    );
    assert.deepEqual(
        detail.commandBlocks.map((block) => block.value),
        [
            "curl -isk 'https://example.org/api/graphql?query={__schema}'",
            "curl -isk 'https://example.org/api/graphql?query={__schema}'",
        ]
    );
});

test("renders shared finding detail html with analyst-first sections and copy-safe actions", () => {
    const html = findingsContract.dom.buildFindingDetailHtml(structuredFinding());

    assert.match(html, /Operational Summary/);
    assert.match(html, /Technical Context/);
    assert.match(html, /Command & Validation/);
    assert.match(html, /Evidence/);
    assert.match(html, /Raw Output/);
    assert.match(html, /Remediation/);
    assert.match(html, /References & Artifacts/);
    assert.match(html, /Validate/);
    assert.match(html, /Copy command/);
    assert.match(html, /graphql-js 16\.8\.1/);
    assert.match(html, /data-copy-encoded=/);
});

test("normalization is non mutating and preserves the input finding", () => {
    const original = structuredFinding();
    const snapshot = JSON.parse(JSON.stringify(original));

    const normalized = findingsContract.normalizeFindingRecord(original);

    assert.notStrictEqual(normalized, original);
    assert.deepEqual(original, snapshot);
    assert.ok(normalized._ui);
    assert.equal(Object.prototype.hasOwnProperty.call(original, "_ui"), false);
});

test("does not promote narrative reproduction text into a validation command", () => {
    const finding = findingsContract.normalizeFindingRecord({
        title: "Manual review note",
        tool_source: "manual",
        category: "review",
        reproduction: "Open the admin page in a browser and inspect the banner manually.",
        metadata: {},
    });

    assert.equal(finding._ui.primaryCommand, "");
    assert.equal(finding._ui.isValidated, false);
});

test("pure matching keeps filter compatibility for status, tool, type, and severity", () => {
    const dataset = findingsContract.contract.getRowDataset(structuredFinding());

    assert.equal(
        findingsContract.contract.matchesDataset(
            dataset,
            findingsContract.contract.buildFilterState({ query: "status:validated type:api sev:high" })
        ),
        true
    );
    assert.equal(
        findingsContract.contract.matchesDataset(
            dataset,
            findingsContract.contract.buildFilterState({ query: "tool:manual" })
        ),
        false
    );
});

test("encodes and decodes copy and validate values with special characters", () => {
    const command = "curl -isk 'https://example.org/debug?x=<tag>&y=1' -H \"X-Test: a;b\"";
    const encoded = findingsContract.encodeDataValue(command);

    assert.ok(encoded.includes("%3Ctag%3E"));
    assert.equal(findingsContract.decodeDataValue(encoded), command);
});

test("applies canonical row datasets and toggles empty state deterministically", () => {
    const matchingRow = makeRow();
    findingsContract.applyRowDataset(matchingRow, structuredFinding());

    const narrativeRow = makeRow();
    findingsContract.applyRowDataset(narrativeRow, {
        title: "Manual review note",
        severity: "medium",
        tool_source: "manual",
        category: "review",
        metadata: {},
    });

    const searchInput = { value: "" };
    const severityFilter = { value: "" };
    const categoryFilter = { value: "" };
    const portStatusFilter = { value: "" };
    const label = { textContent: "" };
    const emptyState = { style: { display: "none" } };

    const originalDocument = global.document;
    try {
        global.document = {
            getElementById(id) {
                return {
                    "findings-search": searchInput,
                    "findings-severity-filter": severityFilter,
                    "findings-category-filter": categoryFilter,
                    "findings-port-status-filter": portStatusFilter,
                    "findings-total-label": label,
                    "findings-empty-state": emptyState,
                }[id] || null;
            },
            querySelectorAll(selector) {
                assert.equal(selector, "#findings-table-body .finding-row");
                return [matchingRow, narrativeRow];
            },
        };

        let visible = findingsContract.dom.applyTableFilters();
        assert.equal(visible, 2);
        assert.equal(label.textContent, "2 findings");
        assert.equal(emptyState.style.display, "none");

        searchInput.value = "aws status:validated";
        visible = findingsContract.dom.applyTableFilters();
        assert.equal(visible, 1);
        assert.equal(matchingRow.style.display, "");
        assert.equal(narrativeRow.style.display, "none");
        assert.equal(label.textContent, "1/2 findings");
        assert.equal(emptyState.style.display, "none");

        searchInput.value = "status:validated tool:manual";
        const noneVisible = findingsContract.dom.applyTableFilters();
        assert.equal(noneVisible, 0);
        assert.equal(label.textContent, "0/2 findings");
        assert.equal(emptyState.style.display, "");
    } finally {
        global.document = originalDocument;
    }
});
