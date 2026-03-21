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
        category: "api",
        endpoint: "https://example.org/api/graphql",
        target: "https://example.org/api/graphql",
        parameter: "query",
        metadata: {
            provider: "aws",
            component: "apigateway",
            version: "2024.1",
            port_state: "open",
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
                response_excerpt: "HTTP/1.1 200 OK",
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

    const searchInput = { value: "aws status:validated" };
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

        const visible = findingsContract.applyTableFilters();
        assert.equal(visible, 1);
        assert.equal(matchingRow.style.display, "");
        assert.equal(narrativeRow.style.display, "none");
        assert.equal(label.textContent, "1 findings");
        assert.equal(emptyState.style.display, "none");

        searchInput.value = "status:validated tool:manual";
        const noneVisible = findingsContract.applyTableFilters();
        assert.equal(noneVisible, 0);
        assert.equal(label.textContent, "0 findings");
        assert.equal(emptyState.style.display, "");
    } finally {
        global.document = originalDocument;
    }
});
