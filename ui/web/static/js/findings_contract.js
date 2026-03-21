/*
 * Mirrored Findings UI contract for live/frontend rendering.
 *
 * This file intentionally mirrors `core/findings_ui_contract.py`.
 * Keep canonical `_ui` fields, searchText composition, and command/URL/
 * validation priority rules aligned with the backend.
 */

(function (global) {
    const INVALID_TEXT_MARKERS = new Set(["", "none", "n/a", "na", "null", "todo", "tbd", "manual", "ui"]);
    const RESULT_STATE_MAP = {
        observation: "observation",
        observed: "observation",
        heuristic: "heuristic",
        signal: "heuristic",
        correlation: "correlation",
        correlated: "correlation",
        validation: "validation",
        validated: "validation",
        confirmed: "confirmed",
        operator_confirmed: "confirmed",
        confirmed_active: "confirmed",
        rejected: "rejected",
        invalidated: "rejected",
        operator_rejected: "rejected",
    };
    const VALIDATION_STATUS_MAP = {
        success: "success",
        succeeded: "success",
        failed: "failed",
        failure: "failed",
        error: "failed",
        uncertain: "uncertain",
        unknown: "uncertain",
        not_run: "not_run",
        "not-executed": "not_run",
    };
    const EXPLICIT_COMMAND_PREFIXES = new Set([
        "aws",
        "bash",
        "cmd",
        "curl",
        "dalfox",
        "dig",
        "dirsearch",
        "docker",
        "feroxbuster",
        "ffuf",
        "ghauri",
        "gobuster",
        "httpx",
        "java",
        "jq",
        "katana",
        "kubectl",
        "nc",
        "nikto",
        "nmap",
        "node",
        "nslookup",
        "nuclei",
        "openssl",
        "perl",
        "php",
        "powershell",
        "pwsh",
        "python",
        "python3",
        "ruby",
        "sh",
        "sqlmap",
        "ssh",
        "ssh-audit",
        "telnet",
        "wget",
        "whois",
        "wpscan",
        "zsh",
    ]);
    const COMMAND_SCRIPT_RE = /^[A-Za-z0-9_.-]+\.(?:pl|ps1|py|rb|sh)$/;
    const VALIDATED_RESULT_STATES = new Set(["validation", "confirmed"]);
    const CANONICAL_UI_FIELDS = [
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
    ];
    const SEARCH_TEXT_FIELD_SOURCES = [
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
    ];

    function asDict(value) {
        return value && typeof value === "object" && !Array.isArray(value) ? value : {};
    }

    function cleanText(value) {
        if (value === null || value === undefined) return "";
        if (typeof value === "string") return value.trim();
        return String(value).trim();
    }

    function isMeaningfulText(value) {
        if (value === null || value === undefined) return false;
        if (Array.isArray(value)) return value.some((item) => item !== null && item !== "");
        if (typeof value === "object") return Object.keys(value).length > 0;
        const normalized = cleanText(value);
        if (!normalized) return false;
        const lowered = normalized.toLowerCase();
        if (INVALID_TEXT_MARKERS.has(lowered)) return false;
        if (normalized === "{}" || normalized === "[]" || normalized === "\"\"") return false;
        return true;
    }

    function isMeaningfulLocator(value) {
        if (!isMeaningfulText(value)) return false;
        return !cleanText(value).toLowerCase().startsWith("port:");
    }

    function firstMeaningful(values, options = {}) {
        const check = options.locator ? isMeaningfulLocator : isMeaningfulText;
        for (const value of values) {
            if (check(value)) return cleanText(value);
        }
        return "";
    }

    function normalizeValidationStatus(finding) {
        const metadata = asDict(finding.metadata);
        const validation = asDict(metadata.validation);
        const candidates = [validation.status, metadata.validation_status, finding.validation_status];
        for (const candidate of candidates) {
            const lowered = cleanText(candidate).toLowerCase();
            if (!lowered) continue;
            const mapped = VALIDATION_STATUS_MAP[lowered];
            if (mapped) return mapped;
        }
        return "not_run";
    }

    function normalizeResultState(finding) {
        const metadata = asDict(finding.metadata);
        const validation = asDict(metadata.validation);
        const candidates = [
            validation.result_state,
            finding.result_state,
            metadata.result_state,
            validation.status,
            metadata.validation_status,
            finding.validation_status,
        ];
        for (const candidate of candidates) {
            const lowered = cleanText(candidate).toLowerCase();
            if (!lowered) continue;
            const mapped = RESULT_STATE_MAP[lowered];
            if (mapped) return mapped;
        }
        return "observation";
    }

    function extractCommandCandidate(value) {
        const command = cleanText(value);
        if (!isMeaningfulText(command)) return "";
        return command;
    }

    function isSafeLegacyCommand(value) {
        const candidate = cleanText(value);
        if (!isMeaningfulText(candidate)) return false;
        const firstLine = candidate
            .split(/\r?\n/)
            .map((line) => line.trim())
            .find(Boolean);
        if (!firstLine) return false;
        let normalized = firstLine;
        for (const prompt of ["$ ", "# ", "> "]) {
            if (normalized.startsWith(prompt)) {
                normalized = normalized.slice(prompt.length).trim();
                break;
            }
        }
        if (!normalized) return false;
        const token = (normalized.split(/\s+/)[0] || "").toLowerCase();
        if (EXPLICIT_COMMAND_PREFIXES.has(token)) return true;
        if (token.startsWith("./") || token.startsWith("/") || token.startsWith("~/")) return true;
        return COMMAND_SCRIPT_RE.test(token);
    }

    function getValidation(finding) {
        return asDict(asDict(finding.metadata).validation);
    }

    function getReproducibility(finding) {
        return asDict(asDict(finding.metadata).reproducibility);
    }

    function getFindingPrimaryCommand(finding) {
        const validation = getValidation(finding);
        const reproducibility = getReproducibility(finding);
        const structuredCandidates = [
            validation.command,
            reproducibility.command,
            finding.repro_command,
        ];
        for (const candidate of structuredCandidates) {
            const command = extractCommandCandidate(candidate);
            if (command) return command;
        }
        const fallback = cleanText(finding.reproduction);
        return isSafeLegacyCommand(fallback) ? fallback : "";
    }

    function getFindingPrimaryUrl(finding) {
        const validation = getValidation(finding);
        const reproducibility = getReproducibility(finding);
        return firstMeaningful(
            [validation.target, reproducibility.url, finding.endpoint, finding.target],
            { locator: true }
        );
    }

    function getFindingVersionInfo(finding) {
        const metadata = asDict(finding.metadata);
        return firstMeaningful([
            finding.version,
            metadata.version,
            metadata.service_version,
            metadata.detected_version,
            metadata.component_version,
        ]);
    }

    function hasMeaningfulEvidence(finding) {
        const validation = getValidation(finding);
        const reproducibility = getReproducibility(finding);
        const evidenceCandidates = [
            finding.request,
            finding.response,
            finding.evidence,
            finding.raw_output,
            finding.artifact,
            validation.artifact,
            reproducibility.request_excerpt,
            reproducibility.response_excerpt,
        ];
        return evidenceCandidates.some((candidate) => isMeaningfulText(candidate));
    }

    function buildFindingSearchTextFields(finding) {
        const metadata = asDict(finding.metadata);
        const validationStatus = normalizeValidationStatus(finding);
        const resultState = normalizeResultState(finding);
        const primaryUrl = getFindingPrimaryUrl(finding);
        const provider = firstMeaningful([finding.provider, metadata.provider]);
        const component = firstMeaningful([finding.component, metadata.component]);
        const version = getFindingVersionInfo(finding);
        const portState = isMeaningfulText(metadata.port_state) ? cleanText(metadata.port_state).toLowerCase() : "";
        const isValidated = validationStatus === "success" || VALIDATED_RESULT_STATES.has(resultState);
        return [
            finding.title,
            finding.tool_source,
            finding.tool,
            finding.source,
            finding.category,
            primaryUrl,
            finding.target,
            provider,
            component,
            version,
            validationStatus,
            resultState,
            isValidated ? "validated" : "",
            finding.parameter,
            portState,
        ];
    }

    function buildFindingSearchText(finding) {
        const tokens = [];
        const seen = new Set();
        for (const field of buildFindingSearchTextFields(finding)) {
            const normalized = cleanText(field).toLowerCase();
            if (!isMeaningfulText(normalized)) continue;
            if (seen.has(normalized)) continue;
            seen.add(normalized);
            tokens.push(normalized);
        }
        return tokens.join(" ");
    }

    function buildFindingUiState(finding) {
        const metadata = asDict(finding.metadata);
        const validationStatus = normalizeValidationStatus(finding);
        const resultState = normalizeResultState(finding);
        const portState = isMeaningfulText(metadata.port_state) ? cleanText(metadata.port_state).toLowerCase() : "";
        const provider = firstMeaningful([finding.provider, metadata.provider]);
        const component = firstMeaningful([finding.component, metadata.component]);
        const version = getFindingVersionInfo(finding);
        const primaryCommand = getFindingPrimaryCommand(finding);
        const primaryUrl = getFindingPrimaryUrl(finding);
        const hasEvidence = hasMeaningfulEvidence(finding);
        const isValidated = validationStatus === "success" || VALIDATED_RESULT_STATES.has(resultState);

        const uiState = {
            validationStatus,
            resultState,
            primaryCommand,
            primaryUrl,
            provider,
            component,
            version,
            portState,
            hasEvidence,
            isValidated,
            searchText: buildFindingSearchText(finding),
        };
        return CANONICAL_UI_FIELDS.reduce((orderedState, fieldName) => {
            orderedState[fieldName] = uiState[fieldName];
            return orderedState;
        }, {});
    }

    function normalizeFindingRecord(finding) {
        if (!finding || typeof finding !== "object") return finding;
        const normalized = {
            ...finding,
            metadata: { ...asDict(finding.metadata) },
        };
        normalized._ui = buildFindingUiState(normalized);
        return normalized;
    }

    function getRowDataset(finding) {
        const normalized = normalizeFindingRecord(finding);
        return {
            title: cleanText(normalized.title).toLowerCase(),
            severity: cleanText(normalized.severity).toLowerCase(),
            tool: cleanText(normalized.tool_source || normalized.tool).toLowerCase(),
            source: cleanText(normalized.source || normalized.tool_source || normalized.tool).toLowerCase(),
            category: cleanText(normalized.category).toLowerCase(),
            portStatus: cleanText(normalized._ui.portState).toLowerCase(),
            validationStatus: cleanText(normalized._ui.validationStatus || "not_run").toLowerCase(),
            resultState: cleanText(normalized._ui.resultState || "observation").toLowerCase(),
            content: cleanText(normalized._ui.searchText).toLowerCase(),
        };
    }

    function applyRowDataset(row, finding) {
        if (!row) return row;
        const dataset = getRowDataset(finding);
        row.setAttribute("data-title", dataset.title);
        row.setAttribute("data-sev", dataset.severity);
        row.setAttribute("data-severity", dataset.severity);
        row.setAttribute("data-tool", dataset.tool);
        row.setAttribute("data-source", dataset.source);
        row.setAttribute("data-category", dataset.category);
        row.setAttribute("data-port-status", dataset.portStatus);
        row.setAttribute("data-validation-status", dataset.validationStatus);
        row.setAttribute("data-result-state", dataset.resultState);
        row.setAttribute("data-content", dataset.content);
        return row;
    }

    function parseSearchQuery(query) {
        const terms = { global: [] };
        const normalized = cleanText(query).toLowerCase();
        if (!normalized) return terms;
        for (const clause of normalized.split(/\s+/)) {
            if (!clause) continue;
            if (clause.includes(":")) {
                const parts = clause.split(":");
                const key = parts[0];
                const value = parts.slice(1).join(":");
                if (key && value) terms[key] = value;
                continue;
            }
            terms.global.push(clause);
        }
        return terms;
    }

    function buildFilterState(values = {}) {
        return {
            severityFilter: cleanText(values.severityFilter).toLowerCase(),
            categoryFilter: cleanText(values.categoryFilter).toLowerCase(),
            portStatusFilter: cleanText(values.portStatusFilter).toLowerCase(),
            terms: values.terms || parseSearchQuery(values.query || ""),
        };
    }

    function matchesDataset(dataset, filters) {
        const normalizedFilters = buildFilterState(filters);
        const severityFilter = normalizedFilters.severityFilter;
        const categoryFilter = normalizedFilters.categoryFilter;
        const portStatusFilter = normalizedFilters.portStatusFilter;
        const terms = normalizedFilters.terms;

        const dropdownSeverityMatch = !severityFilter || dataset.severity === severityFilter;
        const dropdownCategoryMatch = !categoryFilter || dataset.category === categoryFilter;
        const dropdownPortStatusMatch = !portStatusFilter || dataset.portStatus === portStatusFilter;

        let prefixMatch = true;
        if (terms.type && !dataset.category.includes(terms.type)) prefixMatch = false;
        const severityTerm = terms.sev || terms.severity;
        if (severityTerm && !dataset.severity.includes(severityTerm)) prefixMatch = false;
        if (terms.tool && !dataset.tool.includes(terms.tool)) prefixMatch = false;
        if (terms.source && !dataset.source.includes(terms.source)) prefixMatch = false;

        const statusTerm = cleanText(terms.status || terms.validation || terms.state).toLowerCase();
        if (statusTerm) {
            const isValidated = VALIDATED_RESULT_STATES.has(dataset.resultState) || dataset.validationStatus === "success";
            const statusMatch = dataset.validationStatus.includes(statusTerm)
                || dataset.resultState.includes(statusTerm)
                || (statusTerm === "validated" && isValidated)
                || (statusTerm === "success" && isValidated);
            if (!statusMatch) prefixMatch = false;
        }

        let globalMatch = true;
        if (terms.global.length > 0) {
            globalMatch = terms.global.every((word) => dataset.content.includes(word));
        }

        return dropdownSeverityMatch && dropdownCategoryMatch && dropdownPortStatusMatch && prefixMatch && globalMatch;
    }

    function getDatasetFromRow(row) {
        return {
            title: cleanText(row.getAttribute("data-title")).toLowerCase(),
            severity: cleanText(row.getAttribute("data-severity") || row.getAttribute("data-sev")).toLowerCase(),
            tool: cleanText(row.getAttribute("data-tool")).toLowerCase(),
            source: cleanText(row.getAttribute("data-source") || row.getAttribute("data-tool")).toLowerCase(),
            category: cleanText(row.getAttribute("data-category")).toLowerCase(),
            portStatus: cleanText(row.getAttribute("data-port-status")).toLowerCase(),
            validationStatus: cleanText(row.getAttribute("data-validation-status") || "not_run").toLowerCase(),
            resultState: cleanText(row.getAttribute("data-result-state") || "observation").toLowerCase(),
            content: cleanText(row.getAttribute("data-content")).toLowerCase(),
        };
    }

    function readTableFilterState(options = {}) {
        const searchElement = global.document.getElementById(options.searchId || "findings-search");
        const severityElement = global.document.getElementById(options.severityId || "findings-severity-filter");
        const categoryElement = global.document.getElementById(options.categoryId || "findings-category-filter");
        const portStatusElement = global.document.getElementById(options.portStatusId || "findings-port-status-filter");
        return buildFilterState({
            query: searchElement ? searchElement.value : "",
            severityFilter: severityElement ? severityElement.value : "",
            categoryFilter: categoryElement ? categoryElement.value : "",
            portStatusFilter: portStatusElement ? portStatusElement.value : "",
        });
    }

    function updateTableFilterUi(options = {}, visibleCount = 0) {
        const label = global.document.getElementById(options.labelId || "findings-total-label");
        if (label) label.textContent = `${visibleCount} findings`;

        const emptyState = global.document.getElementById(options.emptyStateId || "findings-empty-state");
        if (emptyState) emptyState.style.display = visibleCount === 0 ? "" : "none";
    }

    function applyTableFilters(options = {}) {
        const rows = global.document.querySelectorAll(options.rowSelector || "#findings-table-body .finding-row");
        const filters = readTableFilterState(options);

        let visibleCount = 0;
        rows.forEach((row) => {
            const isVisible = matchesDataset(getDatasetFromRow(row), filters);
            row.style.display = isVisible ? "" : "none";
            if (isVisible) visibleCount += 1;
        });

        updateTableFilterUi(options, visibleCount);
        return visibleCount;
    }

    function encodeDataValue(value) {
        if (!isMeaningfulText(value)) return "";
        return encodeURIComponent(value);
    }

    function decodeDataValue(value) {
        if (!value) return "";
        try {
            return decodeURIComponent(value);
        } catch (_) {
            return value;
        }
    }

    const contractApi = {
        buildFilterState,
        buildFindingSearchText,
        buildFindingSearchTextFields,
        buildFindingUiState,
        decodeDataValue,
        encodeDataValue,
        getFindingPrimaryCommand,
        getFindingPrimaryUrl,
        getFindingVersionInfo,
        getReproducibility,
        getRowDataset,
        getValidation,
        hasMeaningfulEvidence,
        isMeaningfulText,
        matchesDataset,
        normalizeFindingRecord,
        normalizeResultState,
        normalizeValidationStatus,
        parseSearchQuery,
    };
    const domApi = {
        applyRowDataset,
        applyTableFilters,
        getDatasetFromRow,
        readTableFilterState,
        updateTableFilterUi,
    };
    const api = {
        ...contractApi,
        ...domApi,
        contract: contractApi,
        dom: domApi,
        constants: {
            canonicalUiFields: [...CANONICAL_UI_FIELDS],
            searchTextFieldSources: [...SEARCH_TEXT_FIELD_SOURCES],
            validatedResultStates: [...VALIDATED_RESULT_STATES],
        },
    };

    global.RedOpsFindings = api;
    if (typeof module !== "undefined" && module.exports) {
        module.exports = api;
    }
})(typeof window !== "undefined" ? window : globalThis);
