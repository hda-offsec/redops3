/*
 * Mirrored Findings UI contract for live/frontend rendering.
 *
 * This file intentionally mirrors `core/findings_ui_contract.py`.
 * Keep canonical `_ui` fields, searchText composition, and command/URL/
 * validation priority rules aligned with the backend.
 */

(function (global) {
    const INVALID_TEXT_MARKERS = new Set(["", "none", "n/a", "na", "null", "todo", "tbd", "manual", "ui"]);
    const GENERIC_TITLES = new Set(["", "finding", "untitled finding", "unknown finding", "candidate finding"]);
    const RECOMMENDATION_CATEGORIES = new Set(["attack_plan", "next_step", "mission_prep", "objective_path"]);
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
        "visibleTruth",
        "visibleTruthLabel",
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
        "visible_truth",
    ];
    const OBSERVED_VERSION_FIELD_SOURCES = [
        "version",
        "metadata.version",
        "metadata.service_version",
        "metadata.detected_version",
        "metadata.component_version",
    ];
    const DETAIL_COMMAND_BLOCK_SOURCES = [
        "validation.command",
        "reproducibility.command",
        "repro_command",
    ];
    const DETAIL_EVIDENCE_BLOCK_SOURCES = [
        "validation.artifact",
        "request",
        "response",
        "raw_output",
        "evidence",
    ];
    const DETAIL_CONTRACT_FIELDS = [
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
    ];

    function asDict(value) {
        return value && typeof value === "object" && !Array.isArray(value) ? value : {};
    }

    function cleanText(value) {
        if (value === null || value === undefined) return "";
        if (typeof value === "string") return value.trim();
        return String(value).trim();
    }

    function serializeDetailValue(value) {
        if (value === null || value === undefined) return "";
        if (Array.isArray(value) || (value && typeof value === "object")) {
            try {
                return JSON.stringify(value, null, 2);
            } catch (_) {
                return String(value);
            }
        }
        const normalized = cleanText(value);
        if ((normalized.startsWith("{") && normalized.endsWith("}")) || (normalized.startsWith("[") && normalized.endsWith("]"))) {
            try {
                const parsed = JSON.parse(normalized);
                if (parsed && typeof parsed === "object") {
                    return JSON.stringify(parsed, null, 2);
                }
            } catch (_) {
                return normalized;
            }
        }
        return normalized;
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

    function looksLikeRealCommand(value) {
        const command = cleanText(value);
        if (!command) return false;
        if (INVALID_TEXT_MARKERS.has(command.toLowerCase())) return false;
        let firstLine = command.split(/\r?\n/).map((line) => line.trim()).find(Boolean) || "";
        for (const prompt of ["$ ", "# ", "> "]) {
            if (firstLine.startsWith(prompt)) {
                firstLine = firstLine.slice(prompt.length).trim();
                break;
            }
        }
        if (!firstLine) return false;
        const token = firstLine.split(/\s+/)[0].toLowerCase();
        return EXPLICIT_COMMAND_PREFIXES.has(token) || token.startsWith("./") || token.startsWith("/") || token.startsWith("~/");
    }

    function isMeaningfulProofArtifact(value) {
        if (Array.isArray(value)) return value.some((item) => isMeaningfulProofArtifact(item));
        if (value && typeof value === "object") {
            if (Object.keys(value).length === 0) return false;
            try {
                return isMeaningfulProofArtifact(JSON.stringify(value));
            } catch (_) {
                return true;
            }
        }
        const text = cleanText(value);
        if (!isMeaningfulText(text)) return false;
        if (text.length < 12 && !/[{}\[\]:=\/\\]/.test(text)) return false;
        const lowered = text.toLowerCase();
        const weakMarkers = [
            "possible issue",
            "potential issue",
            "appears vulnerable",
            "likely vulnerable",
            "manual verification",
            "needs validation",
            "interesting finding",
            "heuristic",
            "correlation",
            "suspected",
        ];
        if (weakMarkers.some((marker) => lowered.includes(marker)) && !/[{}\[\]:=\/<>]|http\//i.test(text)) return false;
        return /http\/|get |post |put |delete |host:|cookie:|set-cookie|content-type|json|xml|token|jwt|eyj|error|response|status|[:\/=<>{}\[\]]/i.test(lowered) || text.length >= 48;
    }

    function collectFindingQualitySignals(finding) {
        const metadata = asDict(finding.metadata);
        const validation = asDict(metadata.validation);
        const reproducibility = asDict(metadata.reproducibility);
        const validationStatus = normalizeValidationStatus(finding);
        const resultState = normalizeResultState(finding);
        const endpoint = firstMeaningful(
            [validation.target, reproducibility.url, finding.endpoint, finding.target, finding.url],
            { locator: true }
        );
        const command = firstMeaningful(
            [validation.command, reproducibility.command, finding.repro_command, finding.command, finding.reproduction]
        );
        const title = cleanText(finding.title).toLowerCase();
        const description = cleanText(finding.description);
        const proofCandidates = [
            finding.evidence,
            finding.request,
            finding.response,
            finding.raw_output,
            validation.artifact,
            reproducibility.request_excerpt,
            reproducibility.response_excerpt,
        ];
        const proofArtifactCount = proofCandidates.filter((candidate) => isMeaningfulProofArtifact(candidate)).length;
        let qualityScore = 0;
        if (endpoint) qualityScore += 1;
        if (looksLikeRealCommand(command)) qualityScore += 1;
        if (proofArtifactCount >= 1) qualityScore += 1;
        if (proofArtifactCount >= 2) qualityScore += 1;
        if (validationStatus === "success") qualityScore += 2;
        else if (validationStatus === "uncertain") qualityScore += 1;
        if (!GENERIC_TITLES.has(title)) qualityScore += 1;
        if (description.length >= 24) qualityScore += 1;
        if (Array.isArray(finding.signal_ids) && finding.signal_ids.length > 0) qualityScore += 1;
        if (resultState === "confirmed") qualityScore += 1;

        return {
            validationStatus,
            resultState,
            hasEndpoint: Boolean(endpoint),
            hasCommand: looksLikeRealCommand(command),
            proofArtifactCount,
            hasRequestResponse: [finding.request, finding.response, reproducibility.request_excerpt, reproducibility.response_excerpt].some((candidate) => isMeaningfulProofArtifact(candidate)),
            hasNonGenericTitle: !GENERIC_TITLES.has(title),
            qualityScore,
        };
    }

    function classifyVisibleTruth(finding) {
        const metadata = asDict(finding.metadata);
        const title = cleanText(finding.title).toLowerCase();
        const category = cleanText(finding.category).toLowerCase();
        const family = cleanText(finding.family).toLowerCase();

        if ((RECOMMENDATION_CATEGORIES.has(category) || title.startsWith("recommendation:") || family || Object.prototype.hasOwnProperty.call(finding, "internal_priority")) && finding.reason !== undefined) {
            return "recommendation";
        }

        const quality = collectFindingQualitySignals(finding);
        if (
            quality.resultState === "confirmed"
            && quality.validationStatus === "success"
            && quality.hasEndpoint
            && quality.hasCommand
            && quality.proofArtifactCount >= 1
            && quality.hasRequestResponse
            && quality.hasNonGenericTitle
            && quality.qualityScore >= 6
        ) {
            return "confirmed_vulnerability";
        }

        if (
            ["heuristic", "correlation", "validation"].includes(quality.resultState)
            || ["failed", "uncertain"].includes(quality.validationStatus)
            || ["attack_chain", "attack_path"].includes(category)
            || ["heuristic", "correlation", "validation"].includes(cleanText(metadata.validation_state).toLowerCase())
        ) {
            return "suspicion";
        }
        return "observation";
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

    function getFindingObservedVersions(finding) {
        const metadata = asDict(finding.metadata);
        const versions = [];
        const seen = new Set();
        const appendVersion = (value) => {
            const serialized = serializeDetailValue(value);
            if (!isMeaningfulText(serialized)) return;
            if (seen.has(serialized)) return;
            seen.add(serialized);
            versions.push(serialized);
        };

        [
            finding.version,
            metadata.version,
            metadata.service_version,
            metadata.detected_version,
            metadata.component_version,
        ].forEach(appendVersion);

        if (Array.isArray(metadata.versions)) {
            metadata.versions.forEach(appendVersion);
        }
        return versions;
    }

    function getFindingReferences(finding) {
        const metadata = asDict(finding.metadata);
        const references = [];
        const seen = new Set();
        const appendReference = (value) => {
            const normalized = cleanText(value);
            if (!isMeaningfulText(normalized)) return;
            if (seen.has(normalized)) return;
            seen.add(normalized);
            references.push(normalized);
        };

        [finding.references, metadata.references].forEach((source) => {
            const values = Array.isArray(source) ? source : [source];
            values.forEach(appendReference);
        });
        return references;
    }

    function getFindingCommandBlocks(finding) {
        const validation = getValidation(finding);
        const reproducibility = getReproducibility(finding);
        const blocks = [];
        const seen = new Set();
        const appendBlock = (key, label, value) => {
            const serialized = serializeDetailValue(value);
            if (!isMeaningfulText(serialized)) return;
            const dedupeKey = `${key}\u0000${serialized}`;
            if (seen.has(dedupeKey)) return;
            seen.add(dedupeKey);
            blocks.push({ key, label, kind: "command", value: serialized });
        };

        appendBlock("validation_command", "Validation command", validation.command);
        appendBlock("reproducibility_command", "Reproducibility command", reproducibility.command);
        appendBlock("stored_repro_command", "Stored repro command", finding.repro_command);
        return blocks;
    }

    function getFindingValidationGuidance(finding) {
        const guidance = cleanText(finding.reproduction);
        if (!isMeaningfulText(guidance)) return "";
        const primaryCommand = getFindingPrimaryCommand(finding);
        if (guidance === primaryCommand) return "";
        return isSafeLegacyCommand(guidance) ? "" : guidance;
    }

    function getFindingArtifacts(finding) {
        const metadata = asDict(finding.metadata);
        const artifacts = [];
        const screenshotPath = cleanText(finding.screenshot_path);
        if (isMeaningfulText(screenshotPath)) {
            artifacts.push({ label: "Screenshot", kind: "image", value: screenshotPath });
        }
        const rawArtifacts = metadata.artifacts;
        if (Array.isArray(rawArtifacts)) {
            rawArtifacts.forEach((item, index) => {
                const serialized = serializeDetailValue(item);
                if (!isMeaningfulText(serialized)) return;
                artifacts.push({ label: `Artifact ${index + 1}`, kind: "text", value: serialized });
            });
        } else if (isMeaningfulText(rawArtifacts)) {
            artifacts.push({ label: "Artifact", kind: "text", value: serializeDetailValue(rawArtifacts) });
        }
        return artifacts;
    }

    function buildFindingTechnicalContext(finding) {
        const normalized = normalizeFindingRecord(finding);
        const metadata = asDict(normalized.metadata);
        const reproducibility = getReproducibility(normalized);
        const ui = asDict(normalized._ui);
        const rows = [];
        const appendRow = (label, value) => {
            const serialized = serializeDetailValue(value);
            if (!isMeaningfulText(serialized)) return;
            rows.push({ label, value: serialized });
        };

        const toolValue = firstMeaningful([normalized.tool_source, normalized.tool]);
        const sourceValue = cleanText(normalized.source);
        const moduleValue = cleanText(normalized.module);

        appendRow("Tool", toolValue);
        if (sourceValue && sourceValue !== toolValue) appendRow("Source", sourceValue);
        if (moduleValue && moduleValue !== toolValue && moduleValue !== sourceValue) appendRow("Module", moduleValue);
        appendRow("Category", normalized.category);
        appendRow("Parameter", normalized.parameter);
        appendRow("Provider", ui.provider);
        appendRow("Component", ui.component);
        appendRow("Port state", ui.portState);
        appendRow("Visible class", ui.visibleTruthLabel);
        appendRow("Validation status", ui.validationStatus);
        appendRow("Result state", ui.resultState);
        appendRow("Impact area", normalized.impact_area || metadata.impact_area);
        appendRow("Arguments", reproducibility.arguments);
        return rows;
    }

    function buildFindingEvidenceBlocks(finding) {
        const normalized = normalizeFindingRecord(finding);
        const validation = getValidation(normalized);
        const reproducibility = getReproducibility(normalized);
        const blocks = [];
        const seen = new Set();
        const appendBlock = (key, label, kind, value) => {
            const serialized = serializeDetailValue(value);
            if (!isMeaningfulText(serialized)) return;
            const dedupeKey = `${key}\u0000${serialized}`;
            if (seen.has(dedupeKey)) return;
            seen.add(dedupeKey);
            blocks.push({ key, label, kind, value: serialized });
        };

        appendBlock("validation_artifact", "Validation artifact", "proof", validation.artifact);
        appendBlock("request", "Request excerpt", "request", reproducibility.request_excerpt || normalized.request);
        appendBlock("response", "Response excerpt", "response", reproducibility.response_excerpt || normalized.response);
        appendBlock("raw_output", "Raw output", "raw_output", normalized.raw_output);
        appendBlock("evidence", "Evidence", "evidence", normalized.evidence);
        return blocks;
    }

    function buildFindingDetailState(finding) {
        const normalized = normalizeFindingRecord(finding);
        const metadata = asDict(normalized.metadata);
        const ui = asDict(normalized._ui);
        const riskScorecard = asDict(normalized.risk_scorecard);
        const detailState = {
            summary: cleanText(normalized.description),
            technicalContext: buildFindingTechnicalContext(normalized),
            commandExecuted: cleanText(ui.primaryCommand),
            commandBlocks: getFindingCommandBlocks(normalized),
            validationGuidance: getFindingValidationGuidance(normalized),
            target: cleanText(ui.primaryUrl),
            observedVersions: getFindingObservedVersions(normalized),
            evidenceBlocks: buildFindingEvidenceBlocks(normalized),
            // `rawOutput` mirrors the canonical `raw_output` evidence block and
            // stays available for direct access in renderers and reports.
            rawOutput: serializeDetailValue(normalized.raw_output),
            interpretation: firstMeaningful([
                normalized.impact,
                metadata.impact,
                riskScorecard.impact,
                riskScorecard.summary,
            ]),
            severity: cleanText(normalized.severity || "info").toLowerCase() || "info",
            confidence: cleanText(normalized.confidence || "medium").toLowerCase() || "medium",
            remediation: firstMeaningful([normalized.remediation, metadata.remediation]),
            references: getFindingReferences(normalized),
            artifacts: getFindingArtifacts(normalized),
        };
        return DETAIL_CONTRACT_FIELDS.reduce((orderedState, fieldName) => {
            orderedState[fieldName] = detailState[fieldName];
            return orderedState;
        }, {});
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
            classifyVisibleTruth(finding),
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
        const visibleTruth = classifyVisibleTruth(finding);

        const uiState = {
            validationStatus,
            resultState,
            visibleTruth,
            visibleTruthLabel: visibleTruth.replace(/_/g, " "),
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

    function updateTableFilterUi(options = {}, visibleCount = 0, totalCount = visibleCount) {
        const label = global.document.getElementById(options.labelId || "findings-total-label");
        if (label) {
            label.textContent = visibleCount === totalCount
                ? `${visibleCount} findings`
                : `${visibleCount}/${totalCount} findings`;
        }

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

        updateTableFilterUi(options, visibleCount, rows.length);
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

    function escapeHtml(value) {
        return cleanText(value).replace(/[&<>'"]/g, (tag) => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            "'": "&#39;",
            "\"": "&quot;",
        }[tag]));
    }

    function resolveStaticAssetPath(value) {
        const normalized = cleanText(value);
        if (!normalized) return "";
        if (normalized.startsWith("/")) return normalized;
        return `/static/${normalized.replace(/^\/+/, "")}`;
    }

    function buildCopyButtonHtml(value, label, extraClass = "") {
        if (!isMeaningfulText(value)) return "";
        const className = `btn btn-xs btn-outline-secondary copy-inline ${extraClass}`.trim();
        return `<button class="${className}" data-copy-encoded="${encodeDataValue(value)}"><i class="fas fa-copy me-1"></i>${escapeHtml(label)}</button>`;
    }

    function renderContextRows(rows) {
        if (!Array.isArray(rows) || rows.length === 0) return "";
        return rows.map((row) => `
            <div class="small mb-2">
                <div class="text-muted extra-small text-uppercase fw-bold mb-1">${escapeHtml(row.label)}</div>
                <div class="text-light" style="white-space: pre-wrap;">${escapeHtml(row.value)}</div>
            </div>
        `).join("");
    }

    function renderEvidenceBlocks(blocks, accentMap = {}) {
        if (!Array.isArray(blocks) || blocks.length === 0) return "";
        return blocks.map((block) => {
            const accent = accentMap[block.kind] || "secondary";
            return `
                <div class="small mb-3">
                    <div class="d-flex justify-content-between align-items-center gap-2 mb-1">
                        <div class="text-${accent} fw-bold extra-small text-uppercase">${escapeHtml(block.label)}</div>
                        ${buildCopyButtonHtml(block.value, "Copy")}
                    </div>
                    <pre class="evidence-block p-3 bg-dark border border-secondary border-opacity-25 rounded text-light shadow-sm font-monospace mb-0" style="max-height: 280px; overflow-y: auto; font-size: 0.78rem;">${escapeHtml(block.value)}</pre>
                </div>
            `;
        }).join("");
    }

    function renderArtifactBlocks(artifacts) {
        if (!Array.isArray(artifacts) || artifacts.length === 0) return "";
        return artifacts.map((artifact) => {
            if (artifact.kind === "image") {
                const src = resolveStaticAssetPath(artifact.value);
                return `
                    <div class="small mb-3">
                        <div class="text-info fw-bold extra-small text-uppercase mb-2">${escapeHtml(artifact.label)}</div>
                        <img src="${escapeHtml(src)}" class="img-fluid border border-secondary border-opacity-25 rounded shadow-sm" style="max-height: 360px; cursor: pointer;" onclick="window.open(this.src)">
                    </div>
                `;
            }
            return `
                <div class="small mb-3">
                    <div class="d-flex justify-content-between align-items-center gap-2 mb-1">
                        <div class="text-info fw-bold extra-small text-uppercase">${escapeHtml(artifact.label)}</div>
                        ${buildCopyButtonHtml(artifact.value, "Copy")}
                    </div>
                    <pre class="evidence-block p-3 bg-dark border border-secondary border-opacity-25 rounded text-light shadow-sm font-monospace mb-0" style="max-height: 220px; overflow-y: auto; font-size: 0.78rem;">${escapeHtml(artifact.value)}</pre>
                </div>
            `;
        }).join("");
    }

    function buildFindingDetailHtml(finding) {
        const normalized = normalizeFindingRecord(finding);
        if (!normalized) {
            return '<div class="small text-muted fst-italic p-4 text-center">Finding unavailable.</div>';
        }

        const ui = asDict(normalized._ui);
        const detail = buildFindingDetailState(normalized);
        const validationStatus = cleanText(ui.validationStatus || "not_run");
        const resultState = cleanText(ui.resultState || "observation");
        const statusToneMap = { success: "success", failed: "danger", uncertain: "warning", not_run: "secondary" };
        const resultToneMap = { confirmed: "success", validation: "warning", correlation: "info", heuristic: "secondary", observation: "secondary", rejected: "danger" };
        const statusTone = statusToneMap[validationStatus] || "secondary";
        const resultTone = resultToneMap[resultState] || "secondary";
        const proofBlocks = detail.evidenceBlocks.filter((block) => block.kind !== "raw_output");
        const rawOutputBlocks = detail.evidenceBlocks.filter((block) => block.kind === "raw_output");
        const hasSubstance = Boolean(
            detail.summary
            || detail.commandBlocks.length
            || proofBlocks.length
            || rawOutputBlocks.length
            || detail.remediation
            || detail.references.length
            || detail.artifacts.length
        );

        return `
            <div class="mb-4" style="font-family: 'Inter', Helvetica, sans-serif;">
                <div class="d-flex align-items-center justify-content-between mb-4 border-bottom border-secondary border-opacity-25 pb-3">
                    <h4 class="finding-detail-title text-light mb-0 fw-bold d-flex align-items-center gap-3">
                        <span class="badge bg-${escapeHtml(detail.severity)} fs-6 px-3 py-2 border border-${escapeHtml(detail.severity)} bg-opacity-25 shadow-sm text-uppercase" style="letter-spacing: 1px;">
                            ${escapeHtml(detail.severity.toUpperCase())}
                        </span>
                        ${escapeHtml(normalized.title || "Untitled finding")}
                    </h4>
                    <div class="text-end d-none d-md-block">
                        <span class="text-muted extra-small d-block text-uppercase fw-bold mb-1" style="letter-spacing: 1px;">Confidence</span>
                        <span class="badge bg-secondary bg-opacity-20 text-light border border-secondary shadow-sm px-2 py-1">${escapeHtml(detail.confidence.toUpperCase())}</span>
                    </div>
                </div>

                <div class="row g-3 mb-4">
                    <div class="col-md-6">
                        <div class="p-3 h-100 rounded bg-black bg-opacity-30 border border-secondary border-opacity-10 shadow-sm">
                            <h6 class="extra-small text-uppercase text-info mb-3 fw-bold"><i class="fas fa-crosshairs me-2"></i>Target</h6>
                            ${detail.target ? `<div class="small fw-bold text-light mb-2 text-break"><i class="fas fa-link me-2 text-muted"></i>${escapeHtml(detail.target)} ${buildCopyButtonHtml(detail.target, "Copy target")}</div>` : '<div class="small text-muted fst-italic mb-2">No target URL identified.</div>'}
                            ${detail.observedVersions.length ? `<div class="d-flex flex-wrap gap-2 mt-3">${detail.observedVersions.map((version) => `<span class="badge bg-secondary bg-opacity-20 text-light border border-secondary border-opacity-25">${escapeHtml(version)}</span>`).join("")}</div>` : ""}
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="p-3 h-100 rounded bg-black bg-opacity-30 border border-secondary border-opacity-10 shadow-sm">
                            <h6 class="extra-small text-uppercase text-warning mb-3 fw-bold"><i class="fas fa-shield-alt me-2"></i>Status</h6>
                            <div class="small text-muted d-flex align-items-center gap-2 mt-2">
                                <span class="fw-bold text-uppercase extra-small">Visible class:</span>
                                <span class="badge bg-secondary bg-opacity-20 text-light border border-secondary border-opacity-25 px-2 py-1">${escapeHtml(cleanText(ui.visibleTruthLabel || "observation").toUpperCase())}</span>
                            </div>
                            <div class="small text-muted d-flex align-items-center gap-2 mt-2">
                                <span class="fw-bold text-uppercase extra-small">Validation status:</span>
                                <span class="badge bg-${statusTone} bg-opacity-20 text-${statusTone} border border-${statusTone} border-opacity-25 px-2 py-1">${escapeHtml(validationStatus.toUpperCase())}</span>
                            </div>
                            <div class="small text-muted d-flex align-items-center gap-2 mt-2">
                                <span class="fw-bold text-uppercase extra-small">Result state:</span>
                                <span class="badge bg-${resultTone} bg-opacity-20 text-${resultTone} border border-${resultTone} border-opacity-25 px-2 py-1">${escapeHtml(resultState.replace(/_/g, " ").toUpperCase())}</span>
                                ${ui.isValidated ? '<span class="badge bg-success bg-opacity-20 text-success border border-success border-opacity-25 px-2 py-1"><i class="fas fa-check-circle me-1"></i>VALIDATED</span>' : ""}
                            </div>
                            <div class="small text-muted mt-3">
                                <span class="badge bg-dark border border-secondary text-light fw-bold text-uppercase">${escapeHtml(cleanText(normalized.tool_source || normalized.tool || "n/a"))}</span>
                                ${isMeaningfulText(normalized.category) ? `<span class="ms-2 text-light">${escapeHtml(cleanText(normalized.category).replace(/_/g, " "))}</span>` : ""}
                            </div>
                        </div>
                    </div>
                </div>

                ${detail.summary ? `
                <div class="mb-4">
                    <h6 class="extra-small text-uppercase text-muted border-bottom border-secondary border-opacity-25 pb-2 mb-3 fw-bold" style="letter-spacing: 1px;"><i class="fas fa-align-left me-2"></i>Operational Summary</h6>
                    <div class="small text-light bg-black bg-opacity-20 p-4 rounded border border-secondary border-opacity-10 lh-lg shadow-sm" style="white-space: pre-wrap; font-size: 0.9rem;">${escapeHtml(detail.summary)}</div>
                </div>` : ""}

                ${detail.technicalContext.length ? `
                <div class="mb-4">
                    <h6 class="extra-small text-uppercase text-muted border-bottom border-secondary border-opacity-25 pb-2 mb-3 fw-bold" style="letter-spacing: 1px;"><i class="fas fa-network-wired me-2"></i>Technical Context</h6>
                    <div class="rounded bg-black bg-opacity-40 border border-secondary border-opacity-10 p-4 shadow-sm">
                        ${renderContextRows(detail.technicalContext)}
                    </div>
                </div>` : ""}

                ${detail.commandBlocks.length || detail.validationGuidance ? `
                <div class="mb-4">
                    <h6 class="extra-small text-uppercase text-muted border-bottom border-secondary border-opacity-25 pb-2 mb-3 fw-bold" style="letter-spacing: 1px;"><i class="fas fa-terminal me-2"></i>Command & Validation</h6>
                    <div class="rounded bg-black bg-opacity-40 border border-secondary border-opacity-10 p-4 shadow-sm">
                        ${detail.commandExecuted ? `<div class="d-flex flex-wrap gap-2 mb-3">
                            <button class="btn btn-sm btn-outline-warning verify-btn fw-bold px-3 py-2" data-command="${encodeDataValue(detail.commandExecuted)}"><i class="fas fa-play me-2"></i>Validate</button>
                            <button class="btn btn-sm btn-outline-secondary copy-inline fw-bold px-3 py-2" data-copy-encoded="${encodeDataValue(detail.commandExecuted)}"><i class="fas fa-copy me-2"></i>Copy command</button>
                            ${detail.target ? `<button class="btn btn-sm btn-outline-secondary copy-inline fw-bold px-3 py-2" data-copy-encoded="${encodeDataValue(detail.target)}"><i class="fas fa-copy me-2"></i>Copy target</button>` : ""}
                        </div>` : ""}
                        ${renderEvidenceBlocks(detail.commandBlocks, { command: "warning" })}
                        ${detail.validationGuidance ? `<div class="small mt-3"><div class="text-info fw-bold extra-small text-uppercase mb-2">Validation guidance</div><div class="text-light bg-black bg-opacity-20 p-3 rounded border border-secondary border-opacity-10" style="white-space: pre-wrap;">${escapeHtml(detail.validationGuidance)}</div></div>` : ""}
                    </div>
                </div>` : ""}

                ${proofBlocks.length ? `
                <div class="mb-4">
                    <h6 class="extra-small text-uppercase text-muted border-bottom border-secondary border-opacity-25 pb-2 mb-3 fw-bold" style="letter-spacing: 1px;"><i class="fas fa-microscope me-2"></i>Evidence</h6>
                    <div class="rounded bg-black bg-opacity-40 border border-secondary border-opacity-10 p-4 shadow-sm">
                        ${renderEvidenceBlocks(proofBlocks, { proof: "success", request: "info", response: "primary", evidence: "warning" })}
                    </div>
                </div>` : ""}

                ${rawOutputBlocks.length ? `
                <div class="mb-4">
                    <h6 class="extra-small text-uppercase text-muted border-bottom border-secondary border-opacity-25 pb-2 mb-3 fw-bold" style="letter-spacing: 1px;"><i class="fas fa-file-code me-2"></i>Raw Output</h6>
                    <div class="rounded bg-black bg-opacity-40 border border-secondary border-opacity-10 p-4 shadow-sm">
                        ${renderEvidenceBlocks(rawOutputBlocks, { raw_output: "secondary" })}
                    </div>
                </div>` : ""}

                ${detail.interpretation ? `
                <div class="mb-4">
                    <h6 class="extra-small text-uppercase text-muted border-bottom border-secondary border-opacity-25 pb-2 mb-3 fw-bold" style="letter-spacing: 1px;"><i class="fas fa-lightbulb me-2"></i>Interpretation</h6>
                    <div class="small text-light bg-black bg-opacity-20 p-4 rounded border border-secondary border-opacity-10 lh-lg shadow-sm" style="white-space: pre-wrap;">${escapeHtml(detail.interpretation)}</div>
                </div>` : ""}

                ${detail.remediation ? `
                <div class="mb-4">
                    <h6 class="extra-small text-uppercase text-muted border-bottom border-secondary border-opacity-25 pb-2 mb-3 fw-bold" style="letter-spacing: 1px;"><i class="fas fa-wrench me-2"></i>Remediation</h6>
                    <div class="small text-light bg-black bg-opacity-20 p-4 rounded border border-secondary border-opacity-10 lh-lg shadow-sm" style="white-space: pre-wrap;">${escapeHtml(detail.remediation)}</div>
                </div>` : ""}

                ${detail.references.length || detail.artifacts.length ? `
                <div class="mb-4">
                    <h6 class="extra-small text-uppercase text-muted border-bottom border-secondary border-opacity-25 pb-2 mb-3 fw-bold" style="letter-spacing: 1px;"><i class="fas fa-paperclip me-2"></i>References & Artifacts</h6>
                    <div class="rounded bg-black bg-opacity-40 border border-secondary border-opacity-10 p-4 shadow-sm">
                        ${detail.references.length ? `<div class="small mb-4"><div class="text-info fw-bold extra-small text-uppercase mb-2">References</div><ul class="mb-0 ps-3">${detail.references.map((reference) => `<li class="text-light mb-2 text-break">${escapeHtml(reference)}</li>`).join("")}</ul></div>` : ""}
                        ${renderArtifactBlocks(detail.artifacts)}
                    </div>
                </div>` : ""}

                ${!hasSubstance ? '<div class="small text-muted fst-italic p-4 text-center border border-secondary border-opacity-10 rounded bg-black bg-opacity-20 shadow-sm"><i class="fas fa-info-circle fa-2x mb-2 opacity-50 d-block"></i>This finding is observation-only and does not include explicit technical evidence, a reproducible command, or remediation notes.</div>' : ""}
            </div>
        `;
    }

    function handleCopyButtonClick(event) {
        const copyBtn = event && event.target ? event.target.closest(".copy-inline") : null;
        if (!copyBtn) return false;
        const encoded = copyBtn.getAttribute("data-copy-encoded") || "";
        const value = decodeDataValue(encoded);
        if (!isMeaningfulText(value)) return true;
        if (global.navigator && global.navigator.clipboard && typeof global.navigator.clipboard.writeText === "function") {
            global.navigator.clipboard.writeText(value);
        }
        const icon = copyBtn.querySelector("i");
        if (icon) {
            icon.className = "fas fa-check me-1";
            global.setTimeout(() => {
                icon.className = "fas fa-copy me-1";
            }, 1500);
        }
        return true;
    }

    const contractApi = {
        buildFilterState,
        buildFindingDetailState,
        buildFindingEvidenceBlocks,
        buildFindingSearchText,
        buildFindingSearchTextFields,
        buildFindingTechnicalContext,
        buildFindingUiState,
        classifyVisibleTruth,
        collectFindingQualitySignals,
        decodeDataValue,
        encodeDataValue,
        getFindingArtifacts,
        getFindingCommandBlocks,
        getFindingObservedVersions,
        getFindingPrimaryCommand,
        getFindingPrimaryUrl,
        getFindingReferences,
        getFindingValidationGuidance,
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
        buildFindingDetailHtml,
        getDatasetFromRow,
        handleCopyButtonClick,
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
            detailCommandBlockSources: [...DETAIL_COMMAND_BLOCK_SOURCES],
            detailStateFields: [...DETAIL_CONTRACT_FIELDS],
            detailEvidenceBlockSources: [...DETAIL_EVIDENCE_BLOCK_SOURCES],
            observedVersionFieldSources: [...OBSERVED_VERSION_FIELD_SOURCES],
            searchTextFieldSources: [...SEARCH_TEXT_FIELD_SOURCES],
            validatedResultStates: [...VALIDATED_RESULT_STATES],
        },
    };

    global.RedOpsFindings = api;
    if (typeof module !== "undefined" && module.exports) {
        module.exports = api;
    }
})(typeof window !== "undefined" ? window : globalThis);
