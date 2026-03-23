const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function createClassList() {
    const classes = new Set();
    return {
        add(...tokens) {
            tokens.forEach((token) => classes.add(token));
        },
        remove(...tokens) {
            tokens.forEach((token) => classes.delete(token));
        },
        contains(token) {
            return classes.has(token);
        },
    };
}

function createElement(tagName = 'div') {
    return {
        tagName,
        innerHTML: '',
        innerText: '',
        className: '',
        attributes: {},
        style: {},
        classList: createClassList(),
        removed: false,
        onclick: null,
        setAttribute(name, value) {
            this.attributes[name] = value;
        },
        getAttribute(name) {
            return this.attributes[name];
        },
        remove() {
            this.removed = true;
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
        createElement(tagName) { return createElement(tagName); },
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
        path.join(__dirname, '../ui/web/static/js/scan_dashboard.js'),
        'utf8'
    );
    const sandbox = createSandbox(overrides);
    vm.runInNewContext(`${source}\nthis.__ScanDashboard = ScanDashboard;`, sandbox, {
        filename: 'scan_dashboard.js',
    });
    return { ScanDashboard: sandbox.__ScanDashboard, sandbox };
}

test('findings view helper extracts the render-ready display model without changing finding semantics', () => {
    const { ScanDashboard } = loadScanDashboardClass();
    const dashboard = {
        escapeHtml(value) {
            return String(value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        },
        getFindingValidationStatus() {
            return 'not_run';
        },
        getFindingResultState() {
            return 'observation';
        },
        getFindingPrimaryCommand() {
            return '';
        },
        getFindingPrimaryUrl() {
            return '';
        },
    };

    const display = ScanDashboard.internals.findingsView.buildDisplayModel(dashboard, {
        title: 'Stored <XSS>',
        severity: 'High',
        tool_source: 'dalfox',
        description: 'Body <script>alert(1)</script>',
        confidence: 'high',
        screenshot_path: 'loot/xss.png',
        _ui: {
            validationStatus: 'success',
            resultState: 'confirmed',
            primaryCommand: 'dalfox url https://target',
            primaryUrl: 'https://target/app?q=<script>',
            hasEvidence: true,
            isValidated: true,
        },
    });

    assert.equal(display.severity, 'high');
    assert.equal(display.severityLabel, 'HIGH');
    assert.equal(display.escapedTitle, 'Stored &lt;XSS&gt;');
    assert.equal(display.escapedDesc, 'Body &lt;script&gt;alert(1)&lt;/script&gt;');
    assert.equal(display.primaryCommand, 'dalfox url https://target');
    assert.equal(display.primaryUrl, 'https://target/app?q=<script>');
    assert.equal(display.escapedPrimaryUrl, 'https://target/app?q=&lt;script&gt;');
    assert.equal(display.escapedScreenshotPath, 'loot/xss.png');
    assert.equal(display.hasProof, true);
    assert.equal(display.isValidated, true);
    assert.equal(display.confidenceLabel, 'HIGH');
    assert.equal(display.toolLabel, 'DALFOX');
});

test('findings view helper resolves validation, evidence, and primary action state before HTML rendering', () => {
    const { ScanDashboard } = loadScanDashboardClass();
    const dashboard = {
        getFindingValidationStatus() {
            return 'success';
        },
        getFindingResultState() {
            return 'confirmed';
        },
        getFindingPrimaryCommand() {
            return 'curl -isk https://target/health';
        },
        getFindingPrimaryUrl() {
            return 'https://target/health';
        },
    };

    const resolved = ScanDashboard.internals.findingsView.resolveFindingDisplayState(dashboard, {
        title: 'Health endpoint',
        _ui: {
            hasEvidence: true,
        },
    });

    assert.equal(resolved.validationStatus, 'success');
    assert.equal(resolved.resultState, 'confirmed');
    assert.equal(resolved.primaryCommand, 'curl -isk https://target/health');
    assert.equal(resolved.primaryUrl, 'https://target/health');
    assert.equal(resolved.hasProof, true);
    assert.equal(resolved.isValidated, true);
});

test('findings view helper formats escaped text and labels with the existing findings fallbacks intact', () => {
    const { ScanDashboard } = loadScanDashboardClass();
    const dashboard = {
        escapeHtml(value) {
            return String(value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        },
    };

    const displayText = ScanDashboard.internals.findingsView.buildDisplayText(dashboard, {
        tool: 'nuclei',
        description: 'Body <script>alert(1)</script>',
        screenshot_path: 'loot/<proof>.png',
    });

    assert.equal(displayText.severity, 'info');
    assert.equal(displayText.severityLabel, 'INFO');
    assert.equal(displayText.escapedTitle, 'Untitled finding');
    assert.equal(displayText.escapedTool, 'nuclei');
    assert.equal(displayText.escapedDesc, 'Body &lt;script&gt;alert(1)&lt;/script&gt;');
    assert.equal(displayText.escapedScreenshotPath, 'loot/&lt;proof&gt;.png');
    assert.equal(displayText.confidenceLabel, 'MED');
    assert.equal(displayText.toolLabel, 'CORE');
});

test('findings view helper extracts optional result card sections without changing description or screenshot HTML', () => {
    const { ScanDashboard } = loadScanDashboardClass();

    const optionalSections = ScanDashboard.internals.findingsView.buildResultCardOptionalSectionsHtml(
        {
            description: 'Body <script>alert(1)</script>',
            screenshot_path: 'loot/xss-proof.png',
        },
        {
            escapedDesc: 'Body &lt;script&gt;alert(1)&lt;/script&gt;',
            escapedScreenshotPath: 'loot/xss-proof.png',
            escapedTitle: 'Stored &lt;XSS&gt;',
        }
    );

    assert.match(optionalSections, /Body &lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.match(optionalSections, /loot\/xss-proof\.png/);
    assert.match(optionalSections, /screenshot-trigger/);
    assert.match(optionalSections, /title="Port Stored &lt;XSS&gt;"/);

    const emptySections = ScanDashboard.internals.findingsView.buildResultCardOptionalSectionsHtml(
        {},
        {
            escapedDesc: 'ignored',
            escapedScreenshotPath: 'ignored',
            escapedTitle: 'Ignored',
        }
    );

    assert.equal(emptySections, '');
});

test('findings view helper extracts table state indicators without changing badges or validation affordances', () => {
    const { ScanDashboard } = loadScanDashboardClass();

    const indicatorsHtml = ScanDashboard.internals.findingsView.buildTableRowStateIndicatorsHtml({
        primaryCommand: 'curl -isk https://target/graphql',
        hasProof: true,
        isValidated: true,
    });

    assert.match(indicatorsHtml, /fa-terminal text-warning/);
    assert.match(indicatorsHtml, /Validation Command Available/);
    assert.match(indicatorsHtml, /fa-microscope text-info/);
    assert.match(indicatorsHtml, /Technical Evidence Available/);
    assert.match(indicatorsHtml, /VALIDATED/);

    const emptyIndicatorsHtml = ScanDashboard.internals.findingsView.buildTableRowStateIndicatorsHtml({
        primaryCommand: '',
        hasProof: false,
        isValidated: false,
    });

    assert.equal(emptyIndicatorsHtml.replace(/\s/g, ''), '');
});

test('findings view helper keeps the findings table row contract for badges, evidence, validation, and vector rendering', () => {
    const { ScanDashboard } = loadScanDashboardClass();
    const rowHtml = ScanDashboard.internals.findingsView.buildTableRowHtml({
        severity: 'medium',
        severityLabel: 'MEDIUM',
        escapedTitle: 'GraphQL schema leak',
        escapedDesc: 'Introspection still enabled',
        escapedPrimaryUrl: 'https://target/graphql',
        primaryCommand: 'curl -isk https://target/graphql',
        primaryUrl: 'https://target/graphql',
        hasProof: true,
        isValidated: true,
        confidenceLabel: 'HIGH',
        toolLabel: 'NUCLEI',
    });

    assert.match(rowHtml, /badge-severity bg-medium/);
    assert.match(rowHtml, /MEDIUM/);
    assert.match(rowHtml, /GraphQL schema leak/);
    assert.match(rowHtml, /fa-terminal text-warning/);
    assert.match(rowHtml, /fa-microscope text-info/);
    assert.match(rowHtml, /VALIDATED/);
    assert.match(rowHtml, /https:\/\/target\/graphql/);
    assert.match(rowHtml, /NUCLEI/);
    assert.match(rowHtml, /HIGH/);
});

test('findings identity helper preserves the existing dedupe priority before DOM rendering starts', () => {
    const { ScanDashboard } = loadScanDashboardClass();
    const { findingsIdentity } = ScanDashboard.internals;

    assert.equal(
        findingsIdentity.resolveRenderId({ id_stable: 'stable-1', id: 99, title: 'Ignored' }),
        'stable-1'
    );
    assert.equal(
        findingsIdentity.resolveRenderId({ id: 42, title: 'Fallback id' }),
        42
    );
    assert.equal(
        findingsIdentity.resolveRenderId({ title: 'Stored XSS', severity: 'high', tool: 'dalfox' }),
        'temp-Stored XSS-high-dalfox'
    );
});

test('findings sync helper updates the shared findings cache only when findings are present', () => {
    const syncedBatches = [];
    const { ScanDashboard } = loadScanDashboardClass({
        updateFindingsList(items) {
            syncedBatches.push(items);
        },
    });

    ScanDashboard.internals.findingsSync.syncClientFindings([]);
    ScanDashboard.internals.findingsSync.syncClientFinding(null);
    ScanDashboard.internals.findingsSync.syncClientFinding({ id_stable: 'finding-1' });
    ScanDashboard.internals.findingsSync.syncClientFindings([{ id_stable: 'finding-2' }]);

    assert.equal(syncedBatches.length, 2);
    assert.equal(JSON.stringify(syncedBatches[0].map((item) => item.id_stable)), JSON.stringify(['finding-1']));
    assert.equal(JSON.stringify(syncedBatches[1].map((item) => item.id_stable)), JSON.stringify(['finding-2']));
});

test('findings DOM helper keeps the result list and table row contracts intact for extracted findings markup', () => {
    const findingsEmpty = createElement('div');
    findingsEmpty.innerText = 'No findings yet';
    const findingsList = {
        entries: [],
        prepend(node) {
            this.entries.unshift(node);
        },
    };
    const findingsContainer = {
        querySelector(selector) {
            if (selector === '.text-muted') return findingsEmpty;
            if (selector === '.result-list') return findingsList;
            return null;
        },
        appendChild() {},
    };
    const findingsEmptyRow = createElement('tr');
    const rowRegistry = new Map();
    const findingsTableBody = {
        rows: [],
        prepend(row) {
            this.rows.unshift(row);
            rowRegistry.set(row.id, row);
        },
    };
    const document = {
        getElementById(id) {
            if (id === 'findings-table-body') return findingsTableBody;
            if (id === 'findings-empty-state') return findingsEmptyRow;
            return rowRegistry.get(id) || null;
        },
        createElement(tagName) {
            const element = createElement(tagName);
            Object.defineProperty(element, 'id', {
                get() {
                    return this._id || '';
                },
                set(value) {
                    this._id = value;
                },
            });
            return element;
        },
        querySelectorAll() { return []; },
        querySelector() { return null; },
        addEventListener() {},
    };

    const updateFindingsListCalls = [];
    const { ScanDashboard } = loadScanDashboardClass({
        document,
        updateFindingsList(items) {
            updateFindingsListCalls.push(items);
        },
    });

    const display = {
        severity: 'high',
        severityLabel: 'HIGH',
        escapedTitle: 'Stored &lt;XSS&gt;',
        escapedTool: 'dalfox',
        escapedDesc: 'Body &lt;script&gt;alert(1)&lt;/script&gt;',
        escapedPrimaryUrl: 'https://target/app?q=&lt;script&gt;',
        primaryCommand: 'dalfox url https://target/app',
        primaryUrl: 'https://target/app?q=<script>',
        escapedScreenshotPath: 'loot/xss-proof.png',
        hasProof: true,
        isValidated: true,
        confidenceLabel: 'HIGH',
        toolLabel: 'DALFOX',
    };
    const finding = {
        id_stable: 'finding-77',
        title: 'Stored <XSS>',
    };
    const appliedDatasets = [];
    const dashboard = {
        getFindingsContract() {
            return {
                applyRowDataset(row, currentFinding) {
                    appliedDatasets.push({ row, finding: currentFinding });
                    row.setAttribute('data-finding-id', currentFinding.id_stable);
                },
            };
        },
    };

    const card = ScanDashboard.internals.findingsDom.prependResultCard(
        document,
        findingsContainer,
        ScanDashboard.internals.findingsView.buildResultCardHtml(
            { description: 'Body <script>alert(1)</script>', screenshot_path: 'loot/xss-proof.png' },
            display
        )
    );

    assert.equal(findingsEmpty.removed, true);
    assert.equal(findingsList.entries.length, 1);
    assert.equal(findingsList.entries[0], card);
    assert.match(card.className, /animate__fadeInLeft/);
    assert.match(card.innerHTML, /Stored &lt;XSS&gt;/);
    assert.match(card.innerHTML, /Source: dalfox/);

    const row = ScanDashboard.internals.findingsDom.prependTableRow(document, dashboard, 'finding-77', finding, display);
    assert.equal(findingsEmptyRow.removed, true);
    assert.equal(findingsTableBody.rows.length, 1);
    assert.equal(findingsTableBody.rows[0], row);
    assert.equal(row.id, 'finding-row-finding-77');
    assert.equal(row.getAttribute('data-finding-id'), 'finding-77');
    assert.match(row.className, /finding-row cursor-pointer/);
    assert.match(row.innerHTML, /fa-terminal text-warning/);
    assert.match(row.innerHTML, /fa-microscope text-info/);
    assert.match(row.innerHTML, /VALIDATED/);
    assert.deepEqual(appliedDatasets.map(({ finding: currentFinding }) => currentFinding.id_stable), ['finding-77']);
    assert.equal(updateFindingsListCalls.length, 0);

    const duplicateRow = ScanDashboard.internals.findingsDom.prependTableRow(document, dashboard, 'finding-77', finding, display);
    assert.equal(duplicateRow, null);
    assert.equal(findingsTableBody.rows.length, 1);
    assert.equal(updateFindingsListCalls.length, 0);
});

test('findings flow helper deduplicates normalized findings before any DOM work begins', () => {
    const { ScanDashboard } = loadScanDashboardClass();
    const normalized = { id_stable: 'finding-42', title: 'Normalized finding' };
    const dashboard = {
        renderedFindingIds: new Set(),
        normalizeFindingRecord(input) {
            assert.equal(input.title, 'Incoming finding');
            return normalized;
        },
    };

    const firstPass = ScanDashboard.internals.findingsFlow.prepareIncomingFinding(dashboard, {
        title: 'Incoming finding',
    });
    assert.equal(firstPass.fid, 'finding-42');
    assert.equal(firstPass.finding, normalized);
    assert.equal(dashboard.renderedFindingIds.has('finding-42'), true);

    const secondPass = ScanDashboard.internals.findingsFlow.prepareIncomingFinding(dashboard, {
        title: 'Incoming finding',
    });
    assert.equal(secondPass, null);
});

test('findings flow structured batch ingestion syncs findings once before routing them through the canonical live pipeline', () => {
    const cacheSyncCalls = [];
    const handledFindings = [];
    const { ScanDashboard } = loadScanDashboardClass({
        updateFindingsList(items) {
            cacheSyncCalls.push(items);
        },
    });

    const dashboard = {
        scanId: 77,
        normalizeFindingRecord(finding) {
            return {
                ...finding,
                normalized: true,
            };
        },
        handleNewFinding(finding, options) {
            handledFindings.push({ finding, options });
        },
    };

    const findings = [
        { id_stable: 'finding-1', title: 'First', tool_source: 'nuclei', tool: 'nuclei' },
        { id_stable: 'finding-2', title: 'Second', tool_source: 'dalfox', tool: 'dalfox' },
    ];

    const normalizedFindings = ScanDashboard.internals.findingsFlow.ingestStructuredFindings(dashboard, findings);

    assert.equal(cacheSyncCalls.length, 1);
    assert.deepEqual(cacheSyncCalls[0].map((item) => item.id_stable), ['finding-1', 'finding-2']);
    assert.equal(normalizedFindings.length, 2);
    assert.equal(normalizedFindings.every((item) => item.normalized === true), true);
    assert.deepEqual(handledFindings.map(({ finding }) => finding.id_stable), ['finding-1', 'finding-2']);
    assert.equal(handledFindings.every(({ finding }) => finding.scan_id === 77), true);
    assert.equal(handledFindings.every(({ options }) => options.normalized === true && options.skipClientSync === true), true);
});

test('findings flow structured batch ingestion skips malformed entries instead of crashing the runtime pipeline', () => {
    const cacheSyncCalls = [];
    const handledFindings = [];
    const { ScanDashboard } = loadScanDashboardClass({
        updateFindingsList(items) {
            cacheSyncCalls.push(items);
        },
    });

    const dashboard = {
        scanId: 77,
        normalizeFindingRecord(finding) {
            if (!finding || typeof finding !== 'object') return finding;
            return {
                ...finding,
                normalized: true,
            };
        },
        handleNewFinding(finding, options) {
            handledFindings.push({ finding, options });
        },
    };

    const normalizedFindings = ScanDashboard.internals.findingsFlow.ingestStructuredFindings(dashboard, [
        null,
        'noise',
        { id_stable: 'finding-1', title: 'First', tool_source: 'nuclei', tool: 'nuclei' },
        7,
    ]);

    assert.equal(cacheSyncCalls.length, 1);
    assert.deepEqual(cacheSyncCalls[0].map((item) => item.id_stable), ['finding-1']);
    assert.equal(normalizedFindings.length, 1);
    assert.deepEqual(handledFindings.map(({ finding }) => finding.id_stable), ['finding-1']);
    assert.equal(handledFindings.every(({ options }) => options.normalized === true && options.skipClientSync === true), true);
});

test('results view helper keeps findings summaries and derived counters deterministic', () => {
    const { ScanDashboard } = loadScanDashboardClass();
    const { resultsView } = ScanDashboard.internals;

    const findings = [
        { id_stable: 'finding-1', severity: 'critical' },
        { id_stable: 'finding-2', severity: 'high' },
        { id_stable: 'finding-3', severity: 'info' },
    ];
    const results = {
        findings,
        phases: {
            recon: { open_ports: [{ port: 443 }] },
            dns: { subdomains: ['api.example.org'] },
            osint: { cloud: [{ provider: 'aws' }] },
            dirbusting: { ffuf: { endpoints: [{ path: 'admin' }] } },
            enum: {
                api: { endpoints: ['/v1/health'], discovered_endpoints: ['/v1/users'] },
                katana: {
                    '443': ['/health', '/ready'],
                },
            },
        },
    };

    assert.equal(resultsView.getStructuredFindings(results), findings);
    assert.equal(resultsView.countAssets(results), 3);
    assert.equal(resultsView.countEndpoints(results), 5);
    assert.equal(JSON.stringify(resultsView.summarizeFindingSeverities(findings)), JSON.stringify({
        highRisk: 2,
        critical: 1,
        high: 1,
    }));
});

test('updateUI replays structured findings through the canonical ingestion helper without double-calling the shared cache sync', () => {
    const cacheSyncCalls = [];
    const { ScanDashboard } = loadScanDashboardClass({
        updateFindingsList(items) {
            cacheSyncCalls.push(items);
        },
        document: {
            getElementById() { return null; },
            querySelectorAll() { return []; },
            querySelector() { return null; },
            addEventListener() {},
        },
    });

    const handledFindings = [];
    const dashboard = {
        scanId: 77,
        targetIdentifier: 'example.org',
        normalizeFindingRecord(finding) {
            return {
                ...finding,
                normalized: true,
            };
        },
        handleNewFinding(finding, options) {
            handledFindings.push({ finding, options });
        },
        updateAuditJourney() {},
        updateCortexUI() {},
        renderTaskStatus() {},
        activateDiscovery() {},
        handleProgressUpdate() {},
    };

    ScanDashboard.prototype.updateUI.call(dashboard, {
        findings: [
            { id_stable: 'finding-1', severity: 'high', tool_source: 'dalfox' },
            { id_stable: 'finding-2', severity: 'info', tool_source: 'nuclei' },
        ],
        phases: {},
    });

    assert.equal(cacheSyncCalls.length, 1);
    assert.deepEqual(cacheSyncCalls[0].map((item) => item.id_stable), ['finding-1', 'finding-2']);
    assert.deepEqual(handledFindings.map(({ finding }) => finding.id_stable), ['finding-1', 'finding-2']);
    assert.equal(handledFindings.every(({ options }) => options.normalized === true && options.skipClientSync === true), true);
});

test('findings flow helper keeps rendering side effects grouped without changing the findings UI contracts', () => {
    const findingsEmpty = createElement('div');
    findingsEmpty.innerText = 'No findings yet';
    const findingsList = {
        entries: [],
        prepend(node) {
            this.entries.unshift(node);
        },
    };
    const findingsContainer = {
        querySelector(selector) {
            if (selector === '.text-muted') return findingsEmpty;
            if (selector === '.result-list') return findingsList;
            return null;
        },
        appendChild() {},
    };
    const findingsEmptyRow = createElement('tr');
    const rowRegistry = new Map();
    const findingsTableBody = {
        rows: [],
        prepend(row) {
            this.rows.unshift(row);
            rowRegistry.set(row.id, row);
        },
    };
    const document = {
        getElementById(id) {
            if (id === 'findings-container') return findingsContainer;
            if (id === 'findings-table-body') return findingsTableBody;
            if (id === 'findings-empty-state') return findingsEmptyRow;
            return rowRegistry.get(id) || null;
        },
        createElement(tagName) {
            const element = createElement(tagName);
            Object.defineProperty(element, 'id', {
                get() {
                    return this._id || '';
                },
                set(value) {
                    this._id = value;
                },
            });
            return element;
        },
        querySelectorAll() { return []; },
        querySelector() { return null; },
        addEventListener() {},
    };

    const updateFindingsListCalls = [];
    const { ScanDashboard } = loadScanDashboardClass({
        document,
        updateFindingsList(items) {
            updateFindingsListCalls.push(items);
        },
    });

    const galleryCalls = [];
    const riskCalls = [];
    const indicatorCalls = [];
    const appliedDatasets = [];
    const dashboard = {
        escapeHtml(value) {
            return String(value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        },
        getFindingValidationStatus() {
            return 'not_run';
        },
        getFindingResultState() {
            return 'observation';
        },
        getFindingPrimaryCommand() {
            return '';
        },
        getFindingPrimaryUrl() {
            return '';
        },
        getFindingsContract() {
            return {
                applyRowDataset(row, finding) {
                    appliedDatasets.push(finding.id_stable);
                    row.setAttribute('data-finding-id', finding.id_stable);
                },
            };
        },
        addToGallery(finding) {
            galleryCalls.push(finding.id_stable);
        },
        updateRiskCounters(severity) {
            riskCalls.push(severity);
        },
        updateIndicators(finding) {
            indicatorCalls.push(finding.id_stable);
        },
    };

    const finding = {
        id_stable: 'finding-55',
        title: 'Stored <XSS>',
        severity: 'high',
        tool_source: 'dalfox',
        description: 'Body <script>alert(1)</script>',
        confidence: 'high',
        screenshot_path: 'loot/xss-proof.png',
        _ui: {
            validationStatus: 'success',
            resultState: 'confirmed',
            primaryCommand: 'dalfox url https://target/app',
            primaryUrl: 'https://target/app?q=<script>',
            hasEvidence: true,
            isValidated: true,
        },
    };

    const rendered = ScanDashboard.internals.findingsFlow.renderFinding(document, dashboard, 'finding-55', finding);

    assert.equal(rendered.container, findingsContainer);
    assert.equal(rendered.tableRow, findingsTableBody.rows[0]);
    assert.equal(findingsEmpty.removed, true);
    assert.equal(findingsEmptyRow.removed, true);
    assert.equal(findingsList.entries.length, 1);
    assert.match(findingsList.entries[0].innerHTML, /Stored &lt;XSS&gt;/);
    assert.equal(findingsTableBody.rows.length, 1);
    assert.equal(findingsTableBody.rows[0].id, 'finding-row-finding-55');
    assert.match(findingsTableBody.rows[0].innerHTML, /VALIDATED/);
    assert.deepEqual(appliedDatasets, ['finding-55']);
    assert.deepEqual(galleryCalls, ['finding-55']);
    assert.deepEqual(riskCalls, ['high']);
    assert.deepEqual(indicatorCalls, ['finding-55']);
    assert.equal(updateFindingsListCalls.length, 0);
});

test('findings flow render body helper keeps DOM rendering isolated from follow-up findings side effects', () => {
    const findingsEmpty = createElement('div');
    findingsEmpty.innerText = 'No findings yet';
    const findingsList = {
        entries: [],
        prepend(node) {
            this.entries.unshift(node);
        },
    };
    const findingsContainer = {
        querySelector(selector) {
            if (selector === '.text-muted') return findingsEmpty;
            if (selector === '.result-list') return findingsList;
            return null;
        },
        appendChild() {},
    };
    const findingsEmptyRow = createElement('tr');
    const rowRegistry = new Map();
    const findingsTableBody = {
        rows: [],
        prepend(row) {
            this.rows.unshift(row);
            rowRegistry.set(row.id, row);
        },
    };
    const document = {
        getElementById(id) {
            if (id === 'findings-container') return findingsContainer;
            if (id === 'findings-table-body') return findingsTableBody;
            if (id === 'findings-empty-state') return findingsEmptyRow;
            return rowRegistry.get(id) || null;
        },
        createElement(tagName) {
            const element = createElement(tagName);
            Object.defineProperty(element, 'id', {
                get() {
                    return this._id || '';
                },
                set(value) {
                    this._id = value;
                },
            });
            return element;
        },
        querySelectorAll() { return []; },
        querySelector() { return null; },
        addEventListener() {},
    };

    const updateFindingsListCalls = [];
    const { ScanDashboard } = loadScanDashboardClass({
        document,
        updateFindingsList(items) {
            updateFindingsListCalls.push(items);
        },
    });

    const display = {
        severity: 'high',
        severityLabel: 'HIGH',
        escapedTitle: 'Stored &lt;XSS&gt;',
        escapedTool: 'dalfox',
        escapedDesc: 'Body &lt;script&gt;alert(1)&lt;/script&gt;',
        escapedPrimaryUrl: 'https://target/app?q=&lt;script&gt;',
        primaryCommand: 'dalfox url https://target/app',
        primaryUrl: 'https://target/app?q=<script>',
        escapedScreenshotPath: 'loot/xss-proof.png',
        hasProof: true,
        isValidated: true,
        confidenceLabel: 'HIGH',
        toolLabel: 'DALFOX',
    };
    const finding = {
        id_stable: 'finding-88',
        title: 'Stored <XSS>',
        screenshot_path: 'loot/xss-proof.png',
    };
    const dashboard = {
        getFindingsContract() {
            return {
                applyRowDataset(row, currentFinding) {
                    row.setAttribute('data-finding-id', currentFinding.id_stable);
                },
            };
        },
    };

    const renderedBody = ScanDashboard.internals.findingsFlow.renderFindingBody(
        document,
        dashboard,
        'finding-88',
        finding,
        display
    );

    assert.equal(renderedBody.container, findingsContainer);
    assert.equal(renderedBody.tableRow, findingsTableBody.rows[0]);
    assert.equal(findingsEmpty.removed, true);
    assert.equal(findingsEmptyRow.removed, true);
    assert.equal(findingsList.entries.length, 1);
    assert.match(findingsList.entries[0].innerHTML, /Stored &lt;XSS&gt;/);
    assert.equal(findingsTableBody.rows.length, 1);
    assert.equal(findingsTableBody.rows[0].id, 'finding-row-finding-88');
    assert.equal(updateFindingsListCalls.length, 0);
});

test('findings flow side-effect helper preserves the existing gallery, risk, and indicator updates', () => {
    const { ScanDashboard } = loadScanDashboardClass();
    const galleryCalls = [];
    const riskCalls = [];
    const indicatorCalls = [];
    const dashboard = {
        addToGallery(finding) {
            galleryCalls.push(finding.id_stable);
        },
        updateRiskCounters(severity) {
            riskCalls.push(severity);
        },
        updateIndicators(finding) {
            indicatorCalls.push(finding.id_stable);
        },
    };

    ScanDashboard.internals.findingsFlow.applyRenderedFindingEffects(dashboard, {
        id_stable: 'finding-with-proof',
        severity: 'high',
        screenshot_path: 'loot/xss-proof.png',
    });
    ScanDashboard.internals.findingsFlow.applyRenderedFindingEffects(dashboard, {
        id_stable: 'finding-without-proof',
        severity: 'info',
    });

    assert.deepEqual(galleryCalls, ['finding-with-proof']);
    assert.deepEqual(riskCalls, ['high', 'info']);
    assert.deepEqual(indicatorCalls, ['finding-with-proof', 'finding-without-proof']);
});

test('handleNewFinding preserves the existing findings flow while delegating rendering to extracted findings helpers', () => {
    const findingsEmpty = createElement('div');
    findingsEmpty.innerText = 'No findings yet';
    const findingsList = {
        entries: [],
        prepend(node) {
            this.entries.unshift(node);
        },
    };
    const findingsContainer = {
        querySelector(selector) {
            if (selector === '.text-muted') return findingsEmpty;
            if (selector === '.result-list') return findingsList;
            return null;
        },
        appendChild() {},
    };
    const findingsEmptyRow = createElement('tr');
    const rowRegistry = new Map();
    const findingsTableBody = {
        rows: [],
        prepend(row) {
            this.rows.unshift(row);
            rowRegistry.set(row.id, row);
        },
    };

    const document = {
        getElementById(id) {
            if (id === 'findings-container') return findingsContainer;
            if (id === 'findings-table-body') return findingsTableBody;
            if (id === 'findings-empty-state') return findingsEmptyRow;
            return rowRegistry.get(id) || null;
        },
        querySelectorAll() { return []; },
        querySelector() { return null; },
        addEventListener() {},
        createElement(tagName) {
            const element = createElement(tagName);
            Object.defineProperty(element, 'id', {
                get() {
                    return this._id || '';
                },
                set(value) {
                    this._id = value;
                },
            });
            return element;
        },
    };

    const updateFindingsListCalls = [];
    const { ScanDashboard } = loadScanDashboardClass({
        document,
        updateFindingsList(items) {
            updateFindingsListCalls.push(items);
        },
    });

    const appliedDatasets = [];
    const activated = [];
    const galleryCalls = [];
    const riskCalls = [];
    const indicatorCalls = [];
    const dashboard = {
        scanId: 77,
        renderedFindingIds: new Set(),
        normalizeFindingRecord(finding) {
            return finding;
        },
        activateDiscovery(id, state) {
            activated.push({ id, state });
        },
        escapeHtml(value) {
            return String(value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        },
        getFindingValidationStatus() {
            return 'not_run';
        },
        getFindingResultState() {
            return 'observation';
        },
        getFindingPrimaryCommand() {
            return '';
        },
        getFindingPrimaryUrl() {
            return '';
        },
        getFindingsContract() {
            return {
                applyRowDataset(row, finding) {
                    appliedDatasets.push({ row, finding });
                    row.setAttribute('data-finding-id', finding.id_stable);
                },
            };
        },
        addToGallery(finding) {
            galleryCalls.push(finding.id_stable);
        },
        updateRiskCounters(severity) {
            riskCalls.push(severity);
        },
        updateIndicators(finding) {
            indicatorCalls.push(finding.id_stable);
        },
        updateScanNmapDashboard() {
            throw new Error('service detection flow should not run for this finding');
        },
    };

    const finding = {
        scan_id: 77,
        id_stable: 'finding-77',
        title: 'Stored <XSS>',
        severity: 'high',
        tool_source: 'dalfox',
        description: 'Body <script>alert(1)</script>',
        confidence: 'high',
        screenshot_path: 'loot/xss-proof.png',
        _ui: {
            validationStatus: 'success',
            resultState: 'confirmed',
            primaryCommand: 'dalfox url https://target/app',
            primaryUrl: 'https://target/app?q=<script>',
            hasEvidence: true,
            isValidated: true,
        },
    };

    ScanDashboard.prototype.handleNewFinding.call(dashboard, finding);

    assert.deepEqual(activated, [{ id: 'vulns', state: true }]);
    assert.equal(findingsEmpty.removed, true);
    assert.equal(findingsEmptyRow.removed, true);
    assert.equal(findingsList.entries.length, 1);
    assert.match(findingsList.entries[0].className, /animate__fadeInLeft/);
    assert.match(findingsList.entries[0].innerHTML, /severity-badge high/);
    assert.match(findingsList.entries[0].innerHTML, /Stored &lt;XSS&gt;/);
    assert.match(findingsList.entries[0].innerHTML, /Source: dalfox/);
    assert.match(findingsList.entries[0].innerHTML, /loot\/xss-proof\.png/);
    assert.equal(findingsTableBody.rows.length, 1);
    assert.equal(findingsTableBody.rows[0].id, 'finding-row-finding-77');
    assert.equal(findingsTableBody.rows[0].getAttribute('data-finding-id'), 'finding-77');
    assert.match(findingsTableBody.rows[0].className, /finding-row cursor-pointer/);
    assert.match(findingsTableBody.rows[0].innerHTML, /fa-terminal text-warning/);
    assert.match(findingsTableBody.rows[0].innerHTML, /fa-microscope text-info/);
    assert.match(findingsTableBody.rows[0].innerHTML, /VALIDATED/);
    assert.match(findingsTableBody.rows[0].innerHTML, /https:\/\/target\/app\?q=&lt;script&gt;/);
    assert.match(findingsTableBody.rows[0].innerHTML, /DALFOX/);
    assert.deepEqual(galleryCalls, ['finding-77']);
    assert.deepEqual(riskCalls, ['high']);
    assert.deepEqual(indicatorCalls, ['finding-77']);
    assert.equal(appliedDatasets.length, 1);
    assert.equal(updateFindingsListCalls.length, 1);
    assert.equal(updateFindingsListCalls[0].length, 1);
    assert.equal(updateFindingsListCalls[0][0].id_stable, 'finding-77');

    ScanDashboard.prototype.handleNewFinding.call(dashboard, finding);
    assert.equal(findingsList.entries.length, 1);
    assert.equal(findingsTableBody.rows.length, 1);
    assert.equal(updateFindingsListCalls.length, 2);
});
