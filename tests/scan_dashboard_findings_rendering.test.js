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
    assert.equal(updateFindingsListCalls.length, 1);
});
