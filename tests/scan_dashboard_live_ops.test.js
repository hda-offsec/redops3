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
        toArray() {
            return Array.from(classes).sort();
        },
    };
}

function createElement(tagName = 'div') {
    return {
        tagName,
        id: '',
        innerHTML: '',
        innerText: '',
        className: '',
        style: {},
        attributes: {},
        classList: createClassList(),
        removed: false,
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

function createIndicatorCard() {
    const icon = createElement('i');
    icon.classList.add('fa-shield-alt', 'text-success');

    const label = createElement('span');
    label.classList.add('text-success');

    const status = createElement('span');
    status.classList.add('text-muted');
    status.innerText = 'Monitoring';

    const selectors = new Map([
        ['.fa-shield-alt', icon],
        ['.text-success', label],
        ['.text-muted', status],
    ]);

    const card = createElement('div');
    card.classList.add('border-success', 'bg-success', 'bg-opacity-10');
    card.querySelector = (selector) => selectors.get(selector) || null;
    return { card, icon, label, status };
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

function createTableBody() {
    return {
        rows: [],
        prepend(row) {
            this.rows.unshift(row);
        },
    };
}

function createTimelineContainer(initialChildren = []) {
    return {
        children: [...initialChildren],
        prepend(node) {
            this.children.unshift(node);
        },
        get lastElementChild() {
            return this.children[this.children.length - 1] || null;
        },
    };
}

test('module status helper inserts a new row, clears the placeholder, and preserves the badge contract', () => {
    const tableBody = createTableBody();
    const noModulesRow = createElement('tr');
    const rowsById = new Map();
    const countBadge = { innerText: '' };

    const document = {
        getElementById(id) {
            if (id === 'no-modules-row') return noModulesRow;
            if (id === 'module-count') return countBadge;
            return rowsById.get(id) || null;
        },
        querySelectorAll(selector) {
            if (selector === '#modules-table .text-primary') {
                return [{}, {}];
            }
            return [];
        },
        querySelector() { return null; },
        addEventListener() {},
        createElement(tagName) {
            const row = createElement(tagName);
            Object.defineProperty(row, 'id', {
                get() {
                    return this._id || '';
                },
                set(value) {
                    this._id = value;
                    rowsById.set(value, this);
                },
            });
            return row;
        },
    };

    const { ScanDashboard } = loadScanDashboardClass({ document });
    const data = { module: 'nuclei', port: 443, status: 'running', artifacts: 3, reason: '' };

    const synced = ScanDashboard.internals.moduleStatus.syncRow(document, tableBody, data);
    ScanDashboard.internals.moduleStatus.updateActiveCount(document);

    assert.equal(noModulesRow.removed, true);
    assert.equal(synced.existed, false);
    assert.equal(tableBody.rows.length, 1);
    assert.equal(tableBody.rows[0].id, 'mod-row-nuclei-443');
    assert.match(tableBody.rows[0].innerHTML, /RUNNING/);
    assert.match(tableBody.rows[0].innerHTML, /font-monospace text-info small">nuclei</);
    assert.equal(countBadge.innerText, '2 Active');
});

test('handleModuleStatus keeps the public flow intact when refreshing an existing row', async () => {
    const tableBody = createTableBody();
    const existingRow = createElement('tr');
    existingRow.id = 'mod-row-httpx-80';
    const countBadge = { innerText: '' };

    const document = {
        getElementById(id) {
            if (id === 'mod-row-httpx-80') return existingRow;
            if (id === 'module-count') return countBadge;
            return null;
        },
        querySelector(selector) {
            if (selector === '#modules-table tbody') return tableBody;
            return null;
        },
        querySelectorAll(selector) {
            if (selector === '#modules-table .text-primary') return [{}];
            return [];
        },
        addEventListener() {},
        createElement(tagName) {
            return createElement(tagName);
        },
    };

    const { ScanDashboard } = loadScanDashboardClass({ document });
    ScanDashboard.prototype.handleModuleStatus.call({}, {
        module: 'httpx',
        port: 80,
        status: 'done',
        artifacts: 1,
        reason: 'completed',
    });

    assert.match(existingRow.innerHTML, /DONE/);
    assert.equal(countBadge.innerText, '1 Active');
    assert.equal(existingRow.classList.contains('animate__animated'), true);
    assert.equal(existingRow.classList.contains('animate__flash'), true);

    await new Promise((resolve) => setTimeout(resolve, 1100));
    assert.equal(existingRow.classList.contains('animate__animated'), false);
    assert.equal(existingRow.classList.contains('animate__flash'), false);
});

test('pipeline timeline helper renders the timestamp from ISO events and trims beyond the 50-event cap', () => {
    const noTimelineRow = createElement('div');
    const initialChildren = Array.from({ length: 50 }, () => createElement('div'));
    const container = createTimelineContainer(initialChildren);
    const tail = createElement('div');
    tail.remove = function remove() {
        this.removed = true;
        const index = container.children.indexOf(this);
        if (index >= 0) {
            container.children.splice(index, 1);
        }
    };
    container.children.push(tail);
    const document = {
        getElementById(id) {
            if (id === 'no-timeline-row') return noTimelineRow;
            return null;
        },
        createElement(tagName) {
            return createElement(tagName);
        },
        querySelectorAll() { return []; },
        querySelector() { return null; },
        addEventListener() {},
    };

    const { ScanDashboard } = loadScanDashboardClass({ document });
    ScanDashboard.internals.pipelineTimeline.appendEvent(document, container, {
        ts: '2026-03-22T12:34:56.123Z',
        module: 'recon',
        type: 'phase_start',
        level: 'ERROR',
    });

    assert.equal(noTimelineRow.removed, true);
    assert.equal(container.children.length, 51);
    assert.equal(tail.removed, true);
    assert.match(container.children[0].innerHTML, /12:34:56/);
    assert.match(container.children[0].innerHTML, /recon/);
    assert.match(container.children[0].innerHTML, /ERROR/);
});

test('handlePipelineEvent continues to delegate to the extracted helper without changing the DOM contract', () => {
    const container = createTimelineContainer();
    const document = {
        getElementById(id) {
            if (id === 'timeline-container') return container;
            return null;
        },
        createElement(tagName) {
            return createElement(tagName);
        },
        querySelectorAll() { return []; },
        querySelector() { return null; },
        addEventListener() {},
    };

    const { ScanDashboard } = loadScanDashboardClass({ document });
    ScanDashboard.prototype.handlePipelineEvent.call({}, {
        ts: '2026-03-22T05:06:07.000Z',
        module: 'enum',
        type: 'artifact',
        level: 'INFO',
    });

    assert.equal(container.children.length, 1);
    assert.match(container.children[0].className, /animate__fadeInDown/);
    assert.match(container.children[0].innerHTML, /05:06:07/);
    assert.match(container.children[0].innerHTML, /enum/);
    assert.doesNotMatch(container.children[0].innerHTML, /ERROR/);
});

test('log stream helper appends a warning entry, clears placeholders, and preserves the rendered log contract', () => {
    const legacyEmpty = createElement('div');
    legacyEmpty.innerText = 'No logs yet';
    const timelineEmpty = createElement('div');
    const appended = [];
    const consoleDiv = {
        scrollHeight: 64,
        scrollTop: 0,
        querySelector(selector) {
            if (selector === '.text-muted') return legacyEmpty;
            if (selector === '#timeline-empty-msg') return timelineEmpty;
            return null;
        },
        appendChild(node) {
            appended.push(node);
        },
    };

    const document = {
        getElementById() { return null; },
        querySelector(selector) {
            if (selector === '.log-console') return consoleDiv;
            return null;
        },
        querySelectorAll() { return []; },
        addEventListener() {},
        createElement(tagName) {
            return createElement(tagName);
        },
    };

    const { ScanDashboard } = loadScanDashboardClass({ document });
    const appendedEntry = ScanDashboard.internals.logStream.appendLogEntry(document, {
        timestamp: '09:10:11',
        level: 'WARN',
        message: 'Watch the edge',
    });

    assert.equal(appendedEntry, true);
    assert.equal(legacyEmpty.removed, true);
    assert.equal(timelineEmpty.removed, true);
    assert.equal(appended.length, 1);
    assert.match(appended[0].className, /animate__fadeIn/);
    assert.match(appended[0].innerHTML, /\[09:10:11\]/);
    assert.match(appended[0].innerHTML, /text-warning fw-bold/);
    assert.match(appended[0].innerHTML, /Watch the edge/);
    assert.equal(consoleDiv.scrollTop, 64);
});

test('handleNewLog delegates to the extracted helper and keeps trigger, toast, and finished-state flows compatible', () => {
    const statusPill = createElement('span');
    statusPill.className = 'badge status-pill status-running ms-2';
    const logEntryNodes = [];
    const discoveryButton = createElement('button');
    discoveryButton.classList.add('discovery-btn', 'active');
    const consoleDiv = {
        scrollHeight: 41,
        scrollTop: 0,
        querySelector() { return null; },
        appendChild(node) {
            logEntryNodes.push(node);
        },
    };

    const document = {
        getElementById() { return null; },
        querySelector(selector) {
            if (selector === '.log-console') return consoleDiv;
            if (selector === '.status-pill') return statusPill;
            return null;
        },
        querySelectorAll(selector) {
            if (selector === '.discovery-btn') return [discoveryButton];
            return [];
        },
        addEventListener() {},
        createElement(tagName) {
            return createElement(tagName);
        },
    };

    const { ScanDashboard } = loadScanDashboardClass({ document });
    const activated = [];
    const toastStates = [];
    const highlighted = [];
    const dashboard = {
        scanId: 7,
        logTriggers: { Nuclei: 'vulns' },
        highlightPTES(message) {
            highlighted.push(message);
        },
        activateDiscovery(id, state) {
            activated.push({ id, state });
        },
        toggleScanToast(show) {
            toastStates.push(show);
        },
    };

    ScanDashboard.prototype.handleNewLog.call(dashboard, {
        scan_id: 7,
        timestamp: '10:11:12',
        level: 'SUCCESS',
        message: 'Nuclei completed - Scan finished',
    });

    assert.equal(logEntryNodes.length, 1);
    assert.match(logEntryNodes[0].innerHTML, /text-success fw-bold/);
    assert.deepEqual(highlighted, ['Nuclei completed - Scan finished']);
    assert.deepEqual(activated, [{ id: 'vulns', state: true }]);
    assert.deepEqual(toastStates, [false]);
    assert.equal(statusPill.innerText, 'finished');
    assert.equal(statusPill.className, 'badge status-pill status-finished ms-2');
    assert.equal(discoveryButton.classList.contains('active'), false);
    assert.equal(discoveryButton.classList.contains('discovered'), true);
});


test('indicator helper matches keywords and updates the existing card contract without touching unrelated cards', () => {
    const xssCard = createIndicatorCard();
    const apiCard = createIndicatorCard();
    const untouchedCard = createIndicatorCard();
    const selectors = new Map([
        ['.vuln-indicator-xss', xssCard.card],
        ['.vuln-indicator-api', apiCard.card],
        ['.vuln-indicator-secret', untouchedCard.card],
    ]);

    const document = {
        getElementById() { return null; },
        querySelector(selector) {
            return selectors.get(selector) || null;
        },
        querySelectorAll() { return []; },
        addEventListener() {},
        createElement(tagName) {
            return createElement(tagName);
        },
    };

    const { ScanDashboard } = loadScanDashboardClass({ document });

    assert.deepEqual(
        Array.from(ScanDashboard.internals.indicators.getMatchedKeys({
            title: 'Stored XSS on API explorer',
            tool: 'dalfox',
        })),
        ['xss', 'api']
    );

    ScanDashboard.prototype.updateIndicators.call({}, {
        title: 'Stored XSS on API explorer',
        tool: 'dalfox',
    });

    assert.equal(xssCard.card.classList.contains('border-danger'), true);
    assert.equal(xssCard.card.classList.contains('bg-danger'), true);
    assert.equal(xssCard.icon.classList.contains('fa-exclamation-circle'), true);
    assert.equal(xssCard.icon.classList.contains('text-danger'), true);
    assert.equal(xssCard.label.classList.contains('text-danger'), true);
    assert.equal(xssCard.status.innerText, 'Detected');

    assert.equal(apiCard.card.classList.contains('border-danger'), true);
    assert.equal(apiCard.status.innerText, 'Detected');

    assert.equal(untouchedCard.card.classList.contains('border-success'), true);
    assert.equal(untouchedCard.status.innerText, 'Monitoring');
});

test('loot stream helper increments counters and appends a deterministic vault entry without changing the markup contract', async () => {
    const counterA = createElement('span');
    counterA.innerText = '2';
    const counterB = createElement('span');
    counterB.innerText = '0';
    const emptyState = createElement('div');
    const entries = [];
    const vault = {
        querySelector(selector) {
            if (selector === '.text-center') return emptyState;
            return null;
        },
        prepend(node) {
            entries.unshift(node);
        },
    };

    const document = {
        getElementById() { return null; },
        querySelector(selector) {
            if (selector === '#loot-vault-container .list-group') return vault;
            return null;
        },
        querySelectorAll(selector) {
            if (selector === '.loot-counter-val') return [counterA, counterB];
            return [];
        },
        addEventListener() {},
        createElement(tagName) {
            return createElement(tagName);
        },
    };

    const { ScanDashboard } = loadScanDashboardClass({ document });
    const stamp = ScanDashboard.internals.lootStream.formatTimestamp({
        getHours() { return 5; },
        getMinutes() { return 7; },
    });

    assert.equal(stamp, '05:07');

    ScanDashboard.internals.lootStream.incrementCounters(document);
    const appended = ScanDashboard.internals.lootStream.appendVaultEntry(
        document,
        ScanDashboard.internals.lootStream.ensureVaultList(document),
        {
            type: 'token',
            content: 'AKIA-123',
            context: 's3',
        },
        (value) => String(value).replace(/</g, '&lt;'),
        stamp
    );

    assert.equal(appended, true);
    assert.equal(counterA.innerText, 3);
    assert.equal(counterB.innerText, 1);
    assert.equal(counterA.classList.contains('animate__bounceIn'), true);
    assert.equal(counterB.classList.contains('text-success'), true);
    assert.equal(emptyState.removed, true);
    assert.equal(entries.length, 1);
    assert.match(entries[0].className, /animate__fadeInDown/);
    assert.match(entries[0].innerHTML, /token/);
    assert.match(entries[0].innerHTML, /05:07/);
    assert.match(entries[0].innerHTML, /AKIA-123/);
    assert.match(entries[0].innerHTML, /s3/);

    await new Promise((resolve) => setTimeout(resolve, 1100));
    assert.equal(counterA.classList.contains('animate__bounceIn'), false);
    assert.equal(counterB.classList.contains('animate__bounceIn'), false);
});

test('handleNewLoot keeps the public orchestration intact after delegating to the extracted helper', () => {
    const counter = createElement('span');
    counter.innerText = '4';
    const entries = [];
    const vault = {
        querySelector() { return null; },
        prepend(node) {
            entries.unshift(node);
        },
    };

    const document = {
        getElementById() { return null; },
        querySelector(selector) {
            if (selector === '#loot-vault-container .list-group') return vault;
            return null;
        },
        querySelectorAll(selector) {
            if (selector === '.loot-counter-val') return [counter];
            return [];
        },
        addEventListener() {},
        createElement(tagName) {
            return createElement(tagName);
        },
    };

    const FakeDate = class extends Date {
        constructor() {
            super('2026-03-22T13:09:00Z');
        }
    };

    const { ScanDashboard } = loadScanDashboardClass({ document, Date: FakeDate });
    const activated = [];
    const dashboard = {
        scanId: 9,
        activateDiscovery(id, state) {
            activated.push({ id, state });
        },
        escapeHtml(value) {
            return String(value).replace(/&/g, '&amp;');
        },
    };

    ScanDashboard.prototype.handleNewLoot.call(dashboard, {
        scan_id: 9,
        type: 'secret',
        content: 'alpha&beta',
        context: 'headers',
    });

    assert.deepEqual(activated, [{ id: 'loot', state: true }]);
    assert.equal(counter.innerText, 5);
    assert.equal(entries.length, 1);
    assert.match(entries[0].innerHTML, /secret/);
    assert.match(entries[0].innerHTML, /13:09/);
    assert.match(entries[0].innerHTML, /alpha&amp;beta/);
    assert.match(entries[0].innerHTML, /headers/);
});

test('handleProgressUpdate delegates to the extracted progress view and preserves running/completed UI states', () => {
    const progressBar = createElement('div');
    progressBar.classList.add('progress-bar-animated', 'progress-bar-striped');
    const phaseText = createElement('span');
    const statusText = createElement('span');
    const spinner = createElement('div');
    const toastBar = createElement('div');
    const toastPhase = createElement('span');
    const toastPercent = createElement('span');
    const auditPhase = createElement('span');
    const discoveryButton = createElement('button');
    discoveryButton.classList.add('discovery-btn', 'active');

    const nodes = new Map([
        ['scan-progress-bar', progressBar],
        ['scan-phase-text', phaseText],
        ['scan-status-text', statusText],
        ['scan-spinner', spinner],
        ['toast-progress-bar', toastBar],
        ['toast-phase-text', toastPhase],
        ['toast-percent-text', toastPercent],
        ['audit-journey-current-phase', auditPhase],
    ]);

    const document = {
        getElementById(id) {
            return nodes.get(id) || null;
        },
        querySelectorAll(selector) {
            if (selector === '.discovery-btn') return [discoveryButton];
            return [];
        },
        querySelector() { return null; },
        addEventListener() {},
        createElement(tagName) {
            return createElement(tagName);
        },
    };

    const { ScanDashboard } = loadScanDashboardClass({ document });
    const normalizedProgress = ScanDashboard.internals.progressView.normalize({
        percent: 33.6,
        current_phase: 'Nuclei API sweep',
    });
    assert.equal(normalizedProgress.percent, 34);
    assert.equal(normalizedProgress.phase, 'Nuclei API sweep');

    const activated = [];
    const toastStates = [];
    const dashboard = {
        scanId: 42,
        highlightPTESCalls: [],
        highlightPTES(phase) {
            this.highlightPTESCalls.push(phase);
        },
        activateDiscovery(id, state) {
            activated.push({ id, state });
        },
        toggleScanToast(show) {
            toastStates.push(show);
        },
    };

    ScanDashboard.prototype.handleProgressUpdate.call(dashboard, {
        scan_id: 42,
        percent: 33.6,
        current_phase: 'Nuclei API sweep',
    });

    assert.equal(progressBar.style.width, '34%');
    assert.equal(progressBar.getAttribute('aria-valuenow'), 34);
    assert.equal(phaseText.innerText, 'Nuclei API sweep');
    assert.equal(auditPhase.innerText, 'Current Phase: Nuclei API sweep');
    assert.equal(toastBar.style.width, '34%');
    assert.equal(toastPhase.innerText, 'Nuclei API sweep');
    assert.equal(toastPercent.innerText, '34%');
    assert.equal(statusText.innerText, 'running');
    assert.equal(spinner.classList.contains('d-none'), false);
    assert.deepEqual(dashboard.highlightPTESCalls, ['Nuclei API sweep']);
    assert.deepEqual(activated, [{ id: 'api', state: false }, { id: 'vulns', state: false }]);
    assert.deepEqual(toastStates, [true]);
    assert.equal(discoveryButton.classList.contains('discovered'), false);

    ScanDashboard.prototype.handleProgressUpdate.call(dashboard, {
        scan_id: 42,
        percent: 100,
        current_phase: 'Phase complete',
    });

    assert.equal(statusText.innerText, 'completed');
    assert.equal(spinner.classList.contains('d-none'), true);
    assert.equal(progressBar.classList.contains('progress-bar-animated'), false);
    assert.equal(progressBar.classList.contains('progress-bar-striped'), false);
    assert.equal(progressBar.classList.contains('bg-success'), true);
    assert.equal(discoveryButton.classList.contains('active'), false);
    assert.equal(discoveryButton.classList.contains('discovered'), true);
    assert.deepEqual(toastStates, [true, false]);
});
