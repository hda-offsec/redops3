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
        classList: createClassList(),
        removed: false,
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
