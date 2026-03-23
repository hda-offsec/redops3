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

function createNode(tagName = 'div') {
    return {
        tagName,
        className: '',
        style: {},
        children: [],
        attributes: {},
        _innerHTML: '',
        set innerHTML(value) {
            this._innerHTML = value;
        },
        get innerHTML() {
            return this._innerHTML;
        },
        appendChild(child) {
            this.children.push(child);
        },
        querySelector() {
            return null;
        },
        setAttribute(name, value) {
            this.attributes[name] = value;
        },
        getAttribute(name) {
            return this.attributes[name];
        },
        classList: createClassList(),
    };
}

function createDocumentHarness() {
    const nodesById = new Map();

    const deepScanDetails = createNode('div');
    deepScanDetails.id = 'deep-scan-details';
    deepScanDetails.appendChild = function appendChild(child) {
        this.children.push(child);
        if (child._resultContent && child._resultContent.id) {
            nodesById.set(child._resultContent.id, child._resultContent);
        }
    };
    nodesById.set('deep-scan-details', deepScanDetails);

    const deepScanPlaceholder = createNode('div');
    deepScanPlaceholder.id = 'deep-scan-placeholder';
    deepScanPlaceholder.style.display = '';
    nodesById.set('deep-scan-placeholder', deepScanPlaceholder);

    const document = {
        getElementById(id) {
            return nodesById.get(id) || null;
        },
        querySelectorAll() {
            return [];
        },
        querySelector() {
            return null;
        },
        addEventListener() {},
        createElement(tagName) {
            const node = createNode(tagName);
            Object.defineProperty(node, 'innerHTML', {
                get() {
                    return this._innerHTML;
                },
                set(value) {
                    this._innerHTML = value;
                    const match = value.match(/id="([^"]+-results)"/);
                    if (!match) return;

                    const resultContent = createNode('div');
                    resultContent.id = match[1];
                    resultContent.className = 'result-content';
                    this._resultContent = resultContent;
                },
            });
            node.querySelector = function querySelector(selector) {
                if (selector === '.result-content') {
                    return this._resultContent || null;
                }
                return null;
            };
            node.appendChild = function appendChild(child) {
                this.children.push(child);
                if (child._resultContent && child._resultContent.id) {
                    nodesById.set(child._resultContent.id, child._resultContent);
                }
            };
            return node;
        },
    };

    return { document, nodesById, deepScanDetails, deepScanPlaceholder };
}

function createSandbox(overrides = {}) {
    const window = {};
    const document = {
        getElementById() { return null; },
        querySelectorAll() { return []; },
        querySelector() { return null; },
        addEventListener() {},
        createElement(tagName) { return createNode(tagName); },
    };

    const sandbox = {
        console,
        window,
        document,
        navigator: { clipboard: { writeText() {} } },
        io() { return { on() {}, emit() {} }; },
        bootstrap: { Tab: { getOrCreateInstance() { return { show() {} }; } } },
        URL,
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

function createEscapeDashboard(overrides = {}) {
    return {
        escapeHtml(value) {
            return String(value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        },
        ...overrides,
    };
}

test('section rendering registry keeps specialized human renderer dispatch deterministic across aliases', () => {
    const { ScanDashboard } = loadScanDashboardClass();
    const dashboard = createEscapeDashboard({
        renderParamsHuman(data) {
            return `params:${data.label}`;
        },
        renderApiTreeHuman(data) {
            return `api:${data.label}`;
        },
    });

    const rendering = ScanDashboard.internals.sectionRendering;

    assert.equal(rendering.renderSectionHuman(dashboard, 'arjun', { label: 'hidden' }), 'params:hidden');
    assert.equal(rendering.renderSectionHuman(dashboard, 'params', { label: 'query' }), 'params:query');
    assert.equal(rendering.renderSectionHuman(dashboard, 'api', { label: 'tree' }), 'api:tree');
    assert.equal(rendering.renderSectionHuman(dashboard, 'unknown', { label: 'noop' }), null);
});

test('section rendering keeps empty sections out of the deep-scan container', () => {
    const { document, deepScanDetails, deepScanPlaceholder } = createDocumentHarness();
    const { ScanDashboard } = loadScanDashboardClass({ document });
    const rendering = ScanDashboard.internals.sectionRendering;
    const dashboard = createEscapeDashboard();

    rendering.renderJSONSection(document, dashboard, { tls: [] }, 'tls', 'TLS/SSL Audit');
    rendering.renderJSONSection(document, dashboard, { tls: {} }, 'tls', 'TLS/SSL Audit');

    assert.equal(deepScanDetails.children.length, 0);
    assert.equal(deepScanPlaceholder.style.display, '');
});

test('section rendering keeps the generic vulnerability and port-mapped fallbacks intact', () => {
    const { document, nodesById } = createDocumentHarness();
    const genericContainer = createNode('div');
    genericContainer.id = 'custom-vectors-results';
    nodesById.set('custom-vectors-results', genericContainer);

    const portContainer = createNode('div');
    portContainer.id = 'custom-secrets-results';
    nodesById.set('custom-secrets-results', portContainer);

    const { ScanDashboard } = loadScanDashboardClass({ document });
    const rendering = ScanDashboard.internals.sectionRendering;
    const dashboard = createEscapeDashboard();

    rendering.renderJSONSection(document, dashboard, {
        'custom-vectors': [{
            name: 'public-repo',
            severity: 'high',
            description: 'token leak',
            url: 'https://github.com/acme/public-repo',
        }],
    }, 'custom-vectors', 'Custom Vectors');

    rendering.renderJSONSection(document, dashboard, {
        'custom-secrets': {
            443: [{ type: 'API Key', match: 'token-123', file: 'bundle.js' }],
            8443: [],
        },
    }, 'custom-secrets', 'Custom Secrets');

    assert.match(genericContainer.innerHTML, /public-repo/);
    assert.match(genericContainer.innerHTML, /HIGH/);
    assert.match(genericContainer.innerHTML, /github\.com\/acme\/public-repo/);

    assert.match(portContainer.innerHTML, /PORT 443/);
    assert.match(portContainer.innerHTML, /API Key/);
    assert.match(portContainer.innerHTML, /token-123/);
});

test('section rendering preserves the structured key-value fallback for object payloads', () => {
    const { document, nodesById } = createDocumentHarness();
    const container = createNode('div');
    container.id = 'metadata-results';
    nodesById.set('metadata-results', container);

    const { ScanDashboard } = loadScanDashboardClass({ document });
    const rendering = ScanDashboard.internals.sectionRendering;
    const dashboard = createEscapeDashboard();

    rendering.renderJSONSection(document, dashboard, {
        metadata: {
            provider: 'aws',
            metadata: { region: 'us-east-1', exposure: 'private' },
        },
    }, 'metadata', 'Metadata');

    assert.match(container.innerHTML, /provider/);
    assert.match(container.innerHTML, /aws/);
    assert.match(container.innerHTML, /metadata/);
    assert.match(container.innerHTML, /us-east-1/);
});

test('section rendering creates deep-scan cards and keeps the API tree renderer stable', () => {
    const { document, deepScanDetails, deepScanPlaceholder } = createDocumentHarness();
    const { ScanDashboard } = loadScanDashboardClass({ document });
    const rendering = ScanDashboard.internals.sectionRendering;
    const dashboard = createEscapeDashboard({
        renderApiTreeHuman: ScanDashboard.prototype.renderApiTreeHuman,
    });

    rendering.renderJSONSection(document, dashboard, {
        api: {
            endpoints: [
                { url: 'https://target.example/api/users', status: 200 },
                { url: 'https://target.example/api/admin', status: 403 },
                { url: 'https://target.example/health', status: 200 },
            ],
        },
    }, 'api', 'API Endpoints');

    const apiContainer = document.getElementById('api-results');
    assert.equal(deepScanDetails.children.length, 1);
    assert.equal(deepScanPlaceholder.style.display, 'none');
    assert.ok(apiContainer);
    assert.match(apiContainer.innerHTML, /API Endpoint Architecture/);
    assert.match(apiContainer.innerHTML, /target\.example/);
    assert.match(apiContainer.innerHTML, /api\//);
    assert.match(apiContainer.innerHTML, /health/);
    assert.match(apiContainer.innerHTML, /403/);
});
