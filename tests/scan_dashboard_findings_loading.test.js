const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function createSandbox(overrides = {}) {
    const window = {};
    const document = {
        getElementById() { return null; },
        querySelectorAll() { return []; },
        querySelector() { return null; },
        addEventListener() {},
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
        path.join(__dirname, "../ui/web/static/js/scan_dashboard.js"),
        "utf8"
    );
    const sandbox = createSandbox(overrides);
    vm.runInNewContext(`${source}\nthis.__ScanDashboard = ScanDashboard;`, sandbox, {
        filename: "scan_dashboard.js",
    });
    assert.equal(
        typeof sandbox.__ScanDashboard,
        "function",
        "ScanDashboard class was not exposed after evaluating scan_dashboard.js"
    );
    return { ScanDashboard: sandbox.__ScanDashboard, sandbox };
}

test("loadFindingsFromApi stops after a single page when the API total fits in one response", async () => {
    let fetchCount = 0;
    const { ScanDashboard } = loadScanDashboardClass({
        fetch: async () => {
            fetchCount += 1;
            return {
                ok: true,
                json: async () => ({
                    total: 2,
                    items: [
                        { id_stable: "finding-2", title: "Newest" },
                        { id_stable: "finding-1", title: "Oldest" },
                    ],
                }),
            };
        },
    });

    const seen = [];
    const dashboard = {
        scanId: 99,
        handleNewFinding(item) {
            seen.push(item.id_stable);
        },
    };

    await ScanDashboard.prototype.loadFindingsFromApi.call(dashboard, { limit: 200 });

    assert.equal(fetchCount, 1);
    assert.deepEqual(seen, ["finding-1", "finding-2"]);
});

test("loadFindingsFromApi paginates past 500 rows without changing the replay order", async () => {
    const requests = [];
    const { ScanDashboard } = loadScanDashboardClass({
        fetch: async (url) => {
            const parsed = new URL(url, "https://redops.local");
            const limit = Number(parsed.searchParams.get("limit"));
            const offset = Number(parsed.searchParams.get("offset"));
            requests.push({ limit, offset });

            const total = 501;
            const remaining = Math.max(total - offset, 0);
            const batchSize = Math.min(limit, remaining);
            const items = [];

            for (let idx = 0; idx < batchSize; idx += 1) {
                const number = total - offset - idx;
                items.push({
                    id_stable: `finding-${number}`,
                    title: `Finding ${number}`,
                });
            }

            return {
                ok: true,
                json: async () => ({ total, items }),
            };
        },
    });

    const seen = [];
    const dashboard = {
        scanId: 99,
        handleNewFinding(item) {
            seen.push(item.id_stable);
        },
    };

    await ScanDashboard.prototype.loadFindingsFromApi.call(dashboard, { limit: 500 });

    assert.deepEqual(requests, [
        { limit: 500, offset: 0 },
        { limit: 500, offset: 500 },
    ]);
    assert.equal(seen.length, 501);
    assert.equal(seen[0], "finding-1");
    assert.equal(seen[500], "finding-501");
});

test("loadFindingsFromApi updates the DB sync ratio after paginated loading", async () => {
    const loadStateLabel = { textContent: "" };
    const { ScanDashboard } = loadScanDashboardClass({
        document: {
            getElementById(id) {
                if (id === "findings-db-load-state") return loadStateLabel;
                return null;
            },
            querySelectorAll() { return []; },
            querySelector() { return null; },
            addEventListener() {},
        },
        fetch: async (url) => {
            const parsed = new URL(url, "https://redops.local");
            const offset = Number(parsed.searchParams.get("offset"));
            const limit = Number(parsed.searchParams.get("limit"));

            if (offset === 0) {
                return {
                    ok: true,
                    json: async () => ({
                        total: 3,
                        items: [
                            { id_stable: "finding-3", title: "Newest" },
                            { id_stable: "finding-2", title: "Middle" },
                        ].slice(0, limit),
                    }),
                };
            }

            return {
                ok: true,
                json: async () => ({
                    total: 3,
                    items: [{ id_stable: "finding-1", title: "Oldest" }],
                }),
            };
        },
    });

    const seen = [];
    const dashboard = {
        scanId: 99,
        handleNewFinding(item) {
            seen.push(item.id_stable);
        },
    };

    await ScanDashboard.prototype.loadFindingsFromApi.call(dashboard, { limit: 2 });

    assert.deepEqual(seen, ["finding-1", "finding-2", "finding-3"]);
    assert.equal(loadStateLabel.textContent, "DB sync 3/3 loaded");
});
