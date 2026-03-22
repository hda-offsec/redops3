/**
 * RedOps Scan Dashboard Controller
 * Handles real-time updates via Socket.IO and UI state management.
 */

class ScanDashboard {
    constructor(scanId, targetIdentifier) {
        this.scanId = scanId;
        this.targetIdentifier = targetIdentifier;
        this.socket = io();

        // PTES Mapping
        this.ptesMap = {
            'Phase 1': 'recon', 'Phase 2': 'recon', 'Phase 3': 'recon',
            'Phase 4': 'enum', 'Phase 5': 'vuln', 'Phase 6': 'initial',
            'Phase 7': 'privesc', 'Phase 8': 'lateral', 'Phase 9': 'postex'
        };

        this.logTriggers = {
            'Phase 1': 'ports', 'Phase 2': 'ports', 'subdomains': 'dns',
            'Cloud Audit': 'cloud', 'WAF': 'waf', 'Arjun': 'params',
            'Kiterunner': 'api', 'API Discovery': 'api', 'Secret': 'secrets',
            'JS Secrets': 'secrets', 'Katana': 'crawl', 'ffuf': 'fuzz',
            'Dirbusting': 'fuzz', 'Vulnerability': 'vulns', 'Nuclei': 'vulns',
            'Dalfox': 'vulns', 'Intel': 'intel', 'Loot': 'loot',
            'Wayback': 'historic', 'Historic': 'historic', 'Archive': 'historic',
            'Spring': 'apps', 'Firebase': 'apps', 'Actuator': 'apps', 'Docker': 'apps',
            'rfi_expert': 'rfi', 'RFI': 'rfi', 'xss_expert': 'xss', 'XSS': 'xss',
            'logic_expert': 'logic', 'Logic': 'logic', 'sqli_expert': 'sqli', 'SQLi': 'sqli'
        };

        this.renderedFindingIds = new Set();
        this.init();
    }

    updateFindingsLoadState(loaded = 0, total = 0, state = "ready") {
        const label = document.getElementById("findings-db-load-state");
        if (!label) return;

        if (state === "error") {
            label.textContent = "DB sync failed";
            return;
        }

        if (state === "loading" && (!Number.isFinite(total) || total <= 0)) {
            label.textContent = "DB sync loading";
            return;
        }

        const safeLoaded = Number.isFinite(loaded) ? loaded : 0;
        const safeTotal = Number.isFinite(total) ? total : safeLoaded;
        const suffix = state === "loading" ? "loading" : "loaded";
        label.textContent = `DB sync ${safeLoaded}/${safeTotal} ${suffix}`;
    }

    async loadFindingsFromApi(options = {}) {
        const { reset = false, limit = 200, offset = 0 } = options;
        if (reset) {
            const tableBody = document.getElementById("findings-table-body");
            if (tableBody) tableBody.innerHTML = "";
            const container = document.getElementById("findings-container");
            if (container) {
                const list = container.querySelector(".result-list");
                if (list) list.innerHTML = "";
            }
            this.renderedFindingIds.clear();
        }

        try {
            ScanDashboard.prototype.updateFindingsLoadState.call(this, 0, 0, "loading");
            let currentOffset = offset;
            let total = 0;
            const allItems = [];

            while (true) {
                const response = await fetch(`/api/scans/${this.scanId}/findings?limit=${limit}&offset=${currentOffset}`);
                if (!response.ok) throw new Error(`API Error: ${response.status}`);
                const data = await response.json();
                const pageItems = Array.isArray(data.items) ? data.items : [];

                total = Number.isFinite(data.total) ? data.total : allItems.length + pageItems.length;
                allItems.push(...pageItems);
                ScanDashboard.prototype.updateFindingsLoadState.call(
                    this,
                    allItems.length,
                    total,
                    currentOffset + pageItems.length >= total ? "ready" : "loading"
                );

                if (pageItems.length === 0) break;

                currentOffset += pageItems.length;
                if (currentOffset >= total) break;
                if (pageItems.length < limit) break;
            }

            // The API is newest-first. We replay the full batch oldest-first so
            // the existing prepend logic still yields a stable newest-first UI.
            const items = [...allItems].reverse();
            items.forEach(item => {
                this.handleNewFinding({
                    scan_id: this.scanId,
                    ...item
                });
            });

            console.log(`Loaded ${allItems.length}/${total} findings from DB.`);
        } catch (err) {
            ScanDashboard.prototype.updateFindingsLoadState.call(this, 0, 0, "error");
            console.error("Failed to load findings from API:", err);
        }
    }

    init() {
        this.setupSocketListeners();
        this.setupEventListeners();
        this.checkInitialStatus();
        this.setupNotesPreview();

        // Initialize renderedFindingIds from existing DOM elements (Jinja rendered)
        document.querySelectorAll('.finding-row[id^="finding-row-"]').forEach(row => {
            const fid = row.id.replace('finding-row-', '');
            this.renderedFindingIds.add(fid);
        });

        // Load persisted findings from DB (background update, no reset)
        this.loadFindingsFromApi({ reset: false });

        // Expose updateUI globally for initial load
        window.updateUI = (results) => this.updateUI(results);
        window.verifyFinding = (cmd) => this.verifyFinding(cmd);

        // Define filterFindings globally only if not already defined (specialized tabs take precedence)
        if (typeof window.filterFindings === 'undefined') {
            window.filterFindings = () => this.filterFindings();
        }
    }

    setupEventListeners() {
        // Defensive: element might not exist on all page types
        const searchInput = document.getElementById('findingSearch') || document.getElementById('findings-search');
        searchInput?.addEventListener('input', () => window.filterFindings());

        // Delegate search and filter events
        document.addEventListener('change', (e) => {
            if (e.target.matches('.form-check-input')) {
                if (typeof window.filterFindings === 'function') {
                    window.filterFindings();
                } else {
                    this.filterFindings();
                }
            }
        });

        // Delegate copy buttons
        document.addEventListener('click', (e) => {
            const btn = e.target.closest('.copy-btn');
            if (btn) {
                const pre = btn.closest('.tab-pane, .d-flex').querySelector('pre');
                if (pre) {
                    navigator.clipboard.writeText(pre.innerText);
                    const icon = btn.querySelector('i');
                    if (icon) {
                        icon.className = 'fas fa-check';
                        setTimeout(() => { icon.className = 'fas fa-copy'; }, 2000);
                    }
                    this.showToast('Tactical Terminal', 'Command copied to clipboard', 'info');
                }
                return;
            }

            // Screenshot viewing
            const trigger = e.target.closest('.screenshot-trigger');
            if (trigger) {
                window.open(trigger.src);
                return;
            }

            // Manual verification
            const verifyBtn = e.target.closest('.verify-btn');
            if (verifyBtn) {
                const encoded = verifyBtn.getAttribute('data-command');
                const cmd = this.decodeDataValue(encoded);
                this.verifyFinding(cmd);
                return;
            }
        });
    }

    escapeHtml(unsafe) {
        if (!unsafe) return "";
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    getFindingsContract() {
        return window.RedOpsFindings;
    }

    normalizeFindingRecord(finding) {
        return this.getFindingsContract().normalizeFindingRecord(finding);
    }

    isMeaningfulValue(value) {
        return this.getFindingsContract().isMeaningfulText(value);
    }

    getFindingValidation(finding) {
        return this.getFindingsContract().getValidation(finding);
    }

    getFindingReproducibility(finding) {
        return this.getFindingsContract().getReproducibility(finding);
    }

    getFindingValidationStatus(finding) {
        return this.normalizeFindingRecord(finding)?._ui?.validationStatus || 'not_run';
    }

    getFindingResultState(finding) {
        return this.normalizeFindingRecord(finding)?._ui?.resultState || 'observation';
    }

    getFindingPrimaryCommand(finding) {
        return this.normalizeFindingRecord(finding)?._ui?.primaryCommand || '';
    }

    getFindingPrimaryUrl(finding) {
        return this.normalizeFindingRecord(finding)?._ui?.primaryUrl || '';
    }

    decodeDataValue(value) {
        return this.getFindingsContract().decodeDataValue(value);
    }

    hasMeaningfulProof(finding) {
        return this.normalizeFindingRecord(finding)?._ui?.hasEvidence || false;
    }

    getFindingAlertTone(finding) {
        const sev = (finding?.severity || 'info').toLowerCase();
        if (sev === 'critical' || sev === 'high') return 'danger';
        if (sev === 'medium') return 'warning';
        return 'secondary';
    }

    setupSocketListeners() {
        const statusEl = document.getElementById('socket-status');

        this.socket.on('connect', () => {
            console.log("Socket connected, joining room: scan_" + this.scanId);
            if (statusEl) {
                statusEl.innerText = "connected";
                statusEl.className = "badge bg-success";
            }
            this.socket.emit('join_scan', { scan_id: this.scanId });
        });

        this.socket.on('connect_error', (error) => {
            console.error("Socket Connection Error:", error);
            if (statusEl) {
                statusEl.innerText = "offline";
                statusEl.className = "badge bg-danger";
            }
        });

        this.socket.on('disconnect', () => {
            if (statusEl) {
                statusEl.innerText = "reconnecting...";
                statusEl.className = "badge bg-warning";
            }
        });

        this.socket.on("new_log", (data) => this.handleNewLog(data));
        this.socket.on("results_update", (msg) => {
            if (msg.scan_id == this.scanId) this.updateUI(msg.results);
        });
        this.socket.on("new_finding", (data) => this.handleNewFinding(data));
        this.socket.on("new_suggestion", (data) => this.handleNewSuggestion(data));
        this.socket.on("new_loot", (data) => this.handleNewLoot(data));
        this.socket.on("progress_update", (data) => this.handleProgressUpdate(data));
        this.socket.on("module_status", (data) => this.handleModuleStatus(data));
        this.socket.on("pipeline_event", (data) => this.handlePipelineEvent(data));
        this.socket.on("graph_updated", (data) => {
            if (data.scan_id != this.scanId) return;
            if (typeof initGraphData === 'function') {
                initGraphData();
            }
        });
    }

    handleModuleStatus(data) {
        const tableBody = document.querySelector("#modules-table tbody");
        if (!tableBody) return;

        const rowId = `mod-row-${data.module}-${data.port}`;
        let row = document.getElementById(rowId);

        const noModuleRow = document.getElementById("no-modules-row");
        if (noModuleRow) noModuleRow.remove();

        const getStatusBadge = (status) => {
            const s = status.toLowerCase();
            if (s === 'running') return '<span class="badge bg-primary bg-opacity-10 text-primary border border-primary x-small">RUNNING</span>';
            if (s === 'executed' || s === 'done') return '<span class="badge bg-success bg-opacity-10 text-success border border-success x-small">DONE</span>';
            if (s === 'skipped') return '<span class="badge bg-secondary bg-opacity-10 text-secondary border border-secondary x-small">SKIP</span>';
            if (s === 'failed' || s === 'error') return '<span class="badge bg-danger bg-opacity-10 text-danger border border-danger x-small">FAIL</span>';
            return `<span class="badge bg-dark border border-secondary text-muted x-small">${status.toUpperCase()}</span>`;
        };

        const innerHTML = `
            <td class="font-monospace text-info small">${data.module}</td>
            <td class="font-monospace text-muted small">${data.port}</td>
            <td>${getStatusBadge(data.status)}</td>
            <td class="text-end font-monospace small">${data.artifacts || 0}</td>
            <td class="text-muted x-small">${data.reason || '-'}</td>
        `;

        if (row) {
            row.innerHTML = innerHTML;
            row.classList.add('animate__animated', 'animate__flash');
            setTimeout(() => row.classList.remove('animate__animated', 'animate__flash'), 1000);
        } else {
            row = document.createElement("tr");
            row.id = rowId;
            row.innerHTML = innerHTML;
            tableBody.prepend(row);
        }

        // Update active count
        const activeCount = document.querySelectorAll("#modules-table .text-primary").length;
        const countBadge = document.getElementById("module-count");
        if (countBadge) countBadge.innerText = `${activeCount} Active`;
    }

    handlePipelineEvent(data) {
        const container = document.getElementById("timeline-container");
        if (!container) return;

        const noTimelineRow = document.getElementById("no-timeline-row");
        if (noTimelineRow) noTimelineRow.remove();

        const timeString = data.ts.includes('T') ? data.ts.split('T')[1].split('.')[0] : new Date().toLocaleTimeString();

        const div = document.createElement("div");
        div.className = "d-flex justify-content-between align-items-start border-bottom border-dark pb-1 animate__animated animate__fadeInDown";
        div.innerHTML = `
            <div>
                <span class="text-muted x-small font-monospace">${timeString}</span>
                <span class="badge bg-dark border border-secondary text-light x-small ms-1">${data.module}</span>
                <span class="text-secondary small ms-1">${data.type}</span>
            </div>
            ${data.level === 'ERROR' ? '<span class="text-danger x-small fw-bold">ERROR</span>' : ''}
        `;

        container.prepend(div);

        // Keep only last 50 events
        if (container.children.length > 50) {
            container.lastElementChild.remove();
        }
    }

    handleNewLog(data) {
        if (data.scan_id != this.scanId) return;

        const consoleDiv = document.querySelector(".log-console");
        if (consoleDiv) {
            const legacyEmptyMsg = consoleDiv.querySelector(".text-muted");
            if (legacyEmptyMsg && legacyEmptyMsg.innerText.includes("No logs")) legacyEmptyMsg.remove();
            const newEmptyMsg = consoleDiv.querySelector("#timeline-empty-msg");
            if (newEmptyMsg) newEmptyMsg.remove();

            const div = document.createElement("div");
            div.className = "px-3 py-1 border-bottom border-dark hover-bg-dark animate__animated animate__fadeIn";
            const levelClass = data.level === 'SUCCESS' ? 'text-success' : (data.level === 'WARN' ? 'text-warning' : (data.level === 'ERROR' ? 'text-danger' : 'text-secondary'));
            div.innerHTML = `<span class="text-secondary opacity-50">[${data.timestamp}]</span> <span class="${levelClass} fw-bold mx-2">[${data.level}]</span> <span class="text-light">${data.message}</span>`;
            consoleDiv.appendChild(div);
            consoleDiv.scrollTop = consoleDiv.scrollHeight;
        }

        this.highlightPTES(data.message);

        for (const [trigger, id] of Object.entries(this.logTriggers)) {
            if (data.message.includes(trigger)) {
                this.activateDiscovery(id, data.level === 'SUCCESS');
            }
        }

        if (data.message.includes("Scan finished")) {
            const sp = document.querySelector('.status-pill');
            if (sp) {
                sp.innerText = 'finished';
                sp.className = 'badge status-pill status-finished ms-2';
            }
            this.toggleScanToast(false);

            // Mark all buttons as 'discovered' (blue) when the scan is completely finished
            document.querySelectorAll('.discovery-btn').forEach(btn => {
                btn.classList.remove('active');
                btn.classList.add('discovered');
            });
        }
    }

    handleNewFinding(data) {
        if (data.scan_id != this.scanId) return;
        data = this.normalizeFindingRecord(data);

        // Deduplication Logic: Prioritize id_stable, then database id, then heuristic
        const fid = data.id_stable || data.id || `temp-${data.title}-${data.severity}-${data.tool}`;
        if (this.renderedFindingIds.has(fid)) return;
        this.renderedFindingIds.add(fid);

        this.activateDiscovery('vulns', true);

        const container = document.getElementById("findings-container");
        if (container) {
            const empty = container.querySelector(".text-muted");
            if (empty && empty.innerText.includes("No findings")) empty.remove();

            let list = container.querySelector(".result-list");
            if (!list) {
                list = document.createElement("div");
                list.className = "result-list";
                container.appendChild(list);
            }

            const div = document.createElement("div");
            div.className = "result-row flex-column align-items-start p-3 mb-2 bg-black border border-secondary rounded position-relative hover-highlight animate__animated animate__fadeInLeft";

            const severity = (data.severity || 'info').toLowerCase();
            const escapedTitle = this.escapeHtml(data.title || 'Untitled finding');
            const escapedTool = this.escapeHtml(data.tool_source || data.tool || 'core');
            const escapedDesc = this.escapeHtml(data.description || '');
            const ui = data._ui || {};
            const validationStatus = ui.validationStatus || this.getFindingValidationStatus(data);
            const resultState = ui.resultState || this.getFindingResultState(data);
            const primaryCommand = ui.primaryCommand || this.getFindingPrimaryCommand(data);
            const hasProof = ui.hasEvidence === true;

            let innerHTML = `
                <div class="d-flex w-100 justify-content-between mb-2">
                    <span class="badge severity-badge ${severity}">${severity.toUpperCase()}</span>
                    <span class="result-text fw-bold text-break">${escapedTitle}</span>
                </div>
                <div class="mt-1 small text-muted text-break">Source: ${escapedTool}</div>
            `;

            if (data.description) {
                innerHTML += `<div class="mt-1 small text-muted text-break overflow-auto" style="max-height: 200px; white-space: pre-wrap;">${escapedDesc}</div>`;
            }

            if (data.screenshot_path) {
                const escapedPath = this.escapeHtml(data.screenshot_path);
                innerHTML += `
                    <div class="mt-2 w-100">
                        <img src="/static/${escapedPath}" class="img-fluid rounded border border-secondary shadow-sm screenshot-trigger" style="max-height: 150px; cursor: pointer;" title="Port ${escapedTitle}">
                    </div>
                `;
                this.addToGallery(data);
            }

            div.innerHTML = innerHTML;
            list.prepend(div);

            this.updateRiskCounters(data.severity);
            this.updateIndicators(data);

            const tableBody = document.getElementById("findings-table-body");
            if (tableBody) {
                // Remove empty state if present
                const emptyRow = document.getElementById("findings-empty-state");
                if (emptyRow) emptyRow.remove();

                const rowId = `finding-row-${fid}`;
                if (document.getElementById(rowId)) return;

                const tr = document.createElement("tr");
                tr.id = rowId;
                tr.className = "finding-row cursor-pointer animate__animated animate__fadeIn";
                this.getFindingsContract().applyRowDataset(tr, data);

                // Set click handler for new UI
                tr.onclick = () => {
                    if (typeof showFindingDetail === 'function') {
                        showFindingDetail(fid);
                    }
                };

                const sev = severity;
                const confidence = (data.confidence || 'med').toUpperCase().substring(0, 4);
                const toolShow = (data.tool_source || 'CORE').toUpperCase();
                
                const primaryUrl = ui.primaryUrl || this.getFindingPrimaryUrl(data);
                let vectorHtml = '';
                if (primaryUrl) {
                    vectorHtml = `<div class="text-info text-truncate" title="${this.escapeHtml(primaryUrl)}"><i class="fas fa-link me-1 opacity-50"></i>${this.escapeHtml(primaryUrl)}</div>`;
                } else {
                    vectorHtml = `<span class="text-muted opacity-25">N/A</span>`;
                }

                const isValidated = ui.isValidated === true || validationStatus === 'success' || ['validation', 'confirmed'].includes(resultState);

                tr.innerHTML = `
                    <td class="ps-3">
                        <span class="badge-severity bg-${sev} w-100 text-center d-block rounded-1 py-1">
                            ${severity.toUpperCase()}
                        </span>
                    </td>
                    <td>
                        <div class="d-flex align-items-center gap-2">
                            <div class="fw-bold text-light text-truncate" title="${escapedTitle}">${escapedTitle}</div>
                            ${primaryCommand ? `<i class="fas fa-terminal text-warning extra-small" title="Validation Command Available"></i>` : ''}
                            ${hasProof ? `<i class="fas fa-microscope text-info extra-small" title="Technical Evidence Available"></i>` : ''}
                            ${isValidated ? `<span class="badge bg-success bg-opacity-25 text-success border border-success border-opacity-25 extra-small"><i class="fas fa-check-circle me-1"></i>VALIDATED</span>` : ''}
                        </div>
                        <div class="text-muted extra-small text-truncate mt-1 opacity-50" style="max-width: 400px;">
                            ${escapedDesc.replace(/<[^>]*>/g, '')}
                        </div>
                    </td>
                    <td class="font-monospace extra-small">
                        ${vectorHtml}
                    </td>
                    <td class="text-center">
                        <span class="badge bg-secondary bg-opacity-10 text-muted border border-secondary border-opacity-10 extra-small px-2">
                            ${confidence}
                        </span>
                    </td>
                    <td>
                        <span class="extra-small text-primary-emphasis fw-semibold bg-primary bg-opacity-10 px-2 py-1 rounded border border-primary border-opacity-10">
                            ${toolShow}
                        </span>
                    </td>
                    <td class="text-end pe-3">
                        <i class="fas fa-chevron-right text-muted opacity-25 extra-small"></i>
                    </td>
                `;

                tableBody.prepend(tr);

                // Update local memory if updateFindingsList is available (new UI)
                if (typeof updateFindingsList === 'function') {
                    updateFindingsList([data]);
                }
            }
        }

        // ScanNmap Dashboard Specific updates
        if (data.category === 'service_detection') {
            this.updateScanNmapDashboard(data);
        }
    }

    updateScanNmapDashboard(data) {
        const tableBody = document.getElementById("scannmap-services-tbody");
        if (!tableBody) return;

        const m = data.metadata || {};
        const portId = `scannmap-port-${m.host_ip}-${m.port}`;
        if (document.getElementById(portId)) return;

        const tr = document.createElement("tr");
        tr.id = portId;
        tr.setAttribute("data-status", (m.port_state || "open").toLowerCase());

        const confidenceHtml = m.confidence_score ? `
            <div class="progress mt-1" style="height: 2px; width: 60px; background: rgba(255,255,255,0.05);" title="Trust Index: ${m.confidence_score}%">
                <div class="progress-bar bg-success" style="width: ${m.confidence_score}%"></div>
            </div>
        ` : '';

        tr.innerHTML = `
            <td class="ps-3"><span class="badge bg-info bg-opacity-10 border border-info text-info">${m.port || 'N/A'}</span></td>
            <td class="small font-monospace text-info">${m.host_ip || 'N/A'}</td>
            <td class="fw-bold text-light">
                ${(m.service || 'N/A').toUpperCase()}
                ${m.port_state === 'filtered' ? '<i class="fas fa-shield-alt text-warning extra-small ms-1" title="Filtered"></i>' : ''}
            </td>
            <td class="small text-muted">
                ${m.version || 'N/A'}
                ${confidenceHtml}
            </td>
            <td class="text-end pe-3">
                <button class="btn btn-xs btn-outline-secondary" onclick="showFindingDetail('${data.id_stable || data.id}')">
                    <i class="fas fa-eye"></i>
                </button>
            </td>
        `;

        tableBody.prepend(tr);
    }

    addToGallery(data) {
        const gallery = document.getElementById("visual-recon-gallery");
        if (gallery) {
            const emptyImg = gallery.querySelector(".text-center.py-4");
            if (emptyImg) emptyImg.remove();

            const tone = this.getFindingAlertTone(data);
            const label = tone === 'danger' ? 'HIGH RISK' : (tone === 'warning' ? 'REVIEW' : 'DISCOVERY');

            const col = document.createElement("div");
            col.className = "col-md-4 col-lg-3 animate__animated animate__zoomIn";
            col.innerHTML = `
                <div class="screenshot-card bg-black border border-${tone} border-opacity-50 rounded overflow-hidden">
                    <img src="/static/${this.escapeHtml(data.screenshot_path)}" class="img-fluid w-100 screenshot-trigger" style="height: 120px; object-fit: cover; cursor: pointer;" title="${this.escapeHtml(data.title)}">
                    <div class="p-1 text-center bg-${tone} bg-opacity-10 small font-monospace">
                        <span class="text-${tone}">${label}</span>
                    </div>
                </div>
            `;
            gallery.prepend(col);
        }
    }

    updateIndicators(data) {
        const titleLower = data.title.toLowerCase();
        const indicators = {
            'xss': ['xss'],
            'lfi': ['lfi'],
            'sql': ['sql', 'injection'],
            'api': ['api', 'swagger', 'openapi', 'expert'],
            'cms': ['cms', 'wordpress', 'drupal', 'joomla'],
            'secret': ['secret', 'token', 'key']
        };

        for (const [key, keywords] of Object.entries(indicators)) {
            if (keywords.some(k => titleLower.includes(k) || (data.tool && data.tool.toLowerCase().includes(k)))) {
                const indicatorCard = document.querySelector(`.vuln-indicator-${key}`);
                if (indicatorCard) {
                    indicatorCard.classList.remove('border-success', 'bg-success', 'bg-opacity-10');
                    indicatorCard.classList.add('border-danger', 'bg-danger', 'bg-opacity-10');
                    const icon = indicatorCard.querySelector('.fa-shield-alt');
                    if (icon) {
                        icon.classList.remove('fa-shield-alt', 'text-success');
                        icon.classList.add('fa-exclamation-circle', 'text-danger');
                    }
                    const label = indicatorCard.querySelector('.text-success');
                    if (label) {
                        label.classList.remove('text-success');
                        label.classList.add('text-danger');
                    }
                    const status = indicatorCard.querySelector('.text-muted');
                    if (status) status.innerText = 'Detected';
                }
            }
        }
    }

    handleNewSuggestion(data) {
        if (data.scan_id != this.scanId) return;
        const container = document.getElementById("suggestions-container");
        if (container) {
            const empty = container.querySelector(".text-muted");
            if (empty && empty.innerText.includes("No suggestions")) empty.remove();

            let list = container.querySelector(".result-list");
            if (!list) {
                list = document.createElement("div");
                list.className = "result-list";
                container.appendChild(list);
            }

            const div = document.createElement("div");
            div.className = "result-row d-flex justify-content-between align-items-center p-2 mb-2 bg-black border border-secondary rounded animate__animated animate__fadeInUp";
            const escapedCmd = this.escapeHtml(data.command_suggestion);
            const encodedCmd = encodeURIComponent(data.command_suggestion || '');
            div.innerHTML = `
                <div>
                    <span class="badge bg-secondary me-2">${this.escapeHtml(data.tool_name)}</span>
                    <span class="result-text font-monospace small">${escapedCmd}</span>
                </div>
                <button class="btn btn-xs btn-outline-warning verify-btn" data-command="${encodedCmd}">
                    <i class="fas fa-play"></i>
                </button>
            `;
            list.prepend(div);
        }
    }

    handleNewLoot(data) {
        if (data.scan_id != this.scanId) return;
        this.activateDiscovery('loot', true);

        document.querySelectorAll('.loot-counter-val').forEach(counter => {
            let current = parseInt(counter.innerText) || 0;
            counter.innerText = current + 1;
            counter.classList.add('animate__animated', 'animate__bounceIn', 'text-success');
            setTimeout(() => counter.classList.remove('animate__animated', 'animate__bounceIn'), 1000);
        });

        const vault = document.querySelector("#loot-vault-container .list-group");
        if (vault) {
            const empty = vault.querySelector(".text-center");
            if (empty) empty.remove();

            const now = new Date();
            const time = now.getHours().toString().padStart(2, '0') + ":" + now.getMinutes().toString().padStart(2, '0');

            const div = document.createElement("div");
            div.className = "list-group-item bg-transparent border-secondary border-opacity-25 py-2 px-3 animate__animated animate__fadeInDown";
            div.innerHTML = `
                <div class="d-flex justify-content-between align-items-center">
                    <span class="badge bg-black border border-success text-success x-small text-uppercase">${this.escapeHtml(data.type)}</span>
                    <span class="x-small text-muted font-monospace">${time}</span>
                </div>
                <div class="mt-1 small font-monospace text-light text-break">${this.escapeHtml(data.content)}</div>
                ${data.context ? `<div class="x-small text-muted mt-1 italic"><i class="fas fa-info-circle me-1"></i>${this.escapeHtml(data.context)}</div>` : ''}
            `;
            vault.prepend(div);
        }
    }

    handleProgressUpdate(data) {
        if (data.scan_id != this.scanId) return;

        // Defensive: normalize progress data to avoid undefined display
        const percent = (data.percent != null && !isNaN(data.percent)) ? Math.round(data.percent) : 0;
        const phase = data.current_phase || 'Processing...';

        const bar = document.getElementById('scan-progress-bar');
        const phaseText = document.getElementById('scan-phase-text');
        const statusText = document.getElementById('scan-status-text');
        const spinner = document.getElementById('scan-spinner');

        if (bar) {
            bar.style.width = percent + '%';
            bar.setAttribute('aria-valuenow', percent);
        }

        // Toast updates
        const toastBar = document.getElementById('toast-progress-bar');
        const toastPhase = document.getElementById('toast-phase-text');
        const toastPercent = document.getElementById('toast-percent-text');
        if (toastBar) toastBar.style.width = percent + '%';
        if (toastPhase) toastPhase.innerText = phase;
        if (toastPercent) toastPercent.innerText = percent + '%';

        if (phaseText) {
            phaseText.innerText = phase;
            this.highlightPTES(phase);
            const auditPhase = document.getElementById('audit-journey-current-phase');
            if (auditPhase) {
                auditPhase.innerText = `Current Phase: ${phase}`;
            }

            // Real-time Discovery Highlight
            const phaseLower = phase.toLowerCase();
            const phaseToDiscovery = {
                'recon': 'ports', 'dns': 'dns', 'osint': 'cloud', 'cloud': 'cloud',
                'waf': 'waf', 'crawl': 'crawl', 'katana': 'crawl', 'arjun': 'params',
                'params': 'params', 'ffuf': 'fuzz', 'dirbusting': 'fuzz',
                'api': 'api', 'secrets': 'secrets', 'vuln': 'vulns', 'nuclei': 'vulns',
                'intel': 'intel', 'historic': 'historic', 'wayback': 'historic',
                'spring': 'apps', 'firebase': 'apps', 'actuator': 'apps', 'apps': 'apps'
            };

            for (const [key, id] of Object.entries(phaseToDiscovery)) {
                if (phaseLower.includes(key)) {
                    this.activateDiscovery(id, false); // false = 'active' state (pulsing)
                }
            }
        }

        if (percent >= 100) {
            if (statusText) statusText.innerText = 'completed';
            if (spinner) spinner.classList.add('d-none');
            if (bar) {
                bar.classList.remove('progress-bar-animated', 'progress-bar-striped');
                bar.classList.add('bg-success');
            }
            this.toggleScanToast(false);

            // --- CLEANUP: Set all buttons to 'discovered' (blue) when completed ---
            document.querySelectorAll('.discovery-btn').forEach(btn => {
                btn.classList.remove('active');
                btn.classList.add('discovered');
            });
        } else {
            if (statusText) statusText.innerText = 'running';
            if (spinner) spinner.classList.remove('d-none');
            this.toggleScanToast(true);
        }
    }

    highlightPTES(text) {
        for (const [phaseKey, ptesIdSuffix] of Object.entries(this.ptesMap)) {
            if (text.includes(phaseKey)) {
                document.querySelectorAll('.nav-link[id^="sidebar-ptes-"]').forEach(el => el.classList.remove('active'));
                const target = document.getElementById(`sidebar-ptes-${ptesIdSuffix}`);
                if (target) {
                    target.classList.add('active');
                }
                break;
            }
        }
    }

    /**
     * Wave 5.7: Multi-state discovery button activation
     * @param {string} id - The discovery button ID suffix
     * @param {string|boolean} state - 'launching', 'active', or true/false (true=discovered, false=active)
     */
    activateDiscovery(id, state) {
        const btn = document.getElementById(`discovery-${id}`);
        if (!btn) return;

        // Map boolean to legacy states for backward compatibility
        let finalState = state;
        if (state === true) finalState = 'discovered';
        if (state === false) finalState = 'active';

        // Remove all state classes first to ensure clean transition
        btn.classList.remove('launching', 'active', 'discovered');

        if (finalState === 'discovered') {
            btn.classList.add('discovered');
        } else if (finalState === 'active') {
            btn.classList.add('active');
        } else if (finalState === 'launching') {
            btn.classList.add('launching');
        }
    }

    toggleScanToast(show) {
        const toast = document.getElementById("scan-toast");
        if (toast) {
            if (show) toast.classList.add("visible");
            else toast.classList.remove("visible");
        }
    }

    showToast(title, message, type = 'info') {
        const id = 'toast-' + Math.random().toString(36).substr(2, 9);
        const html = `
            <div id="${id}" class="toast show bg-black border border-secondary text-light animate__animated animate__fadeInRight" role="alert" style="position: fixed; bottom: 1rem; right: 1rem; z-index: 10000; min-width: 250px;">
                <div class="toast-header bg-dark border-bottom border-secondary text-light">
                    <i class="fas fa-satellite-dish me-2 text-${type}"></i>
                    <strong class="me-auto font-monospace x-small text-uppercase">${title}</strong>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="toast"></button>
                </div>
                <div class="toast-body small">
                    ${message}
                </div>
            </div>`;
        const div = document.createElement('div');
        div.innerHTML = html;
        document.body.appendChild(div.firstElementChild);
        setTimeout(() => {
            const el = document.getElementById(id);
            if (el) {
                el.classList.replace('animate__fadeInRight', 'animate__fadeOutRight');
                setTimeout(() => el.remove(), 500);
            }
        }, 5000);
    }

    checkInitialStatus() {
        const statusPill = document.querySelector('.status-pill');
        const currentStatus = statusPill ? statusPill.innerText.toLowerCase() : '';
        this.toggleScanToast(currentStatus === 'running');

        document.querySelectorAll('.log-console > div').forEach(logDiv => {
            this.highlightPTES(logDiv.innerText);
        });
    }

    setupNotesPreview() {
        const notesArea = document.querySelector('textarea[name="notes"]');
        if (notesArea) {
            const preview = document.createElement('div');
            preview.className = "p-3 bg-black border border-secondary rounded mt-2 text-muted small";
            notesArea.parentNode.insertBefore(preview, notesArea.nextSibling);

            // Assuming marked and DOMPurify are available globally
            const updatePreview = () => {
                if (window.marked && window.DOMPurify) {
                    preview.innerHTML = DOMPurify.sanitize(marked.parse(notesArea.value || "*No notes recorded.*"));
                }
            };
            notesArea.addEventListener('input', updatePreview);
            updatePreview();
        }
    }

    verifyFinding(command) {
        navigator.clipboard.writeText(command);
        this.showToast('Verification Protocol', 'Validation command synchronized to clipboard.', 'warning');
    }

    updateRiskCounters(severity) {
        const sev = severity.toLowerCase();
        if (sev === 'critical' || sev === 'high') {
            const el = document.querySelector(`.tactical-summary-bar .h4.text-${sev === 'critical' ? 'danger' : 'warning'}`);
            if (el) {
                let count = (parseInt(el.innerText) || 0) + 1;
                el.innerText = count;
                el.classList.remove('text-muted');
                if (sev === 'critical') el.classList.add('pulse-danger');
            }
        }
    }

    deriveAuditJourney(results) {
        const phases = results?.phases || {};
        const findings = Array.isArray(results?.findings) ? results.findings : [];
        const progressPhase = String(results?.progress?.current_phase || '').toLowerCase();
        const status = String(results?.status || '').toLowerCase();
        const target = String(results?.target || this.targetIdentifier || '');

        const reconPorts = Array.isArray(phases?.recon?.open_ports) ? phases.recon.open_ports : [];
        const dnsSubs = Array.isArray(phases?.dns?.subdomains) ? phases.dns.subdomains : [];
        const katana = (phases?.enum?.katana && typeof phases.enum.katana === 'object') ? phases.enum.katana : {};
        const api = (phases?.enum?.api && typeof phases.enum.api === 'object') ? phases.enum.api : {};
        const attackPlan = Array.isArray(results?.attack_plan) ? results.attack_plan : [];

        let enumEndpointCount = 0;
        Object.values(katana).forEach(urls => {
            if (Array.isArray(urls)) enumEndpointCount += urls.length;
        });
        if (Array.isArray(api.endpoints)) enumEndpointCount += api.endpoints.length;
        if (Array.isArray(api.discovered_endpoints)) enumEndpointCount += api.discovered_endpoints.length;

        let validated = 0;
        let correlated = 0;
        let missingProof = 0;
        let missingCommand = 0;

        findings.forEach(f => {
            const state = this.getFindingResultState(f);
            const validationStatus = String(this.getFindingValidationStatus(f) || '').toLowerCase();
            const severity = String(f?.severity || 'info').toLowerCase();
            const isHigh = severity === 'critical' || severity === 'high';
            const command = this.getFindingPrimaryCommand(f);
            const hasProof = this.hasMeaningfulProof(f);

            if (validationStatus === 'success' || ['validation', 'confirmed'].includes(state)) validated += 1;
            if (String(f?.category || '').toLowerCase() === 'attack_chain') correlated += 1;
            if (f?.chain_metadata && (f.chain_metadata.related_findings || f.chain_metadata.attack_path_summary)) correlated += 1;
            if (isHigh && !hasProof) missingProof += 1;
            if (isHigh && !this.isMeaningfulValue(command)) missingCommand += 1;
        });

        const scopeReady = target.length > 0;
        const reconReady = reconPorts.length > 0 || dnsSubs.length > 0;
        const enumReady = enumEndpointCount > 0;
        const detectionReady = findings.length > 0;
        const validationReady = validated > 0;
        const correlationReady = correlated > 0 || attackPlan.length > 0;
        // Keep the readiness booleans strict. Completed scans with detections can
        // show an in-progress visual tone without being marked as truly validated
        // or correlated.
        const validationVisualInProgress = status === 'completed' && detectionReady && !validationReady;
        const correlationVisualInProgress = status === 'completed' && detectionReady && !correlationReady;
        const reportingReady = status === 'completed' && detectionReady;
        const closureReady = status === 'completed' && missingProof === 0 && missingCommand === 0;

        const stageMap = {
            cadrage: scopeReady ? 'done' : 'pending',
            recon: reconReady ? 'done' : (progressPhase.includes('recon') ? 'in-progress' : 'pending'),
            enum: enumReady ? 'done' : (progressPhase.includes('enum') ? 'in-progress' : 'pending'),
            detection: detectionReady ? 'done' : (progressPhase.includes('vuln') ? 'in-progress' : 'pending'),
            validation: validationReady ? 'done' : ((validationVisualInProgress || progressPhase.includes('validation')) ? 'in-progress' : 'pending'),
            correlation: correlationReady ? 'done' : ((correlationVisualInProgress || progressPhase.includes('correlation')) ? 'in-progress' : 'pending'),
            reporting: reportingReady ? 'done' : (progressPhase.includes('report') ? 'in-progress' : 'pending'),
            closure: closureReady ? 'done' : (status === 'completed' ? 'in-progress' : 'pending')
        };

        return {
            stageMap,
            gates: {
                total: findings.length,
                validated,
                missingProof,
                missingCommand
            }
        };
    }

    setAuditStageState(stage, state) {
        const node = document.getElementById(`audit-stage-${stage}`);
        if (!node) return;
        node.classList.remove('done', 'in-progress', 'pending');
        node.classList.add(state);
    }

    updateAuditJourney(results) {
        const summary = this.deriveAuditJourney(results || {});
        Object.entries(summary.stageMap).forEach(([stage, state]) => this.setAuditStageState(stage, state));

        const gateTotal = document.getElementById('audit-gate-total');
        const gateValidated = document.getElementById('audit-gate-validated');
        const gateMissingProof = document.getElementById('audit-gate-missing-proof');
        const gateMissingCommand = document.getElementById('audit-gate-missing-command');

        if (gateTotal) gateTotal.innerText = String(summary.gates.total);
        if (gateValidated) gateValidated.innerText = String(summary.gates.validated);
        if (gateMissingProof) {
            gateMissingProof.innerText = String(summary.gates.missingProof);
            gateMissingProof.classList.toggle('text-danger', summary.gates.missingProof > 0);
            gateMissingProof.classList.toggle('text-success', summary.gates.missingProof === 0);
        }
        if (gateMissingCommand) {
            gateMissingCommand.innerText = String(summary.gates.missingCommand);
            gateMissingCommand.classList.toggle('text-danger', summary.gates.missingCommand > 0);
            gateMissingCommand.classList.toggle('text-success', summary.gates.missingCommand === 0);
        }
    }

    filterFindings() {
        const findingsSearch = document.getElementById('findings-search');
        const findingsSeverity = document.getElementById('findings-severity-filter');
        const findingsCategory = document.getElementById('findings-category-filter');
        const findingsPortStatus = document.getElementById('findings-port-status-filter');

        if (findingsSearch && findingsSeverity && findingsCategory && findingsPortStatus) {
            this.getFindingsContract().applyTableFilters();
            return;
        }

        const search = (document.getElementById('findingSearch')?.value || '').toLowerCase().trim();
        const checkedSeverities = Array.from(document.querySelectorAll('.form-check-input:checked')).map(cb => cb.value);
        const rows = document.querySelectorAll('.finding-row');
        let visibleCount = 0;

        const globalTerms = search !== '' ? search.split(/\s+/) : [];

        rows.forEach(row => {
            const severity = row.getAttribute('data-severity') || row.getAttribute('data-sev') || '';
            const content = (row.getAttribute('data-content') || '').toLowerCase();
            
            let matchesSearch = true;
            if (globalTerms.length > 0) {
                matchesSearch = globalTerms.every(word => content.includes(word));
            }
            
            const matchesSev = checkedSeverities.length === 0 || checkedSeverities.includes(severity);

            if (matchesSearch && matchesSev) {
                row.classList.remove('d-none');
                visibleCount++;
            } else {
                row.classList.add('d-none');
            }
        });

        const noMatchRow = document.getElementById('no-findings-match');
        if (noMatchRow) noMatchRow.classList.toggle('d-none', !(visibleCount === 0 && rows.length > 0));
    }


    renderTaskStatus(taskStatus) {
        const tableBody = document.querySelector("#tasks-table tbody");
        if (!tableBody || !taskStatus) return;
        tableBody.innerHTML = "";

        const getTaskBadge = (state) => {
            const s = (state || 'pending').toLowerCase();
            if (s === 'running') return '<span class="badge bg-primary bg-opacity-10 text-primary border border-primary x-small">RUNNING</span>';
            if (s === 'executed') return '<span class="badge bg-success bg-opacity-10 text-success border border-success x-small">DONE</span>';
            if (s === 'skipped') return '<span class="badge bg-secondary bg-opacity-10 text-secondary border border-secondary x-small">SKIP</span>';
            if (s === 'failed') return '<span class="badge bg-danger bg-opacity-10 text-danger border border-danger x-small">FAIL</span>';
            return `<span class="badge bg-dark border border-secondary text-muted x-small"> ${s.toUpperCase()}</span> `;
        };

        Object.entries(taskStatus).forEach(([taskId, data]) => {
            const row = document.createElement('tr');
            row.id = `task-row-${taskId}`;
            row.innerHTML = `
                <td class="font-monospace text-info x-small">${taskId}</td>
                <td class="x-small">${getTaskBadge(data.state)}</td>
                <td class="x-small text-muted">${data.reason || '-'}</td>
`;
            tableBody.appendChild(row);
        });

        if (!Object.keys(taskStatus).length) {
            tableBody.innerHTML = '<tr id="no-tasks-row"><td colspan="3" class="text-center text-muted small fst-italic py-3">No task state yet.</td></tr>';
        }
    }
    updateUI(results) {
        if (!results) return;

        // Sync with dynamic explorers if they are present in the DOM
        if (typeof updateSurfaceExplorer === 'function') {
            updateSurfaceExplorer(results);
        }
        if (typeof updateFindingsList === 'function' && results.findings) {
            updateFindingsList(results.findings);
        }

        // Keep a global copy for other tab scripts (like attack_graph)
        window.scanResults = results;
        this.updateAuditJourney(results);

        // 0. Update Target Intelligence Dashboard
        this.updateCortexUI(results);
        const statPorts = document.getElementById('stat-open-ports');
        const statFindings = document.getElementById('stat-findings');
        const portContainer = document.getElementById('port-badges-container');

        if (results.phases && results.phases.recon && results.phases.recon.open_ports) {
            const ports = results.phases.recon.open_ports;
            if (statPorts) statPorts.innerText = ports.length;

            if (portContainer) {
                if (portContainer.querySelector('.text-center')) portContainer.innerHTML = '';
                let portsHtml = '';
                ports.forEach(port => {
                    const isWeb = [80, 443, 8080, 8443].includes(port.port);
                    const service = (port.service_name || 'unknown').toUpperCase();
                    const version = (port.version && port.version !== "Unknown") ? port.version.substring(0, 15) : '';

                    portsHtml += `
    <div class="port-badge-item">
        <span class="badge p-2 ${isWeb ? 'bg-info bg-opacity-10 border-info text-info' : 'bg-secondary bg-opacity-10 border-secondary text-light'} border d-flex align-items-center gap-2"
            title="${service}">
            <span class="font-monospace fs-6 fw-bold">${port.port}</span>
            <span class="text-uppercase opacity-75 small border-start border-secondary ps-2">${port.service_name}</span>
            ${version ? `<span class="badge bg-black text-muted x-small border border-secondary ms-1 d-none d-lg-inline-block">${version}</span>` : ''}
        </span>
                        </div> `;
                });
                portContainer.innerHTML = portsHtml;
            }
        }

        if (results.findings && statFindings) {
            statFindings.innerText = results.findings.length;

            // Sync new mission overview counters
            const statAssets = document.getElementById('stat-assets');
            const statEndpoints = document.getElementById('stat-endpoints');
            const statHighRisk = document.getElementById('stat-high-risk');
            const statCritical = document.getElementById('stat-critical');
            const statHigh = document.getElementById('stat-high');

            let highRiskCount = 0;
            let criticalCount = 0;
            let highCount = 0;

            results.findings.forEach(f => {
                const sev = (f.severity || "info").toLowerCase();
                if (sev === 'critical') { criticalCount++; highRiskCount++; }
                if (sev === 'high') { highCount++; highRiskCount++; }

                this.handleNewFinding({ scan_id: this.scanId, ...f, tool: f.tool_source || f.tool });
            });

            if (statHighRisk) statHighRisk.innerText = highRiskCount;
            if (statCritical) statCritical.innerText = criticalCount;
            if (statHigh) statHigh.innerText = highCount;

            // Update assets/endpoints if available
            if (statAssets) {
                const ports = results.phases?.recon?.open_ports?.length || 0;
                const subs = results.phases?.dns?.subdomains?.length || 0;
                const clouds = results.phases?.osint?.cloud?.length || 0;
                statAssets.innerText = ports + subs + clouds;
            }
            if (statEndpoints) {
                let totalEps = results.phases?.dirbusting?.ffuf?.endpoints?.length || 0;
                totalEps += results.phases?.enum?.api?.endpoints?.length || 0;
                if (results.phases?.enum?.katana) {
                    Object.values(results.phases.enum.katana).forEach(urls => {
                        if (Array.isArray(urls)) totalEps += urls.length;
                    });
                }
                statEndpoints.innerText = totalEps;
            }
        }

        // Sync Progress UI
        if (results.progress) {
            this.handleProgressUpdate({
                scan_id: this.scanId,
                percent: results.progress.percent,
                current_phase: results.progress.current_phase
            });
        }

        this.renderTaskStatus(results.task_status || {});

        // --- RESTORE DISCOVERY BUTTON STATES ---
        const discoveryMap = {
            'dns': results.phases?.dns?.subdomains?.length > 0,
            'ports': results.phases?.recon?.open_ports?.length > 0,
            'cloud': results.phases?.osint?.cloud?.length > 0,
            'waf': (results.phases?.enum?.waf && Object.keys(results.phases.enum.waf).length > 0) || (results.phases?.enum?.derived?.waf_info),
            'crawl': (results.phases?.enum?.katana && Object.keys(results.phases.enum.katana).length > 0) || (results.phases?.enum?.httpx),
            'params': (results.phases?.enum?.arjun && Object.keys(results.phases.enum.arjun).length > 0) || (results.phases?.enum?.params && Object.keys(results.phases.enum.params).length > 0),
            'fuzz': (results.phases?.dirbusting?.ffuf?.endpoints?.length > 0) || (results.phases?.dirbusting?.ffuf?.length > 0),
            'api': (results.phases?.enum?.api && Object.keys(results.phases.enum.api).length > 0) || (results.phases?.enum?.openapi),
            'secrets': (results.phases?.enum?.js_secrets && Object.keys(results.phases.enum.js_secrets).length > 0) || (results.phases?.vuln?.secrets && results.phases.vuln.secrets.length > 0),
            'vulns': (results.findings?.length > 0) || (results.metrics?.findings_count > 0) || (results.phases?.vuln?.nuclei?.findings?.length > 0) || (results.phases?.vuln?.xss?.length > 0),
            'intel': results.phases?.intel && Object.keys(results.phases.intel).length > 0,
            'historic': (results.phases?.osint?.historic_urls?.length > 0) || (results.phases?.osint?.gau_urls),
            'apps': (results.phases?.vuln?.wordpress && Object.keys(results.phases.vuln.wordpress).length > 0) || (results.phases?.vuln?.tech && Object.keys(results.phases.vuln.tech).length > 0) || (results.phases?.vuln?.actuator) || (results.phases?.vuln?.graphql),
            'tls': results.phases?.vuln?.tls && Object.keys(results.phases.vuln.tls).length > 0,
            'expert': (results.phases?.vuln?.ssrf?.length > 0) || (results.phases?.vuln?.graphql?.length > 0) || (results.phases?.vuln?.git?.length > 0) || (results.phases?.vuln?.backups?.length > 0) || (results.phases?.vuln?.lfi?.length > 0),
            'miner': (results.phases?.vuln?.data_leaks?.length > 0) || (results.phases?.osint?.historic_urls?.length > 0),
            'loot': (results.loot_count > 0) || (results.metrics?.loot_count > 0)
        };

        for (const [id, discovered] of Object.entries(discoveryMap)) {
            this.activateDiscovery(id, discovered);
        }

        if (!results.phases) return;

        // 1. DNS
        if (results.phases.dns && results.phases.dns.subdomains) {
            const dnsDiv = document.querySelector("#dns-results");
            if (dnsDiv) {
                const subdomains = results.phases.dns.subdomains;
                const displayLimit = 500;
                let dnsHtml = '<div class="d-flex flex-wrap gap-2">';

                subdomains.slice(0, displayLimit).forEach(sub => {
                    dnsHtml += `<div class="tag-item px-2 py-1 bg-black border border-secondary rounded small font-monospace text-cyber"> ${sub}</div> `;
                });

                if (subdomains.length > displayLimit) {
                    dnsHtml += `<div class="tag-item px-2 py-1 bg-black border border-secondary rounded small font-monospace text-muted"> + ${subdomains.length - displayLimit} more...</div> `;
                }

                dnsHtml += '</div>';
                dnsDiv.innerHTML = subdomains.length ? dnsHtml : '<div class="text-muted small fst-italic">No subdomains discovered.</div>';
            }
        }

        // 2. Recon Matrix (Deep Audit)
        const matrixBody = document.querySelector("#recon-matrix-body");
        if (matrixBody && results.phases.recon && results.phases.recon.open_ports) {
            let html = "";
            const ports = results.phases.recon.open_ports.sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0));

            ports.forEach(port => {
                const score = port.priority_score || 0;
                const scoreClass = score >= 85 ? 'text-danger fw-bold' : (score >= 50 ? 'text-warning' : 'text-info');
                const barClass = score >= 85 ? 'bg-danger shadow-danger' : (score >= 50 ? 'bg-warning' : 'bg-info');
                const bgStyle = score >= 80 ? 'background: rgba(255, 42, 42, 0.05);' : '';
                const isWeb = (port.port == 80 || port.port == 443 || port.port == 8080 || port.port == 8443);
                const proto = (port.port == 443 || port.port == 8443) ? 'https' : 'http';

                let techHtml = '<span class="text-muted small">-</span>';
                const portKey = port.port.toString();
                if (results.phases.enum && results.phases.enum.whatweb && results.phases.enum.whatweb[portKey]) {
                    const ww = results.phases.enum.whatweb[portKey];
                    techHtml = '<div class="d-flex flex-wrap gap-1">';
                    if (ww.includes('Title[')) {
                        const title = ww.split('Title[')[1].split(']')[0];
                        techHtml += `<span class="badge rounded-pill bg-dark border border-secondary text-info x-small"> ${title.substring(0, 15)}...</span> `;
                    }
                    if (ww.includes('HTTPServer[')) {
                        const server = ww.split('HTTPServer[')[1].split(']')[0];
                        techHtml += `<span class="badge rounded-pill bg-dark border border-secondary text-warning x-small"> ${server}</span> `;
                    }
                    techHtml += '</div>';
                }

                html += `<tr style = "border-bottom: 1px solid #333; height: 65px; vertical-align: middle; ${bgStyle}">
                    <td class="p-3"><span class="badge bg-secondary-subtle text-secondary border border-secondary-subtle text-uppercase">${port.service_name}</span></td>
                    <td class="p-3">
                        <div class="d-flex align-items-center">
                            <div class="progress bg-dark border border-secondary" style="height: 6px; width: 40px; margin-right: 10px;">
                                <div class="progress-bar ${barClass}" style="width: ${score}%"></div>
                            </div>
                            <span class="badge ${scoreClass} font-monospace" style="font-size: 0.75rem;">${score}</span>
                        </div>
                    </td>
                    <td class="p-3"><code class="text-info fw-bold">${port.port}/tcp</code></td>
                    <td class="p-3"><span class="text-light opacity-75 small font-monospace">${port.version || '-'}</span></td>
                    <td class="p-3">${techHtml}</td>
                    <td class="p-3 text-end">
                        ${isWeb ? `<a href="${proto}://${this.targetIdentifier}:${port.port}" target="_blank" class="btn btn-xs btn-outline-info"><i class="fas fa-external-link-alt"></i></a>` : ''}
                    </td>
                </tr> `;
            });
            matrixBody.innerHTML = html;
        }

        // 3. Visual Recon Gallery
        const gallery = document.querySelector("#visual-recon-gallery");
        if (gallery && results.phases.recon && results.phases.recon.open_ports) {
            let galleryHtml = "";
            let hasShots = false;
            results.phases.recon.open_ports.forEach(port => {
                if (port.screenshot_path) {
                    hasShots = true;
                    let cardContent = "";
                    if (port.screenshot_path === 'pending') {
                        cardContent = `
    <div class="d-flex flex-column align-items-center justify-content-center" style = "height: 120px; background: rgba(0,240,255,0.05);">
                                <div class="spinner-border text-info spinner-border-sm mb-2" role="status"></div>
                                <div class="x-small text-info font-monospace text-uppercase flicker">Capturing...</div>
                            </div> `;
                    } else {
                        cardContent = `<img src = "/static/${port.screenshot_path}" class="img-fluid w-100" style = "height: 120px; object-fit: cover; cursor: pointer;" onclick = "window.open(this.src)" title = "Port ${port.port}"> `;
                    }

                    galleryHtml += `
    <div class="col-md-4 col-lg-3 animate__animated animate__fadeIn">
        <div class="screenshot-card bg-black border ${port.screenshot_path === 'pending' ? 'border-info animate-pulse' : 'border-secondary'} rounded overflow-hidden">
            ${cardContent}
            <div class="p-1 text-center bg-dark small font-monospace">
                <span class="text-info">PORT ${port.port}</span>
            </div>
        </div>
                        </div> `;
                }
            });

            if (results.findings) {
                results.findings.forEach(f => {
                    if (f.screenshot_path) {
                        hasShots = true;
                        galleryHtml += `
    <div class="col-md-4 col-lg-3 animate__animated animate__fadeIn">
        <div class="screenshot-card bg-black border border-danger border-opacity-50 rounded overflow-hidden">
            <img src="/static/${f.screenshot_path}" class="img-fluid w-100" style="height: 120px; object-fit: cover; cursor: pointer;" onclick="window.open(this.src)" title="${f.title}">
                <div class="p-1 text-center bg-danger bg-opacity-10 small font-monospace">
                    <span class="text-danger">EXPOSURE</span>
                </div>
        </div>
                            </div> `;
                    }
                });
            }

            if (hasShots) {
                gallery.innerHTML = galleryHtml;
            } else {
                gallery.innerHTML = `
    <div class="col-12 text-center py-5">
        <div class="text-muted small opacity-50">
            <i class="fas fa-image fa-3x mb-3 d-block"></i>
            No visual assets captured yet.
        </div>
                    </div> `;
            }
        }

        // 4. Intel
        if (results.phases.intel) {
            const intelDiv = document.querySelector("#intel-results");
            if (intelDiv) {
                let intelHtml = '<div class="accordion" id="accordionIntel">';
                for (const [port, vectors] of Object.entries(results.phases.intel)) {
                    intelHtml += `
    <div class="accordion-item bg-black border-secondary">
                            <h2 class="accordion-header">
                                <button class="accordion-button collapsed bg-dark text-light border-secondary shadow-none" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-intel-${port}">
                                    <span class="badge bg-warning me-2">Port ${port}</span>
                                    <span class="font-monospace small text-muted">${vectors.length} Vectors</span>
                                </button>
                            </h2 > 
                            <div id="collapse-intel-${port}" class="accordion-collapse collapse" data-bs-parent="#accordionIntel">
                                <div class="accordion-body p-2">
                                    ${vectors.map(v => `
                                        <div class="mb-2 p-2 border border-secondary rounded bg-dark-subtle">
                                            <div class="d-flex justify-content-between align-items-center mb-1">
                                                <span class="fw-bold text-info small">${v.name}</span>
                                                <span class="badge ${v.score >= 80 ? 'bg-danger' : 'bg-secondary'}">${v.score}</span>
                                            </div>
                                            <div class="small text-muted mb-1">${v.description}</div>
                                            <div class="font-monospace x-small text-warning bg-black p-1 rounded">Action: ${v.action}</div>
                                        </div>
                                    `).join('')}
                                </div>
                            </div>
                        </div> `;
                }
                intelHtml += '</div>';
                intelDiv.innerHTML = Object.keys(results.phases.intel).length ? intelHtml : '<div class="text-muted small fst-italic">Analyzing vectors...</div>';
            }
        }

        // 5. WhatWeb
        if (results.phases.enum && results.phases.enum.whatweb) {
            const wwDiv = document.querySelector("#whatweb-results");
            if (wwDiv) {
                let wwHtml = "";
                const wwData = results.phases.enum.whatweb;
                if (wwData.summary) {
                    wwHtml += '<div class="tag-grid d-flex flex-wrap gap-2 mb-3">';
                    for (const [k, v] of Object.entries(wwData.summary)) {
                        wwHtml += `<div class="tag-item px-2 py-1 bg-black border border-secondary rounded small"><span class="tag-key text-muted me-1">${k}:</span><span class="tag-value text-cyber">${v}</span></div> `;
                    }
                    wwHtml += '</div>';
                }
                for (const [port, output] of Object.entries(wwData)) {
                    if (port !== 'summary') {
                        wwHtml += `<div class="whatweb-entry small font-monospace text-muted border-bottom border-dark pb-1 mb-2 text-break"> <span class="badge bg-secondary me-2">Port ${port}</span> ${output}</div> `;
                    }
                }
                wwDiv.innerHTML = wwHtml || '<div class="text-muted small fst-italic">Waiting for fingerprinter...</div>';
            }
        }

        // 6. Katana
        if (results.phases.enum && results.phases.enum.katana) {
            const katDiv = document.querySelector("#katana-results");
            if (katDiv) {
                let katHtml = '<div class="accordion" id="accordionKatana">';
                for (const [port, endpoints] of Object.entries(results.phases.enum.katana)) {
                    katHtml += `
    <div class="accordion-item bg-black border-secondary">
                            <h2 class="accordion-header">
                                <button class="accordion-button collapsed bg-dark text-light border-secondary shadow-none" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-katana-${port}">
                                    <span class="badge bg-info me-2">Port ${port}</span>
                                    <span class="font-monospace small text-muted">${endpoints.length} Endpoints</span>
                                </button>
                            </h2 > 
                            <div id="collapse-katana-${port}" class="accordion-collapse collapse" data-bs-parent="#accordionKatana">
                                <div class="accordion-body p-2" style="max-height: 200px; overflow-y: auto;">
                                    ${endpoints.map(ep => `<div class="small font-monospace text-muted mb-1 border-bottom border-dark pb-1 text-break"><a href="${ep}" target="_blank" class="text-decoration-none text-cyber">${ep}</a></div>`).join('')}
                                </div>
                            </div>
                        </div> `;
                }
                katHtml += '</div>';
                katDiv.innerHTML = Object.keys(results.phases.enum.katana).length ? katHtml : '<div class="text-muted small fst-italic">No crawling results yet.</div>';
            }
        }

        // 7. Nuclei
        if (results.phases.vuln && results.phases.vuln.nuclei) {
            const nucDiv = document.querySelector("#nuclei-results");
            if (nucDiv) {
                const findings = results.phases.vuln.nuclei.findings || [];
                let nucHtml = '<div class="result-list">';
                findings.forEach(f => {
                    nucHtml += `
    <div class="result-row p-2 mb-2 bg-black border border-secondary rounded d-flex align-items-center justify-content-between animate__animated animate__fadeIn">
                        <span class="badge severity-badge ${f.severity} me-2 text-uppercase">${f.severity}</span>
                        <span class="result-text flex-grow-1 small">${f.title}</span>
                    </div> `;
                });
                nucHtml += '</div>';
                nucDiv.innerHTML = findings.length ? nucHtml : '<div class="text-muted small fst-italic">No vulnerabilities reported.</div>';
            }
        }

        // 8. ffuf
        if (results.phases.dirbusting && results.phases.dirbusting.ffuf) {
            const ffufDiv = document.querySelector("#ffuf-results");
            if (ffufDiv) {
                const endpoints = results.phases.dirbusting.ffuf.endpoints || [];
                let ffufHtml = '<div class="result-list">';
                endpoints.forEach(ep => {
                    ffufHtml += `
    <div class="result-row p-2 mb-2 bg-black border border-secondary rounded d-flex justify-content-between animate__animated animate__fadeIn">
                            <span class="badge bg-secondary font-monospace" style="font-size: 0.7rem;">/${ep.path}</span>
                            <span class="result-text small text-muted">Status ${ep.status} · Size ${ep.size}</span>
                        </div> `;
                });
                ffufHtml += '</div>';
                ffufDiv.innerHTML = endpoints.length ? ffufHtml : '<div class="text-muted small fst-italic">No endpoints discovered.</div>';
            }
        }

        // 9. Extended Enumeration (WAF, Headers, API, Arjun, JS Secrets)
        if (results.phases.enum) {
            const enumHtml = [];

            // WAF
            if (results.phases.enum.waf && Object.keys(results.phases.enum.waf).length > 0) {
                let wafContent = '<div class="mb-3"><h6 class="text-secondary small">WAF Detection</h6 > ';
                for (const [port, waf] of Object.entries(results.phases.enum.waf)) {
                    wafContent += `<div class="d-flex justify-content-between border-bottom border-dark pb-1 mb-1 small font-monospace"><span class="text-muted">Port ${port}</span><span class="text-warning">${waf}</span></div> `;
                }
                wafContent += '</div>';
                enumHtml.push(wafContent);
            }

            // Headers
            if (results.phases.enum.headers) {
                // Determine if interesting headers found? 
                // Mostly just want to show if we have data.
                // For now, let's skip full header dump unless requested, or maybe a summary.
            }

            // API (Kiterunner)
            if (results.phases.enum.api && results.phases.enum.api['discovered_endpoints']) { // Check simplified structure or port-based
                // Port based extraction from earlier fix
            }

            // Re-render Arjun and JS Secrets better if needed, or leave existing logic?
            // Existing logic for Arjun/JS Secrets was at the end. 
            // I will replace `// 9. Expert Findings` block entirely.
        }

        // --- NEW: GENERIC & EXPERT VULN RENDERER ---
        if (results.phases.vuln) {
            const vulnDiv = document.getElementById("expert-vuln-results"); // Need to ensure this exists or append to main findings
            // If specific container doesn't exist, we might need to rely on the main findings list which is populated by 'new_finding' events.
            // BUT user said "UI doesn't read JSON -> invisible". 
            // This implies the 'new_finding' events might not be firing or the user wants to see the raw data structure in a specific panel.
            // Let's create a dynamic section for these if they don't exist in the findings list.

            // Actually, orchestrator calls `orch.add_finding` for all these sections!
            // So they SHOULD be in the findings list.
            // UNLESS the user is reloading the page and fetching 'results' via API/Socket, and the 'findings' list in 'results' 
            // is not being fully populated or sent.

            // The `results` object in `updateUI(results)` comes from `orchestrator.results`.
            // `orchestrator.results` DOES NOT have a `findings` key at the top level in the python code!
            // Check `orchestrator.py`: `results` structure (lines 43-67) does NOT have `findings`.
            // Queries separate `findings` list? 
            // `orch.add_finding` usually writes to database.
            // Does `results` contain findings?
            // In `handleNewFinding`, it appends to UI.
            // But on fresh load/updateUI, where do findings come from?
            // The `results` passed to `updateUI` usually has `findings` injected if the backend sends it.
            // If the backend `get_scan_results` only sends `orch.results` (the JSON blob), it lacks the DB findings!

            // This is the "Architectural Issue" the user hinted at.
            // "Modules create Finding" vs "Modules write JSON".
            // If `updateUI` relies on `results` JSON, it misses DB findings unless they are injected.

            // I will strictly implement the rendering of the JSON `phases.vuln` and `phases.enum` sections 
            // into the "Expert Findings" or a new "Deep Analysis" container.

            const containers = {
                'waf': '#waf-details',
                'arjun': '#arjun-results',
                'api': '#api-results',
                'git': '#git-results',
                'tech': '#tech-results',
                'js_secrets': '#js-secrets-results'
            }; // specialized containers if they exist

            // Render specific JSON sections
            this.renderJSONSection(results.phases.osint, 'cloud', 'Cloud Assets');
            this.renderJSONSection(results.phases.osint, 'dorks', 'Google Hacking');
            this.renderJSONSection(results.phases.osint, 'origin_ips', 'Origin Unmasking');
            this.renderJSONSection(results.phases.osint, 'emails', 'Email Discovery');
            this.renderJSONSection(results.phases.osint, 'github', 'GitHub Leaks');
            this.renderJSONSection(results.phases.dns, 'subdomains', 'Discovered Subdomains');
            this.renderJSONSection(results.phases.dns, 'records', 'DNS Records');

            const knownEnumTitles = {
                waf: 'WAF Detection', arjun: 'Hidden Parameters', api: 'API Endpoints',
                js_secrets: 'JS Secrets', headers: 'Security Headers', whatweb: 'Technology Footprint'
            };

            for (const key of Object.keys(results.phases.enum || {})) {
                // Skip structural keys parsed via custom UI components
                if (['derived', 'targets', 'seed_meta', 'normalized', 'injection_points', 'attack_profile', 'mutation_strategy', 'katana'].includes(key)) continue;

                let title = knownEnumTitles[key];
                if (!title) {
                    title = key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
                }
                this.renderJSONSection(results.phases.enum, key, title);
            }

            // Dynamically render all vulnerabilities to ensure no module is missed
            const knownVulnTitles = {
                tls: 'TLS/SSL Audit', git: 'Git Exposure', backups: 'Backup Files', tech: 'Technology Leaks',
                graphql: 'GraphQL', ssrf: 'SSRF Candidates', redirects: 'Open Redirects', xss: 'XSS Reflections',
                prototype: 'Prototype Pollution', ssti: 'SSTI Finds', lfi: 'LFI Assaults', cors_audit: 'CORS Audit',
                crlf: 'CRLF Injection', firebase: 'Firebase Exposure', xxe: 'XXE Analysis', deserialization: 'Deserialization',
                acl_bypass: 'ACL Bypass', email_security: 'Email Infrastructure', container_exposure: 'Container/Docker',
                infra_exposure: 'Infrastructure Exposure', websocket: 'WebSocket Security', data_leaks: 'Sensitive Data Mining',
                oauth: 'OAuth & OIDC Flows', nosql: 'NoSQL Injection', cache_audit: 'Web Cache Audit', upload_bypass: 'File Upload Expert',
                logic_flaws: 'Business Logic Auditor', deep_ssrf: 'Cloud SSRF Deep Probe', api_shadow: 'API Shadow Hunter',
                csti: 'CSTI Framework Auditor', metadata_leaks: 'Metadata Forensics', waf_audit: 'WAF Fingerprinting',
                java_rce: 'Java RCE Expert', h2c_smuggling: 'H2C Smuggling', spring_boot: 'Spring Boot Expert', cloud_perms: 'Cloud IAM Perms',
                logic_assault: 'Logic Assault', waf_bypass: 'WAF Bypass Expert', js_vulns: 'JS Vulnerabilities',
                api_expert: 'API Expert Scan', tech_exposure: 'Tech Exposure', db_audit: 'Database Audit', surface_mapping: 'Surface Mapping'
            };

            for (const key of Object.keys(results.phases.vuln || {})) {
                // Skip explicit blocks handled elsewhere
                if (['wordpress', 'nuclei'].includes(key)) continue;

                let title = knownVulnTitles[key];
                if (!title) {
                    title = key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
                }
                this.renderJSONSection(results.phases.vuln, key, title);
            }

            // --- NATIVE WORDPRESS ADAPTIVE UPDATES ---
            if (results.phases.vuln.wordpress) {
                for (const [port, wp] of Object.entries(results.phases.vuln.wordpress)) {
                    const panel = document.getElementById(`wp-waf-panel-${port}`);
                    const icon = document.getElementById(`wp-waf-icon-${port}`);
                    const text = document.getElementById(`wp-waf-text-${port}`);
                    const evasion = document.getElementById(`wp-evasion-status-${port}`);

                    if (panel && wp.wordfence_detected) {
                        panel.classList.remove('border-secondary');
                        panel.classList.add('border-warning');
                        if (icon) {
                            icon.classList.remove('text-muted');
                            icon.classList.add('text-warning', 'animate-pulse');
                        }
                        if (text) {
                            text.innerHTML = '<span class="text-warning fw-bold"><i class="fas fa-exclamation-triangle me-1"></i>Detected Wordfence WAF</span>';
                        }
                    }

                    if (evasion) {
                        if (wp.evasion_active) {
                            evasion.innerHTML = `
                                <span class="badge bg-success bg-opacity-10 text-success border border-success border-opacity-25 px-3">
                                    <i class="fas fa-bolt me-1"></i> MUTATION & THROTTLE ACTIVE
                                </span>`;
                        } else {
                            evasion.innerHTML = `
                                <span class="badge bg-secondary bg-opacity-10 text-muted border border-secondary border-opacity-25 px-3">
                                    STANDARD MODE
                                </span>`;
                        }
                    }
                }
            }
        }

        // Final Step: Global Graph Update if structural data changed
        if (results.findings || results.phases) {
            if (typeof initGraphData === 'function') {
                setTimeout(() => initGraphData(), 200);
            }
        }
    }

    // --- HUMAN READABLE RENDERING ENGINE (V6) ---
    renderJSONSection(parent, key, title) {
        if (!parent || !parent[key]) return;

        const data = parent[key];
        if (Array.isArray(data) && data.length === 0) return;
        if (typeof data === 'object' && Object.keys(data).length === 0) return;

        let container = document.getElementById(`${key}-results`);

        if (!container) {
            let deepContainer = document.getElementById('deep-scan-details');
            if (!deepContainer) return;

            let placeholder = document.getElementById('deep-scan-placeholder');
            if (placeholder) placeholder.style.display = 'none';

            const wrapper = document.createElement('div');
            wrapper.id = `${key}-results`;
            wrapper.className = 'col-lg-6 mb-4 animate__animated animate__fadeIn';
            wrapper.innerHTML = `
                <div class="card h-100 glass-panel border-secondary border-opacity-25">
                    <div class="card-header glass-header d-flex justify-content-between align-items-center">
                        <span class="text-cyber small fw-bold text-uppercase"><i class="fas fa-microscope me-2 text-primary"></i>${title}</span>
                        <span class="badge bg-dark border border-secondary text-muted x-small">${key.toUpperCase()}</span>
                    </div>
                    <div class="card-body result-content p-3" style="max-height: 400px; overflow-y: auto;"></div>
                </div>`;
            deepContainer.appendChild(wrapper);
            container = wrapper.querySelector('.result-content');
        }

        // Try Human-Readable First
        const humanHtml = this.renderSectionHuman(key, data);
        if (humanHtml) {
            container.innerHTML = humanHtml;
            return;
        }

        // Smart Fallback: Vulnerability List
        if (Array.isArray(data) && data.length > 0 && typeof data[0] === 'object' && !Array.isArray(data[0])) {
            container.innerHTML = this.renderGenericVulnList(data);
            return;
        }

        // Smart Fallback: Port mapped arrays
        if (typeof data === 'object' && !Array.isArray(data)) {
            const keys = Object.keys(data);
            if (keys.length > 0 && keys.every(k => !isNaN(k) && Array.isArray(data[k]))) {
                let html = '<div class="row g-2 w-100">';
                for (const [port, items] of Object.entries(data)) {
                    html += `<div class="col-12 mb-2"><div class="badge bg-cyber x-small mb-1 text-dark">PORT ${port}</div>${this.renderGenericVulnList(items)}</div>`;
                }
                html += '</div>';
                container.innerHTML = html;
                return;
            }
        }

        // Original Fallback: Structured Key/Value
        let html = '<div class="list-group list-group-flush bg-transparent w-100">';
        if (Array.isArray(data)) {
            data.slice(0, 100).forEach(item => {
                const content = typeof item === 'object' ? JSON.stringify(item) : item;
                html += `<div class="list-group-item bg-transparent border-secondary border-opacity-10 py-1 font-monospace x-small text-muted text-break">${this.escapeHtml(content)}</div>`;
            });
            if (data.length > 100) html += `<div class="p-2 x-small text-center text-muted">+ ${data.length - 100} more...</div>`;
        } else {
            Object.entries(data).forEach(([k, v]) => {
                html += `
                    <div class="mb-2 w-100">
                        <div class="x-small text-cyber font-monospace text-uppercase fw-bold">${k}</div>
                        <pre class="bg-black p-2 rounded border border-secondary border-opacity-10 x-small text-muted mb-0 overflow-auto" style="max-height: 150px;">${this.escapeHtml(typeof v === 'object' ? JSON.stringify(v, null, 2) : v)}</pre>
                    </div>`;
            });
        }
        html += '</div>';
        container.innerHTML = html;
    }

    renderGenericVulnList(data) {
        if (!Array.isArray(data)) return '';
        let html = '<div class="list-group list-group-flush bg-transparent w-100">';
        data.slice(0, 50).forEach(item => {
            if (!item || typeof item !== 'object') {
                html += `<div class="list-group-item bg-transparent border-secondary border-opacity-10 py-1 font-monospace x-small text-muted text-break">${this.escapeHtml(item)}</div>`;
                return;
            }
            const title = item.title || item.name || item.id || item.type || 'Discovered Vector';
            let severity = item.severity || item.risk || 'info';
            if (typeof severity !== 'string') severity = 'info';
            const sevClass = ['critical', 'high'].includes(severity.toLowerCase()) ? 'danger' : (['medium'].includes(severity.toLowerCase()) ? 'warning' : 'info');
            const desc = item.description || item.reason || item.details || '';
            const tool = item.tool || item.source || item.tool_source || '-';

            html += `
            <div class="list-group-item bg-black bg-opacity-40 border-secondary border-opacity-25 py-2 mb-2 rounded border border-start border-${sevClass} border-2">
                <div class="d-flex justify-content-between align-items-center mb-1">
                    <span class="text-light fw-bold small text-truncate" style="max-width: 80%;">${this.escapeHtml(title)}</span>
                    <span class="badge bg-${sevClass} x-small bg-opacity-75">${severity.toUpperCase()}</span>
                </div>
                <div class="d-flex gap-2 mb-2">
                    <span class="badge bg-dark border border-secondary text-muted x-small">${this.escapeHtml(tool)}</span>
                </div>
                ${desc ? `<div class="x-small text-muted mb-2 lh-sm overflow-hidden" style="max-height: 60px;">${this.escapeHtml(desc)}</div>` : ''}
                ${item.url || item.endpoint ? `<div class="x-small text-cyber font-monospace text-truncate w-100 d-block"><i class="fas fa-link me-1 opacity-50"></i><a href="${this.escapeHtml(item.url || item.endpoint)}" target="_blank" class="text-cyber text-decoration-none">${this.escapeHtml(item.url || item.endpoint)}</a></div>` : ''}
                ${item.match || item.evidence ? `<div class="bg-dark bg-opacity-50 p-1 border border-secondary border-opacity-10 rounded mt-2 x-small text-warning font-monospace text-truncate"><i class="fas fa-search me-1"></i>${this.escapeHtml(item.match || item.evidence)}</div>` : ''}
                ${item.repro_command ? `<div class="bg-black p-1 border border-secondary border-opacity-25 rounded mt-2 x-small text-muted font-monospace text-truncate"><i class="fas fa-terminal me-1"></i>${this.escapeHtml(item.repro_command)}</div>` : ''}
            </div>`;
        });
        if (data.length > 50) html += `<div class="p-2 x-small text-center text-muted">+ ${data.length - 50} more...</div>`;
        html += '</div>';
        return html;
    }

    renderSectionHuman(key, data) {
        try {
            switch (key) {
                case 'tls':
                    return this.renderTLSHuman(data);
                case 'waf':
                    return this.renderWAFHuman(data);
                case 'headers':
                    return this.renderHeadersHuman(data);
                case 'whatweb':
                    return this.renderTechHuman(data);
                case 'arjun':
                case 'params':
                    return this.renderParamsHuman(data);
                case 'katana':
                    return this.renderCrawlerHuman(data);
                case 'js_secrets':
                case 'secrets':
                    return this.renderSecretsHuman(data);
                case 'cloud':
                    return this.renderCloudHuman(data);
                case 'dorks':
                    return this.renderDorksHuman(data);
                case 'origin_ips':
                    return this.renderOriginHuman(data);
                case 'emails':
                    return this.renderEmailsHuman(data);
                case 'github':
                    return this.renderGithubHuman(data);
                case 'records':
                    return this.renderDNSRecordsHuman(data);
                case 'subdomains':
                    return this.renderSubdomainsHuman(data);
                case 'api':
                    return this.renderApiTreeHuman(data);

                default:
                    return null;
            }
        } catch (e) {
            console.error(`Human renderer failed for ${key}:`, e);
            return null;
        }
    }

    renderTLSHuman(data) {
        let html = '';
        Object.entries(data).forEach(([port, info]) => {
            html += `<div class="mb-3 p-2 bg-black bg-opacity-20 rounded border border-secondary border-opacity-10">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <span class="badge bg-info text-dark">PORT ${port}</span>
                    <span class="small font-monospace ${info.expired ? 'text-danger' : 'text-success'}">${info.expired ? 'EXPIRED' : 'VALID'}</span>
                </div>
                <div class="small fw-bold text-light mb-1">${info.subject || 'Unknown Subject'}</div>
                <div class="x-small text-muted font-monospace mb-1">Issuer: ${info.issuer || '-'}</div>
                <div class="x-small text-muted font-monospace">Expires: ${info.expiry || '-'}</div>
                ${info.cipher ? `<div class="mt-2 text-cyber x-small font-monospace border-top border-secondary border-opacity-10 pt-1">${info.cipher}</div>` : ''}
            </div>`;
        });
        return html;
    }

    renderWAFHuman(data) {
        let html = '';
        Object.entries(data).forEach(([port, name]) => {
            html += `
            <div class="d-flex align-items-center justify-content-between p-2 bg-warning bg-opacity-10 border border-warning border-opacity-20 rounded mb-2">
                <div class="d-flex align-items-center">
                    <i class="fas fa-shield-halved text-warning me-2"></i>
                    <div>
                        <div class="small fw-bold text-light">${name}</div>
                        <div class="x-small text-muted font-monospace">Protection active on port ${port}</div>
                    </div>
                </div>
                <span class="badge bg-warning text-dark x-small">DETECTED</span>
            </div>`;
        });
        return html;
    }

    renderHeadersHuman(data) {
        let html = '<div class="row g-2">';
        const securityHeaders = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy'];

        Object.entries(data).forEach(([port, headers]) => {
            html += `<div class="col-12 mb-2"><div class="badge bg-secondary x-small w-100">PORT ${port}</div></div>`;
            securityHeaders.forEach(sh => {
                const found = headers[sh] || headers[sh.toLowerCase()];
                html += `
                <div class="col-6 mb-2">
                    <div class="p-2 bg-black bg-opacity-30 border border-secondary border-opacity-10 rounded h-100">
                        <div class="x-small text-muted text-uppercase mb-1">${sh.replace('X-', '')}</div>
                        <div class="d-flex align-items-center">
                            <i class="fas ${found ? 'fa-check-circle text-success' : 'fa-times-circle text-danger'} me-1 x-small"></i>
                            <span class="x-small font-monospace text-truncate">${found ? 'Enabled' : 'Missing'}</span>
                        </div>
                    </div>
                </div>`;
            });
        });
        html += '</div>';
        return html;
    }

    renderApiTreeHuman(data) {
        let endpoints = [];
        if (Array.isArray(data)) {
            endpoints = data;
        } else if (data && data.endpoints && Array.isArray(data.endpoints)) {
            endpoints = data.endpoints;
        } else if (data && data.discovered_endpoints && Array.isArray(data.discovered_endpoints)) {
            endpoints = data.discovered_endpoints;
        }

        if (!endpoints || !endpoints.length) return null;

        const tree = { name: "ROOT", children: {}, endpoints: [] };
        let hasElements = false;
        let rootUrlText = '';

        endpoints.forEach(ep => {
            let urlStr = typeof ep === 'string' ? ep : (ep.url || ep.endpoint);
            if (!urlStr) return;

            let url;
            try { url = new URL(urlStr); } catch (e) { return; }
            if (!rootUrlText) rootUrlText = url.origin;

            const parts = url.pathname.split('/').filter(p => p);
            let current = tree;
            for (let i = 0; i < parts.length; i++) {
                const part = parts[i];
                if (!current.children[part]) {
                    current.children[part] = { name: part, children: {}, endpoints: [] };
                }
                current = current.children[part];
            }
            if (typeof ep === 'string') {
                current.endpoints.push({ url: ep });
            } else {
                current.endpoints.push(ep);
            }
            hasElements = true;
        });

        if (!hasElements) return null;

        const renderNode = (node, depth) => {
            let html = '';
            const indentSpacing = depth > 1 ? '<span class="d-inline-block opacity-25" style="width: 20px; border-left: 1px dashed #fff; height: 24px; vertical-align: middle; margin-right: 5px;"></span>'.repeat(depth - 1) : '';

            if (depth > 0) {
                const hasEndpoints = node.endpoints.length > 0;
                let iconHtml = '<i class="far fa-folder-open text-warning me-2 opacity-75"></i>';
                let stBadge = '';

                if (hasEndpoints) {
                    const ep = node.endpoints[0];
                    const st = ep.status || '';
                    if (st) {
                        const stColor = (st >= 200 && st < 300) ? 'success' : ((st >= 300 && st < 400) ? 'info' : ((st >= 400 && st < 500) ? 'warning' : 'danger'));
                        stBadge = `<span class="badge rounded-pill bg-${stColor} bg-opacity-75 ms-2" style="font-size: 0.65em;">${st}</span>`;
                    }
                }

                const hasChildren = Object.keys(node.children).length > 0;
                if (!hasChildren) {
                    iconHtml = '<i class="fas fa-leaf text-info me-2 opacity-50 x-small" style="vertical-align: middle;"></i>';
                }

                html += `
                <div class="d-flex align-items-center py-1 hover-bg-dark rounded px-2">
                    <div class="d-flex align-items-center font-monospace small w-100">
                        ${indentSpacing}
                        <span class="text-secondary opacity-50 me-2" style="font-size: 0.8em;">├──</span>
                        ${iconHtml}
                        <span class="${hasChildren ? 'text-light fw-bold opacity-75' : 'text-info'}">${this.escapeHtml(node.name)}${hasChildren ? '/' : ''}</span>
                        ${stBadge}
                    </div>
                </div>`;
            }

            Object.values(node.children).sort((a, b) => a.name.localeCompare(b.name)).forEach(child => {
                html += renderNode(child, depth + 1);
            });
            return html;
        };

        const finalHtml = `
        <div class="bg-black border border-secondary border-opacity-25 rounded p-3 overflow-auto w-100" style="max-height: 400px;">
            <div class="text-info x-small fw-bold mb-3 text-uppercase"><i class="fas fa-sitemap me-2"></i>API Endpoint Architecture</div>
            <div class="font-monospace text-muted x-small mb-2 p-2 bg-dark rounded border border-secondary border-opacity-10 shadow-sm"><i class="fas fa-globe-americas me-2"></i>${this.escapeHtml(rootUrlText)}</div>
            <div class="ps-1 pt-2">
            ${renderNode(tree, 0)}
            </div>
        </div>`;
        return finalHtml;
    }

    renderTechHuman(data) {
        let html = '';
        if (data.summary) {
            html += '<div class="d-flex flex-wrap gap-1 mb-3">';
            Object.entries(data.summary).forEach(([tech, count]) => {
                html += `<span class="badge bg-info bg-opacity-10 text-info border border-info border-opacity-25">${tech}</span>`;
            });
            html += '</div>';
        }
        Object.entries(data).forEach(([port, output]) => {
            if (port === 'summary') return;
            html += `
            <div class="mb-2 pb-2 border-bottom border-secondary border-opacity-10">
                <div class="badge bg-secondary x-small mb-1">Port ${port}</div>
                <div class="x-small text-muted font-monospace text-break">${this.escapeHtml(output)}</div>
            </div>`;
        });
        return html;
    }

    renderParamsHuman(data) {
        let html = '<div class="row g-2">';
        Object.entries(data).forEach(([port, params]) => {
            const list = Array.isArray(params) ? params : (params.params || []);
            html += `<div class="col-12 mb-1"><div class="badge bg-dark border border-secondary x-small">PORT ${port}: ${list.length} VARS</div></div>`;
            list.slice(0, 20).forEach(p => {
                html += `<div class="col-4"><div class="p-1 bg-black border border-secondary border-opacity-10 rounded x-small text-center text-cyber font-monospace text-truncate">${p}</div></div>`;
            });
            if (list.length > 20) html += `<div class="col-12 text-center x-small text-muted">+ ${list.length - 20} more</div>`;
        });
        html += '</div>';
        return html;
    }

    renderCrawlerHuman(data) {
        let html = '';
        Object.entries(data).forEach(([port, list]) => {
            html += `
            <div class="mb-3">
                <div class="d-flex justify-content-between align-items-center mb-2">
                    <span class="badge bg-secondary x-small">PORT ${port}</span>
                    <span class="x-small text-muted font-monospace">${list.length} Endpoints</span>
                </div>
                <div class="list-group list-group-flush">
                    ${list.slice(0, 10).map(ep => `<div class="list-group-item bg-transparent border-secondary border-opacity-10 p-1 x-small text-muted font-monospace text-truncate"><i class="fas fa-link me-1 opacity-50"></i>${this.escapeHtml(ep)}</div>`).join('')}
                    ${list.length > 10 ? `<div class="p-1 text-center x-small text-muted">... viewing 10 of ${list.length}</div>` : ''}
                </div>
            </div>`;
        });
        return html;
    }

    renderSecretsHuman(data) {
        let html = '<div class="list-group list-group-flush">';
        Object.entries(data).forEach(([port, secrets]) => {
            const list = Array.isArray(secrets) ? secrets : [];
            list.forEach(s => {
                const type = s.type || 'Secret';
                html += `
                <div class="list-group-item bg-transparent border-danger border-opacity-10 p-2 mb-2 rounded bg-danger bg-opacity-10">
                    <div class="d-flex justify-content-between mb-1">
                        <span class="x-small fw-bold text-danger text-uppercase">${type}</span>
                        <span class="badge bg-dark border border-danger text-danger x-small">PORT ${port}</span>
                    </div>
                    <div class="x-small font-monospace text-light text-break">${this.escapeHtml(s.match || s.data || s)}</div>
                    <div class="x-small text-muted mt-1 text-truncate">${this.escapeHtml(s.file || '')}</div>
                </div>`;
            });
        });
        html += '</div>';
        return html;
    }

    updateCortexUI(results) {
        if (!results || !results.phases || !results.phases.enum || !results.phases.enum.derived) return;
        const derived = results.phases.enum.derived;

        // NEW: JS Expert Badge logic
        const headerBadges = document.querySelector('#cortex-intel-card .card-header .d-flex.gap-2');
        if (headerBadges && derived.js_expert_mining && !headerBadges.querySelector('.fa-microscope')) {
            const badge = document.createElement('span');
            badge.className = 'badge bg-warning bg-opacity-10 text-warning border border-warning border-opacity-25 animate-pulse';
            badge.innerHTML = '<i class="fas fa-microscope me-1"></i>JS EXPERT ACTIVE';
            headerBadges.prepend(badge);
        }

        // 1. Recommendations
        const recsContainer = document.getElementById('cortex-recs-container');
        if (recsContainer && derived.cortex_recommendations) {
            let html = '';
            derived.cortex_recommendations.forEach(rec => {
                const catClass = rec.category === 'intel' ? 'info' : (rec.category === 'enum' ? 'warning' : 'danger');
                html += `
                <div class="mb-3 p-3 bg-black bg-opacity-40 border border-secondary border-opacity-25 rounded-sm hover-glow animate__animated animate__fadeIn">
                    <div class="d-flex justify-content-between align-items-start mb-2">
                        <div class="d-flex align-items-center">
                            <div class="category-indicator me-2 bg-${catClass}" style="width: 4px; height: 16px;"></div>
                            <span class="fw-bold text-light small">${rec.title}</span>
                        </div>
                        <span class="badge bg-dark text-${rec.confidence > 80 ? 'info' : 'muted'} border border-secondary x-small font-monospace">CONF: ${rec.confidence}%</span>
                    </div>
                    <div class="text-muted x-small mb-2 ps-3">${rec.reason}</div>
                    <div class="d-flex gap-2 ps-3">
                        ${rec.port ? `<span class="badge bg-secondary bg-opacity-10 text-info border border-info border-opacity-25 x-small">PORT: ${rec.port}</span>` : ''}
                        <span class="badge bg-dark text-uppercase x-small text-muted">${rec.category}</span>
                    </div>
                </div>`;
            });
            if (html) recsContainer.innerHTML = html;
        }

        // 2. Surface Expansion
        const expansionContainer = document.getElementById('surface-expansion-container');
        if (expansionContainer && derived.surface_expansion) {
            const exp = derived.surface_expansion;
            let html = '';

            if (exp.global && exp.global.derived_endpoints && exp.global.derived_endpoints.length) {
                html += `
                <div class="mb-4 animate__animated animate__fadeIn">
                    <div class="text-info x-small fw-bold mb-2 text-uppercase">Heuristic Search Surfaces</div>
                    <div class="d-flex flex-wrap gap-1">
                        ${exp.global.derived_endpoints.map(ep => `<span class="badge bg-black border border-secondary text-muted font-monospace x-small" title="Heuristic Match">${ep}</span>`).join('')}
                    </div>
                </div>`;
            }

            if (exp.per_port && Object.keys(exp.per_port).length) {
                html += `<div class="mb-2"><div class="text-warning x-small fw-bold mb-2 text-uppercase">Signals Detected</div>`;
                Object.entries(exp.per_port).forEach(([port, data]) => {
                    html += `
                    <div class="mb-2 p-2 bg-black bg-opacity-20 rounded animate__animated animate__fadeIn">
                        <div class="d-flex align-items-center gap-2 mb-1">
                            <span class="badge bg-info bg-opacity-25 text-info x-small">PORT ${port}</span>
                            <div class="d-flex gap-1">
                                ${data.reasons.map(r => `<span class="x-small text-muted border-bottom border-warning">${r.replace(/_/g, ' ')}</span>`).join('')}
                            </div>
                        </div>
                        ${data.derived_params && data.derived_params.length ? `
                        <div class="ps-2 mt-3 border-start border-secondary border-2">
                            <div class="x-small text-muted mb-1"><i class="fas fa-search-plus me-1 text-info opacity-75"></i>Extracted Parameters <span class="badge bg-dark border border-secondary border-opacity-50 text-muted ms-1">${data.derived_params.length}</span></div>
                            <div class="d-flex flex-wrap gap-1 mt-1">
                                ${data.derived_params.slice(0, 20).map(p => {
                        let decoded = p;
                        try { decoded = decodeURIComponent(p); } catch (e) { }
                        const safeP = decoded.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
                        return '<span class="badge bg-black bg-opacity-50 border border-info border-opacity-25 text-warning font-monospace x-small">' + safeP + '</span>';
                    }).join('')}
                                ${data.derived_params.length > 20 ? `
                                <div class="collapse w-100" id="collapse-params-${port}">
                                    <div class="d-flex flex-wrap gap-1 mt-1">
                                    ${data.derived_params.slice(20).map(p => {
                        let decoded = p;
                        try { decoded = decodeURIComponent(p); } catch (e) { }
                        const safeP = decoded.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
                        return '<span class="badge bg-black bg-opacity-50 border border-secondary border-opacity-25 text-muted font-monospace x-small">' + safeP + '</span>';
                    }).join('')}
                                    </div>
                                </div>
                                <a data-bs-toggle="collapse" href="#collapse-params-${port}" role="button" aria-expanded="false" class="badge bg-black bg-opacity-20 border border-secondary border-opacity-25 text-cyber text-decoration-none x-small mt-1 hover-glow w-100 text-center py-1">
                                    <i class="fas fa-chevron-down me-1"></i>+${data.derived_params.length - 20} more variables (Toggle)
                                </a>` : ''}
                            </div>
                        </div>` : ''}
                    </div>`;
                });
                html += `</div>`;
            }
            if (html) expansionContainer.innerHTML = html;
        }

        // 3. Service Intel
        const intelContainer = document.getElementById('service-intel-container');
        if (intelContainer && derived.service_intelligence) {
            let tagsHtml = '<div class="d-flex flex-wrap gap-2">';
            derived.service_intelligence.forEach(item => {
                item.tags.forEach(tag => {
                    const tagColor = (tag.includes('api') || tag.includes('web')) ? 'info' : 'warning';
                    tagsHtml += `
                    <span class="badge bg-dark border border-${tagColor} text-light x-small animate__animated animate__zoomIn" title="Port: ${item.port}">
                        <i class="fas fa-tag me-1 text-muted"></i>${tag.toUpperCase()}
                    </span>`;
                });
            });
            tagsHtml += '</div>';
            if (derived.service_intelligence.length) intelContainer.innerHTML = tagsHtml;
        }

        // 4. Thought Stream Status
        const statusBadge = document.getElementById('cortex-dynamic-status');
        if (statusBadge) {
            if (derived.status && derived.status !== 'idle') {
                statusBadge.innerHTML = `<i class="fas fa-brain me-1"></i>${derived.status.toUpperCase()}`;
                statusBadge.classList.remove('d-none');
            } else {
                statusBadge.classList.add('d-none');
            }
        }
    }
    renderCloudHuman(data) {
        let html = '<div class="row g-2">';
        data.forEach(asset => {
            const providerIcon = asset.provider.toLowerCase().includes('s3') ? 'fab fa-aws' : (asset.provider.toLowerCase().includes('azure') ? 'fab fa-microsoft' : 'fab fa-google');
            const statusClass = asset.status === 'OPEN/PUBLIC' ? 'text-danger fw-bold' : 'text-success';
            html += `
            <div class="col-md-6">
                <div class="p-2 bg-black border border-secondary rounded d-flex align-items-center h-100">
                    <div class="me-3 fs-3 text-info"><i class="${providerIcon}"></i></div>
                    <div>
                        <div class="fw-bold small text-truncate" style="max-width: 150px;">${this.escapeHtml(asset.bucket || asset.account)}</div>
                        <div class="text-muted x-small font-monospace">${this.escapeHtml(asset.provider)} · <span class="${statusClass}">${asset.status}</span></div>
                        <a href="${asset.url}" target="_blank" class="x-small text-cyber text-decoration-none">Visit Storage <i class="fas fa-external-link-alt"></i></a>
                    </div>
                </div>
            </div>`;
        });
        html += '</div>';
        return html;
    }

    renderDorksHuman(data) {
        let html = '<div class="d-flex flex-wrap gap-2" style="max-height: 250px; overflow-y: auto;">';
        data.forEach(dork => {
            html += `
            <a href="${dork.link}" target="_blank" class="btn btn-outline-secondary btn-sm text-start w-100 mb-1 border-opacity-25 hover-action">
                <div class="d-flex justify-content-between align-items-center">
                    <span class="text-light small">${this.escapeHtml(dork.name)}</span>
                    <i class="fas fa-external-link-alt text-muted x-small"></i>
                </div>
                <div class="text-muted x-small font-monospace text-truncate opacity-50">${this.escapeHtml(dork.query)}</div>
            </a>`;
        });
        html += '</div>';
        return html;
    }

    renderOriginHuman(data) {
        let html = '<div class="list-group list-group-flush bg-transparent">';
        data.forEach(origin => {
            const confClass = origin.confidence === 'high' ? 'bg-danger' : 'bg-warning';
            html += `
            <div class="list-group-item bg-transparent text-light border-secondary p-2">
                <div class="d-flex justify-content-between align-items-center">
                    <span class="font-monospace fw-bold text-danger">${origin.ip}</span>
                    <span class="badge ${confClass}">${origin.confidence.toUpperCase()}</span>
                </div>
                <div class="text-muted x-small mt-1">${this.escapeHtml(origin.reason)}</div>
            </div>`;
        });
        html += '</div>';
        return html;
    }

    renderEmailsHuman(data) {
        let html = '<div class="list-group list-group-flush">';
        data.forEach(email => {
            html += `
            <div class="list-group-item bg-transparent border-secondary border-opacity-10 py-1">
                <div class="d-flex align-items-center">
                    <i class="fas fa-envelope text-info me-2 x-small"></i>
                    <span class="font-monospace small text-light">${this.escapeHtml(email)}</span>
                </div>
            </div>`;
        });
        html += '</div>';
        return html;
    }

    renderGithubHuman(data) {
        let html = '<div class="list-group list-group-flush">';
        data.forEach(repo => {
            html += `
            <div class="list-group-item bg-transparent border-secondary border-opacity-10 py-2">
                <div class="fw-bold text-info small mb-1">${this.escapeHtml(repo.name || repo)}</div>
                ${repo.url ? `<a href="${repo.url}" target="_blank" class="x-small text-muted text-decoration-none text-truncate d-block">${repo.url}</a>` : ''}
            </div>`;
        });
        html += '</div>';
        return html;
    }

    renderDNSRecordsHuman(data) {
        let html = `
        <div class="table-responsive border border-secondary border-opacity-10 rounded">
            <table class="table table-dark table-hover mb-0 x-small font-monospace">
                <thead class="bg-black bg-opacity-50">
                    <tr>
                        <th class="text-muted">Type</th>
                        <th class="text-muted">Name</th>
                        <th class="text-muted">Address/Data</th>
                        <th class="text-muted text-end">TTL</th>
                    </tr>
                </thead>
                <tbody>`;
        data.forEach(rec => {
            html += `
            <tr>
                <td><span class="badge bg-secondary x-small">${rec.type}</span></td>
                <td class="text-cyber opacity-75">${this.escapeHtml(rec.name)}</td>
                <td class="text-light opacity-75">${this.escapeHtml(rec.address || rec.data)}</td>
                <td class="text-muted text-end">${rec.ttl || '-'}</td>
            </tr>`;
        });
        html += `</tbody></table></div>`;
        return html;
    }

    renderSubdomainsHuman(data) {
        if (!Array.isArray(data) || data.length === 0) return null;
        let html = '<div class="d-flex flex-wrap gap-2 p-1">';
        data.slice(0, 150).forEach(sub => {
            html += `<a href="https://${this.escapeHtml(sub)}" target="_blank" class="badge bg-black bg-opacity-75 border border-secondary border-opacity-50 text-light font-monospace x-small text-decoration-none hover-glow"><i class="fas fa-satellite-dish me-2 text-info opacity-75"></i>${this.escapeHtml(sub)}</a>`;
        });
        if (data.length > 150) {
            html += `<span class="badge bg-transparent border border-secondary border-opacity-25 text-muted x-small d-flex align-items-center">+ ${data.length - 150} more entries</span>`;
        }
        html += '</div>';
        return html;
    }
}

// Global Routing & Filtering Helper
window.applyTacticalFilter = function (targetTab, filterValue) {
    const tabMap = {
        mission: 'mission-tab',
        surface: 'surface-tab',
        findings: 'findings-tab',
        graph: 'graph-tab',
        report: 'report-tab',
        hood: 'hood-tab',
    };
    const tabId = tabMap[targetTab] || 'surface-tab';
    const tabBtn = document.getElementById(tabId);
    if (!tabBtn) return;

    // Use Bootstrap's Tab API to switch
    const tab = bootstrap.Tab.getOrCreateInstance(tabBtn);
    tab.show();

    // Delay ensures the target tab's DOM is fully ready/visible before filtering
    setTimeout(() => {
        if (targetTab === 'findings') {
            const searchInput = document.getElementById('findings-search');
            const sevFilter = document.getElementById('findings-severity-filter');
            
            if (filterValue.startsWith('sev:')) {
                const sev = filterValue.substring(4).toLowerCase();
                if (sevFilter) sevFilter.value = sev;
                if (searchInput) searchInput.value = '';
            } else {
                if (searchInput) searchInput.value = filterValue;
                if (sevFilter) sevFilter.value = '';
            }
            
            // Trigger the local filter function defined in findings.html
            if (typeof filterFindings === 'function') {
                filterFindings();
            }
        } else if (targetTab === 'surface') {
            const filterInput = document.getElementById('surface-filter');
            if (filterInput) {
                filterInput.value = filterValue;
                // Trigger the local filter function defined in attack_surface.html
                if (typeof window.applySurfaceFilter === 'function') {
                    window.applySurfaceFilter();
                }
            }
        }

        // Scroll to top of results
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }, 150);
};

window.goToAuditStage = function (stage) {
    const map = {
        cadrage: { tab: 'mission', filter: '' },
        recon: { tab: 'surface', filter: 'type:service' },
        enum: { tab: 'surface', filter: 'type:endpoint' },
        detection: { tab: 'findings', filter: '' },
        validation: { tab: 'findings', filter: 'status:success' },
        correlation: { tab: 'graph', filter: '' },
        reporting: { tab: 'report', filter: '' },
        closure: { tab: 'report', filter: '' },
    };
    const route = map[stage] || map.detection;
    window.applyTacticalFilter(route.tab, route.filter);
};

// --- SEARCH INTEL HELPERS ---
window.addSearchPrefix = function (inputId, prefix) {
    const input = document.getElementById(inputId);
    if (!input) return;

    let currentVal = input.value.trim();
    // Check if the prefix is already there to avoid duplicates
    if (!currentVal.includes(prefix)) {
        input.value = currentVal ? currentVal + ' ' + prefix : prefix;
    }

    input.focus();

    // Trigger localized filter functions
    if (inputId === 'surface-filter' && typeof window.applySurfaceFilter === 'function') {
        window.applySurfaceFilter();
    } else if (typeof filterFindings === 'function') {
        filterFindings();
    }
};

window.clearSearch = function (inputId, callback) {
    const input = document.getElementById(inputId);
    if (!input) return;
    input.value = '';
    input.focus();
    if (typeof callback === 'function') {
        callback();
    }
};
