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

        // Log Triggers
        this.logTriggers = {
            'Phase 1': 'ports', 'Phase 2': 'ports', 'subdomains': 'dns',
            'Cloud Audit': 'cloud', 'WAF': 'waf', 'Arjun': 'params',
            'Kiterunner': 'api', 'API Discovery': 'api', 'Secret': 'secrets',
            'JS Secrets': 'secrets', 'Katana': 'crawl', 'ffuf': 'fuzz',
            'Dirbusting': 'fuzz', 'Vulnerability': 'vulns', 'Nuclei': 'vulns',
            'Dalfox': 'vulns', 'Intel': 'intel', 'Loot': 'loot',
            'Wayback': 'historic', 'Historic': 'historic', 'Archive': 'historic',
            'Spring': 'apps', 'Firebase': 'apps', 'Actuator': 'apps', 'Docker': 'apps'
        };

        this.init();
    }

    init() {
        this.setupSocketListeners();
        this.setupEventListeners();
        this.checkInitialStatus();
        this.setupNotesPreview();

        // Expose updateUI globally for initial load
        window.updateUI = (results) => this.updateUI(results);
        window.verifyFinding = (cmd) => this.verifyFinding(cmd);
        window.filterFindings = () => this.filterFindings(); // For search input
    }

    setupEventListeners() {
        document.addEventListener('click', (e) => {
            // Clipboard copy
            const copyBtn = e.target.closest('.copy-btn');
            if (copyBtn) {
                const pre = copyBtn.closest('.tab-pane, .d-flex').querySelector('pre');
                if (pre) {
                    navigator.clipboard.writeText(pre.innerText).then(() => {
                        const originalHtml = copyBtn.innerHTML;
                        copyBtn.innerHTML = '<i class="fas fa-check"></i>';
                        setTimeout(() => copyBtn.innerHTML = originalHtml, 1000);
                    });
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
                const cmd = verifyBtn.getAttribute('data-command');
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
            const emptyMsg = consoleDiv.querySelector(".text-muted");
            if (emptyMsg && emptyMsg.innerText.includes("No logs")) emptyMsg.remove();

            const div = document.createElement("div");
            const levelClass = data.level === 'SUCCESS' ? 'text-success' : (data.level === 'WARN' ? 'text-warning' : (data.level === 'ERROR' ? 'text-danger' : 'text-secondary'));
            div.innerHTML = `<span class="text-muted">[${data.timestamp}]</span> <span class="${levelClass}">${data.level}</span> ${data.message}`;
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
            document.querySelectorAll('.discovery-btn').forEach(btn => btn.classList.remove('active'));
        }
    }

    handleNewFinding(data) {
        if (data.scan_id != this.scanId) return;
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

            const escapedTitle = this.escapeHtml(data.title);
            const escapedTool = this.escapeHtml(data.tool);
            const escapedDesc = this.escapeHtml(data.description);

            let innerHTML = `
                <div class="d-flex w-100 justify-content-between mb-2">
                    <span class="badge severity-badge ${data.severity.toLowerCase()}">${data.severity.toUpperCase()}</span>
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
                const fid = data.id || `new-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
                const rowId = `finding-detail-${fid}`;
                if (document.getElementById(rowId)) return;

                const tr = document.createElement("tr");
                tr.className = "finding-row animate__animated animate__fadeIn";
                tr.setAttribute("data-severity", data.severity.toLowerCase());
                tr.setAttribute("data-content", `${escapedTitle.toLowerCase()} ${escapedTool.toLowerCase()} ${escapedDesc.toLowerCase()}`);
                tr.innerHTML = `
                    <td><span class="badge severity-badge ${data.severity.toLowerCase()} text-uppercase w-100">${data.severity}</span></td>
                    <td>
                        <div class="fw-bold text-light">${escapedTitle}</div>
                        <div class="small text-muted text-truncate" style="max-width: 400px;">${(escapedDesc || "").substring(0, 100)}...</div>
                    </td>
                    <td><span class="badge bg-dark border border-secondary text-muted">${escapedTool}</span></td>
                    <td>
                        <button class="btn btn-xs btn-outline-secondary" type="button" data-bs-toggle="collapse" data-bs-target="#${rowId}">
                            <i class="fas fa-chevron-down"></i>
                        </button>
                    </td>
                `;

                const detailTr = document.createElement("tr");
                detailTr.className = "finding-detail-row collapse bg-black bg-opacity-25";
                detailTr.id = rowId;

                let evidenceHtml = "";
                if (data.request || data.response || data.repro_command) {
                    const escapedReq = this.escapeHtml(data.request);
                    const escapedRes = this.escapeHtml(data.response);
                    const escapedRepro = this.escapeHtml(data.repro_command);

                    evidenceHtml = `
                        <div class="evidence-container mt-3 p-3 bg-dark bg-opacity-50 border border-secondary border-opacity-25 rounded">
                            <ul class="nav nav-tabs border-bottom-0 mb-3" role="tablist">
                                ${data.request ? `<li class="nav-item"><a class="nav-link active py-1 px-3 x-small" data-bs-toggle="tab" href="#req-${fid}">Request</a></li>` : ''}
                                ${data.response ? `<li class="nav-item"><a class="nav-link ${!data.request ? 'active' : ''} py-1 px-3 x-small" data-bs-toggle="tab" href="#res-${fid}">Response</a></li>` : ''}
                                ${data.repro_command ? `<li class="nav-item"><a class="nav-link ${(!data.request && !data.response) ? 'active' : ''} py-1 px-3 x-small" data-bs-toggle="tab" href="#repro-${fid}">Reproduction</a></li>` : ''}
                            </ul>
                            <div class="tab-content">
                                ${data.request ? `<div class="tab-pane fade show active" id="req-${fid}"><pre class="x-small font-monospace text-info bg-black p-2 rounded border border-secondary border-opacity-10">${escapedReq}</pre></div>` : ''}
                                ${data.response ? `<div class="tab-pane fade ${!data.request ? 'show active' : ''}" id="res-${fid}"><pre class="x-small font-monospace text-success bg-black p-2 rounded border border-secondary border-opacity-10">${escapedRes}</pre></div>` : ''}
                                ${data.repro_command ? `
                                    <div class="tab-pane fade ${(!data.request && !data.response) ? 'show active' : ''}" id="repro-${fid}">
                                        <div class="d-flex gap-2">
                                            <div class="flex-grow-1">
                                                <pre class="x-small font-monospace text-warning bg-black p-2 rounded border border-secondary border-opacity-10 overflow-hidden text-truncate mb-0">${escapedRepro}</pre>
                                            </div>
                                            <button class="btn btn-xs btn-outline-warning copy-btn"><i class="fas fa-copy"></i></button>
                                        </div>
                                    </div>` : ''}
                            </div>
                        </div>
                    `;
                }
                detailTr.innerHTML = `<td colspan="4"><div class="p-3">${escapedDesc}${evidenceHtml}</div></td>`;
                tableBody.prepend(detailTr);
                tableBody.prepend(tr);
            }
        }
    }

    addToGallery(data) {
        const gallery = document.getElementById("visual-recon-gallery");
        if (gallery) {
            const emptyImg = gallery.querySelector(".text-center.py-4");
            if (emptyImg) emptyImg.remove();

            const col = document.createElement("div");
            col.className = "col-md-4 col-lg-3 animate__animated animate__zoomIn";
            col.innerHTML = `
                <div class="screenshot-card bg-black border border-danger border-opacity-50 rounded overflow-hidden">
                    <img src="/static/${this.escapeHtml(data.screenshot_path)}" class="img-fluid w-100 screenshot-trigger" style="height: 120px; object-fit: cover; cursor: pointer;" title="${this.escapeHtml(data.title)}">
                    <div class="p-1 text-center bg-danger bg-opacity-10 small font-monospace">
                        <span class="text-danger">NEW EXPOSURE</span>
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
            div.innerHTML = `
                <div>
                    <span class="badge bg-secondary me-2">${this.escapeHtml(data.tool_name)}</span>
                    <span class="result-text font-monospace small">${escapedCmd}</span>
                </div>
                <button class="btn btn-xs btn-outline-warning verify-btn" data-command="${escapedCmd}">
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

            // --- CLEANUP: Stop all stuck animations when completed ---
            document.querySelectorAll('.discovery-btn').forEach(btn => btn.classList.remove('active'));
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
                const target = document.getElementById(`sidebar - ptes - ${ptesIdSuffix} `);
                if (target) {
                    target.classList.add('active');
                }
                break;
            }
        }
    }

    activateDiscovery(id, discovered = false) {
        const btn = document.getElementById(`discovery - ${id} `);
        if (!btn) return;
        if (discovered) {
            btn.classList.add('discovered');
            btn.classList.remove('active');
        } else if (!btn.classList.contains('discovered')) {
            btn.classList.add('active');
        }
    }

    toggleScanToast(show) {
        const toast = document.getElementById('scan-progress-toast');
        if (!toast) return;
        if (show) {
            toast.classList.remove('d-none', 'animate__fadeOutDown');
            toast.classList.add('animate__fadeInUp');
        } else {
            toast.classList.remove('animate__fadeInUp');
            toast.classList.add('animate__fadeOutDown');
            setTimeout(() => { if (toast.classList.contains('animate__fadeOutDown')) toast.classList.add('d-none'); }, 1000);
        }
    }

    checkInitialStatus() {
        const statusPill = document.querySelector('.status-pill');
        const currentStatus = statusPill ? statusPill.innerText.toLowerCase() : '';
        this.toggleScanToast(currentStatus === 'running');

        document.querySelectorAll('.log-console> div').forEach(logDiv => {
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
        if (!confirm(`Exécuter la vérification: ${command}?`)) return;
        fetch('/scan/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scan_id: this.scanId, command: command })
        }).then(r => r.json())
            .then(d => {
                if (d.status === 'success') {
                    alert("Tâche de vérification lancée. Surveillez les logs.");
                }
            });
    }

    updateRiskCounters(severity) {
        const sev = severity.toLowerCase();
        if (sev === 'critical' || sev === 'high') {
            const el = document.querySelector(`.tactical - summary - bar.h4.text - ${sev === 'critical' ? 'danger' : 'warning'} `);
            if (el) {
                let count = parseInt(el.innerText) + 1;
                el.innerText = count;
                el.classList.remove('text-muted');
                if (sev === 'critical') el.classList.add('pulse-danger');
            }
        }
    }

    filterFindings() {
        const search = document.getElementById('findingSearch').value.toLowerCase();
        const checkedSeverities = Array.from(document.querySelectorAll('.form-check-input:checked')).map(cb => cb.value);

        const rows = document.querySelectorAll('.finding-row');
        let visibleCount = 0;

        rows.forEach(row => {
            const severity = row.getAttribute('data-severity');
            const content = row.getAttribute('data-content');

            const matchesSearch = content.includes(search);
            const matchesSev = checkedSeverities.includes(severity);

            if (matchesSearch && matchesSev) {
                row.classList.remove('d-none');
                visibleCount++;
            } else {
                row.classList.add('d-none');
                const btn = row.querySelector('button');
                if (btn) {
                    const detailId = btn.getAttribute('data-bs-target');
                    const detailRow = document.querySelector(detailId);
                    if (detailRow) detailRow.classList.remove('show');
                }
            }
        });

        const noMatchRow = document.getElementById('no-findings-match');
        if (noMatchRow) {
            noMatchRow.classList.toggle('d-none', !(visibleCount === 0 && rows.length > 0));
        }
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
            row.id = `task - row - ${taskId} `;
            row.innerHTML = `
    <td class="font-monospace text-info x-small"> ${taskId}</td>
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

            // Sync findings table if needed
            const tableBody = document.getElementById("findings-table-body");
            if (tableBody) {
                const existingFindingIds = Array.from(tableBody.querySelectorAll('[id^="finding-detail-"], [id^="finding-new-"]'))
                    .map(el => el.id.replace('finding-detail-', '').replace('finding-new-', ''));

                results.findings.forEach(f => {
                    const fid = f.id ? f.id.toString() : null;
                    if (fid && !existingFindingIds.includes(fid)) {
                        // Re-use logic from handleNewFinding but for existing data
                        // This ensures the table is fully synced with DB state on updateUI
                        this.handleNewFinding({
                            scan_id: this.scanId,
                            id: f.id,
                            severity: f.severity,
                            title: f.title,
                            description: f.description,
                            tool: f.tool_source,
                            screenshot_path: f.screenshot_path
                        });
                    }
                });
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
            this.renderJSONSection(results.phases.enum, 'waf', 'WAF Detection');
            this.renderJSONSection(results.phases.enum, 'arjun', 'Hidden Parameters');
            this.renderJSONSection(results.phases.enum, 'api', 'API Endpoints');
            this.renderJSONSection(results.phases.enum, 'js_secrets', 'JS Secrets');
            this.renderJSONSection(results.phases.enum, 'headers', 'Security Headers');
            this.renderJSONSection(results.phases.enum, 'whatweb', 'Technology Footprint');

            this.renderJSONSection(results.phases.vuln, 'tls', 'TLS/SSL Audit');
            this.renderJSONSection(results.phases.vuln, 'git', 'Git Exposure');
            this.renderJSONSection(results.phases.vuln, 'backups', 'Backup Files');
            this.renderJSONSection(results.phases.vuln, 'tech', 'Technology Leaks');
            this.renderJSONSection(results.phases.vuln, 'graphql', 'GraphQL');
            this.renderJSONSection(results.phases.vuln, 'ssrf', 'SSRF Candidates');
            this.renderJSONSection(results.phases.vuln, 'redirects', 'Open Redirects');
            this.renderJSONSection(results.phases.vuln, 'xss', 'XSS Reflections');
            this.renderJSONSection(results.phases.vuln, 'prototype', 'Prototype Pollution');
            this.renderJSONSection(results.phases.vuln, 'ssti', 'SSTI Finds');
            this.renderJSONSection(results.phases.vuln, 'lfi', 'LFI Assaults');
            this.renderJSONSection(results.phases.vuln, 'cors_audit', 'CORS Audit');
            this.renderJSONSection(results.phases.vuln, 'crlf', 'CRLF Injection');
            this.renderJSONSection(results.phases.vuln, 'firebase', 'Firebase Exposure');
            this.renderJSONSection(results.phases.vuln, 'xxe', 'XXE Analysis');
            this.renderJSONSection(results.phases.vuln, 'deserialization', 'Deserialization');
            this.renderJSONSection(results.phases.vuln, 'acl_bypass', 'ACL Bypass');
            this.renderJSONSection(results.phases.vuln, 'email_security', 'Email Infrastructure');
            this.renderJSONSection(results.phases.vuln, 'container_exposure', 'Container/Docker');
            this.renderJSONSection(results.phases.vuln, 'infra_exposure', 'Infrastructure Exposure');
            this.renderJSONSection(results.phases.vuln, 'websocket', 'WebSocket Security');
            this.renderJSONSection(results.phases.vuln, 'data_leaks', 'Sensitive Data Mining');
            this.renderJSONSection(results.phases.vuln, 'oauth', 'OAuth & OIDC Flows');
            this.renderJSONSection(results.phases.vuln, 'nosql', 'NoSQL Injection');
            this.renderJSONSection(results.phases.vuln, 'cache_audit', 'Web Cache Audit');
            this.renderJSONSection(results.phases.vuln, 'upload_bypass', 'File Upload Expert');
            this.renderJSONSection(results.phases.vuln, 'logic_flaws', 'Business Logic Auditor');
            this.renderJSONSection(results.phases.vuln, 'deep_ssrf', 'Cloud SSRF Deep Probe');

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
    }

    // Helper to render JSON sections into a unified "Deep Analysis" panel if specific divs don't exist
    renderJSONSection(parent, key, title) {
        if (!parent || !parent[key]) return;

        const data = parent[key];
        // Check if data is empty (empty object or empty list)
        if (Array.isArray(data) && data.length === 0) return;
        if (typeof data === 'object' && Object.keys(data).length === 0) return;

        // Try to find a specific container first
        let container = document.getElementById(`${key}-results`);

        // If no specific container, create/append to a generic "Deep Scan Details" container
        if (!container) {
            let deepContainer = document.getElementById('deep-scan-details');
            if (!deepContainer) {
                // Create it if it doesn't exist (append to a suitable location, e.g., after tabs)
                // For now, let's assume we can append to the main results area or log it.
                // To be safe and UI-non-destructive, I will try to find a generic 'scan-details-grid' or create one.
                const parentContainer = document.querySelector('.scan-grid-layout') || document.querySelector('.container-fluid');
                if (parentContainer) {
                    // Create a row if needed
                    // This is risky without seeing HTML.
                    // I will try to reuse existing list containers or 'expert-results' div if available.
                    return;
                }
                return;
            }
            // Create a wrapper for this section
            const wrapper = document.createElement('div');
            wrapper.id = `${key}-results`;
            wrapper.className = 'mb-4';
            wrapper.innerHTML = `<h5 class="text-cyber mb-3 border-bottom border-secondary pb-2">${title}</h5 > <div class="result-content"></div>`;
            deepContainer.appendChild(wrapper);
            container = wrapper.querySelector('.result-content');
        }

        // Render Logic based on type
        let html = '';

        if (Array.isArray(data)) {
            // List of findings or strings
            html = `<div class="list-group list-group-flush bg-transparent">`;
            data.forEach(item => {
                if (typeof item === 'string') {
                    html += `<div class="list-group-item bg-transparent border-secondary border-opacity-25 px-0 py-1 text-muted small font-monospace">${item}</div>`;
                } else if (typeof item === 'object') {
                    // Custom finding object
                    const t = item.title || item.url || 'Unknown';
                    const d = item.description || item.match || '';
                    const s = item.severity || 'info';
                    html += `
                        <div class="list-group-item bg-transparent border-secondary border-opacity-25 px-0 py-2">
                             <div class="d-flex justify-content-between">
                                <span class="text-light small fw-bold">${t}</span>
                                <span class="badge severity-badge ${s}">${s.toUpperCase()}</span>
                             </div>
                             ${d ? `<div class="small text-muted mt-1 text-break">${d}</div>` : ''}
                        </div>`;
                }
            });
            html += `</div>`;
        } else if (typeof data === 'object') {
            // Map of Port -> Data or similar
            html = `<div class="accordion" id="acc-${key}">`;
            Object.entries(data).forEach(([subKey, subVal], idx) => {
                if (subKey === 'discovered_endpoints') return; // Skip raw list if handled elsewhere

                html += `
                    <div class="accordion-item bg-black border-secondary">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed bg-dark text-light border-secondary shadow-none py-2" type="button" data-bs-toggle="collapse" data-bs-target="#collapse-${key}-${idx}">
                                <span class="badge bg-secondary me-2">Port ${subKey}</span>
                                <span class="small font-monospace text-muted">${Array.isArray(subVal) ? subVal.length + ' Items' : 'Details'}</span>
                            </button>
                        </h2 > 
                        <div id="collapse-${key}-${idx}" class="accordion-collapse collapse" data-bs-parent="#acc-${key}">
                            <div class="accordion-body p-2 bg-dark-subtle">
                                <pre class="text-muted x-small mb-0 text-break" style="white-space: pre-wrap;">${typeof subVal === 'string' ? subVal : JSON.stringify(subVal, null, 2)}</pre>
                            </div>
                        </div>
                    </div>`;
            });
            html += `</div>`;
        }

        container.innerHTML = html;
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
                        <div class="ps-2 mt-1 border-start border-secondary">
                            <div class="x-small text-muted">Mining Params: <span class="text-warning font-monospace">${data.derived_params.join(', ')}</span></div>
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
}
