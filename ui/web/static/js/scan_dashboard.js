/**
 * RedOps Scan Dashboard Controller
 * Handles real-time updates via Socket.IO and UI state management.
 */

const scanDashboardFindingsLoader = {
    resetRenderedFindings(dashboard) {
        const tableBody = document.getElementById("findings-table-body");
        if (tableBody) tableBody.innerHTML = "";

        const container = document.getElementById("findings-container");
        if (container) {
            const list = container.querySelector(".result-list");
            if (list) list.innerHTML = "";
        }

        dashboard.renderedFindingIds.clear();
    },

    async fetchAllPages(dashboard, limit, offset) {
        let currentOffset = offset;
        let total = 0;
        const allItems = [];

        while (true) {
            const response = await fetch(`/api/scans/${dashboard.scanId}/findings?limit=${limit}&offset=${currentOffset}`);
            if (!response.ok) throw new Error(`API Error: ${response.status}`);

            const data = await response.json();
            const pageItems = Array.isArray(data.items) ? data.items : [];

            total = Number.isFinite(data.total) ? data.total : allItems.length + pageItems.length;
            allItems.push(...pageItems);
            ScanDashboard.prototype.updateFindingsLoadState.call(
                dashboard,
                allItems.length,
                total,
                currentOffset + pageItems.length >= total ? "ready" : "loading"
            );

            if (pageItems.length === 0) break;

            currentOffset += pageItems.length;
            if (currentOffset >= total) break;
            if (pageItems.length < limit) break;
        }

        return { items: allItems, total };
    },

    replayPersistedFindings(dashboard, items) {
        [...items].reverse().forEach(item => {
            dashboard.handleNewFinding({
                scan_id: dashboard.scanId,
                ...item
            });
        });
    }
};

const scanDashboardFindingsIdentity = {
    resolveRenderId(finding) {
        return finding?.id_stable || finding?.id || `temp-${finding?.title}-${finding?.severity}-${finding?.tool}`;
    }
};

const scanDashboardFindingsSync = {
    syncClientFindings(findings) {
        if (typeof updateFindingsList !== 'function') return;
        if (!Array.isArray(findings) || findings.length === 0) return;
        updateFindingsList(findings);
    },

    syncClientFinding(finding) {
        if (!finding) return;
        this.syncClientFindings([finding]);
    },
};

const scanDashboardFindingsView = {
    resolveFindingDisplayState(dashboard, finding) {
        const ui = finding?._ui || {};
        const validationStatus = ui.validationStatus || dashboard.getFindingValidationStatus(finding);
        const resultState = ui.resultState || dashboard.getFindingResultState(finding);
        const primaryCommand = ui.primaryCommand || dashboard.getFindingPrimaryCommand(finding);
        const primaryUrl = ui.primaryUrl || dashboard.getFindingPrimaryUrl(finding);
        const hasProof = ui.hasEvidence === true;
        const isValidated = ui.isValidated === true || validationStatus === 'success' || ['validation', 'confirmed'].includes(resultState);

        return {
            validationStatus,
            resultState,
            primaryCommand,
            primaryUrl,
            hasProof,
            isValidated,
        };
    },

    buildDisplayText(dashboard, finding) {
        const severity = String(finding?.severity || 'info').toLowerCase();
        const title = finding?.title || 'Untitled finding';
        const tool = finding?.tool_source || finding?.tool || 'core';
        const description = finding?.description || '';
        const screenshotPath = finding?.screenshot_path || '';

        return {
            severity,
            severityLabel: severity.toUpperCase(),
            escapedTitle: dashboard.escapeHtml(title),
            escapedTool: dashboard.escapeHtml(tool),
            escapedDesc: dashboard.escapeHtml(description),
            escapedScreenshotPath: dashboard.escapeHtml(screenshotPath),
            confidenceLabel: String(finding?.confidence || 'med').toUpperCase().substring(0, 4),
            toolLabel: String(finding?.tool_source || 'CORE').toUpperCase(),
        };
    },

    buildDisplayModel(dashboard, finding) {
        const displayState = this.resolveFindingDisplayState(dashboard, finding);
        const displayText = this.buildDisplayText(dashboard, finding);

        return {
            ...displayText,
            ...displayState,
            escapedPrimaryUrl: dashboard.escapeHtml(displayState.primaryUrl),
        };
    },

    buildResultCardHtml(finding, display) {
        return `
            <div class="d-flex w-100 justify-content-between mb-2">
                <span class="badge severity-badge ${display.severity}">${display.severityLabel}</span>
                <span class="result-text fw-bold text-break">${display.escapedTitle}</span>
            </div>
            <div class="mt-1 small text-muted text-break">Source: ${display.escapedTool}</div>
            ${this.buildResultCardOptionalSectionsHtml(finding, display)}
        `;
    },

    buildResultCardOptionalSectionsHtml(finding, display) {
        let sectionsHtml = '';

        if (finding?.description) {
            sectionsHtml += `<div class="mt-1 small text-muted text-break overflow-auto" style="max-height: 200px; white-space: pre-wrap;">${display.escapedDesc}</div>`;
        }

        if (finding?.screenshot_path) {
            sectionsHtml += `
                <div class="mt-2 w-100">
                    <img src="/static/${display.escapedScreenshotPath}" class="img-fluid rounded border border-secondary shadow-sm screenshot-trigger" style="max-height: 150px; cursor: pointer;" title="Port ${display.escapedTitle}">
                </div>
            `;
        }

        return sectionsHtml;
    },

    buildTableRowStateIndicatorsHtml(display) {
        return `
            ${display.primaryCommand ? '<i class="fas fa-terminal text-warning extra-small" title="Validation Command Available"></i>' : ''}
            ${display.hasProof ? '<i class="fas fa-microscope text-info extra-small" title="Technical Evidence Available"></i>' : ''}
            ${display.isValidated ? '<span class="badge bg-success bg-opacity-25 text-success border border-success border-opacity-25 extra-small"><i class="fas fa-check-circle me-1"></i>VALIDATED</span>' : ''}
        `;
    },

    buildTableRowHtml(display) {
        const vectorHtml = display.primaryUrl
            ? `<div class="text-info text-truncate" title="${display.escapedPrimaryUrl}"><i class="fas fa-link me-1 opacity-50"></i>${display.escapedPrimaryUrl}</div>`
            : '<span class="text-muted opacity-25">N/A</span>';

        return `
            <td class="ps-3">
                <span class="badge-severity bg-${display.severity} w-100 text-center d-block rounded-1 py-1">
                    ${display.severityLabel}
                </span>
            </td>
            <td>
                <div class="d-flex align-items-center gap-2">
                    <div class="fw-bold text-light text-truncate" title="${display.escapedTitle}">${display.escapedTitle}</div>
                    ${this.buildTableRowStateIndicatorsHtml(display)}
                </div>
                <div class="text-muted extra-small text-truncate mt-1 opacity-50" style="max-width: 400px;">
                    ${display.escapedDesc.replace(/<[^>]*>/g, '')}
                </div>
            </td>
            <td class="font-monospace extra-small">
                ${vectorHtml}
            </td>
            <td class="text-center">
                <span class="badge bg-secondary bg-opacity-10 text-muted border border-secondary border-opacity-10 extra-small px-2">
                    ${display.confidenceLabel}
                </span>
            </td>
            <td>
                <span class="extra-small text-primary-emphasis fw-semibold bg-primary bg-opacity-10 px-2 py-1 rounded border border-primary border-opacity-10">
                    ${display.toolLabel}
                </span>
            </td>
            <td class="text-end pe-3">
                <i class="fas fa-chevron-right text-muted opacity-25 extra-small"></i>
            </td>
        `;
    }
};

const scanDashboardFindingsDom = {
    ensureResultList(documentRef, container) {
        let list = container.querySelector('.result-list');
        if (list) return list;

        list = documentRef.createElement('div');
        list.className = 'result-list';
        container.appendChild(list);
        return list;
    },

    prependResultCard(documentRef, container, cardHtml) {
        if (!container) return null;

        const empty = container.querySelector('.text-muted');
        if (empty && empty.innerText.includes('No findings')) empty.remove();

        const list = this.ensureResultList(documentRef, container);
        const div = documentRef.createElement('div');
        div.className = 'result-row flex-column align-items-start p-3 mb-2 bg-black border border-secondary rounded position-relative hover-highlight animate__animated animate__fadeInLeft';
        div.innerHTML = cardHtml;
        list.prepend(div);
        return div;
    },

    prependTableRow(documentRef, dashboard, fid, finding, display) {
        const tableBody = documentRef.getElementById('findings-table-body');
        if (!tableBody) return null;

        const emptyRow = documentRef.getElementById('findings-empty-state');
        if (emptyRow) emptyRow.remove();

        const rowId = `finding-row-${fid}`;
        if (documentRef.getElementById(rowId)) return null;

        const tr = documentRef.createElement('tr');
        tr.id = rowId;
        tr.className = 'finding-row cursor-pointer animate__animated animate__fadeIn';
        dashboard.getFindingsContract().applyRowDataset(tr, finding);
        tr.onclick = () => {
            if (typeof showFindingDetail === 'function') {
                showFindingDetail(fid);
            }
        };
        tr.innerHTML = scanDashboardFindingsView.buildTableRowHtml(display);
        tableBody.prepend(tr);

        return tr;
    }
};

const scanDashboardFindingsFlow = {
    prepareIncomingFinding(dashboard, data, options = {}) {
        const finding = options.normalized === true ? data : dashboard.normalizeFindingRecord(data);
        const fid = scanDashboardFindingsIdentity.resolveRenderId(finding);

        if (dashboard.renderedFindingIds.has(fid)) {
            return null;
        }

        dashboard.renderedFindingIds.add(fid);
        return { fid, finding };
    },

    renderFindingBody(documentRef, dashboard, fid, finding, display) {
        const container = documentRef.getElementById('findings-container');

        scanDashboardFindingsDom.prependResultCard(
            documentRef,
            container,
            scanDashboardFindingsView.buildResultCardHtml(finding, display)
        );

        if (!container) {
            return { container: null, tableRow: null };
        }

        return {
            container,
            tableRow: scanDashboardFindingsDom.prependTableRow(documentRef, dashboard, fid, finding, display),
        };
    },

    applyRenderedFindingEffects(dashboard, finding) {
        if (finding.screenshot_path) {
            dashboard.addToGallery(finding);
        }

        dashboard.updateRiskCounters(finding.severity);
        dashboard.updateIndicators(finding);
    },

    renderFinding(documentRef, dashboard, fid, finding) {
        const display = scanDashboardFindingsView.buildDisplayModel(dashboard, finding);
        const renderedBody = this.renderFindingBody(documentRef, dashboard, fid, finding, display);

        if (!renderedBody.container) {
            return { display, ...renderedBody };
        }

        this.applyRenderedFindingEffects(dashboard, finding);
        return {
            display,
            ...renderedBody,
        };
    },

    ingestStructuredFindings(dashboard, findings) {
        if (!Array.isArray(findings) || findings.length === 0) return [];

        const normalizedFindings = findings
            .map((finding) => dashboard.normalizeFindingRecord(finding))
            .filter((finding) => finding && typeof finding === 'object');
        const handleIncomingFinding = typeof dashboard.handleNewFinding === 'function'
            ? dashboard.handleNewFinding
            : ScanDashboard.prototype.handleNewFinding;
        if (normalizedFindings.length === 0) return [];
        scanDashboardFindingsSync.syncClientFindings(normalizedFindings);

        normalizedFindings.forEach((finding) => {
            handleIncomingFinding.call(
                dashboard,
                {
                    scan_id: dashboard.scanId,
                    ...finding,
                    tool: finding.tool_source || finding.tool,
                },
                { normalized: true, skipClientSync: true }
            );
        });

        return normalizedFindings;
    },
};

const scanDashboardSectionRendering = {
    humanRendererRegistry: Object.freeze({
        tls: 'renderTLSHuman',
        waf: 'renderWAFHuman',
        headers: 'renderHeadersHuman',
        whatweb: 'renderTechHuman',
        arjun: 'renderParamsHuman',
        params: 'renderParamsHuman',
        katana: 'renderCrawlerHuman',
        js_secrets: 'renderSecretsHuman',
        secrets: 'renderSecretsHuman',
        cloud: 'renderCloudHuman',
        dorks: 'renderDorksHuman',
        origin_ips: 'renderOriginHuman',
        emails: 'renderEmailsHuman',
        github: 'renderGithubHuman',
        records: 'renderDNSRecordsHuman',
        subdomains: 'renderSubdomainsHuman',
        api: 'renderApiTreeHuman',
    }),

    hasRenderableData(data) {
        if (!data) return false;
        if (Array.isArray(data)) return data.length > 0;
        if (typeof data === 'object') return Object.keys(data).length > 0;
        return true;
    },

    resolveContainer(documentRef, key) {
        const existing = documentRef.getElementById(`${key}-results`);
        if (!existing) return null;
        return existing.querySelector?.('.result-content') || existing;
    },

    ensureContainer(documentRef, key, title) {
        let container = this.resolveContainer(documentRef, key);
        if (container) return container;

        const deepContainer = documentRef.getElementById('deep-scan-details');
        if (!deepContainer) return null;

        const placeholder = documentRef.getElementById('deep-scan-placeholder');
        if (placeholder) placeholder.style.display = 'none';

        const wrapper = documentRef.createElement('div');
        wrapper.className = 'col-lg-6 mb-4 animate__animated animate__fadeIn';
        wrapper.innerHTML = `
            <div class="card h-100 glass-panel border-secondary border-opacity-25">
                <div class="card-header glass-header d-flex justify-content-between align-items-center">
                    <span class="text-cyber small fw-bold text-uppercase"><i class="fas fa-microscope me-2 text-primary"></i>${title}</span>
                    <span class="badge bg-dark border border-secondary text-muted x-small">${key.toUpperCase()}</span>
                </div>
                <div class="card-body result-content p-3" id="${key}-results" style="max-height: 400px; overflow-y: auto;"></div>
            </div>`;
        deepContainer.appendChild(wrapper);
        return this.resolveContainer(documentRef, key);
    },

    renderStructuredFallback(dashboard, data) {
        let html = '<div class="list-group list-group-flush bg-transparent w-100">';
        if (Array.isArray(data)) {
            data.slice(0, 100).forEach(item => {
                const content = typeof item === 'object' ? JSON.stringify(item) : item;
                html += `<div class="list-group-item bg-transparent border-secondary border-opacity-10 py-1 font-monospace x-small text-muted text-break">${dashboard.escapeHtml(content)}</div>`;
            });
            if (data.length > 100) html += `<div class="p-2 x-small text-center text-muted">+ ${data.length - 100} more...</div>`;
        } else {
            Object.entries(data).forEach(([k, v]) => {
                html += `
                    <div class="mb-2 w-100">
                        <div class="x-small text-cyber font-monospace text-uppercase fw-bold">${k}</div>
                        <pre class="bg-black p-2 rounded border border-secondary border-opacity-10 x-small text-muted mb-0 overflow-auto" style="max-height: 150px;">${dashboard.escapeHtml(typeof v === 'object' ? JSON.stringify(v, null, 2) : v)}</pre>
                    </div>`;
            });
        }
        html += '</div>';
        return html;
    },

    renderPortMappedArrayFallback(dashboard, data) {
        const keys = Object.keys(data || {});
        if (!keys.length || !keys.every(k => !isNaN(k) && Array.isArray(data[k]))) {
            return null;
        }

        let html = '<div class="row g-2 w-100">';
        for (const [port, items] of Object.entries(data)) {
            html += `<div class="col-12 mb-2"><div class="badge bg-cyber x-small mb-1 text-dark">PORT ${port}</div>${this.renderGenericVulnList(dashboard, items)}</div>`;
        }
        html += '</div>';
        return html;
    },

    renderGenericVulnList(dashboard, data) {
        if (!Array.isArray(data)) return '';
        let html = '<div class="list-group list-group-flush bg-transparent w-100">';
        data.slice(0, 50).forEach(item => {
            if (!item || typeof item !== 'object') {
                html += `<div class="list-group-item bg-transparent border-secondary border-opacity-10 py-1 font-monospace x-small text-muted text-break">${dashboard.escapeHtml(item)}</div>`;
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
                    <span class="text-light fw-bold small text-truncate" style="max-width: 80%;">${dashboard.escapeHtml(title)}</span>
                    <span class="badge bg-${sevClass} x-small bg-opacity-75">${severity.toUpperCase()}</span>
                </div>
                <div class="d-flex gap-2 mb-2">
                    <span class="badge bg-dark border border-secondary text-muted x-small">${dashboard.escapeHtml(tool)}</span>
                </div>
                ${desc ? `<div class="x-small text-muted mb-2 lh-sm overflow-hidden" style="max-height: 60px;">${dashboard.escapeHtml(desc)}</div>` : ''}
                ${item.url || item.endpoint ? `<div class="x-small text-cyber font-monospace text-truncate w-100 d-block"><i class="fas fa-link me-1 opacity-50"></i><a href="${dashboard.escapeHtml(item.url || item.endpoint)}" target="_blank" class="text-cyber text-decoration-none">${dashboard.escapeHtml(item.url || item.endpoint)}</a></div>` : ''}
                ${item.match || item.evidence ? `<div class="bg-dark bg-opacity-50 p-1 border border-secondary border-opacity-10 rounded mt-2 x-small text-warning font-monospace text-truncate"><i class="fas fa-search me-1"></i>${dashboard.escapeHtml(item.match || item.evidence)}</div>` : ''}
                ${item.repro_command ? `<div class="bg-black p-1 border border-secondary border-opacity-25 rounded mt-2 x-small text-muted font-monospace text-truncate"><i class="fas fa-terminal me-1"></i>${dashboard.escapeHtml(item.repro_command)}</div>` : ''}
            </div>`;
        });
        if (data.length > 50) html += `<div class="p-2 x-small text-center text-muted">+ ${data.length - 50} more...</div>`;
        html += '</div>';
        return html;
    },

    renderSectionHuman(dashboard, key, data) {
        const rendererName = this.humanRendererRegistry[key];
        if (!rendererName || typeof dashboard[rendererName] !== 'function') {
            return null;
        }

        try {
            return dashboard[rendererName](data);
        } catch (e) {
            console.error(`Human renderer failed for ${key}:`, e);
            return null;
        }
    },

    renderJSONSection(documentRef, dashboard, parent, key, title) {
        if (!parent || !Object.prototype.hasOwnProperty.call(parent, key)) return;

        const data = parent[key];
        if (!this.hasRenderableData(data)) return;

        const container = this.ensureContainer(documentRef, key, title);
        if (!container) return;

        const humanHtml = this.renderSectionHuman(dashboard, key, data);
        if (humanHtml) {
            container.innerHTML = humanHtml;
            return;
        }

        if (Array.isArray(data) && data.length > 0 && typeof data[0] === 'object' && !Array.isArray(data[0])) {
            container.innerHTML = this.renderGenericVulnList(dashboard, data);
            return;
        }

        if (typeof data === 'object' && !Array.isArray(data)) {
            const portMappedHtml = this.renderPortMappedArrayFallback(dashboard, data);
            if (portMappedHtml) {
                container.innerHTML = portMappedHtml;
                return;
            }
        }

        container.innerHTML = this.renderStructuredFallback(dashboard, data);
    },
};

const scanDashboardResultsView = {
    getStructuredFindings(results) {
        return Array.isArray(results?.findings) ? results.findings : [];
    },

    countAssets(results) {
        const ports = results?.phases?.recon?.open_ports?.length || 0;
        const subs = results?.phases?.dns?.subdomains?.length || 0;
        const clouds = results?.phases?.osint?.cloud?.length || 0;
        return ports + subs + clouds;
    },

    countEndpoints(results) {
        let totalEndpoints = results?.phases?.dirbusting?.ffuf?.endpoints?.length || 0;
        totalEndpoints += results?.phases?.enum?.api?.endpoints?.length || 0;
        totalEndpoints += results?.phases?.enum?.api?.discovered_endpoints?.length || 0;

        if (results?.phases?.enum?.katana) {
            Object.values(results.phases.enum.katana).forEach((urls) => {
                if (Array.isArray(urls)) totalEndpoints += urls.length;
            });
        }

        return totalEndpoints;
    },

    summarizeFindingSeverities(findings) {
        return findings.reduce((summary, finding) => {
            const severity = String(finding?.severity || 'info').toLowerCase();
            if (severity === 'critical') {
                summary.critical += 1;
                summary.highRisk += 1;
            } else if (severity === 'high') {
                summary.high += 1;
                summary.highRisk += 1;
            }
            return summary;
        }, {
            highRisk: 0,
            critical: 0,
            high: 0,
        });
    },
};

const scanDashboardUIRefresh = {
    syncReconOverview(documentRef, results) {
        const statPorts = documentRef.getElementById('stat-open-ports');
        const portContainer = documentRef.getElementById('port-badges-container');
        const ports = Array.isArray(results?.phases?.recon?.open_ports) ? results.phases.recon.open_ports : [];

        if (statPorts) statPorts.innerText = ports.length;

        if (!portContainer) return;
        if (ports.length === 0) {
            portContainer.innerHTML = `
    <div class="text-center text-muted small py-4">
        <i class="fas fa-network-wired opacity-50 me-2"></i>No open ports discovered yet.
    </div> `;
            return;
        }

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
    },

    syncFindingSummary(documentRef, results, structuredFindings) {
        const statFindings = documentRef.getElementById('stat-findings');
        if (statFindings) statFindings.innerText = structuredFindings.length;

        const severitySummary = scanDashboardResultsView.summarizeFindingSeverities(structuredFindings);
        const statAssets = documentRef.getElementById('stat-assets');
        const statEndpoints = documentRef.getElementById('stat-endpoints');
        const statHighRisk = documentRef.getElementById('stat-high-risk');
        const statCritical = documentRef.getElementById('stat-critical');
        const statHigh = documentRef.getElementById('stat-high');

        if (statHighRisk) statHighRisk.innerText = severitySummary.highRisk;
        if (statCritical) statCritical.innerText = severitySummary.critical;
        if (statHigh) statHigh.innerText = severitySummary.high;
        if (statAssets) statAssets.innerText = scanDashboardResultsView.countAssets(results);
        if (statEndpoints) statEndpoints.innerText = scanDashboardResultsView.countEndpoints(results);

        if (!structuredFindings.length) return;
    },

    buildDiscoveryMap(results) {
        return {
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
    },

    restoreDiscoveryStates(dashboard, results) {
        Object.entries(this.buildDiscoveryMap(results)).forEach(([id, discovered]) => {
            dashboard.activateDiscovery(id, discovered);
        });
    },

    renderDnsResults(documentRef, results) {
        if (!results.phases?.dns?.subdomains) return;

        const dnsDiv = documentRef.querySelector("#dns-results");
        if (!dnsDiv) return;

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
    },

    renderReconMatrix(documentRef, dashboard, results) {
        const matrixBody = documentRef.querySelector("#recon-matrix-body");
        if (!matrixBody || !results.phases?.recon?.open_ports) return;

        let html = "";
        const ports = [...results.phases.recon.open_ports].sort((a, b) => (b.priority_score || 0) - (a.priority_score || 0));

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
                        ${isWeb ? `<a href="${proto}://${dashboard.targetIdentifier}:${port.port}" target="_blank" class="btn btn-xs btn-outline-info"><i class="fas fa-external-link-alt"></i></a>` : ''}
                    </td>
                </tr> `;
        });
        matrixBody.innerHTML = html;
    },

    renderVisualReconGallery(documentRef, results) {
        const gallery = documentRef.querySelector("#visual-recon-gallery");
        if (!gallery || !results.phases?.recon?.open_ports) return;

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
    },

    renderIntelResults(documentRef, results) {
        if (!results.phases?.intel) return;

        const intelDiv = documentRef.querySelector("#intel-results");
        if (!intelDiv) return;

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
    },

    renderWhatwebResults(documentRef, results) {
        if (!results.phases?.enum?.whatweb) return;

        const wwDiv = documentRef.querySelector("#whatweb-results");
        if (!wwDiv) return;

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
    },

    renderKatanaResults(documentRef, results) {
        if (!results.phases?.enum?.katana) return;

        const katDiv = documentRef.querySelector("#katana-results");
        if (!katDiv) return;

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
    },

    renderNucleiResults(documentRef, results) {
        if (!results.phases?.vuln?.nuclei) return;

        const nucDiv = documentRef.querySelector("#nuclei-results");
        if (!nucDiv) return;

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
    },

    renderFfufResults(documentRef, results) {
        if (!results.phases?.dirbusting?.ffuf) return;

        const ffufDiv = documentRef.querySelector("#ffuf-results");
        if (!ffufDiv) return;

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
    },

    renderStructuredSections(dashboard, results) {
        if (!results.phases?.vuln) return;

        this.renderJsonBackedSections(dashboard, results);
        this.syncWordpressPanels(results);
    },

    renderJsonBackedSections(dashboard, results) {
        const knownEnumTitles = {
            waf: 'WAF Detection', arjun: 'Hidden Parameters', api: 'API Endpoints',
            js_secrets: 'JS Secrets', headers: 'Security Headers', whatweb: 'Technology Footprint'
        };
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

        dashboard.renderJSONSection(results.phases.osint, 'cloud', 'Cloud Assets');
        dashboard.renderJSONSection(results.phases.osint, 'dorks', 'Google Hacking');
        dashboard.renderJSONSection(results.phases.osint, 'origin_ips', 'Origin Unmasking');
        dashboard.renderJSONSection(results.phases.osint, 'emails', 'Email Discovery');
        dashboard.renderJSONSection(results.phases.osint, 'github', 'GitHub Leaks');
        dashboard.renderJSONSection(results.phases.dns, 'subdomains', 'Discovered Subdomains');
        dashboard.renderJSONSection(results.phases.dns, 'records', 'DNS Records');

        for (const key of Object.keys(results.phases.enum || {})) {
            if (['derived', 'targets', 'seed_meta', 'normalized', 'injection_points', 'attack_profile', 'mutation_strategy', 'katana'].includes(key)) continue;

            let title = knownEnumTitles[key];
            if (!title) {
                title = key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
            }
            dashboard.renderJSONSection(results.phases.enum, key, title);
        }

        for (const key of Object.keys(results.phases.vuln || {})) {
            if (['wordpress', 'nuclei'].includes(key)) continue;

            let title = knownVulnTitles[key];
            if (!title) {
                title = key.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');
            }
            dashboard.renderJSONSection(results.phases.vuln, key, title);
        }
    },

    syncWordpressPanels(results) {
        if (!results.phases?.vuln?.wordpress) return;

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
    },

    renderPhaseSections(documentRef, dashboard, results) {
        if (!results.phases) return;

        this.renderDnsResults(documentRef, results);
        this.renderReconMatrix(documentRef, dashboard, results);
        this.renderVisualReconGallery(documentRef, results);
        this.renderIntelResults(documentRef, results);
        this.renderWhatwebResults(documentRef, results);
        this.renderKatanaResults(documentRef, results);
        this.renderNucleiResults(documentRef, results);
        this.renderFfufResults(documentRef, results);
        this.renderStructuredSections(dashboard, results);
    },

    refreshGraph(results) {
        if ((results.findings || results.phases) && typeof initGraphData === 'function') {
            setTimeout(() => initGraphData(), 200);
        }
    }
};

const scanDashboardAuditJourney = {
    countEnumeratedEndpoints(phases) {
        const katana = (phases?.enum?.katana && typeof phases.enum.katana === 'object') ? phases.enum.katana : {};
        const api = (phases?.enum?.api && typeof phases.enum.api === 'object') ? phases.enum.api : {};
        let enumEndpointCount = 0;

        Object.values(katana).forEach(urls => {
            if (Array.isArray(urls)) enumEndpointCount += urls.length;
        });

        if (Array.isArray(api.endpoints)) enumEndpointCount += api.endpoints.length;
        if (Array.isArray(api.discovered_endpoints)) enumEndpointCount += api.discovered_endpoints.length;
        return enumEndpointCount;
    },

    inspectFinding(dashboard, finding) {
        const state = dashboard.getFindingResultState(finding);
        const validationStatus = String(dashboard.getFindingValidationStatus(finding) || '').toLowerCase();
        const severity = String(finding?.severity || 'info').toLowerCase();
        const command = dashboard.getFindingPrimaryCommand(finding);

        return {
            state,
            validationStatus,
            isHighSeverity: severity === 'critical' || severity === 'high',
            hasProof: dashboard.hasMeaningfulProof(finding),
            hasCommand: dashboard.isMeaningfulValue(command),
            isValidated: validationStatus === 'success' || ['validation', 'confirmed'].includes(state),
            isCorrelated:
                String(finding?.category || '').toLowerCase() === 'attack_chain' ||
                Boolean(finding?.chain_metadata && (finding.chain_metadata.related_findings || finding.chain_metadata.attack_path_summary)),
        };
    },

    summarizeFindings(dashboard, findings) {
        return findings.reduce((summary, finding) => {
            const findingState = this.inspectFinding(dashboard, finding);

            if (findingState.isValidated) {
                summary.validated += 1;
            }
            if (findingState.isCorrelated) {
                summary.correlated += 1;
            }
            if (findingState.isHighSeverity && !findingState.hasProof) {
                summary.missingProof += 1;
            }
            if (findingState.isHighSeverity && !findingState.hasCommand) {
                summary.missingCommand += 1;
            }
            return summary;
        }, {
            validated: 0,
            correlated: 0,
            missingProof: 0,
            missingCommand: 0,
        });
    },

    deriveJourneyInputs(results, targetIdentifier) {
        const phases = results?.phases || {};
        const findings = Array.isArray(results?.findings) ? results.findings : [];
        const attackPlan = Array.isArray(results?.attack_plan) ? results.attack_plan : [];

        return {
            phases,
            findings,
            attackPlan,
            progressPhase: String(results?.progress?.current_phase || '').toLowerCase(),
            status: String(results?.status || '').toLowerCase(),
            target: String(results?.target || targetIdentifier || ''),
            reconPorts: Array.isArray(phases?.recon?.open_ports) ? phases.recon.open_ports : [],
            dnsSubs: Array.isArray(phases?.dns?.subdomains) ? phases.dns.subdomains : [],
            enumEndpointCount: this.countEnumeratedEndpoints(phases),
        };
    },

    deriveStageMap({ scopeReady, reconReady, enumReady, detectionReady, validationReady, correlationReady, reportingReady, closureReady, progressPhase, status }) {
        const validationVisualInProgress = status === 'completed' && detectionReady && !validationReady;
        const correlationVisualInProgress = status === 'completed' && detectionReady && !correlationReady;

        return {
            cadrage: scopeReady ? 'done' : 'pending',
            recon: reconReady ? 'done' : (progressPhase.includes('recon') ? 'in-progress' : 'pending'),
            enum: enumReady ? 'done' : (progressPhase.includes('enum') ? 'in-progress' : 'pending'),
            detection: detectionReady ? 'done' : (progressPhase.includes('vuln') ? 'in-progress' : 'pending'),
            validation: validationReady ? 'done' : ((validationVisualInProgress || progressPhase.includes('validation')) ? 'in-progress' : 'pending'),
            correlation: correlationReady ? 'done' : ((correlationVisualInProgress || progressPhase.includes('correlation')) ? 'in-progress' : 'pending'),
            reporting: reportingReady ? 'done' : (progressPhase.includes('report') ? 'in-progress' : 'pending'),
            closure: closureReady ? 'done' : (status === 'completed' ? 'in-progress' : 'pending')
        };
    },

    updateGateText(node, value, isAlert) {
        if (!node) return;
        node.innerText = String(value);
        if (typeof isAlert === 'boolean') {
            node.classList.toggle('text-danger', isAlert);
            node.classList.toggle('text-success', !isAlert);
        }
    }
};

const scanDashboardSocketEvents = [
    ['new_log', 'handleNewLog'],
    ['new_finding', 'handleNewFinding'],
    ['new_suggestion', 'handleNewSuggestion'],
    ['new_loot', 'handleNewLoot'],
    ['progress_update', 'handleProgressUpdate'],
    ['module_status', 'handleModuleStatus'],
    ['pipeline_event', 'handlePipelineEvent'],
];

const scanDashboardLogStream = {
    getLevelClass(level) {
        if (level === 'SUCCESS') return 'text-success';
        if (level === 'WARN') return 'text-warning';
        if (level === 'ERROR') return 'text-danger';
        return 'text-secondary';
    },

    appendLogEntry(documentRef, data) {
        const consoleDiv = documentRef.querySelector(".log-console");
        if (!consoleDiv) return false;

        const legacyEmptyMsg = consoleDiv.querySelector(".text-muted");
        if (legacyEmptyMsg && legacyEmptyMsg.innerText.includes("No logs")) legacyEmptyMsg.remove();

        const newEmptyMsg = consoleDiv.querySelector("#timeline-empty-msg");
        if (newEmptyMsg) newEmptyMsg.remove();

        const div = documentRef.createElement("div");
        div.className = "px-3 py-1 border-bottom border-dark hover-bg-dark animate__animated animate__fadeIn";
        div.innerHTML = `<span class="text-secondary opacity-50">[${data.timestamp}]</span> <span class="${scanDashboardLogStream.getLevelClass(data.level)} fw-bold mx-2">[${data.level}]</span> <span class="text-light">${data.message}</span>`;
        consoleDiv.appendChild(div);
        consoleDiv.scrollTop = consoleDiv.scrollHeight;
        return true;
    },

    activateTriggeredDiscoveries(dashboard, data) {
        Object.entries(dashboard.logTriggers || {}).forEach(([trigger, id]) => {
            if (data.message.includes(trigger)) {
                dashboard.activateDiscovery(id, data.level === 'SUCCESS');
            }
        });
    },

    syncScanFinishedState(documentRef, toggleScanToast) {
        const sp = documentRef.querySelector('.status-pill');
        if (sp) {
            sp.innerText = 'finished';
            sp.className = 'badge status-pill status-finished ms-2';
        }

        toggleScanToast(false);

        documentRef.querySelectorAll('.discovery-btn').forEach(btn => {
            btn.classList.remove('active');
            btn.classList.add('discovered');
        });
    }
};

const scanDashboardModuleStatus = {
    getStatusBadge(status) {
        const normalizedStatus = String(status || '').toLowerCase();
        if (normalizedStatus === 'running') return '<span class="badge bg-primary bg-opacity-10 text-primary border border-primary x-small">RUNNING</span>';
        if (normalizedStatus === 'executed' || normalizedStatus === 'done') return '<span class="badge bg-success bg-opacity-10 text-success border border-success x-small">DONE</span>';
        if (normalizedStatus === 'skipped') return '<span class="badge bg-secondary bg-opacity-10 text-secondary border border-secondary x-small">SKIP</span>';
        if (normalizedStatus === 'failed' || normalizedStatus === 'error') return '<span class="badge bg-danger bg-opacity-10 text-danger border border-danger x-small">FAIL</span>';
        return `<span class="badge bg-dark border border-secondary text-muted x-small">${String(status || '').toUpperCase()}</span>`;
    },

    buildRowHtml(data) {
        return `
            <td class="font-monospace text-info small">${data.module}</td>
            <td class="font-monospace text-muted small">${data.port}</td>
            <td>${scanDashboardModuleStatus.getStatusBadge(data.status)}</td>
            <td class="text-end font-monospace small">${data.artifacts || 0}</td>
            <td class="text-muted x-small">${data.reason || '-'}</td>
        `;
    },

    syncRow(documentRef, tableBody, data) {
        if (!tableBody) return null;

        const rowId = `mod-row-${data.module}-${data.port}`;
        let row = documentRef.getElementById(rowId);
        const noModuleRow = documentRef.getElementById("no-modules-row");
        if (noModuleRow) noModuleRow.remove();

        const innerHTML = scanDashboardModuleStatus.buildRowHtml(data);
        const existed = Boolean(row);

        if (row) {
            row.innerHTML = innerHTML;
        } else {
            row = documentRef.createElement("tr");
            row.id = rowId;
            row.innerHTML = innerHTML;
            tableBody.prepend(row);
        }

        return { row, existed };
    },

    updateActiveCount(documentRef) {
        const activeCount = documentRef.querySelectorAll("#modules-table .text-primary").length;
        const countBadge = documentRef.getElementById("module-count");
        if (countBadge) countBadge.innerText = `${activeCount} Active`;
    }
};

const scanDashboardPipelineTimeline = {
    resolveTimeString(ts) {
        const rawTs = String(ts || '');
        if (rawTs.includes('T')) return rawTs.split('T')[1].split('.')[0];
        return new Date().toLocaleTimeString();
    },

    buildEventNode(documentRef, data) {
        const div = documentRef.createElement("div");
        div.className = "d-flex justify-content-between align-items-start border-bottom border-dark pb-1 animate__animated animate__fadeInDown";
        div.innerHTML = `
            <div>
                <span class="text-muted x-small font-monospace">${scanDashboardPipelineTimeline.resolveTimeString(data.ts)}</span>
                <span class="badge bg-dark border border-secondary text-light x-small ms-1">${data.module}</span>
                <span class="text-secondary small ms-1">${data.type}</span>
            </div>
            ${data.level === 'ERROR' ? '<span class="text-danger x-small fw-bold">ERROR</span>' : ''}
        `;
        return div;
    },

    appendEvent(documentRef, container, data, limit = 50) {
        if (!container) return;

        const noTimelineRow = documentRef.getElementById("no-timeline-row");
        if (noTimelineRow) noTimelineRow.remove();

        container.prepend(scanDashboardPipelineTimeline.buildEventNode(documentRef, data));

        if (container.children.length > limit && container.lastElementChild) {
            container.lastElementChild.remove();
        }
    }
};

const scanDashboardIndicators = {
    indicatorKeywords: {
        xss: ['xss'],
        lfi: ['lfi'],
        sql: ['sql', 'injection'],
        api: ['api', 'swagger', 'openapi', 'expert'],
        cms: ['cms', 'wordpress', 'drupal', 'joomla'],
        secret: ['secret', 'token', 'key']
    },

    getMatchedKeys(data) {
        const titleLower = String(data?.title || '').toLowerCase();
        const toolLower = String(data?.tool || '').toLowerCase();

        return Object.entries(scanDashboardIndicators.indicatorKeywords)
            .filter(([, keywords]) => keywords.some((keyword) => titleLower.includes(keyword) || toolLower.includes(keyword)))
            .map(([key]) => key);
    },

    updateIndicatorCard(indicatorCard) {
        if (!indicatorCard) return;

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
    },

    sync(documentRef, data) {
        scanDashboardIndicators.getMatchedKeys(data).forEach((key) => {
            scanDashboardIndicators.updateIndicatorCard(documentRef.querySelector(`.vuln-indicator-${key}`));
        });
    }
};

const scanDashboardLootStream = {
    formatTimestamp(now = new Date()) {
        return now.getHours().toString().padStart(2, '0') + ":" + now.getMinutes().toString().padStart(2, '0');
    },

    incrementCounters(documentRef) {
        documentRef.querySelectorAll('.loot-counter-val').forEach(counter => {
            let current = parseInt(counter.innerText) || 0;
            counter.innerText = current + 1;
            counter.classList.add('animate__animated', 'animate__bounceIn', 'text-success');
            setTimeout(() => counter.classList.remove('animate__animated', 'animate__bounceIn'), 1000);
        });
    },

    ensureVaultList(documentRef) {
        return documentRef.querySelector("#loot-vault-container .list-group");
    },

    appendVaultEntry(documentRef, vault, data, escapeHtml, timeText) {
        if (!vault) return false;

        const empty = vault.querySelector(".text-center");
        if (empty) empty.remove();

        const div = documentRef.createElement("div");
        div.className = "list-group-item bg-transparent border-secondary border-opacity-25 py-2 px-3 animate__animated animate__fadeInDown";
        div.innerHTML = `
            <div class="d-flex justify-content-between align-items-center">
                <span class="badge bg-black border border-success text-success x-small text-uppercase">${escapeHtml(data.type)}</span>
                <span class="x-small text-muted font-monospace">${timeText}</span>
            </div>
            <div class="mt-1 small font-monospace text-light text-break">${escapeHtml(data.content)}</div>
            ${data.context ? `<div class="x-small text-muted mt-1 italic"><i class="fas fa-info-circle me-1"></i>${escapeHtml(data.context)}</div>` : ''}
        `;
        vault.prepend(div);
        return true;
    }
};

const scanDashboardProgressView = {
    phaseToDiscovery: {
        recon: 'ports', dns: 'dns', osint: 'cloud', cloud: 'cloud',
        waf: 'waf', crawl: 'crawl', katana: 'crawl', arjun: 'params',
        params: 'params', ffuf: 'fuzz', dirbusting: 'fuzz',
        api: 'api', secrets: 'secrets', vuln: 'vulns', nuclei: 'vulns',
        intel: 'intel', historic: 'historic', wayback: 'historic',
        spring: 'apps', firebase: 'apps', actuator: 'apps', apps: 'apps'
    },

    normalize(data) {
        return {
            percent: (data?.percent != null && !isNaN(data.percent)) ? Math.round(data.percent) : 0,
            phase: data?.current_phase || 'Processing...'
        };
    },

    getDiscoveryIds(phase) {
        const phaseLower = String(phase || '').toLowerCase();
        return Object.entries(this.phaseToDiscovery)
            .filter(([key]) => phaseLower.includes(key))
            .map(([, id]) => id);
    },

    deriveVisualState(percent) {
        if (percent >= 100) {
            return {
                completed: true,
                statusText: 'completed',
                showToast: false
            };
        }

        return {
            completed: false,
            statusText: 'running',
            showToast: true
        };
    },

    deriveProgressUpdate(data) {
        const normalized = this.normalize(data);
        return {
            ...normalized,
            discoveryIds: this.getDiscoveryIds(normalized.phase),
            visualState: this.deriveVisualState(normalized.percent)
        };
    },

    deriveRenderState(progressUpdate) {
        return {
            percent: progressUpdate.percent,
            phase: progressUpdate.phase,
            percentText: `${progressUpdate.percent}%`,
            auditPhaseText: `Current Phase: ${progressUpdate.phase}`,
            visualState: progressUpdate.visualState
        };
    },

    resolveRefs(documentRef) {
        return {
            bar: documentRef.getElementById('scan-progress-bar'),
            statusText: documentRef.getElementById('scan-status-text'),
            spinner: documentRef.getElementById('scan-spinner'),
            phaseText: documentRef.getElementById('scan-phase-text'),
            auditPhase: documentRef.getElementById('audit-journey-current-phase'),
            toastBar: documentRef.getElementById('toast-progress-bar'),
            toastPhase: documentRef.getElementById('toast-phase-text'),
            toastPercent: documentRef.getElementById('toast-percent-text')
        };
    },

    updateBars(refs, renderState) {
        const { bar, toastBar } = refs;
        if (bar) {
            bar.style.width = renderState.percentText;
            bar.setAttribute('aria-valuenow', renderState.percent);
        }

        if (toastBar) toastBar.style.width = renderState.percentText;
    },

    updatePhaseText(refs, renderState) {
        const { phaseText, auditPhase, toastPhase } = refs;
        if (phaseText) {
            phaseText.innerText = renderState.phase;
        }

        if (auditPhase) {
            auditPhase.innerText = renderState.auditPhaseText;
        }

        if (toastPhase) toastPhase.innerText = renderState.phase;

        return phaseText;
    },

    updateToastPercent(refs, renderState) {
        if (refs.toastPercent) refs.toastPercent.innerText = renderState.percentText;
    },

    activatePhaseDiscoveries(dashboard, phaseOrIds) {
        const discoveryIds = Array.isArray(phaseOrIds) ? phaseOrIds : this.getDiscoveryIds(phaseOrIds);
        discoveryIds.forEach((id) => dashboard.activateDiscovery(id, false));
    },

    syncCompletionState(documentRef, refs, visualState, toggleScanToast) {
        const { bar, statusText, spinner } = refs;
        if (statusText) statusText.innerText = visualState.statusText;

        if (visualState.completed) {
            if (spinner) spinner.classList.add('d-none');
            if (bar) {
                bar.classList.remove('progress-bar-animated', 'progress-bar-striped');
                bar.classList.add('bg-success');
            }
            toggleScanToast(visualState.showToast);

            documentRef.querySelectorAll('.discovery-btn').forEach(btn => {
                btn.classList.remove('active');
                btn.classList.add('discovered');
            });
            return;
        }

        if (spinner) spinner.classList.remove('d-none');
        toggleScanToast(visualState.showToast);
    },

    render(documentRef, progressUpdate, toggleScanToast) {
        const refs = this.resolveRefs(documentRef);
        const renderState = this.deriveRenderState(progressUpdate);
        this.updateBars(refs, renderState);
        const phaseText = this.updatePhaseText(refs, renderState);
        this.updateToastPercent(refs, renderState);
        this.syncCompletionState(documentRef, refs, progressUpdate.visualState, toggleScanToast);
        return { refs, phaseText };
    }
};


const scanDashboardCortexView = {
    resolveDerived(results) {
        return results?.phases?.enum?.derived || null;
    },

    ensureJsExpertBadge(documentRef, derived) {
        const headerBadges = documentRef.querySelector('#cortex-intel-card .card-header .d-flex.gap-2');
        if (!headerBadges || !derived?.js_expert_mining || headerBadges.querySelector('.fa-microscope')) return;

        const badge = documentRef.createElement('span');
        badge.className = 'badge bg-warning bg-opacity-10 text-warning border border-warning border-opacity-25 animate-pulse';
        badge.innerHTML = '<i class="fas fa-microscope me-1"></i>JS EXPERT ACTIVE';
        headerBadges.prepend(badge);
    },

    buildRecommendationsHtml(recommendations) {
        if (!Array.isArray(recommendations) || recommendations.length === 0) return '';

        let html = '';
        recommendations.forEach(rec => {
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
        return html;
    },

    decodeDerivedParam(value) {
        let decoded = value;
        try {
            decoded = decodeURIComponent(value);
        } catch (e) {}
        return decoded;
    },

    escapeDerivedParam(value) {
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    },

    buildDerivedParamBadgeHtml(param, className) {
        const decoded = this.decodeDerivedParam(param);
        const safeParam = this.escapeDerivedParam(decoded);
        return `<span class="badge ${className} font-monospace x-small">${safeParam}</span>`;
    },

    buildSurfaceExpansionGlobalHtml(globalExpansion) {
        if (!globalExpansion?.derived_endpoints?.length) return '';

        return `
                <div class="mb-4 animate__animated animate__fadeIn">
                    <div class="text-info x-small fw-bold mb-2 text-uppercase">Heuristic Search Surfaces</div>
                    <div class="d-flex flex-wrap gap-1">
                        ${globalExpansion.derived_endpoints.map(ep => `<span class="badge bg-black border border-secondary text-muted font-monospace x-small" title="Heuristic Match">${ep}</span>`).join('')}
                    </div>
                </div>`;
    },

    buildSurfaceExpansionParamsHtml(port, data) {
        if (!data?.derived_params?.length) return '';

        const collapsedCount = data.derived_params.length - 20;
        return `
                        <div class="ps-2 mt-3 border-start border-secondary border-2">
                            <div class="x-small text-muted mb-1"><i class="fas fa-search-plus me-1 text-info opacity-75"></i>Extracted Parameters <span class="badge bg-dark border border-secondary border-opacity-50 text-muted ms-1">${data.derived_params.length}</span></div>
                            <div class="d-flex flex-wrap gap-1 mt-1">
                                ${data.derived_params.slice(0, 20).map(p => this.buildDerivedParamBadgeHtml(p, 'bg-black bg-opacity-50 border border-info border-opacity-25 text-warning')).join('')}
                                ${collapsedCount > 0 ? `
                                <div class="collapse w-100" id="collapse-params-${port}">
                                    <div class="d-flex flex-wrap gap-1 mt-1">
                                    ${data.derived_params.slice(20).map(p => this.buildDerivedParamBadgeHtml(p, 'bg-black bg-opacity-50 border border-secondary border-opacity-25 text-muted')).join('')}
                                    </div>
                                </div>
                                <a data-bs-toggle="collapse" href="#collapse-params-${port}" role="button" aria-expanded="false" class="badge bg-black bg-opacity-20 border border-secondary border-opacity-25 text-cyber text-decoration-none x-small mt-1 hover-glow w-100 text-center py-1">
                                    <i class="fas fa-chevron-down me-1"></i>+${collapsedCount} more variables (Toggle)
                                </a>` : ''}
                            </div>
                        </div>`;
    },

    buildSurfaceExpansionPerPortHtml(perPort) {
        if (!perPort || Object.keys(perPort).length === 0) return '';

        let html = `<div class="mb-2"><div class="text-warning x-small fw-bold mb-2 text-uppercase">Signals Detected</div>`;
        Object.entries(perPort).forEach(([port, data]) => {
            html += `
                    <div class="mb-2 p-2 bg-black bg-opacity-20 rounded animate__animated animate__fadeIn">
                        <div class="d-flex align-items-center gap-2 mb-1">
                            <span class="badge bg-info bg-opacity-25 text-info x-small">PORT ${port}</span>
                            <div class="d-flex gap-1">
                                ${data.reasons.map(r => `<span class="x-small text-muted border-bottom border-warning">${r.replace(/_/g, ' ')}</span>`).join('')}
                            </div>
                        </div>
                        ${this.buildSurfaceExpansionParamsHtml(port, data)}
                    </div>`;
        });
        html += `</div>`;
        return html;
    },

    buildSurfaceExpansionHtml(surfaceExpansion) {
        if (!surfaceExpansion) return '';

        return [
            this.buildSurfaceExpansionGlobalHtml(surfaceExpansion.global),
            this.buildSurfaceExpansionPerPortHtml(surfaceExpansion.per_port),
        ].join('');
    },

    buildServiceIntelligenceHtml(serviceIntelligence) {
        if (!Array.isArray(serviceIntelligence) || serviceIntelligence.length === 0) return '';

        let tagsHtml = '<div class="d-flex flex-wrap gap-2">';
        serviceIntelligence.forEach(item => {
            item.tags.forEach(tag => {
                const tagColor = (tag.includes('api') || tag.includes('web')) ? 'info' : 'warning';
                tagsHtml += `
                    <span class="badge bg-dark border border-${tagColor} text-light x-small animate__animated animate__zoomIn" title="Port: ${item.port}">
                        <i class="fas fa-tag me-1 text-muted"></i>${tag.toUpperCase()}
                    </span>`;
            });
        });
        tagsHtml += '</div>';
        return tagsHtml;
    },

    syncDynamicStatus(documentRef, derived) {
        const statusBadge = documentRef.getElementById('cortex-dynamic-status');
        if (!statusBadge) return;

        if (derived?.status && derived.status !== 'idle') {
            statusBadge.innerHTML = `<i class="fas fa-brain me-1"></i>${derived.status.toUpperCase()}`;
            statusBadge.classList.remove('d-none');
            return;
        }

        statusBadge.classList.add('d-none');
    },

    render(documentRef, results) {
        const derived = this.resolveDerived(results);
        if (!derived) return;

        this.ensureJsExpertBadge(documentRef, derived);

        const recommendationsHtml = this.buildRecommendationsHtml(derived.cortex_recommendations);
        const recommendationsContainer = documentRef.getElementById('cortex-recs-container');
        if (recommendationsContainer && recommendationsHtml) {
            recommendationsContainer.innerHTML = recommendationsHtml;
        }

        const surfaceExpansionHtml = this.buildSurfaceExpansionHtml(derived.surface_expansion);
        const expansionContainer = documentRef.getElementById('surface-expansion-container');
        if (expansionContainer && surfaceExpansionHtml) {
            expansionContainer.innerHTML = surfaceExpansionHtml;
        }

        const serviceIntelligenceHtml = this.buildServiceIntelligenceHtml(derived.service_intelligence);
        const serviceIntelContainer = documentRef.getElementById('service-intel-container');
        if (serviceIntelContainer && serviceIntelligenceHtml) {
            serviceIntelContainer.innerHTML = serviceIntelligenceHtml;
        }

        this.syncDynamicStatus(documentRef, derived);
    },
};

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
            scanDashboardFindingsLoader.resetRenderedFindings(this);
        }

        try {
            ScanDashboard.prototype.updateFindingsLoadState.call(this, 0, 0, "loading");
            const { items, total } = await scanDashboardFindingsLoader.fetchAllPages(this, limit, offset);

            // The API is newest-first. We replay the full batch oldest-first so
            // the existing prepend logic still yields a stable newest-first UI.
            scanDashboardFindingsLoader.replayPersistedFindings(this, items);

            console.log(`Loaded ${items.length}/${total} findings from DB.`);
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

        this.socket.on("results_update", (msg) => {
            if (!msg || msg.scan_id != this.scanId || !msg.results) return;
            this.updateUI(msg.results);
        });

        scanDashboardSocketEvents.forEach(([eventName, handlerName]) => {
            this.socket.on(eventName, (data) => this[handlerName](data));
        });

        this.socket.on("graph_updated", (data) => {
            if (!data || data.scan_id != this.scanId) return;
            if (typeof initGraphData === 'function') {
                initGraphData();
            }
        });
    }

    handleModuleStatus(data) {
        const tableBody = document.querySelector("#modules-table tbody");
        if (!tableBody) return;

        const syncedRow = scanDashboardModuleStatus.syncRow(document, tableBody, data);
        if (!syncedRow) return;

        if (syncedRow.existed) {
            const { row } = syncedRow;
            row.classList.add('animate__animated', 'animate__flash');
            setTimeout(() => row.classList.remove('animate__animated', 'animate__flash'), 1000);
        }

        scanDashboardModuleStatus.updateActiveCount(document);
    }

    handlePipelineEvent(data) {
        const container = document.getElementById("timeline-container");
        if (!container) return;
        scanDashboardPipelineTimeline.appendEvent(document, container, data);
    }

    handleNewLog(data) {
        if (data.scan_id != this.scanId) return;

        scanDashboardLogStream.appendLogEntry(document, data);

        this.highlightPTES(data.message);
        scanDashboardLogStream.activateTriggeredDiscoveries(this, data);

        if (data.message.includes("Scan finished")) {
            scanDashboardLogStream.syncScanFinishedState(document, (show) => this.toggleScanToast(show));
        }
    }

    handleNewFinding(data, options = {}) {
        if (data.scan_id != this.scanId) return;
        const finding = options.normalized === true ? data : this.normalizeFindingRecord(data);
        if (options.skipClientSync !== true) {
            scanDashboardFindingsSync.syncClientFinding(finding);
        }

        const preparedFinding = scanDashboardFindingsFlow.prepareIncomingFinding(this, finding, { normalized: true });
        if (!preparedFinding) return;

        const { fid } = preparedFinding;

        this.activateDiscovery('vulns', true);
        scanDashboardFindingsFlow.renderFinding(document, this, fid, finding);

        // ScanNmap Dashboard Specific updates
        if (finding.category === 'service_detection') {
            this.updateScanNmapDashboard(finding);
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
        scanDashboardIndicators.sync(document, data);
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
        scanDashboardLootStream.incrementCounters(document);
        scanDashboardLootStream.appendVaultEntry(
            document,
            scanDashboardLootStream.ensureVaultList(document),
            data,
            (value) => this.escapeHtml(value),
            scanDashboardLootStream.formatTimestamp()
        );
    }

    handleProgressUpdate(data) {
        if (data.scan_id != this.scanId) return;

        const progressUpdate = scanDashboardProgressView.deriveProgressUpdate(data);
        const { phaseText } = scanDashboardProgressView.render(
            document,
            progressUpdate,
            (show) => this.toggleScanToast(show)
        );

        if (phaseText) {
            this.highlightPTES(progressUpdate.phase);
            scanDashboardProgressView.activatePhaseDiscoveries(this, progressUpdate.discoveryIds);
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
        const auditInputs = scanDashboardAuditJourney.deriveJourneyInputs(results, this.targetIdentifier);
        const findingSummary = scanDashboardAuditJourney.summarizeFindings(this, auditInputs.findings);

        const scopeReady = auditInputs.target.length > 0;
        const reconReady = auditInputs.reconPorts.length > 0 || auditInputs.dnsSubs.length > 0;
        const enumReady = auditInputs.enumEndpointCount > 0;
        const detectionReady = auditInputs.findings.length > 0;
        const validationReady = findingSummary.validated > 0;
        const correlationReady = findingSummary.correlated > 0 || auditInputs.attackPlan.length > 0;
        // Keep the readiness booleans strict. Completed scans with detections can
        // show an in-progress visual tone without being marked as truly validated
        // or correlated.
        const reportingReady = auditInputs.status === 'completed' && detectionReady;
        const closureReady = auditInputs.status === 'completed' && findingSummary.missingProof === 0 && findingSummary.missingCommand === 0;

        return {
            stageMap: scanDashboardAuditJourney.deriveStageMap({
                scopeReady,
                reconReady,
                enumReady,
                detectionReady,
                validationReady,
                correlationReady,
                reportingReady,
                closureReady,
                progressPhase: auditInputs.progressPhase,
                status: auditInputs.status,
            }),
            gates: {
                total: auditInputs.findings.length,
                validated: findingSummary.validated,
                missingProof: findingSummary.missingProof,
                missingCommand: findingSummary.missingCommand
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

        scanDashboardAuditJourney.updateGateText(document.getElementById('audit-gate-total'), summary.gates.total);
        scanDashboardAuditJourney.updateGateText(document.getElementById('audit-gate-validated'), summary.gates.validated);
        scanDashboardAuditJourney.updateGateText(
            document.getElementById('audit-gate-missing-proof'),
            summary.gates.missingProof,
            summary.gates.missingProof > 0
        );
        scanDashboardAuditJourney.updateGateText(
            document.getElementById('audit-gate-missing-command'),
            summary.gates.missingCommand,
            summary.gates.missingCommand > 0
        );
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
        const structuredFindings = scanDashboardResultsView.getStructuredFindings(results);

        if (typeof updateSurfaceExplorer === 'function') {
            updateSurfaceExplorer(results);
        }

        window.scanResults = results;
        this.updateAuditJourney(results);
        this.updateCortexUI(results);
        scanDashboardUIRefresh.syncReconOverview(document, results);

        if (structuredFindings.length) {
            scanDashboardFindingsFlow.ingestStructuredFindings(this, structuredFindings);
        }

        scanDashboardUIRefresh.syncFindingSummary(document, results, structuredFindings);

        if (results.progress) {
            this.handleProgressUpdate({
                scan_id: this.scanId,
                percent: results.progress.percent,
                current_phase: results.progress.current_phase
            });
        }

        this.renderTaskStatus(results.task_status || {});
        scanDashboardUIRefresh.restoreDiscoveryStates(this, results);
        scanDashboardUIRefresh.renderPhaseSections(document, this, results);
        scanDashboardUIRefresh.refreshGraph(results);
    }

    // --- HUMAN READABLE RENDERING ENGINE (V6) ---
    renderJSONSection(parent, key, title) {
        return scanDashboardSectionRendering.renderJSONSection(document, this, parent, key, title);
    }

    renderGenericVulnList(data) {
        return scanDashboardSectionRendering.renderGenericVulnList(this, data);
    }

    renderSectionHuman(key, data) {
        return scanDashboardSectionRendering.renderSectionHuman(this, key, data);
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
        scanDashboardCortexView.render(document, results);
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
ScanDashboard.internals = {
    findingsLoader: scanDashboardFindingsLoader,
    findingsIdentity: scanDashboardFindingsIdentity,
    findingsSync: scanDashboardFindingsSync,
    findingsView: scanDashboardFindingsView,
    findingsDom: scanDashboardFindingsDom,
    findingsFlow: scanDashboardFindingsFlow,
    resultsView: scanDashboardResultsView,
    cortexView: scanDashboardCortexView,
    uiRefresh: scanDashboardUIRefresh,
    auditJourney: scanDashboardAuditJourney,
    socketEvents: scanDashboardSocketEvents,
    logStream: scanDashboardLogStream,
    moduleStatus: scanDashboardModuleStatus,
    pipelineTimeline: scanDashboardPipelineTimeline,
    sectionRendering: scanDashboardSectionRendering,
    indicators: scanDashboardIndicators,
    progressView: scanDashboardProgressView,
    lootStream: scanDashboardLootStream,
};

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
