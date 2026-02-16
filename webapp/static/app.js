/*
 * Spectra Frontend - Vanilla JS.
 *
 * Estructura:
 *   1. API functions   - fetch() calls al backend FastAPI
 *   2. Render functions - Construyen HTML a partir de datos JSON
 *   3. Event handlers   - Clicks, inputs, tabs
 *   4. Init             - Carga inicial al abrir la pagina
 *
 * Sin frameworks, sin build step. Solo DOM APIs nativas.
 */

// ============================================================
// 0. Session - Thread ID para memoria multi-turn del agente
// ============================================================

/**
 * Genera un thread_id unico por sesion de chat.
 * Se renueva al hacer click en "New Chat".
 */
let chatThreadId = crypto.randomUUID();


// ============================================================
// 1. API Functions
// ============================================================

const API = {
    /**
     * Health check - verifica conectividad con Neo4j.
     * @returns {{status, neo4j, nodes, relationships, agent}}
     */
    async health() {
        const res = await fetch('/api/health');
        return res.json();
    },

    /**
     * Stats del grafo - conteo de nodos por tipo.
     * @returns {{Domain, Host, Port, Service, Technology, Vulnerability, ...}}
     */
    async stats() {
        const res = await fetch('/api/graph/stats');
        return res.json();
    },

    /**
     * Lista de hosts con puertos y conteo de vulns.
     * @returns {Array<{address, hostname, os, ports, vuln_count}>}
     */
    async hosts() {
        const res = await fetch('/api/graph/hosts');
        return res.json();
    },

    /**
     * Vulnerabilidades filtradas.
     * @param {string} severity - "all", "critical", "high", "medium", "low"
     * @returns {Array<{vuln_id, severity, score, description, service, version, port, host}>}
     */
    async vulns(severity = 'all') {
        const params = new URLSearchParams();
        if (severity !== 'all') params.set('severity', severity);
        const res = await fetch(`/api/graph/vulns?${params}`);
        return res.json();
    },

    /**
     * Cadenas de ataque.
     * @returns {Array<{domain, host, port, protocol, service, version, cve, severity, score, description}>}
     */
    async paths() {
        const res = await fetch('/api/graph/paths');
        return res.json();
    },

    /**
     * Enviar mensaje al agente IA (legacy non-streaming).
     * @param {string} message
     * @returns {{response, tool_calls}}
     */
    async chat(message) {
        const res = await fetch('/api/chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message, thread_id: chatThreadId }),
        });
        return res.json();
    },

    /**
     * Enviar mensaje al agente IA con streaming SSE.
     * Devuelve un ReadableStream que emite eventos SSE.
     * @param {string} message
     * @returns {Response} raw fetch response for streaming
     */
    async chatStream(message) {
        return fetch('/api/chat/stream', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message, thread_id: chatThreadId }),
        });
    },

    /**
     * Datos del grafo para visualizacion force-directed.
     * @returns {{nodes: Array, links: Array}}
     */
    async graphVisual() {
        const res = await fetch('/api/graph/visual');
        return res.json();
    },

    /**
     * Lanzar un scan.
     * @param {string} target
     * @param {string} profile
     */
    async scanStart(target, profile) {
        const res = await fetch('/api/scan/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, profile }),
        });
        return res.json();
    },

    /**
     * Estado del scan en curso.
     * @returns {{status, target, profile, elapsed, error, summary}}
     */
    async scanStatus() {
        const res = await fetch('/api/scan/status');
        return res.json();
    },
};


// ============================================================
// 2. Render Functions
// ============================================================

/**
 * Actualiza las 6 stat cards del dashboard.
 */
function renderStats(stats) {
    document.getElementById('stat-domains').textContent = stats.Domain || 0;
    document.getElementById('stat-hosts').textContent = stats.Host || 0;
    document.getElementById('stat-ports').textContent = stats.Port || 0;
    document.getElementById('stat-services').textContent = stats.Service || 0;
    document.getElementById('stat-techs').textContent = stats.Technology || 0;
    document.getElementById('stat-vulns').textContent = stats.Vulnerability || 0;
}


/**
 * Renderiza la lista de hosts como cards.
 */
function renderHosts(hosts) {
    const container = document.getElementById('hosts-container');

    if (!hosts || hosts.length === 0) {
        container.innerHTML = '<p class="placeholder">No hosts found in the graph.</p>';
        return;
    }

    container.innerHTML = hosts.map(host => {
        const portsHtml = (host.ports || []).map(p => {
            const svc = p.service !== 'unknown' ? p.service : '';
            const ver = p.version || '';
            const label = svc ? `${svc} ${ver}`.trim() : '';
            return `
                <span class="port-tag">
                    <span class="port-num">${p.number}/${p.protocol || 'tcp'}</span>
                    ${label ? `<span class="port-svc">${label}</span>` : ''}
                </span>
            `;
        }).join('');

        const vulnBadge = host.vuln_count > 0
            ? `<span class="badge badge-critical">${host.vuln_count} vulns</span>`
            : '<span class="badge badge-low">clean</span>';

        return `
            <div class="host-card">
                <div class="host-header">
                    <div>
                        <span class="host-ip">${host.address}</span>
                        <span class="host-hostname">${host.hostname || ''}</span>
                    </div>
                    ${vulnBadge}
                </div>
                <div class="host-ports">${portsHtml || '<span class="placeholder">No open ports</span>'}</div>
            </div>
        `;
    }).join('');
}


/**
 * Renderiza la tabla de vulnerabilidades.
 */
function renderVulns(vulns) {
    const tbody = document.getElementById('vulns-body');

    if (!vulns || vulns.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="placeholder">No vulnerabilities found.</td></tr>';
        return;
    }

    tbody.innerHTML = vulns.map(v => {
        const sev = (v.severity || 'info').toLowerCase();
        const desc = (v.description || '').substring(0, 120);
        const svc = [v.service, v.version].filter(Boolean).join(' ');

        return `
            <tr>
                <td><code>${v.vuln_id || '-'}</code></td>
                <td><span class="badge badge-${sev}">${sev}</span></td>
                <td>${v.score != null ? v.score.toFixed(1) : '-'}</td>
                <td>${svc || '-'}</td>
                <td>${v.port || '-'}</td>
                <td><code>${v.host || '-'}</code></td>
                <td class="desc-cell" title="${(v.description || '').replace(/"/g, '&quot;')}">${desc}</td>
            </tr>
        `;
    }).join('');
}


/**
 * Renderiza las cadenas de ataque como cards visuales.
 */
function renderPaths(paths) {
    const container = document.getElementById('paths-container');

    if (!paths || paths.length === 0) {
        container.innerHTML = '<p class="placeholder">No attack paths found.</p>';
        return;
    }

    // Agrupar por CVE para evitar duplicados visuales
    const seen = new Set();
    const unique = paths.filter(p => {
        const key = `${p.host}:${p.port}-${p.cve}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });

    container.innerHTML = unique.map(p => {
        const sev = (p.severity || 'info').toLowerCase();
        const svc = [p.service, p.version].filter(Boolean).join(' ') || '?';
        const desc = (p.description || '').substring(0, 150);

        return `
            <div class="path-card">
                <div class="path-chain">
                    <span class="node-domain">${p.domain}</span>
                    <span class="arrow">-></span>
                    <span class="node-host">${p.host}</span>
                    <span class="arrow">:</span>
                    <span class="node-port">${p.port}/${p.protocol || 'tcp'}</span>
                    <span class="arrow">-></span>
                    <span class="node-service">${svc}</span>
                    <span class="arrow">-></span>
                    <span class="node-vuln">${p.cve}</span>
                    <span class="badge badge-${sev}" style="margin-left: 0.5rem;">
                        CVSS ${p.score != null ? p.score.toFixed(1) : '?'}
                    </span>
                </div>
                <div class="path-desc">${desc}</div>
            </div>
        `;
    }).join('');
}


/**
 * Anade un mensaje al chat.
 * @param {'user'|'assistant'|'system'|'error'} role
 * @param {string} content
 * @param {Array} toolCalls - opcional, tool calls del agente
 */
function appendChatMessage(role, content, toolCalls = []) {
    const container = document.getElementById('chat-messages');
    const div = document.createElement('div');
    div.className = `chat-msg ${role}`;

    let html = `<div class="msg-content">${escapeHtml(content)}</div>`;

    // Mostrar tool calls como detalle colapsable
    if (toolCalls && toolCalls.length > 0) {
        const toolsHtml = toolCalls.map(tc =>
            `<div class="msg-tool-item">${tc.name}(${JSON.stringify(tc.args)})</div>`
        ).join('');
        html += `
            <div class="msg-tools">
                <details>
                    <summary>${toolCalls.length} tool call${toolCalls.length > 1 ? 's' : ''}</summary>
                    ${toolsHtml}
                </details>
            </div>
        `;
    }

    div.innerHTML = html;
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
    return div;
}


/**
 * Escape HTML para prevenir XSS en el chat.
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}


/**
 * Extrae y parsea el bloque JSON estructurado de la respuesta del agente.
 * Devuelve {text, assessment} donde text es la respuesta sin el JSON
 * y assessment es el objeto parseado (o null si no hay).
 */
function parseStructuredResponse(fullText) {
    // Look for ```json ... ``` block at the end of the response
    const jsonBlockRegex = /```json\s*\n([\s\S]*?)\n```\s*$/;
    const match = fullText.match(jsonBlockRegex);

    if (!match) {
        return { text: fullText, assessment: null };
    }

    const text = fullText.slice(0, match.index).trim();
    let assessment = null;

    try {
        assessment = JSON.parse(match[1]);
    } catch {
        // Invalid JSON — keep it as part of the text
        return { text: fullText, assessment: null };
    }

    return { text, assessment };
}


/**
 * Renderiza un assessment estructurado como HTML visual.
 */
function renderAssessment(assessment) {
    if (!assessment) return '';

    const levelColors = {
        'CRITICAL': 'var(--sev-critical)',
        'HIGH': 'var(--sev-high)',
        'MEDIUM': 'var(--sev-medium)',
        'LOW': 'var(--sev-low)',
        'MINIMAL': 'var(--accent)',
    };

    const levelColor = levelColors[assessment.risk_level] || 'var(--text-secondary)';

    let html = `<div class="assessment-panel">`;

    // Risk level badge
    html += `<div class="assessment-header">
        <span class="assessment-badge" style="background:${levelColor}">
            ${assessment.risk_level || '?'} RISK
        </span>
        <span class="assessment-confidence">Confidence: ${assessment.confidence || '?'}</span>
    </div>`;

    // Findings count
    if (assessment.findings_count) {
        const fc = assessment.findings_count;
        html += `<div class="assessment-counts">`;
        if (fc.critical) html += `<span class="badge badge-critical">${fc.critical} critical</span>`;
        if (fc.high) html += `<span class="badge badge-high">${fc.high} high</span>`;
        if (fc.medium) html += `<span class="badge badge-medium">${fc.medium} medium</span>`;
        if (fc.low) html += `<span class="badge badge-low">${fc.low} low</span>`;
        html += `</div>`;
    }

    // Top risks
    if (assessment.top_risks && assessment.top_risks.length > 0) {
        html += `<div class="assessment-section">
            <div class="assessment-section-title">Top Risks</div>`;
        for (const risk of assessment.top_risks) {
            const priorityClass = (risk.priority || '').toLowerCase().replace('-', '');
            html += `<div class="assessment-risk">
                <div class="risk-title">
                    ${escapeHtml(risk.title || '?')}
                    ${risk.cve ? `<code>${escapeHtml(risk.cve)}</code>` : ''}
                    ${risk.cvss ? `<span class="risk-cvss">CVSS ${risk.cvss}</span>` : ''}
                </div>
                <div class="risk-meta">
                    ${risk.affected ? escapeHtml(risk.affected) : ''}
                    <span class="risk-priority risk-${priorityClass}">${risk.priority || '?'}</span>
                </div>
            </div>`;
        }
        html += `</div>`;
    }

    // Recommended actions
    if (assessment.recommended_actions && assessment.recommended_actions.length > 0) {
        html += `<div class="assessment-section">
            <div class="assessment-section-title">Recommended Actions</div>
            <ol class="assessment-actions">`;
        for (const action of assessment.recommended_actions) {
            html += `<li>${escapeHtml(action)}</li>`;
        }
        html += `</ol></div>`;
    }

    html += `</div>`;
    return html;
}


/**
 * Renderiza el grafo force-directed en el container.
 */
let graphInstance = null;

// Colores por tipo de nodo
const NODE_COLORS = {
    Domain: '#3b82f6',
    Subdomain: '#60a5fa',
    Host: '#00ff88',
    Port: '#eab308',
    Service: '#a78bfa',
    Technology: '#f472b6',
    Vulnerability: '#ef4444',
    Scan: '#6b7280',
};

// Tamano por tipo de nodo
const NODE_SIZES = {
    Domain: 8,
    Host: 7,
    Vulnerability: 6,
    Service: 5,
    Port: 4,
    Technology: 4,
    Scan: 3,
    Subdomain: 4,
};

function renderGraph(data) {
    const container = document.getElementById('graph-container');
    if (!container || !data.nodes || data.nodes.length === 0) return;

    // Destruir grafo previo si existe
    if (graphInstance) {
        graphInstance._destructor && graphInstance._destructor();
    }

    graphInstance = ForceGraph()(container)
        .graphData({
            nodes: data.nodes.map(n => ({
                id: n.id,
                type: n.type,
                label: n.label || n.type,
                extra: n.extra,
            })),
            links: data.links.map(l => ({
                source: l.source,
                target: l.target,
                type: l.type,
            })),
        })
        .nodeId('id')
        .nodeLabel(n => `[${n.type}] ${n.label}`)
        .nodeColor(n => NODE_COLORS[n.type] || '#6b7280')
        .nodeVal(n => NODE_SIZES[n.type] || 4)
        .linkLabel(l => l.type)
        .linkColor(() => 'rgba(255,255,255,0.12)')
        .linkDirectionalArrowLength(4)
        .linkDirectionalArrowRelPos(1)
        .linkWidth(0.5)
        .backgroundColor('#0a0e17')
        .nodeCanvasObject((node, ctx, globalScale) => {
            // Circulo relleno
            const size = NODE_SIZES[node.type] || 4;
            ctx.beginPath();
            ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
            ctx.fillStyle = NODE_COLORS[node.type] || '#6b7280';
            ctx.fill();

            // Label si el zoom es suficiente
            if (globalScale > 1.5) {
                ctx.font = `${Math.max(10 / globalScale, 2)}px sans-serif`;
                ctx.fillStyle = '#e5e7eb';
                ctx.textAlign = 'center';
                ctx.fillText(node.label || '', node.x, node.y + size + 8 / globalScale);
            }
        })
        .nodePointerAreaPaint((node, color, ctx) => {
            const size = NODE_SIZES[node.type] || 4;
            ctx.beginPath();
            ctx.arc(node.x, node.y, size + 2, 0, 2 * Math.PI);
            ctx.fillStyle = color;
            ctx.fill();
        })
        .warmupTicks(50)
        .cooldownTicks(100);
}


/**
 * Renderiza el auto-analysis brief del agente IA despues de un scan.
 * Lo muestra tanto en el panel de scan como en el chat.
 */
function renderAutoAnalysis(analysis) {
    // Show in scan panel
    let container = document.getElementById('scan-analysis');
    if (!container) {
        // Create the analysis container dynamically below scan-status
        const statusDiv = document.getElementById('scan-status');
        container = document.createElement('div');
        container.id = 'scan-analysis';
        container.className = 'scan-analysis';
        statusDiv.parentNode.insertBefore(container, statusDiv.nextSibling);
    }

    container.innerHTML = `
        <div class="analysis-header">AI Security Brief</div>
        <div class="analysis-content">${escapeHtml(analysis)}</div>
    `;
    container.style.display = 'block';

    // Also inject into chat as a system message so the user sees it there too
    appendChatMessage('assistant', '[Auto-Analysis]\n' + analysis);
}


/**
 * Pollea el auto-analysis si el agente aun no ha terminado
 * cuando el scan ya se completo.
 */
function pollAutoAnalysis() {
    let attempts = 0;
    const maxAttempts = 30; // 30 * 3s = 90s max wait

    const interval = setInterval(async () => {
        attempts++;
        try {
            const s = await API.scanStatus();
            if (s.analysis) {
                clearInterval(interval);
                renderAutoAnalysis(s.analysis);
            } else if (attempts >= maxAttempts) {
                clearInterval(interval);
                // Timeout — no brief generated
            }
        } catch (err) {
            // Network error, keep trying
        }
    }, 3000);
}


// ============================================================
// 3. Event Handlers
// ============================================================

/**
 * Tab switching: Dashboard <-> Graph <-> Scan <-> Chat
 */
function initTabs() {
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            // Update nav buttons
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Update tab content
            const tabId = btn.dataset.tab;
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');

            // Si se activa el tab Graph, redimensionar el grafo
            if (tabId === 'graph' && graphInstance) {
                const container = document.getElementById('graph-container');
                graphInstance.width(container.clientWidth);
                graphInstance.height(container.clientHeight);
            }
        });
    });
}


/**
 * Vulnerability severity filter.
 */
function initVulnFilter() {
    const select = document.getElementById('vuln-severity-filter');
    select.addEventListener('change', async () => {
        const vulns = await API.vulns(select.value);
        renderVulns(vulns);
    });
}


/**
 * Chat: enviar mensaje y mostrar respuesta.
 * Incluye boton "New Chat" para resetear la conversacion (nuevo thread_id).
 */
function initChat() {
    const input = document.getElementById('chat-input');
    const sendBtn = document.getElementById('chat-send');
    const newChatBtn = document.getElementById('chat-new');

    // New Chat: genera nuevo thread_id y limpia el historial visual
    if (newChatBtn) {
        newChatBtn.addEventListener('click', () => {
            chatThreadId = crypto.randomUUID();
            const container = document.getElementById('chat-messages');
            container.innerHTML = '';
            appendChatMessage('system', 'New conversation started. The agent has no memory of previous messages.');
            input.focus();
        });
    }

    async function sendMessage() {
        const message = input.value.trim();
        if (!message) return;

        // Mostrar mensaje del usuario
        appendChatMessage('user', message);
        input.value = '';

        // Deshabilitar input mientras el agente piensa
        input.disabled = true;
        sendBtn.disabled = true;

        // Crear mensaje del assistant vacio para streaming
        const assistantDiv = appendChatMessage('assistant', '');
        const contentEl = assistantDiv.querySelector('.msg-content');
        contentEl.classList.add('thinking-dots');
        contentEl.textContent = 'Analyzing';

        let fullText = '';
        const toolCalls = [];

        try {
            const response = await API.chatStream(message);

            if (!response.ok) {
                const err = await response.json();
                contentEl.classList.remove('thinking-dots');
                contentEl.textContent = err.error || 'Error connecting to agent.';
                input.disabled = false;
                sendBtn.disabled = false;
                input.focus();
                return;
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = '';

            // Clear thinking state on first token
            let firstToken = true;

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                buffer += decoder.decode(value, { stream: true });

                // Parse SSE events from buffer
                const lines = buffer.split('\n');
                buffer = lines.pop() || ''; // Keep incomplete line in buffer

                for (const line of lines) {
                    if (!line.startsWith('data: ')) continue;
                    const jsonStr = line.slice(6).trim();
                    if (!jsonStr) continue;

                    let event;
                    try {
                        event = JSON.parse(jsonStr);
                    } catch {
                        continue;
                    }

                    if (event.type === 'token') {
                        if (firstToken) {
                            contentEl.classList.remove('thinking-dots');
                            contentEl.textContent = '';
                            firstToken = false;
                        }
                        fullText += event.content;
                        contentEl.textContent = fullText;
                        // Auto-scroll
                        const container = document.getElementById('chat-messages');
                        container.scrollTop = container.scrollHeight;

                    } else if (event.type === 'tool_call') {
                        toolCalls.push({ name: event.name, args: event.args });
                        // Show tool activity indicator
                        if (firstToken) {
                            contentEl.classList.remove('thinking-dots');
                            contentEl.textContent = '';
                            firstToken = false;
                        }
                        contentEl.textContent = fullText || `Using tool: ${event.name}...`;

                    } else if (event.type === 'tool_result') {
                        // Agent got tool result, will continue reasoning
                        contentEl.textContent = fullText || `Processing ${event.name} results...`;

                    } else if (event.type === 'error') {
                        fullText = event.message;
                        contentEl.textContent = fullText;

                    } else if (event.type === 'done') {
                        // Streaming complete
                        if (firstToken) {
                            contentEl.classList.remove('thinking-dots');
                        }
                        if (!fullText) {
                            contentEl.textContent = 'No response generated.';
                        }
                    }
                }
            }

            // Parse structured assessment from the response
            const { text: cleanText, assessment } = parseStructuredResponse(fullText);
            if (assessment) {
                // Replace content with clean text (without JSON block)
                contentEl.textContent = cleanText;
                // Render assessment panel
                const assessmentHtml = renderAssessment(assessment);
                if (assessmentHtml) {
                    const assessDiv = document.createElement('div');
                    assessDiv.innerHTML = assessmentHtml;
                    assistantDiv.appendChild(assessDiv);
                }
            }

            // Add tool calls details if any
            if (toolCalls.length > 0) {
                const toolsHtml = toolCalls.map(tc =>
                    `<div class="msg-tool-item">${tc.name}(${typeof tc.args === 'string' ? tc.args : JSON.stringify(tc.args)})</div>`
                ).join('');
                const toolsDiv = document.createElement('div');
                toolsDiv.className = 'msg-tools';
                toolsDiv.innerHTML = `
                    <details>
                        <summary>${toolCalls.length} tool call${toolCalls.length > 1 ? 's' : ''}</summary>
                        ${toolsHtml}
                    </details>
                `;
                assistantDiv.appendChild(toolsDiv);
            }

        } catch (err) {
            contentEl.classList.remove('thinking-dots');
            contentEl.textContent = `Error: ${err.message}`;
        }

        // Re-habilitar input
        input.disabled = false;
        sendBtn.disabled = false;
        input.focus();
    }

    sendBtn.addEventListener('click', sendMessage);

    input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            sendMessage();
        }
    });
}


/**
 * Preset suggestion buttons: click -> fill input -> send.
 */
function initPresets() {
    document.querySelectorAll('.preset-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const input = document.getElementById('chat-input');
            input.value = btn.dataset.msg;
            // Activar chat tab si no esta activo
            const chatTab = document.querySelector('[data-tab="chat"]');
            if (!chatTab.classList.contains('active')) {
                chatTab.click();
            }
            // Enviar automaticamente
            document.getElementById('chat-send').click();
        });
    });
}


/**
 * Scan launcher: form submit + polling.
 */
function initScan() {
    const startBtn = document.getElementById('scan-start');
    const targetInput = document.getElementById('scan-target');
    const profileSelect = document.getElementById('scan-profile');
    const statusDiv = document.getElementById('scan-status');
    const statusText = document.getElementById('scan-status-text');
    const statusDetail = document.getElementById('scan-status-detail');
    const statusIcon = document.getElementById('scan-status-icon');

    startBtn.addEventListener('click', async () => {
        const target = targetInput.value.trim();
        if (!target) {
            targetInput.focus();
            return;
        }

        // Deshabilitar form
        startBtn.disabled = true;
        targetInput.disabled = true;
        profileSelect.disabled = true;
        statusDiv.style.display = 'block';
        statusText.textContent = 'Starting scan...';
        statusDetail.textContent = '';
        statusIcon.className = 'scan-spinner';

        try {
            const res = await API.scanStart(target, profileSelect.value);
            if (res.error) {
                statusText.textContent = res.error;
                statusIcon.className = 'scan-failed-icon';
                statusIcon.textContent = 'X';
                startBtn.disabled = false;
                targetInput.disabled = false;
                profileSelect.disabled = false;
                return;
            }

            // Empezar polling
            statusText.textContent = `Scanning ${target}...`;
            pollScanStatus();

        } catch (err) {
            statusText.textContent = `Error: ${err.message}`;
            statusIcon.className = 'scan-failed-icon';
            statusIcon.textContent = 'X';
            startBtn.disabled = false;
            targetInput.disabled = false;
            profileSelect.disabled = false;
        }
    });
}


/**
 * Pollea el estado del scan cada 3 segundos.
 */
function pollScanStatus() {
    const statusText = document.getElementById('scan-status-text');
    const statusDetail = document.getElementById('scan-status-detail');
    const statusIcon = document.getElementById('scan-status-icon');
    const startBtn = document.getElementById('scan-start');
    const targetInput = document.getElementById('scan-target');
    const profileSelect = document.getElementById('scan-profile');

    const interval = setInterval(async () => {
        try {
            const s = await API.scanStatus();

            if (s.status === 'running') {
                statusText.textContent = `Scanning ${s.target}...`;
                statusDetail.textContent = s.elapsed ? `Elapsed: ${s.elapsed}` : '';

            } else if (s.status === 'completed') {
                clearInterval(interval);
                statusIcon.className = 'scan-complete-icon';
                statusIcon.textContent = '\u2713';
                statusText.textContent = 'Scan completed!';

                const sum = s.summary || {};
                statusDetail.textContent =
                    `${sum.hosts || 0} hosts | ${sum.open_ports || 0} ports | ` +
                    `${sum.vulnerabilities || 0} vulns | ${sum.duration || '?'}`;

                // Re-habilitar form
                startBtn.disabled = false;
                targetInput.disabled = false;
                profileSelect.disabled = false;

                // Recargar dashboard con nuevos datos
                reloadDashboard();

                // Auto-analysis: show AI brief or poll for it
                if (s.analysis) {
                    renderAutoAnalysis(s.analysis);
                } else {
                    // Agent is still generating — poll for analysis
                    pollAutoAnalysis();
                }

            } else if (s.status === 'failed') {
                clearInterval(interval);
                statusIcon.className = 'scan-failed-icon';
                statusIcon.textContent = 'X';
                statusText.textContent = 'Scan failed';
                statusDetail.textContent = s.error || 'Unknown error';

                startBtn.disabled = false;
                targetInput.disabled = false;
                profileSelect.disabled = false;
            }
        } catch (err) {
            // Network error, keep polling
        }
    }, 3000);
}


/**
 * Recarga los datos del dashboard y el grafo despues de un scan.
 */
async function reloadDashboard() {
    try {
        const [stats, hosts, vulns, paths, graphData] = await Promise.all([
            API.stats(),
            API.hosts(),
            API.vulns(),
            API.paths(),
            API.graphVisual(),
        ]);

        renderStats(stats);
        renderHosts(hosts);
        renderVulns(vulns);
        renderPaths(paths);
        renderGraph(graphData);

        // Actualizar status bar
        const statusDot = document.getElementById('status-dot');
        const headerStatus = document.getElementById('status-text');
        const total = Object.entries(stats)
            .filter(([k]) => k !== 'relationships')
            .reduce((sum, [, v]) => sum + (v || 0), 0);
        statusDot.className = 'status-dot connected';
        headerStatus.textContent = `${total} nodes | ${stats.relationships || 0} rels`;

    } catch (err) {
        console.error('Error reloading dashboard:', err);
    }
}


// ============================================================
// 4. Init - Carga inicial
// ============================================================

async function init() {
    // Inicializar event handlers
    initTabs();
    initVulnFilter();
    initChat();
    initPresets();
    initScan();

    // Health check
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');

    try {
        const health = await API.health();

        if (health.status === 'ok') {
            statusDot.className = 'status-dot connected';
            statusText.textContent = `${health.nodes} nodes | ${health.relationships} rels`;
        } else {
            statusDot.className = 'status-dot error';
            statusText.textContent = 'Neo4j error';
            return;
        }
    } catch (err) {
        statusDot.className = 'status-dot error';
        statusText.textContent = 'Backend offline';
        return;
    }

    // Cargar datos del dashboard y grafo en paralelo
    try {
        const [stats, hosts, vulns, paths, graphData] = await Promise.all([
            API.stats(),
            API.hosts(),
            API.vulns(),
            API.paths(),
            API.graphVisual(),
        ]);

        renderStats(stats);
        renderHosts(hosts);
        renderVulns(vulns);
        renderPaths(paths);
        renderGraph(graphData);

    } catch (err) {
        console.error('Error loading dashboard data:', err);
    }
}


// Arrancar cuando el DOM este listo
document.addEventListener('DOMContentLoaded', init);
