/* SpencerWeb Dashboard — Frontend Logic */

let allReports = [];
let ws = null;

// Tab switching
document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById(tab).classList.add('active');
        if (tab === 'overview' || tab === 'reports') loadReports();
    });
});

// Load reports
async function loadReports() {
    try {
        const res = await fetch('/api/reports');
        const data = await res.json();
        allReports = data.reports || [];
        renderOverview();
        renderReports();
    } catch (e) { console.error('Failed to load:', e); }
}

function renderOverview() {
    document.getElementById('stat-total-scans').textContent = allReports.length;
    const vulns = allReports.reduce((s, r) => s + (r.total_failed || 0), 0);
    document.getElementById('stat-vulnerabilities').textContent = vulns;

    if (allReports.length > 0) {
        document.getElementById('stat-last-scan').textContent = timeAgo(new Date(allReports[0].timestamp));
        const gv = { A: 5, B: 4, C: 3, D: 2, F: 1 };
        const gs = allReports.map(r => gv[r.grade] || 0).filter(g => g > 0);
        if (gs.length) {
            const avg = gs.reduce((a, b) => a + b, 0) / gs.length;
            document.getElementById('stat-avg-grade').textContent =
                avg >= 4.5 ? 'A' : avg >= 3.5 ? 'B' : avg >= 2.5 ? 'C' : avg >= 1.5 ? 'D' : 'F';
        }
    } else {
        document.getElementById('stat-last-scan').textContent = '—';
        document.getElementById('stat-avg-grade').textContent = '—';
    }

    const el = document.getElementById('recent-scans');
    el.innerHTML = allReports.length === 0
        ? empty('No scans yet', 'Run your first security audit from the "New scan" tab')
        : allReports.slice(0, 6).map(reportRow).join('');
}

function renderReports() {
    const el = document.getElementById('all-reports');
    el.innerHTML = allReports.length === 0
        ? empty('No reports', 'Reports appear here after a scan completes')
        : allReports.map(reportRow).join('');
}

function reportRow(r) {
    const g = r.grade || '?';
    const gc = g === '?' ? 'grade-q' : `grade-${g}`;
    return `
    <div class="report-row" onclick="openReport('${esc(r.filename)}')">
        <div class="grade-circle ${gc}">${g}</div>
        <div class="report-info">
            <h3>${esc(r.target || 'Unknown')}</h3>
            <div class="report-meta">
                <span>Score ${r.score || 0}/100</span>
                <span>${(r.total_checks || 0) - (r.total_failed || 0)}/${r.total_checks || 0} passed</span>
                <span>${r.total_failed || 0} issues</span>
                <span>${r.duration ? r.duration + 's' : '—'}</span>
                <span>${timeAgo(new Date(r.timestamp))}</span>
            </div>
        </div>
        <div class="report-actions">
            <button class="btn-delete" onclick="event.stopPropagation(); deleteReport('${esc(r.filename)}')">Delete</button>
        </div>
    </div>`;
}

function empty(title, desc) {
    return `<div class="empty"><div class="empty-icon">📭</div><h3>${title}</h3><p>${desc}</p></div>`;
}

// Report detail modal
async function openReport(filename) {
    try {
        const res = await fetch(`/api/reports/${filename}`);
        const data = await res.json();
        renderDetail(data);
        document.getElementById('report-modal').style.display = 'flex';
    } catch (e) { alert('Failed to load report'); }
}

function renderDetail(data) {
    const info = data.scan_info || {};
    const grade = data.grade || {};
    const g = grade.grade || '?';
    const gc = g === '?' ? 'grade-q' : `grade-${g}`;
    const findings = data.all_findings || [];
    const fails = findings.filter(f => f.status === 'FAIL')
        .sort((a, b) => (sevOrd(a.severity) - sevOrd(b.severity)));
    const stats = data.statistics || {};

    document.getElementById('report-detail').innerHTML = `
        <div style="display:flex;align-items:center;gap:20px;margin-bottom:24px;">
            <div class="grade-circle ${gc}" style="width:72px;height:72px;font-size:28px;flex-shrink:0;">${g}</div>
            <div>
                <h2 style="font-size:18px;font-weight:700;margin-bottom:4px;">${esc(info.target || '')}</h2>
                <p style="font-size:14px;color:var(--text-secondary);">Score: ${grade.score || 0}/100 · ${grade.summary || ''}</p>
                <p style="font-size:13px;color:var(--text-muted);">${info.timestamp ? new Date(info.timestamp).toLocaleString('id-ID') : ''}</p>
            </div>
        </div>

        <div class="detail-metrics">
            <div class="detail-metric">
                <div class="detail-metric-value">${stats.total_checks || 0}</div>
                <div class="detail-metric-label">Checks</div>
            </div>
            <div class="detail-metric">
                <div class="detail-metric-value" style="color:var(--success)">${stats.total_passed || 0}</div>
                <div class="detail-metric-label">Passed</div>
            </div>
            <div class="detail-metric">
                <div class="detail-metric-value" style="color:var(--danger)">${stats.total_failed || 0}</div>
                <div class="detail-metric-label">Failed</div>
            </div>
            <div class="detail-metric">
                <div class="detail-metric-value">${info.scan_duration_seconds || 0}s</div>
                <div class="detail-metric-label">Duration</div>
            </div>
        </div>

        <h3 style="font-size:16px;font-weight:600;margin:24px 0 12px;">Vulnerabilities (${fails.length})</h3>
        ${fails.length === 0 ? '<p style="color:var(--text-muted);padding:24px;text-align:center;">No vulnerabilities found</p>' :
        fails.map(f => `
            <div class="finding sev-${f.severity}">
                <div class="finding-top">
                    <span class="finding-name">${esc(f.check || '')}</span>
                    <span class="sev-tag ${f.severity}">${f.severity}</span>
                </div>
                <div class="finding-detail">${esc(f.detail || '')}</div>
                <div class="finding-rec">${esc(f.recommendation || '')}</div>
            </div>`).join('')}

        <h3 style="font-size:16px;font-weight:600;margin:28px 0 12px;">Modules</h3>
        ${Object.entries(data.modules || {}).map(([k, m]) => `
            <div class="mod-section">
                <h4>${modName(k)}</h4>
                ${m.error ? `<p class="mod-stats">Error: ${esc(m.error)}</p>` :
                `<p class="mod-stats">Passed: <strong style="color:var(--success)">${m.passed||0}</strong> · Failed: <strong style="color:var(--danger)">${m.failed||0}</strong></p>`}
            </div>`).join('')}`;
}

document.getElementById('modal-close').addEventListener('click', () => {
    document.getElementById('report-modal').style.display = 'none';
});
document.getElementById('report-modal').addEventListener('click', (e) => {
    if (e.target.id === 'report-modal') document.getElementById('report-modal').style.display = 'none';
});

async function deleteReport(filename) {
    if (!confirm(`Delete "${filename}"?`)) return;
    await fetch(`/api/reports/${filename}`, { method: 'DELETE' });
    loadReports();
}

// Scan
document.getElementById('start-scan-btn').addEventListener('click', async () => {
    const target = document.getElementById('target-url').value.trim();
    if (!target) return alert('Please enter a target URL');

    const mode = document.querySelector('input[name="mode"]:checked').value;
    const skipPorts = document.getElementById('skip-ports').checked;
    const skipActive = document.getElementById('skip-active').checked;

    const btn = document.getElementById('start-scan-btn');
    btn.disabled = true;
    btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> Scanning...';

    document.getElementById('scan-output-card').style.display = 'block';
    document.getElementById('terminal').textContent = '';
    document.getElementById('progress-fill').style.width = '0%';
    document.getElementById('current-module').textContent = '';
    setStatus('running', 'Running');

    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, mode, skipPorts, skipActive })
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Scan failed');
    } catch (e) {
        alert(`Error: ${e.message}`);
        btn.disabled = false;
        btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg> Start scan';
        setStatus('error', 'Error');
    }
});

function setStatus(state, text) {
    const el = document.getElementById('scan-status');
    el.className = `status-pill ${state}`;
    el.textContent = text;
}

// WebSocket
function connectWS() {
    const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host;
    ws = new WebSocket(url);
    ws.onmessage = (e) => {
        try { handleMsg(JSON.parse(e.data)); } catch (err) {}
    };
    ws.onclose = () => setTimeout(connectWS, 2000);
}

function handleMsg(msg) {
    const term = document.getElementById('terminal');
    const btn = document.getElementById('start-scan-btn');

    switch (msg.type) {
        case 'scan_started':
            term.textContent += `[SpencerWeb] Scan started for ${msg.target}\n`;
            break;
        case 'output':
            term.textContent += msg.text;
            term.scrollTop = term.scrollHeight;
            break;
        case 'module_started':
            document.getElementById('progress-fill').style.width = `${msg.progress}%`;
            document.getElementById('current-module').textContent = `Module ${msg.module}: ${msg.title}`;
            break;
        case 'scan_finished':
            setStatus(msg.exitCode === 0 ? 'success' : 'error',
                msg.exitCode === 0 ? 'Completed' : `Failed`);
            document.getElementById('progress-fill').style.width = '100%';
            btn.disabled = false;
            btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg> Start scan';
            setTimeout(loadReports, 1000);
            break;
        case 'error':
            term.textContent += `\n[ERROR] ${msg.text}\n`;
            break;
    }
}

// Utilities
function esc(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
function timeAgo(d) {
    const s = Math.floor((Date.now() - d) / 1000);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s/60)}m ago`;
    if (s < 86400) return `${Math.floor(s/3600)}h ago`;
    return d.toLocaleDateString('id-ID');
}
function sevOrd(s) { return { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }[s] || 4; }
function modName(k) {
    return {
        headers: 'HTTP Security Headers', ssl: 'SSL/TLS Certificate',
        sensitive_files: 'Sensitive File Exposure', cms: 'CMS Detection',
        wordpress: 'WordPress Plugin Scanner', sqli_advanced: 'Advanced SQL Injection',
        sqli: 'SQL Injection', xss: 'Reflected XSS', stored_xss: 'Stored XSS',
        csrf: 'CSRF Checker', open_redirect: 'Open Redirect',
        cors: 'CORS Misconfiguration', http_methods: 'HTTP Method Testing',
        info_leak: 'Information Leak', cookies: 'Cookie Deep Audit',
        clickjacking: 'Clickjacking Tester', dir_discovery: 'Directory Discovery',
        tech: 'Technology Fingerprint', security_txt: 'Security.txt & robots.txt',
        waf: 'WAF Detection', ports: 'Port Reconnaissance',
    }[k] || k;
}

// Init
loadReports();
connectWS();
setInterval(loadReports, 10000);
