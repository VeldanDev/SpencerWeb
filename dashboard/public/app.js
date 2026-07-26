let allReports = [];
let ws = null;

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

async function loadReports() {
    try {
        const res = await fetch('/api/reports');
        const data = await res.json();
        allReports = data.reports || [];
        renderOverview();
        renderReports();
    } catch (e) { console.error('Failed to load:', e); }
}

function gradeHint(g) {
    return { A: 'Sangat Baik', B: 'Baik', C: 'Cukup', D: 'Buruk', F: 'Sangat Buruk' }[g] || '';
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
            const avgGrade = avg >= 4.5 ? 'A' : avg >= 3.5 ? 'B' : avg >= 2.5 ? 'C' : avg >= 1.5 ? 'D' : 'F';
            document.getElementById('stat-avg-grade').textContent = avgGrade;
        }
    } else {
        document.getElementById('stat-last-scan').textContent = '—';
        document.getElementById('stat-avg-grade').textContent = '—';
    }

    const el = document.getElementById('recent-scans');
    el.innerHTML = allReports.length === 0
        ? empty('Belum ada pemindaian', 'Mulai audit keamanan pertama Anda dari menu Pemindaian Baru')
        : allReports.slice(0, 6).map(reportRow).join('');
}

function renderReports() {
    const el = document.getElementById('all-reports');
    el.innerHTML = allReports.length === 0
        ? empty('Belum ada laporan', 'Laporan akan muncul di sini setelah pemindaian selesai')
        : allReports.map(reportRow).join('');
}

function reportRow(r) {
    const g = r.grade || '?';
    const gc = g === '?' ? 'grade-q' : `grade-${g}`;
    const hint = gradeHint(g);
    return `
    <div class="report-row" onclick="openReport('${esc(r.filename)}')">
        <div class="grade-badge ${gc}">
            <span class="grade-badge-letter">${g}</span>
            ${hint ? `<span class="grade-badge-hint">${hint}</span>` : ''}
        </div>
        <div class="report-info">
            <h3>${esc(r.target || 'Tidak diketahui')}</h3>
            <div class="report-meta">
                <span class="report-meta-item">Skor ${r.score || 0}/100</span>
                <span class="report-meta-item">${(r.total_checks || 0) - (r.total_failed || 0)}/${r.total_checks || 0} lolos</span>
                <span class="report-meta-item">${r.total_failed || 0} temuan</span>
                <span class="report-meta-item">${r.duration ? r.duration + ' detik' : '—'}</span>
                <span class="report-meta-item">${timeAgo(new Date(r.timestamp))}</span>
            </div>
        </div>
        <div class="report-actions">
            <button class="btn-pdf" onclick="event.stopPropagation(); unduhPdf('${esc(r.filename)}', this)">Unduh PDF</button>
            <button class="btn-delete" onclick="event.stopPropagation(); deleteReport('${esc(r.filename)}')">Hapus</button>
        </div>
    </div>`;
}

function empty(title, desc) {
    return `<div class="empty">
        <div class="empty-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>
        </div>
        <h3>${title}</h3>
        <p>${desc}</p>
    </div>`;
}

async function openReport(filename) {
    try {
        const res = await fetch(`/api/reports/${filename}`);
        const data = await res.json();
        renderDetail(data, filename);
        document.getElementById('report-modal').style.display = 'flex';
    } catch (e) { alert('Gagal memuat laporan'); }
}

function renderDetail(data, filename) {
    const info = data.scan_info || {};
    const grade = data.grade || {};
    const g = grade.grade || '?';
    const gc = g === '?' ? 'grade-q' : `grade-${g}`;
    const hint = gradeHint(g);
    const findings = data.all_findings || [];
    const fails = findings.filter(f => f.status === 'FAIL')
        .sort((a, b) => (sevOrd(a.severity) - sevOrd(b.severity)));
    const stats = data.statistics || {};

    const sevCounts = {};
    fails.forEach(f => { sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1; });

    document.getElementById('report-detail').innerHTML = `
        <div class="modal-header">
            <div class="grade-badge grade-hero ${gc}">
                <span class="grade-badge-letter">${g}</span>
                ${hint ? `<span class="grade-badge-hint">${hint}</span>` : ''}
            </div>
            <div class="modal-header-info">
                <h2>${esc(info.target || '')}</h2>
                <p>Skor: ${grade.score || 0}/100 &middot; ${esc(grade.summary || '')}</p>
                <p class="modal-date">${info.timestamp ? new Date(info.timestamp).toLocaleString('id-ID') : ''}</p>
            </div>
            <div class="modal-header-actions">
                <button class="btn-pdf" onclick="unduhPdf('${esc(filename || '')}', this)">Unduh Hasil (PDF)</button>
            </div>
        </div>

        <div class="detail-metrics">
            <div class="detail-metric">
                <div class="detail-metric-value">${stats.total_checks || 0}</div>
                <div class="detail-metric-label">Total Pemeriksaan</div>
            </div>
            <div class="detail-metric">
                <div class="detail-metric-value" style="color:var(--success)">${stats.total_passed || 0}</div>
                <div class="detail-metric-label">Lolos</div>
            </div>
            <div class="detail-metric">
                <div class="detail-metric-value" style="color:var(--danger)">${stats.total_failed || 0}</div>
                <div class="detail-metric-label">Gagal</div>
            </div>
            <div class="detail-metric">
                <div class="detail-metric-value">${info.scan_duration_seconds || 0} dtk</div>
                <div class="detail-metric-label">Durasi</div>
            </div>
        </div>

        ${fails.length > 0 ? `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:20px;">
            ${Object.entries(sevCounts).sort((a,b) => sevOrd(a[0]) - sevOrd(b[0])).map(([sev, count]) =>
                `<span class="sev-pill sev-${sev.toLowerCase()}">${count} ${sevLabel(sev)}</span>`
            ).join('')}
        </div>` : ''}

        <h3 style="font-size:17px;font-weight:600;margin:24px 0 14px;letter-spacing:-0.2px;">Kerentanan Ditemukan (${fails.length})</h3>
        ${fails.length === 0 ? '<p style="color:var(--text-muted);padding:32px;text-align:center;background:var(--bg);border-radius:var(--radius);font-size:14px;">Tidak ditemukan kerentanan. Situs ini aman.</p>' :
        fails.map(f => `
            <div class="finding sev-${f.severity}">
                <div class="finding-top">
                    <span class="finding-name">${esc(f.check || '')}</span>
                    <span class="sev-tag ${f.severity}">${sevLabel(f.severity)}</span>
                </div>
                <div class="finding-detail">${esc(f.detail || '')}</div>
                ${f.recommendation ? `<div class="finding-rec">${esc(f.recommendation)}</div>` : ''}
            </div>`).join('')}

        <h3 style="font-size:17px;font-weight:600;margin:28px 0 14px;letter-spacing:-0.2px;">Modul Pemindaian</h3>
        ${Object.entries(data.modules || {}).map(([k, m]) => `
            <div class="mod-section">
                <h4>${modName(k)}</h4>
                ${m.error ? `<p class="mod-stats">Kesalahan: ${esc(m.error)}</p>` :
                `<p class="mod-stats">Lolos: <strong style="color:var(--success)">${m.passed||0}</strong> &middot; Gagal: <strong style="color:var(--danger)">${m.failed||0}</strong></p>`}
            </div>`).join('')}`;
}

document.getElementById('modal-close').addEventListener('click', () => {
    document.getElementById('report-modal').style.display = 'none';
});
document.getElementById('report-modal').addEventListener('click', (e) => {
    if (e.target.id === 'report-modal') document.getElementById('report-modal').style.display = 'none';
});

async function unduhPdf(filename, btn) {
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = 'Membuat PDF...';
    try {
        const res = await fetch(`/api/reports/${encodeURIComponent(filename)}/pdf`);
        if (!res.ok) {
            let msg = 'Gagal mengunduh PDF';
            try { msg = (await res.json()).error || msg; } catch (e) {}
            throw new Error(msg);
        }
        const blob = await res.blob();

        const disposition = res.headers.get('Content-Disposition') || '';
        const match = disposition.match(/filename="?([^"]+)"?/);
        const pdfName = match ? match[1] : filename.replace(/^spencer_v2_/, 'spencer_').replace(/\.json$/i, '.pdf');

        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = pdfName;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    } catch (e) {
        alert(`Kesalahan: ${e.message}`);
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function deleteReport(filename) {
    if (!confirm(`Hapus laporan "${filename}"?`)) return;
    await fetch(`/api/reports/${filename}`, { method: 'DELETE' });
    loadReports();
}

document.getElementById('start-scan-btn').addEventListener('click', async () => {
    const target = document.getElementById('target-url').value.trim();
    if (!target) return alert('Masukkan URL target terlebih dahulu');

    const mode = document.querySelector('input[name="mode"]:checked').value;
    const skipPorts = document.getElementById('skip-ports').checked;
    const skipActive = document.getElementById('skip-active').checked;

    const btn = document.getElementById('start-scan-btn');
    btn.disabled = true;
    btn.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg> Memindai...';

    document.getElementById('scan-output-card').style.display = 'block';
    document.getElementById('terminal').textContent = '';
    document.getElementById('progress-fill').style.width = '0%';
    document.getElementById('current-module').textContent = '';
    setStatus('running', 'Berjalan');

    try {
        const res = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, mode, skipPorts, skipActive })
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Pemindaian gagal');
    } catch (e) {
        alert(`Kesalahan: ${e.message}`);
        btn.disabled = false;
        btn.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg> Mulai Pemindaian';
        setStatus('error', 'Gagal');
    }
});

function setStatus(state, text) {
    const el = document.getElementById('scan-status');
    el.className = `status-pill ${state}`;
    el.textContent = text;
}

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
            term.textContent += `[SpencerWeb] Pemindaian dimulai untuk ${msg.target}\n`;
            break;
        case 'output':
            term.textContent += msg.text;
            term.scrollTop = term.scrollHeight;
            break;
        case 'module_started':
            document.getElementById('progress-fill').style.width = `${msg.progress}%`;
            document.getElementById('current-module').textContent = `Modul ${msg.module}: ${msg.title}`;
            break;
        case 'scan_finished':
            setStatus(msg.exitCode === 0 ? 'success' : 'error',
                msg.exitCode === 0 ? 'Selesai' : 'Gagal');
            document.getElementById('progress-fill').style.width = '100%';
            btn.disabled = false;
            btn.innerHTML = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg> Mulai Pemindaian';
            setTimeout(loadReports, 1000);
            break;
        case 'error':
            term.textContent += `\n[KESALAHAN] ${msg.text}\n`;
            break;
    }
}

function esc(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
function timeAgo(d) {
    const s = Math.floor((Date.now() - d) / 1000);
    if (s < 60) return `${s} detik lalu`;
    if (s < 3600) return `${Math.floor(s/60)} menit lalu`;
    if (s < 86400) return `${Math.floor(s/3600)} jam lalu`;
    return d.toLocaleDateString('id-ID');
}
function sevOrd(s) { return { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }[s] || 4; }
function sevLabel(s) {
    return { CRITICAL: 'Kritis', HIGH: 'Tinggi', MEDIUM: 'Sedang', LOW: 'Rendah', INFO: 'Info' }[s] || s;
}
function modName(k) {
    return {
        headers: 'Header Keamanan HTTP', ssl: 'Sertifikat SSL/TLS',
        sensitive_files: 'Paparan File Sensitif', cms: 'Deteksi CMS',
        wordpress: 'Pemindai Plugin WordPress', sqli_advanced: 'SQL Injection Lanjutan',
        sqli: 'SQL Injection', xss: 'Reflected XSS', stored_xss: 'Stored XSS',
        csrf: 'Pemeriksaan CSRF', open_redirect: 'Open Redirect',
        cors: 'Miskonfigurasi CORS', http_methods: 'Pengujian Metode HTTP',
        info_leak: 'Kebocoran Informasi', cookies: 'Audit Mendalam Cookie',
        clickjacking: 'Pengujian Clickjacking', dir_discovery: 'Penemuan Direktori',
        tech: 'Sidik Jari Teknologi', security_txt: 'Security.txt & robots.txt',
        waf: 'Deteksi WAF', ports: 'Rekognisi Port',
    }[k] || k;
}

loadReports();
connectWS();
setInterval(loadReports, 10000);
