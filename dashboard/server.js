/**
 * Spencer v2.0 — Dashboard Server (Node.js + Express)
 * Web UI untuk menampilkan hasil scan Spencer
 *
 * Endpoints:
 *   GET  /                  → Dashboard UI
 *   GET  /api/reports       → List semua scan reports
 *   GET  /api/reports/:file → Get specific report JSON
 *   POST /api/scan          → Trigger new scan (executes Python main.py)
 *   GET  /api/scan/status   → Get current scan status (via WebSocket)
 *
 * Author: TA Teknik Komputer — Politeknik Negeri Medan
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const { spawn, spawnSync, execFile } = require('child_process');
const http = require('http');
const WebSocket = require('ws');

const app = express();
const PORT = process.env.PORT || 3000;

// Path ke folder reports (Python scanner output)
const REPORTS_DIR = path.join(__dirname, '..', 'reports');
const PROJECT_ROOT = path.join(__dirname, '..');
const MAKE_PDF_SCRIPT = path.join(PROJECT_ROOT, 'tools', 'make_pdf.py');

// ─── Pilih interpreter Python untuk generate PDF ──────
// Prioritaskan venv (bila ada DAN reportlab terpasang di sana),
// fallback ke Python global. reportlab belum tentu ada di venv.
function hasReportlab(pythonExec) {
    try {
        const r = spawnSync(pythonExec, ['-c', 'import reportlab'], { encoding: 'utf-8' });
        return r.status === 0;
    } catch (e) {
        return false;
    }
}

function resolvePdfPython() {
    const venvPython = process.platform === 'win32'
        ? path.join(PROJECT_ROOT, 'venv', 'Scripts', 'python.exe')
        : path.join(PROJECT_ROOT, 'venv', 'bin', 'python');

    if (fs.existsSync(venvPython) && hasReportlab(venvPython)) {
        return venvPython;
    }
    if (hasReportlab('python')) {
        return 'python';
    }
    return null; // reportlab tidak ditemukan di interpreter manapun
}

const PDF_PYTHON = resolvePdfPython();
console.log(`[PDF] Python untuk generate PDF: ${PDF_PYTHON || 'TIDAK TERSEDIA (reportlab belum terpasang)'}`);

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// HTTP server + WebSocket untuk real-time scan progress
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// State: current scan progress
let currentScan = null;

// ─── Routes ───────────────────────────────────────────

// Dashboard UI
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// List semua reports
app.get('/api/reports', (req, res) => {
    try {
        if (!fs.existsSync(REPORTS_DIR)) {
            return res.json({ reports: [] });
        }
        
        const files = fs.readdirSync(REPORTS_DIR)
            .filter(f => f.endsWith('.json'))
            .map(f => {
                const filepath = path.join(REPORTS_DIR, f);
                const stat = fs.statSync(filepath);
                try {
                    const data = JSON.parse(fs.readFileSync(filepath, 'utf-8'));
                    return {
                        filename: f,
                        size: stat.size,
                        modified: stat.mtime,
                        target: data.scan_info?.target || 'Unknown',
                        grade: data.grade?.grade || '?',
                        score: data.grade?.score || 0,
                        total_checks: data.statistics?.total_checks || 0,
                        total_failed: data.statistics?.total_failed || 0,
                        timestamp: data.scan_info?.timestamp || stat.mtime,
                        duration: data.scan_info?.scan_duration_seconds || 0,
                        tool_version: data.scan_info?.tool || 'Spencer'
                    };
                } catch (e) {
                    return { filename: f, error: 'Failed to parse', modified: stat.mtime };
                }
            })
            .sort((a, b) => new Date(b.modified) - new Date(a.modified));
        
        res.json({ reports: files });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Get specific report
app.get('/api/reports/:filename', (req, res) => {
    try {
        const safeName = path.basename(req.params.filename);
        const filepath = path.join(REPORTS_DIR, safeName);
        
        // Security: prevent path traversal
        if (!filepath.startsWith(REPORTS_DIR)) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        
        if (!fs.existsSync(filepath)) {
            return res.status(404).json({ error: 'Report not found' });
        }
        
        const data = JSON.parse(fs.readFileSync(filepath, 'utf-8'));
        res.json(data);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Unduh laporan sebagai PDF — generate on-demand bila PDF belum ada
app.get('/api/reports/:filename/pdf', (req, res) => {
    const safeName = path.basename(req.params.filename);
    const jsonPath = path.join(REPORTS_DIR, safeName);

    // Security: cegah path traversal
    if (!jsonPath.startsWith(REPORTS_DIR) || !safeName.toLowerCase().endsWith('.json')) {
        return res.status(403).json({ error: 'Akses ditolak' });
    }

    if (!fs.existsSync(jsonPath)) {
        return res.status(404).json({ error: 'Laporan tidak ditemukan' });
    }

    // Petakan nama JSON -> PDF sesuai pola penamaan reports/:
    //   spencer_v2_{domain}_{timestamp}.json -> spencer_{domain}_{timestamp}.pdf
    const pdfName = safeName.startsWith('spencer_v2_')
        ? 'spencer_' + safeName.slice('spencer_v2_'.length).replace(/\.json$/i, '.pdf')
        : safeName.replace(/\.json$/i, '.pdf');
    const pdfPath = path.join(REPORTS_DIR, pdfName);

    if (!pdfPath.startsWith(REPORTS_DIR)) {
        return res.status(403).json({ error: 'Akses ditolak' });
    }

    // Sudah ada -> langsung kirim
    if (fs.existsSync(pdfPath)) {
        return res.download(pdfPath, pdfName, (err) => {
            if (err && !res.headersSent) {
                res.status(500).json({ error: 'Gagal mengirim berkas PDF' });
            }
        });
    }

    // Belum ada -> generate on-demand via tools/make_pdf.py
    if (!PDF_PYTHON) {
        return res.status(501).json({ error: 'reportlab tidak terpasang di server. Jalankan: pip install reportlab' });
    }

    execFile(PDF_PYTHON, [MAKE_PDF_SCRIPT, jsonPath], { cwd: PROJECT_ROOT }, (err, stdout, stderr) => {
        if (err) {
            if (err.code === 2) {
                return res.status(501).json({ error: 'reportlab tidak terpasang di server. Jalankan: pip install reportlab' });
            }
            console.error('[PDF] Gagal generate:', (stderr || err.message).trim());
            return res.status(500).json({ error: 'Gagal membuat PDF: ' + (stderr || err.message).trim() });
        }

        const outPath = stdout.trim().split('\n').pop().trim();
        if (!outPath || !fs.existsSync(outPath)) {
            return res.status(500).json({ error: 'PDF gagal dibuat' });
        }

        res.download(outPath, path.basename(outPath), (dlErr) => {
            if (dlErr && !res.headersSent) {
                res.status(500).json({ error: 'Gagal mengirim berkas PDF' });
            }
        });
    });
});

// Delete report
app.delete('/api/reports/:filename', (req, res) => {
    try {
        const safeName = path.basename(req.params.filename);
        const filepath = path.join(REPORTS_DIR, safeName);
        if (!filepath.startsWith(REPORTS_DIR)) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        if (fs.existsSync(filepath)) {
            fs.unlinkSync(filepath);
        }
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// Trigger new scan
app.post('/api/scan', (req, res) => {
    if (currentScan && !currentScan.finished) {
        return res.status(409).json({ error: 'Scan already in progress' });
    }
    
    const { target, mode = 'standard', skipPorts = false, skipActive = false } = req.body;
    
    if (!target) {
        return res.status(400).json({ error: 'Target URL required' });
    }
    
    // Build python command args
    const args = ['main.py', target];
    if (mode === 'quick') args.push('--quick');
    if (mode === 'deep') args.push('--deep');
    if (skipPorts) args.push('--skip-ports');
    if (skipActive) args.push('--skip-active');
    
    // Detect python executable
    const pythonCmd = process.platform === 'win32' 
        ? path.join(PROJECT_ROOT, 'venv', 'Scripts', 'python.exe')
        : path.join(PROJECT_ROOT, 'venv', 'bin', 'python');
    
    const pythonExec = fs.existsSync(pythonCmd) ? pythonCmd : 'python';
    
    currentScan = {
        target,
        startTime: Date.now(),
        finished: false,
        output: [],
        currentModule: '',
        progress: 0
    };
    
    broadcastStatus({ type: 'scan_started', target, mode });
    
    const proc = spawn(pythonExec, args, { 
        cwd: PROJECT_ROOT,
        env: { ...process.env, PYTHONIOENCODING: 'utf-8' }
    });
    
    proc.stdout.on('data', (data) => {
        const text = data.toString();
        currentScan.output.push(text);
        
        // Detect module headers untuk progress tracking
        const moduleMatch = text.match(/\[MODULE (\d+)\]\s*(.+)/);
        if (moduleMatch) {
            currentScan.currentModule = moduleMatch[2].trim();
            currentScan.progress = (parseInt(moduleMatch[1]) / 10) * 100;
            broadcastStatus({
                type: 'module_started',
                module: parseInt(moduleMatch[1]),
                title: currentScan.currentModule,
                progress: currentScan.progress
            });
        }
        
        // Clean ANSI codes untuk live output
        const clean = text.replace(/\x1b\[[0-9;]*m/g, '');
        broadcastStatus({ type: 'output', text: clean });
    });
    
    proc.stderr.on('data', (data) => {
        broadcastStatus({ type: 'error', text: data.toString() });
    });
    
    proc.on('close', (code) => {
        currentScan.finished = true;
        currentScan.exitCode = code;
        currentScan.endTime = Date.now();
        
        broadcastStatus({
            type: 'scan_finished',
            exitCode: code,
            duration: currentScan.endTime - currentScan.startTime
        });
    });
    
    res.json({ success: true, message: 'Scan started' });
});

// Scan status
app.get('/api/scan/status', (req, res) => {
    res.json(currentScan || { finished: true, idle: true });
});

// WebSocket broadcast
function broadcastStatus(msg) {
    const data = JSON.stringify(msg);
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(data);
        }
    });
}

wss.on('connection', (ws) => {
    console.log('[WS] Client connected');
    if (currentScan) {
        ws.send(JSON.stringify({
            type: 'current_status',
            scan: {
                target: currentScan.target,
                finished: currentScan.finished,
                currentModule: currentScan.currentModule,
                progress: currentScan.progress
            }
        }));
    }
    
    ws.on('close', () => console.log('[WS] Client disconnected'));
});

// ─── Start server ─────────────────────────────────────

server.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════╗
║   Spencer Dashboard v2.0                         ║
║   Running on http://localhost:${PORT}              ║
╚══════════════════════════════════════════════════╝
    `);
    console.log(`Reports directory: ${REPORTS_DIR}`);
});
