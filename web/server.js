#!/usr/bin/env node
'use strict';

const express = require('express');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const { spawn } = require('child_process');
const { v4: uuidv4 } = require('uuid');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const archiver = require('archiver');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const PORT = process.env.PORT || 3000;
const HTTPS_PORT = process.env.HTTPS_PORT || 3443;
const DATA_DIR = path.join(__dirname, '..', 'data');
const JOBS_DIR = path.join(DATA_DIR, 'jobs');
const TEMPLATES_DIR = path.join(__dirname, '..', 'templates');
const SCRIPTS_DIR = path.join(__dirname, '..', 'python_scripts');
const TMAS_SCRIPTS_DIR = path.join(__dirname, '..', 'scripts');
const HISTORY_FILE = path.join(DATA_DIR, 'history.json');

// Ensure directories exist
[DATA_DIR, JOBS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

const app = express();

// Security headers
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: 60, standardHeaders: true });
const runLimiter = rateLimit({ windowMs: 60 * 1000, max: 5, message: { error: 'Too many requests. Please wait.' } });
app.use('/api/', apiLimiter);
app.use('/api/assessment/run', runLimiter);
app.use('/api/aiscan/run', runLimiter);

// File upload (CSV, max 2MB)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 } });

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ─── In-memory job tracking ─────────────────────────────────────────────────
const jobs = new Map();

function createJob(type, meta = {}) {
  const id = uuidv4().slice(0, 8);
  const jobDir = path.join(JOBS_DIR, id);
  fs.mkdirSync(jobDir, { recursive: true });
  fs.mkdirSync(path.join(jobDir, 'excel'), { recursive: true });
  const job = {
    id, type, status: 'running', progress: 0, total: 0, current: '',
    startedAt: Date.now(), console: [], results: null, error: null, ...meta,
  };
  jobs.set(id, job);
  saveJobState(id);
  return job;
}

function updateJob(id, updates) {
  const job = jobs.get(id);
  if (!job) return;
  Object.assign(job, updates);
  saveJobState(id);
}

function saveJobState(id) {
  const job = jobs.get(id);
  if (!job) return;
  const statePath = path.join(JOBS_DIR, id, 'state.json');
  const { console: _, ...state } = job;
  try { fs.writeFileSync(statePath, JSON.stringify(state, null, 2)); } catch (e) { /* ignore */ }
}

// ─── History persistence ────────────────────────────────────────────────────
function loadHistory() {
  try {
    if (fs.existsSync(HISTORY_FILE)) return JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf-8'));
  } catch (e) { /* ignore */ }
  return [];
}

function saveHistory(history) {
  try { fs.writeFileSync(HISTORY_FILE, JSON.stringify(history.slice(-200), null, 2)); } catch (e) { /* ignore */ }
}

function addHistoryEntry(entry) {
  const history = loadHistory();
  history.push({ ...entry, timestamp: new Date().toISOString() });
  saveHistory(history);
}

// ─── Helper: spawn Python with JSON marker parsing ──────────────────────────
function spawnPython(scriptPath, args, env, jobId, onProgress, timeoutMs = 7200000) {
  return new Promise((resolve, reject) => {
    const job = jobs.get(jobId);
    const proc = spawn('python3', [scriptPath, ...args], {
      env: { ...process.env, ...env },
      cwd: path.join(__dirname, '..'),
    });

    let stdout = '';
    let jsonResult = null;

    // Kill process after timeout (default 2h)
    const timer = setTimeout(() => {
      proc.kill('SIGTERM');
      if (job) job.console.push({ type: 'stderr', text: `Process killed after ${timeoutMs/1000}s timeout\n`, ts: Date.now() });
    }, timeoutMs);

    proc.stdout.on('data', (data) => {
      const text = data.toString();
      stdout += text;
      if (job) job.console.push({ type: 'stdout', text, ts: Date.now() });

      for (const line of text.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.type === 'progress' && onProgress) onProgress(obj);
          if (obj.type === 'complete') jsonResult = obj;
        } catch (e) { /* not JSON */ }
      }
    });

    proc.stderr.on('data', (data) => {
      const text = data.toString();
      if (job) job.console.push({ type: 'stderr', text, ts: Date.now() });
    });

    proc.on('close', (code) => {
      clearTimeout(timer);
      if (!jsonResult) {
        const startMarker = '---JSON_START---';
        const endMarker = '---JSON_END---';
        const si = stdout.indexOf(startMarker);
        const ei = stdout.indexOf(endMarker);
        if (si !== -1 && ei !== -1) {
          try { jsonResult = JSON.parse(stdout.slice(si + startMarker.length, ei)); } catch (e) { /* ignore */ }
        }
      }
      resolve({ code, result: jsonResult, stdout });
    });

    proc.on('error', (err) => { clearTimeout(timer); reject(err); });

    if (job) job._proc = proc;
  });
}

// ═══════════════════════════════════════════════════════════════════════════════
// API ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Health ─────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), jobs: jobs.size });
});

// ─── Config ─────────────────────────────────────────────────────────────────
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');

app.get('/api/config', (req, res) => {
  try {
    const config = fs.existsSync(CONFIG_FILE) ? JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8')) : {};
    res.json({ visionOneBaseUrl: config.visionOneBaseUrl || 'https://api.eu.xdr.trendmicro.com', hasServerKey: !!process.env.TREND_MICRO_API_KEY });
  } catch (e) { res.json({ visionOneBaseUrl: 'https://api.eu.xdr.trendmicro.com', hasServerKey: false }); }
});

app.post('/api/config', (req, res) => {
  const { visionOneBaseUrl } = req.body;
  const config = { visionOneBaseUrl };
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
  res.json({ success: true });
});

// ─── Pre-built Searches ─────────────────────────────────────────────────────
app.get('/api/searches/prebuilt', (req, res) => {
  try {
    const csvPath = path.join(TEMPLATES_DIR, 'input.csv');
    if (!fs.existsSync(csvPath)) return res.status(404).json({ error: 'input.csv not found' });
    const content = fs.readFileSync(csvPath, 'utf-8');
    const lines = content.trim().split('\n');
    const headers = lines[0].split(',').map(h => h.trim());
    const searches = lines.slice(1).map(line => {
      const values = parseCSVLine(line);
      const obj = {};
      headers.forEach((h, i) => { obj[h] = values[i] || ''; });
      return obj;
    });
    res.json({ searches, headers });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Simple CSV line parser (handles quoted fields)
function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') { inQuotes = !inQuotes; }
    else if (ch === ',' && !inQuotes) { result.push(current.trim()); current = ''; }
    else { current += ch; }
  }
  result.push(current.trim());
  return result;
}

// ─── CSV Upload & Validation ────────────────────────────────────────────────
app.post('/api/csv/upload', upload.single('csv'), (req, res) => {
  try {
    const content = req.file ? req.file.buffer.toString('utf-8') : req.body.csvContent;
    if (!content) return res.status(400).json({ error: 'No CSV content provided' });

    const lines = content.trim().split('\n');
    if (lines.length < 2) return res.status(400).json({ error: 'CSV must have header + at least 1 row' });

    const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
    const required = ['name', 'query'];
    const missing = required.filter(r => !headers.includes(r));
    if (missing.length) return res.status(400).json({ error: `Missing required columns: ${missing.join(', ')}` });

    const searches = [];
    const warnings = [];
    for (let i = 1; i < lines.length; i++) {
      const values = parseCSVLine(lines[i]);
      const obj = {};
      headers.forEach((h, j) => { obj[h] = values[j] || ''; });
      if (!obj.name) warnings.push(`Row ${i}: missing name`);
      if (!obj.query) warnings.push(`Row ${i}: missing query`);
      else if (!obj.query.includes(':')) warnings.push(`Row ${i}: query may be invalid (no field operator)`);
      searches.push({ ...obj, enabled: (obj.enabled || 'true').toLowerCase() !== 'false' });
    }

    res.json({ valid: warnings.length === 0, searches, warnings, headers });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ─── CSV Template Download ──────────────────────────────────────────────────
app.get('/api/csv/template/:category?', (req, res) => {
  const category = req.params.category || 'basic';
  const templates = {
    basic: `name,description,sorting,log_type,orientation,query
AI_Usage_OpenAI,Monitor OpenAI API and ChatGPT usage,hostnameDNS,network,vertical,"hostName:(api.openai.com OR chat.openai.com OR platform.openai.com)"
Suspicious_Ports,Monitor commonly exploited ports,default,network,horizontal,"dstPort:(22 OR 3389 OR 5900 OR 1433 OR 3306)"`,
    ai_services: `name,description,sorting,log_type,orientation,query
OpenAI_Usage,Monitor OpenAI services,hostnameDNS,network,vertical,"hostName:(*.openai.com)"
GitHub_Copilot,Monitor GitHub Copilot,hostnameDNS,network,vertical,"hostName:(*.copilot.github.com OR *.api.github.com)"
Claude_AI,Monitor Anthropic Claude,hostnameDNS,network,vertical,"hostName:(*.claude.ai OR *.anthropic.com)"
Google_AI,Monitor Google AI services,hostnameDNS,network,vertical,"hostName:(*.bard.google.com OR *.generativelanguage.googleapis.com)"`,
    cloud_storage: `name,description,sorting,log_type,orientation,query
Dropbox,Monitor Dropbox,hostnameDNS,network,vertical,"hostName:(*.dropbox.com)"
Google_Drive,Monitor Google Drive,hostnameDNS,network,vertical,"hostName:(*.drive.google.com OR *.docs.google.com)"
OneDrive,Monitor OneDrive/SharePoint,hostnameDNS,network,vertical,"hostName:(*.onedrive.live.com OR *.sharepoint.com)"`,
    remote_access: `name,description,sorting,log_type,orientation,query
TeamViewer,Monitor TeamViewer,hostnameDNS,network,vertical,"hostName:(*.teamviewer.com) OR dstPort:(5938)"
AnyDesk,Monitor AnyDesk,hostnameDNS,network,vertical,"hostName:(*.anydesk.com) OR dstPort:(7070)"
RDP_External,Monitor external RDP,serverIp,network,horizontal,"app:RDP AND dstPort:(3389)"`,
    geographic: `name,description,sorting,log_type,orientation,query
China_Connections,Connections to Chinese TLDs,hostName,network,horizontal,"hostName:(*.cn)"
Russia_Connections,Connections to Russian TLDs,hostName,network,horizontal,"hostName:(*.ru)"
Sanctioned_States,Connections to sanctioned countries,hostName,network,horizontal,"hostName:(*.kp OR *.ru OR *.cu OR *.by OR *.sy OR *.ir)"`,
  };
  const csv = templates[category] || templates.basic;
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="search_template_${category}.csv"`);
  res.send(csv);
});

// ─── Assessment: Run ────────────────────────────────────────────────────────
app.post('/api/assessment/run', async (req, res) => {
  const { apiKey, baseUrl, timeInterval, searches, csvContent } = req.body;
  if (!apiKey) return res.status(400).json({ error: 'API key required' });

  // Validate inputs
  const ti = parseInt(timeInterval) || 720;
  if (ti < 1 || ti > 8760) return res.status(400).json({ error: 'Time interval must be 1-8760 hours' });
  if (searches && searches.length > 100) return res.status(400).json({ error: 'Max 100 searches per assessment' });
  if (csvContent && csvContent.length > 500000) return res.status(400).json({ error: 'CSV too large (max 500KB)' });

  const job = createJob('assessment', { total: (searches || []).length });

  // Write CSV for this job
  const jobDir = path.join(JOBS_DIR, job.id);
  let csvPath;
  if (csvContent) {
    csvPath = path.join(jobDir, 'custom_input.csv');
    fs.writeFileSync(csvPath, csvContent);
  } else if (searches && searches.length > 0) {
    csvPath = path.join(jobDir, 'input.csv');
    const headers = 'name,description,sorting,log_type,orientation,query';
    const rows = searches.map(s =>
      `${s.name},"${(s.description || '').replace(/"/g, '""')}",${s.sorting || 'default'},${s.log_type || 'network'},${s.orientation || 'horizontal'},"${(s.query || '').replace(/"/g, '""')}"`
    );
    fs.writeFileSync(csvPath, [headers, ...rows].join('\n'));
    updateJob(job.id, { total: searches.length });
  } else {
    csvPath = path.join(TEMPLATES_DIR, 'input.csv');
  }

  res.json({ jobId: job.id });

  // Run assessment asynchronously
  try {
    const scriptPath = path.join(SCRIPTS_DIR, 'run_assessment.py');
    const args = [
      '--csv', csvPath,
      '--output', jobDir,
      '--time-interval', String(timeInterval || 720),
    ];
    const env = {
      TREND_MICRO_API_KEY: apiKey,
      TREND_MICRO_BASE_URL: baseUrl || 'https://api.eu.xdr.trendmicro.com',
    };

    const { code, result } = await spawnPython(scriptPath, args, env, job.id, (progress) => {
      updateJob(job.id, {
        progress: progress.current || 0,
        total: progress.total || job.total,
        current: progress.name || '',
      });
    });

    if (code === 0 && result) {
      updateJob(job.id, { status: 'completed', results: result, finishedAt: Date.now() });
    } else {
      updateJob(job.id, { status: code === 0 ? 'completed' : 'failed', finishedAt: Date.now(), results: result });
    }
    addHistoryEntry({ type: 'assessment', jobId: job.id, status: job.status, searches: job.total });
  } catch (e) {
    updateJob(job.id, { status: 'failed', error: e.message, finishedAt: Date.now() });
  }
});

// ─── Assessment: Status / Results / Download ────────────────────────────────
app.get('/api/assessment/status/:jobId', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) {
    // Check if job exists on disk (after server restart)
    const statePath = path.join(JOBS_DIR, req.params.jobId, 'state.json');
    if (fs.existsSync(statePath)) {
      try {
        const state = JSON.parse(fs.readFileSync(statePath, 'utf-8'));
        return res.json({ ...state, console: '' });
      } catch (e) { /* fall through */ }
    }
    return res.status(404).json({ error: 'Job not found' });
  }
  const { _proc, console: lines, ...safe } = job;
  const recentConsole = lines.slice(-50).map(l => l.text).join('');
  res.json({ ...safe, console: recentConsole });
});

app.get('/api/assessment/results/:jobId', (req, res) => {
  const jobDir = path.join(JOBS_DIR, req.params.jobId);
  if (!fs.existsSync(jobDir)) return res.status(404).json({ error: 'Job not found' });

  const job = jobs.get(req.params.jobId);
  const summaryPath = path.join(jobDir, 'summary.json');

  // Read summary.json (persisted by Python script - survives server restarts)
  let summary = null;
  if (fs.existsSync(summaryPath)) {
    try { summary = JSON.parse(fs.readFileSync(summaryPath, 'utf-8')); } catch (e) { /* ignore */ }
  }
  // Fallback: extract from in-memory job results
  if (!summary && job && job.results) {
    summary = job.results.summary || job.results;
  }

  // List Excel files
  const excelDir = path.join(jobDir, 'excel');
  let excelFiles = [];
  if (fs.existsSync(excelDir)) {
    excelFiles = fs.readdirSync(excelDir).filter(f => f.endsWith('.xlsx')).map(f => ({
      name: f, size: fs.statSync(path.join(excelDir, f)).size,
    }));
  }

  const pptPath = path.join(jobDir, 'report.pptx');
  const hasPpt = fs.existsSync(pptPath);

  res.json({ status: job.status, summary, excelFiles, hasPpt });
});

app.get('/api/assessment/download/:jobId', (req, res) => {
  const jobDir = path.join(JOBS_DIR, req.params.jobId);
  if (!fs.existsSync(jobDir)) return res.status(404).json({ error: 'Job not found' });

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="security-assessment-${req.params.jobId}.zip"`);

  const archive = archiver('zip', { zlib: { level: 6 } });
  archive.on('error', (err) => res.status(500).json({ error: err.message }));
  archive.pipe(res);

  const excelDir = path.join(jobDir, 'excel');
  if (fs.existsSync(excelDir)) archive.directory(excelDir, 'excel');

  const pptPath = path.join(jobDir, 'report.pptx');
  if (fs.existsSync(pptPath)) archive.file(pptPath, { name: 'NDR_Security_Assessment_Report.pptx' });

  const summaryPath = path.join(jobDir, 'summary.json');
  if (fs.existsSync(summaryPath)) archive.file(summaryPath, { name: 'summary.json' });

  archive.finalize();
});

app.get('/api/assessment/excel/:jobId/:filename', (req, res) => {
  const filePath = path.join(JOBS_DIR, req.params.jobId, 'excel', path.basename(req.params.filename));
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'File not found' });
  res.download(filePath);
});

app.get('/api/assessment/ppt/:jobId', (req, res) => {
  const filePath = path.join(JOBS_DIR, req.params.jobId, 'report.pptx');
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'Report not found' });
  res.download(filePath, 'NDR_Security_Assessment_Report.pptx');
});

// ─── AI Scan: Run ───────────────────────────────────────────────────────────
app.post('/api/aiscan/run', async (req, res) => {
  const { provider, endpoint, model, llmApiKey, visionOneApiKey, region, preset, systemPrompt, timeout } = req.body;
  if (!visionOneApiKey) return res.status(400).json({ error: 'Vision One API key required' });

  const job = createJob('aiscan', { provider, model, preset });
  res.json({ jobId: job.id });

  try {
    const scriptPath = path.join(SCRIPTS_DIR, 'run_ai_scan.py');
    const args = [
      '--provider', provider || 'openai',
      '--model', model || 'gpt-4',
      '--preset', preset || 'owasp',
      '--region', region || 'eu-central-1',
      '--output', path.join(JOBS_DIR, job.id),
      '--timeout', String(timeout || 3600),
    ];
    if (endpoint) args.push('--endpoint', endpoint);
    if (systemPrompt) args.push('--system-prompt', systemPrompt);

    const env = {
      TMAS_API_KEY: visionOneApiKey,
      LLM_API_KEY: llmApiKey || 'not-needed',
    };

    const { code, result } = await spawnPython(scriptPath, args, env, job.id, (progress) => {
      updateJob(job.id, { current: progress.step || '' });
    });

    updateJob(job.id, {
      status: code === 0 ? 'completed' : 'failed',
      results: result, finishedAt: Date.now(),
    });
    addHistoryEntry({ type: 'aiscan', jobId: job.id, status: job.status, provider, model, preset });
  } catch (e) {
    updateJob(job.id, { status: 'failed', error: e.message, finishedAt: Date.now() });
  }
});

app.get('/api/aiscan/status/:jobId', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  const { _proc, console: lines, ...safe } = job;
  const recentConsole = lines.slice(-100).map(l => l.text).join('');
  res.json({ ...safe, console: recentConsole });
});

app.get('/api/aiscan/results/:jobId', (req, res) => {
  const job = jobs.get(req.params.jobId);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  const jobDir = path.join(JOBS_DIR, req.params.jobId);
  const resultPath = path.join(jobDir, 'scan_results.json');
  let results = job.results;
  if (!results && fs.existsSync(resultPath)) {
    try { results = JSON.parse(fs.readFileSync(resultPath, 'utf-8')); } catch (e) { /* ignore */ }
  }
  const htmlPath = path.join(jobDir, 'scan_report.html');
  const hasHtml = fs.existsSync(htmlPath);
  res.json({ status: job.status, results, hasHtml });
});

app.get('/api/aiscan/report/:jobId', (req, res) => {
  const htmlPath = path.join(JOBS_DIR, req.params.jobId, 'scan_report.html');
  if (!fs.existsSync(htmlPath)) return res.status(404).json({ error: 'Report not found' });
  res.sendFile(htmlPath);
});

// ─── GitHub Actions ─────────────────────────────────────────────────────────
const GH_REPOS = [
  'Angelmountain/tmas-ai-scanner',
  'Angelmountain/security-assesment',  // note: repo name has single 's'
];

app.get('/api/github/runs', (req, res) => {
  const repo = req.query.repo || GH_REPOS[0];
  if (!GH_REPOS.includes(repo)) return res.status(400).json({ error: 'Invalid repo' });

  const fields = 'databaseId,displayTitle,status,conclusion,headBranch,createdAt,updatedAt,event,workflowName';
  const limit = Math.min(parseInt(req.query.limit) || 20, 50);
  const proc = spawn('gh', ['run', 'list', '--repo', repo, '--json', fields, '--limit', String(limit)]);

  let stdout = '';
  let stderr = '';
  proc.stdout.on('data', d => stdout += d);
  proc.stderr.on('data', d => stderr += d);
  proc.on('close', code => {
    if (code === 0) {
      try { res.json(JSON.parse(stdout)); } catch (e) { res.status(500).json({ error: 'Parse error' }); }
    } else { res.status(500).json({ error: stderr || 'Failed to fetch runs' }); }
  });
});

app.get('/api/github/runs/:id', (req, res) => {
  const repo = req.query.repo || GH_REPOS[0];
  const proc = spawn('gh', ['run', 'view', req.params.id, '--repo', repo, '--json',
    'databaseId,displayTitle,status,conclusion,jobs,createdAt,updatedAt,headBranch,event,workflowName']);

  let stdout = '';
  proc.stdout.on('data', d => stdout += d);
  proc.on('close', code => {
    if (code === 0) {
      try { res.json(JSON.parse(stdout)); } catch (e) { res.status(500).json({ error: 'Parse error' }); }
    } else { res.status(500).json({ error: 'Failed to fetch run details' }); }
  });
});

app.get('/api/github/workflows', (req, res) => {
  const repo = req.query.repo || GH_REPOS[0];
  const proc = spawn('gh', ['workflow', 'list', '--repo', repo, '--json', 'id,name,state']);

  let stdout = '';
  proc.stdout.on('data', d => stdout += d);
  proc.on('close', code => {
    if (code === 0) {
      try { res.json(JSON.parse(stdout)); } catch (e) { res.status(500).json({ error: 'Parse error' }); }
    } else { res.status(500).json({ error: 'Failed to fetch workflows' }); }
  });
});

app.post('/api/github/dispatch/:workflow', (req, res) => {
  const repo = req.query.repo || GH_REPOS[0];
  if (!GH_REPOS.includes(repo)) return res.status(400).json({ error: 'Invalid repo' });

  const { inputs } = req.body;
  const workflowName = req.params.workflow.replace(/[^a-zA-Z0-9._-]/g, '');
  const args = ['workflow', 'run', workflowName, '--repo', repo];
  if (inputs) {
    for (const [key, val] of Object.entries(inputs)) {
      const safeKey = key.replace(/[^a-zA-Z0-9_]/g, '');
      args.push('-f', `${safeKey}=${String(val)}`);
    }
  }

  const proc = spawn('gh', args);
  let stderr = '';
  proc.stderr.on('data', d => stderr += d);
  proc.on('close', code => {
    if (code === 0) { res.json({ success: true }); }
    else { res.status(500).json({ error: stderr || 'Failed to dispatch workflow' }); }
  });
});

// ─── History ────────────────────────────────────────────────────────────────
app.get('/api/history', (req, res) => res.json(loadHistory()));
app.delete('/api/history', (req, res) => { saveHistory([]); res.json({ success: true }); });

// ─── SPA Fallback ───────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── Start Server ───────────────────────────────────────────────────────────
http.createServer(app).listen(PORT, '0.0.0.0', () => {
  console.log(`Security Assessment Platform running on http://0.0.0.0:${PORT}`);
});

// Optional HTTPS for local dev
const certPath = path.join(__dirname, 'certs', 'cert.pem');
const keyPath = path.join(__dirname, 'certs', 'key.pem');
if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
  const sslOptions = { key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) };
  https.createServer(sslOptions, app).listen(HTTPS_PORT, '0.0.0.0', () => {
    console.log(`HTTPS available on https://0.0.0.0:${HTTPS_PORT}`);
  });
}
