const API_URL = "https://soc-log-analyzer-rhld.onrender.com";

// Render's free tier spins the backend down after ~15 min idle, and waking
// it back up takes 30-60s. Ping it the moment the page loads so it's
// usually already awake by the time the user clicks a button; both
// analyze/generate handlers also await this before their real request in
// case the user acts fast and it's still warming up.
let wakePromise = null;
function wakeBackend() {
    if (!wakePromise) {
        wakePromise = fetch(`${API_URL}/`).catch(() => {});
    }
    return wakePromise;
}
wakeBackend();

// Screenshot stores for each mode
let shots1 = [];
let shots2 = [];
let activeShots = [];
let analysisFindings = [];
let selectedFile = null;
let lastReportRaw = '';       // raw text from the AI, kept for copy/txt-download
let lastIncidentName = '';
let lastSeverity = '';

// ============================================
// MITRE ATT&CK kill-chain visual
// ============================================
const ATTACK_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact"
];

const MITRE_TECHNIQUE_TACTIC = {
    "T1595": "Reconnaissance",
    "T1583": "Resource Development",
    "T1566": "Initial Access",
    "T1204": "Execution",
    "T1204.002": "Execution",
    "T1059": "Execution",
    "T1059.001": "Execution",
    "T1047": "Execution",
    "T1105": "Command and Control",
    "T1140": "Defense Evasion",
    "T1197": "Defense Evasion",
    "T1218": "Defense Evasion",
    "T1218.005": "Defense Evasion",
    "T1218.010": "Defense Evasion",
    "T1218.011": "Defense Evasion",
    "T1490": "Impact",
    "T1136": "Persistence",
    "T1033": "Discovery",
    "T1482": "Discovery",
    "T1571": "Command and Control",
    "T1071": "Command and Control",
    "T1071.001": "Command and Control",
    "T1071.004": "Command and Control",
    "T1048": "Exfiltration",
    "T1110": "Credential Access"
};

function extractTacticsFromText(text) {
    const ids = text.match(/T\d{4}(?:\.\d{3})?/g) || [];
    const tactics = new Set();
    ids.forEach(id => {
        const tactic = MITRE_TECHNIQUE_TACTIC[id] || MITRE_TECHNIQUE_TACTIC[id.split('.')[0]];
        if (tactic) tactics.add(tactic);
    });
    return tactics;
}

function buildMitreChainHtml(reportText, forPdf) {
    const matched = extractTacticsFromText(reportText || '');
    if (matched.size === 0) return '';
    const stepClass = forPdf ? 'pdf-mitre-step' : 'mitre-step';
    const arrowClass = forPdf ? 'pdf-mitre-arrow' : 'mitre-arrow';
    return ATTACK_TACTICS.map((tactic, i) => {
        const active = matched.has(tactic);
        const arrow = i < ATTACK_TACTICS.length - 1 ? `<span class="${arrowClass}">→</span>` : '';
        return `<div class="${stepClass} ${active ? 'active' : ''}">${tactic}</div>${arrow}`;
    }).join('');
}

function renderMitreChain(reportText) {
    const wrap = document.getElementById('mitreChainWrap');
    const chain = document.getElementById('mitreChain');
    const html = buildMitreChainHtml(reportText, false);
    if (!html) { wrap.style.display = 'none'; return; }
    wrap.style.display = 'block';
    chain.innerHTML = html;
}

// ============================================
// Markdown / plain-report -> HTML renderer.
// Tolerant of two header styles: "## Title" (real markdown) AND
// "1. TITLE" / "TITLE" plain numbered/caps headings (what the AI sometimes
// writes despite instructions). Also accepts "-" or "•" bullets.
// ============================================
function looksLikeHeading(line) {
    if (/^\d+\.\s+.{2,60}$/.test(line) && !/[.:]$/.test(line.trim().slice(-1))) return true;
    return false;
}

function renderMarkdown(md) {
    if (!md) return '';

    const escape = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const lines = md.split('\n');
    let html = '';
    let inList = false;

    for (let rawLine of lines) {
        const line = escape(rawLine).trim();

        if (line === '') {
            if (inList) { html += '</ul>'; inList = false; }
            continue;
        }

        let m;
        if ((m = line.match(/^#\s+(.*)/))) {
            if (inList) { html += '</ul>'; inList = false; }
            html += `<h1>${inlineFormat(m[1])}</h1>`;
        } else if ((m = line.match(/^##\s+(.*)/))) {
            if (inList) { html += '</ul>'; inList = false; }
            html += `<h2>${inlineFormat(m[1])}</h2>`;
        } else if ((m = line.match(/^###\s+(.*)/))) {
            if (inList) { html += '</ul>'; inList = false; }
            html += `<h3>${inlineFormat(m[1])}</h3>`;
        } else if ((m = line.match(/^[-•]\s+(.*)/))) {
            if (!inList) { html += '<ul>'; inList = true; }
            html += `<li>${inlineFormat(m[1])}</li>`;
        } else if (looksLikeHeading(line)) {
            if (inList) { html += '</ul>'; inList = false; }
            html += `<h2>${inlineFormat(line)}</h2>`;
        } else {
            if (inList) { html += '</ul>'; inList = false; }
            html += `<p>${inlineFormat(line)}</p>`;
        }
    }
    if (inList) html += '</ul>';
    return html;
}

function inlineFormat(text) {
    return text.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
}

// Strips markdown/plain symbols for the raw .txt export.
function stripMarkdownSymbols(md) {
    return (md || '')
        .replace(/^#{1,3}\s+/gm, '')
        .replace(/\*\*(.+?)\*\*/g, '$1')
        .replace(/^[-•]\s+/gm, '• ');
}

// ============================================
// Mode Selection
// ============================================
function selectMode(mode) {
    document.getElementById('modeSelection').style.display = 'none';
    document.getElementById('reportSection').style.display = 'none';
    if (mode === 'upload') document.getElementById('uploadSection').style.display = 'block';
    else document.getElementById('writeSection').style.display = 'block';
}

function goBack() {
    document.getElementById('uploadSection').style.display = 'none';
    document.getElementById('writeSection').style.display = 'none';
    document.getElementById('reportSection').style.display = 'none';
    document.getElementById('analysisResults').style.display = 'none';
    document.getElementById('modeSelection').style.display = 'block';
}

function resetAll() {
    selectedFile = null;
    document.getElementById('fileInput').value = '';
    document.getElementById('fileName').textContent = '';
    document.getElementById('fileInfo').style.display = 'none';
    document.getElementById('analysisResults').style.display = 'none';
    document.getElementById('additionalNotes').value = '';
    document.getElementById('incidentName1').value = '';

    document.getElementById('incidentName2').value = '';
    document.getElementById('findingsText').value = '';
    document.getElementById('notesUploadBtn').textContent = '📂 Upload Notes File';
    document.getElementById('notesFileInput').value = '';

    shots1 = []; shots2 = []; activeShots = [];
    document.getElementById('shotsPreview1').innerHTML = '';
    document.getElementById('shotsPreview2').innerHTML = '';

    lastReportRaw = '';
    lastIncidentName = '';
    lastSeverity = '';

    document.getElementById('reportSection').style.display = 'none';
    document.getElementById('uploadSection').style.display = 'none';
    document.getElementById('writeSection').style.display = 'none';
    document.getElementById('modeSelection').style.display = 'block';

    window.scrollTo(0, 0);
}

// ============================================
// Screenshot Upload (shared for both modes)
// ============================================
function setupScreenshotUpload(inputId, btnId, previewId, store) {
    const input = document.getElementById(inputId);
    const btn = document.getElementById(btnId);
    const preview = document.getElementById(previewId);

    btn.addEventListener('click', () => input.click());

    input.addEventListener('change', (e) => {
        Array.from(e.target.files).forEach(file => {
            const reader = new FileReader();
            reader.onload = (ev) => {
                store.push({ dataUrl: ev.target.result, caption: '' });
                renderShots(preview, store);
            };
            reader.readAsDataURL(file);
        });
        input.value = '';
    });
}

function renderShots(previewEl, store) {
    previewEl.innerHTML = '';
    store.forEach((shot, i) => {
        const div = document.createElement('div');
        div.className = 'shot-item';

        const img = document.createElement('img');
        img.src = shot.dataUrl;

        const num = document.createElement('span');
        num.className = 'shot-num';
        num.textContent = '#' + (i + 1);

        const cap = document.createElement('input');
        cap.type = 'text';
        cap.placeholder = 'Caption (optional)';
        cap.value = shot.caption;
        cap.addEventListener('input', (e) => { shot.caption = e.target.value; });

        const rm = document.createElement('button');
        rm.className = 'shot-remove';
        rm.textContent = '✕';
        rm.addEventListener('click', () => {
            store.splice(i, 1);
            renderShots(previewEl, store);
        });

        div.appendChild(img);
        div.appendChild(num);
        div.appendChild(rm);
        div.appendChild(cap);
        previewEl.appendChild(div);
    });
}

function shotsToText(store) {
    if (store.length === 0) return '';
    return store.map((s, i) => `Screenshot #${i + 1}: ${s.caption || '(no caption)'}`).join('\n');
}

setupScreenshotUpload('shots1', 'shotsBtn1', 'shotsPreview1', shots1);
setupScreenshotUpload('shots2', 'shotsBtn2', 'shotsPreview2', shots2);

// ============================================
// MODE 1: File Upload & Analyze
// ============================================
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const browseBtn = document.getElementById('browseBtn');
const fileInfo = document.getElementById('fileInfo');
const fileName = document.getElementById('fileName');
const analyzeBtn = document.getElementById('analyzeBtn');
const loading = document.getElementById('loading');

browseBtn.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        selectedFile = e.target.files[0];
        fileName.textContent = `📄 ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;
        fileInfo.style.display = 'flex';
    }
});

dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.style.borderColor = '#00d4ff'; });
dropZone.addEventListener('dragleave', () => { dropZone.style.borderColor = ''; });
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.style.borderColor = '';
    if (e.dataTransfer.files.length > 0) {
        selectedFile = e.dataTransfer.files[0];
        fileName.textContent = `📄 ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;
        fileInfo.style.display = 'flex';
    }
});

analyzeBtn.addEventListener('click', async () => {
    if (!selectedFile) return;

    if (selectedFile.size > 20 * 1024 * 1024) {
        alert('⚠️ File too large. Please upload a file under 20 MB (free hosting limit).');
        return;
    }

    loading.style.display = 'block';
    fileInfo.style.display = 'none';
    loading.querySelector('p').textContent = 'Waking up the server (can take up to a minute if it was idle)...';
    await wakeBackend();
    loading.querySelector('p').textContent = 'Analyzing your file...';

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
        const response = await fetch(`${API_URL}/analyze`, { method: 'POST', body: formData });
        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `Server error: ${response.status}`);
        }
        const data = await response.json();
        analysisFindings = data.findings || [];
        displayAnalysisResults(data);
    } catch (error) {
        alert(`Error: ${error.message}`);
    } finally {
        loading.style.display = 'none';
    }
});

function displayAnalysisResults(data) {
    document.getElementById('analysisResults').style.display = 'block';

    const summaryCards = document.getElementById('summaryCards');
    summaryCards.innerHTML = '';
    addSummaryCard('📄 File', data.filename || 'Unknown');
    addSummaryCard('📊 Events', data.total_lines || (data.summary && data.summary.total_rows) || '0');
    if (data.summary && data.summary.top_ips) addSummaryCard('🌐 Top IP', data.summary.top_ips[0].ip);

    const findingsList = document.getElementById('findingsList');
    findingsList.innerHTML = '';
    (data.findings || []).forEach(f => {
        const sev = f.severity.toLowerCase();
        const card = document.createElement('div');
        card.className = `finding-card ${sev}`;
        card.innerHTML = `
            <div class="finding-header">
                <span class="finding-title">${f.title}</span>
                <span class="finding-severity">${f.severity}</span>
            </div>
            <p class="finding-desc">${f.description}</p>
            ${f.mitre ? `<p class="finding-mitre">🎯 ${f.mitre}</p>` : ''}
        `;
        findingsList.appendChild(card);
    });

    document.getElementById('analysisResults').scrollIntoView({ behavior: 'smooth' });
}

function addSummaryCard(label, value) {
    const card = document.createElement('div');
    card.className = 'summary-card';
    card.innerHTML = `<div class="card-value">${value}</div><div class="card-label">${label}</div>`;
    document.getElementById('summaryCards').appendChild(card);
}

document.getElementById('generateReportBtn1').addEventListener('click', async () => {
    const findingsText = analysisFindings.map(f =>
        `[${f.severity}] ${f.title}: ${f.description} ${f.mitre ? '(MITRE: ' + f.mitre + ')' : ''}`
    ).join('\n');

    await generateReport(
        findingsText,
        document.getElementById('incidentName1').value || 'Security Incident',
        document.getElementById('severity1').value,
        document.getElementById('additionalNotes').value,
        shots1
    );
});

// ============================================
// MODE 2: Write / Upload Findings
// ============================================
const notesFileInput = document.getElementById('notesFileInput');
const notesUploadBtn = document.getElementById('notesUploadBtn');

notesUploadBtn.addEventListener('click', () => notesFileInput.click());

notesFileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
        document.getElementById('findingsText').value = ev.target.result;
        notesUploadBtn.textContent = `✅ Loaded: ${file.name}`;
    };
    reader.readAsText(file);
});

document.getElementById('generateReportBtn2').addEventListener('click', async () => {
    const findingsText = document.getElementById('findingsText').value;
    if (!findingsText.trim()) {
        alert('Please type your findings or upload a notes file first.');
        return;
    }
    await generateReport(
        findingsText,
        document.getElementById('incidentName2').value || 'Security Incident',
        document.getElementById('severity2').value,
        '',
        shots2
    );
});

// ============================================
// Shared: Generate Report via AI
// ============================================
async function generateReport(findingsText, incidentName, severity, additionalNotes, shotsStore) {
    activeShots = shotsStore;
    lastIncidentName = incidentName;
    lastSeverity = severity;
    document.getElementById('reportLoading').style.display = 'block';
    document.getElementById('reportSection').style.display = 'none';
    document.querySelector('#reportLoading p').textContent = 'Waking up the server (can take up to a minute if it was idle)...';
    await wakeBackend();
    document.querySelector('#reportLoading p').textContent = 'AI is writing your professional report... (15-30 seconds)';

    try {
        const response = await fetch(`${API_URL}/generate-report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                findings: findingsText,
                incident_name: incidentName,
                severity: severity,
                additional_notes: additionalNotes,
                screenshots: shotsToText(shotsStore)
            })
        });

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            throw new Error(err.error || `Server error: ${response.status}`);
        }
        const data = await response.json();

        lastReportRaw = data.report;
        document.getElementById('reportContent').innerHTML = renderMarkdown(data.report);
        renderMitreChain(data.report);
        renderGallery(activeShots);
        document.getElementById('reportSection').style.display = 'block';
        document.getElementById('reportSection').scrollIntoView({ behavior: 'smooth' });

    } catch (error) {
        alert(`Error generating report: ${error.message}`);
    } finally {
        document.getElementById('reportLoading').style.display = 'none';
    }
}

function renderGallery(store) {
    const wrap = document.getElementById('screenshotGallery');
    const grid = document.getElementById('galleryGrid');
    grid.innerHTML = '';
    if (!store || store.length === 0) { wrap.style.display = 'none'; return; }

    wrap.style.display = 'block';
    store.forEach((s, i) => {
        const fig = document.createElement('figure');
        fig.className = 'gallery-item';
        const img = document.createElement('img');
        img.src = s.dataUrl;
        const cap = document.createElement('figcaption');
        cap.textContent = `#${i + 1}${s.caption ? ' - ' + s.caption : ''}`;
        fig.appendChild(img);
        fig.appendChild(cap);
        grid.appendChild(fig);
    });
}

// ============================================
// Copy Report
// ============================================
document.getElementById('copyBtn').addEventListener('click', () => {
    const text = stripMarkdownSymbols(lastReportRaw);
    navigator.clipboard.writeText(text).then(() => {
        document.getElementById('copyBtn').textContent = '✅ Copied!';
        setTimeout(() => { document.getElementById('copyBtn').textContent = '📋 Copy Report'; }, 2000);
    });
});

// ============================================
// Download Report as PDF (primary, professional format)
// ============================================
document.getElementById('downloadPdfBtn').addEventListener('click', async () => {
    const btn = document.getElementById('downloadPdfBtn');
    btn.textContent = '⏳ Building PDF...';
    btn.disabled = true;

    const date = new Date().toISOString().slice(0, 10);
    const mitreHtml = buildMitreChainHtml(lastReportRaw, true);

    const shotsHtml = (activeShots && activeShots.length > 0)
        ? `<h2>Evidence Screenshots</h2><div class="pdf-gallery">` +
          activeShots.map((s, i) => `
            <div class="pdf-shot">
                <img src="${s.dataUrl}" />
                <p>#${i + 1}${s.caption ? ' — ' + s.caption : ''}</p>
            </div>`).join('') +
          `</div>`
        : '';

    const container = document.createElement('div');
    container.className = 'pdf-export';
    container.innerHTML = `
        <div class="pdf-header">
            <div class="pdf-title">INCIDENT RESPONSE REPORT</div>
            <div class="pdf-subtitle">${lastIncidentName || 'Security Incident'}</div>
            <div class="pdf-meta">
                <span>Severity: <strong>${lastSeverity || 'N/A'}</strong></span>
                <span>Generated: <strong>${date}</strong></span>
            </div>
        </div>
        ${mitreHtml ? `<div class="pdf-mitre-wrap"><h2>MITRE ATT&CK Kill Chain</h2><div class="pdf-mitre-chain">${mitreHtml}</div></div>` : ''}
        <div class="pdf-body">${renderMarkdown(lastReportRaw)}</div>
        ${shotsHtml}
        <div class="pdf-footer">Generated by SOC Analyzer — soc-log-analyzer-rhld.onrender.com</div>
    `;
    // Render it fully visible on top of everything during capture. Hiding
    // tricks (extreme off-screen coordinates, opacity ~0, negative z-index)
    // all cause html2canvas to silently skip rendering — it treats those as
    // "not actually visible" and produces a blank capture. A brief visible
    // flash during the "Building PDF..." state is the reliable approach.
    container.style.position = 'fixed';
    container.style.top = '0';
    container.style.left = '0';
    container.style.right = '0';
    container.style.zIndex = '99999';
    container.style.maxHeight = '100vh';
    container.style.overflowY = 'auto';
    container.style.boxShadow = '0 0 40px rgba(0,0,0,0.6)';
    document.body.appendChild(container);
    document.body.style.overflow = 'hidden';

    // Make sure every screenshot <img> has actually finished loading —
    // html2canvas captures whatever is painted at that instant, so an
    // unloaded image would just render as blank space.
    const imgs = container.querySelectorAll('img');
    await Promise.all(Array.from(imgs).map(img =>
        img.complete ? Promise.resolve() : new Promise(res => { img.onload = img.onerror = res; })
    ));

    try {
        await html2pdf().set({
            margin: [15, 15, 15, 15],
            filename: `IR_Report_${date}.pdf`,
            image: { type: 'jpeg', quality: 0.95 },
            html2canvas: { scale: 2, useCORS: true },
            jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
            pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
        }).from(container).save();
    } catch (e) {
        alert('Error building PDF: ' + e.message);
    } finally {
        document.body.removeChild(container);
        document.body.style.overflow = '';
        btn.textContent = '📥 Download PDF';
        btn.disabled = false;
    }
});

// ============================================
// Download Report as plain .txt (backup / raw text option)
// ============================================
document.getElementById('downloadTxtBtn').addEventListener('click', async () => {
    const text = stripMarkdownSymbols(lastReportRaw);
    const date = new Date().toISOString().slice(0, 10);

    if (activeShots && activeShots.length > 0) {
        const zip = new JSZip();
        zip.file("IR_Report.txt", text);

        activeShots.forEach((shot, i) => {
            const matches = shot.dataUrl.match(/^data:image\/(\w+);base64,(.+)$/);
            if (matches) {
                const ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
                zip.file(`screenshot_${i + 1}.${ext}`, matches[2], { base64: true });
            }
        });

        let readme = "Evidence Screenshots\n\n";
        activeShots.forEach((s, i) => {
            readme += `- Screenshot #${i + 1}: ${s.caption || '(no caption)'}\n`;
        });
        zip.file("screenshots_readme.txt", readme);

        const blob = await zip.generateAsync({ type: "blob" });
        triggerDownload(blob, `IR_Report_${date}.zip`);
    } else {
        const blob = new Blob([text], { type: 'text/plain' });
        triggerDownload(blob, `IR_Report_${date}.txt`);
    }

    const btn = document.getElementById('downloadTxtBtn');
    btn.textContent = '✅ Saved!';
    setTimeout(() => { btn.textContent = '📄 Download .txt'; }, 2000);
});

function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
