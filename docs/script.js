
const API_URL = "https://soc-log-analyzer-rhld.onrender.com";

// Screenshot stores for each mode
let shots1 = [];
let shots2 = [];
let activeShots = [];
let analysisFindings = [];
let selectedFile = null;

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
    loading.style.display = 'block';
    fileInfo.style.display = 'none';

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
        const response = await fetch(`${API_URL}/analyze`, { method: 'POST', body: formData });
        if (!response.ok) throw new Error(`Server error: ${response.status}`);
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
    document.getElementById('reportLoading').style.display = 'block';
    document.getElementById('reportSection').style.display = 'none';

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

        if (!response.ok) throw new Error(`Server error: ${response.status}`);
        const data = await response.json();

        document.getElementById('reportContent').textContent = data.report;
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
    const text = document.getElementById('reportContent').textContent;
    navigator.clipboard.writeText(text).then(() => {
        document.getElementById('copyBtn').textContent = '✅ Copied!';
        setTimeout(() => { document.getElementById('copyBtn').textContent = '📋 Copy Report'; }, 2000);
    });
});
