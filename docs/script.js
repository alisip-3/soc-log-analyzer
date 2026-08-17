
const API_URL = "https://soc-log-analyzer-rhld.onrender.com";

// ============================================
// Mode Selection
// ============================================
function selectMode(mode) {
    document.getElementById('modeSelection').style.display = 'none';
    document.getElementById('reportSection').style.display = 'none';

    if (mode === 'upload') {
        document.getElementById('uploadSection').style.display = 'block';
    } else {
        document.getElementById('writeSection').style.display = 'block';
    }
}

function goBack() {
    document.getElementById('uploadSection').style.display = 'none';
    document.getElementById('writeSection').style.display = 'none';
    document.getElementById('reportSection').style.display = 'none';
    document.getElementById('analysisResults').style.display = 'none';
    document.getElementById('modeSelection').style.display = 'block';
}

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

let selectedFile = null;
let analysisFindings = [];

browseBtn.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        selectedFile = e.target.files[0];
        fileName.textContent = `📄 ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;
        fileInfo.style.display = 'block';
    }
});

dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.style.borderColor = '#58a6ff'; });
dropZone.addEventListener('dragleave', () => { dropZone.style.borderColor = '#30363d'; });
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.style.borderColor = '#30363d';
    if (e.dataTransfer.files.length > 0) {
        selectedFile = e.dataTransfer.files[0];
        fileName.textContent = `📄 ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;
        fileInfo.style.display = 'block';
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
    addSummaryCard('📊 Events', data.total_lines || data.summary?.total_rows || '0');
    if (data.summary?.top_ips) addSummaryCard('🌐 Top IP', data.summary.top_ips[0].ip);

    const findingsList = document.getElementById('findingsList');
    findingsList.innerHTML = '';
    (data.findings || []).forEach(f => {
        const sev = f.severity.toLowerCase();
        findingsList.innerHTML += `
            <div class="finding-card ${sev}">
                <div class="finding-header">
                    <span class="finding-title">${f.title}</span>
                    <span class="finding-severity">${f.severity}</span>
                </div>
                <p class="finding-desc">${f.description}</p>
                ${f.mitre ? `<p class="finding-mitre">🎯 ${f.mitre}</p>` : ''}
            </div>`;
    });

    document.getElementById('analysisResults').scrollIntoView({ behavior: 'smooth' });
}

function addSummaryCard(label, value) {
    document.getElementById('summaryCards').innerHTML += `
        <div class="summary-card">
            <div class="card-value">${value}</div>
            <div class="card-label">${label}</div>
        </div>`;
}

// Generate Report from Analysis
document.getElementById('generateReportBtn1').addEventListener('click', async () => {
    const findingsText = analysisFindings.map(f =>
        `[${f.severity}] ${f.title}: ${f.description} ${f.mitre ? '(MITRE: ' + f.mitre + ')' : ''}`
    ).join('\n');

    const additionalNotes = document.getElementById('additionalNotes').value;
    const incidentName = document.getElementById('incidentName1').value || 'Security Incident';
    const severity = document.getElementById('severity1').value;

    await generateReport(findingsText, incidentName, severity, additionalNotes);
});

// ============================================
// MODE 2: Write Findings
// ============================================
document.getElementById('generateReportBtn2').addEventListener('click', async () => {
    const findingsText = document.getElementById('findingsText').value;
    if (!findingsText.trim()) {
        alert('Please type your findings first.');
        return;
    }
    const incidentName = document.getElementById('incidentName2').value || 'Security Incident';
    const severity = document.getElementById('severity2').value;

    await generateReport(findingsText, incidentName, severity, '');
});

// ============================================
// Shared: Generate Report via AI
// ============================================
async function generateReport(findingsText, incidentName, severity, additionalNotes) {
    const reportLoading = document.getElementById('reportLoading');
    reportLoading.style.display = 'block';
    document.getElementById('reportSection').style.display = 'none';

    try {
        const response = await fetch(`${API_URL}/generate-report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                findings: findingsText,
                incident_name: incidentName,
                severity: severity,
                additional_notes: additionalNotes
            })
        });

        if (!response.ok) throw new Error(`Server error: ${response.status}`);
        const data = await response.json();

        document.getElementById('reportContent').textContent = data.report;
        document.getElementById('reportSection').style.display = 'block';
        document.getElementById('reportSection').scrollIntoView({ behavior: 'smooth' });

    } catch (error) {
        alert(`Error generating report: ${error.message}`);
    } finally {
        reportLoading.style.display = 'none';
    }
}

// ============================================
// Copy Report
// ============================================
document.getElementById('copyBtn').addEventListener('click', () => {
    const text = document.getElementById('reportContent').textContent;
    navigator.clipboard.writeText(text).then(() => {
        document.getElementById('copyBtn').textContent = '✅ Copied!';
        setTimeout(() => {
            document.getElementById('copyBtn').textContent = '📋 Copy Report';
        }, 2000);
    });
});
