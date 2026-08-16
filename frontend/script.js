
const API_URL = "https://soc-log-analyzer-rhld.onrender.com";

// ============================================
// DOM Elements
// ============================================
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const browseBtn = document.getElementById('browseBtn');
const fileInfo = document.getElementById('fileInfo');
const fileName = document.getElementById('fileName');
const analyzeBtn = document.getElementById('analyzeBtn');
const loading = document.getElementById('loading');
const resultsSection = document.getElementById('resultsSection');
const summaryCards = document.getElementById('summaryCards');
const findingsList = document.getElementById('findingsList');
const reportBtn = document.getElementById('reportBtn');
const reportOutput = document.getElementById('reportOutput');
const reportContent = document.getElementById('reportContent');
const copyBtn = document.getElementById('copyBtn');

let selectedFile = null;
let analysisResults = null;

// ============================================
// File Upload Handlers
// ============================================
browseBtn.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        selectedFile = e.target.files[0];
        showFileInfo();
    }
});

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
        selectedFile = e.dataTransfer.files[0];
        showFileInfo();
    }
});

function showFileInfo() {
    fileName.textContent = `📄 ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)`;
    fileInfo.style.display = 'block';
}

// ============================================
// Analyze Button
// ============================================
analyzeBtn.addEventListener('click', async () => {
    if (!selectedFile) return;

    loading.style.display = 'block';
    resultsSection.style.display = 'none';
    fileInfo.style.display = 'none';

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
        const response = await fetch(`${API_URL}/analyze`, {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }

        analysisResults = await response.json();
        displayResults(analysisResults);

    } catch (error) {
        alert(`Error: ${error.message}\n\nMake sure the Render server is awake. Try again in 30 seconds.`);
    } finally {
        loading.style.display = 'none';
    }
});

// ============================================
// Display Results
// ============================================
function displayResults(data) {
    resultsSection.style.display = 'block';

    // Summary Cards
    summaryCards.innerHTML = '';
    const summary = data.summary || {};

    addSummaryCard('📄 File', data.filename || 'Unknown');
    addSummaryCard('📊 Total Events', data.total_lines || summary.total_rows || '0');

    if (summary.top_ips) {
        addSummaryCard('🌐 Top IP', summary.top_ips[0].ip);
    }
    if (summary.top_src_ip) {
        addSummaryCard('🌐 Top Source', summary.top_src_ip.ip);
    }

    // Findings
    findingsList.innerHTML = '';
    const findings = data.findings || [];

    if (findings.length === 0) {
        findingsList.innerHTML = '<p style="color: #8b949e;">No findings detected.</p>';
        return;
    }

    findings.forEach(finding => {
        const severity = finding.severity.toLowerCase();
        const card = document.createElement('div');
        card.className = `finding-card ${severity}`;
        card.innerHTML = `
            <div class="finding-header">
                <span class="finding-title">${finding.title}</span>
                <span class="finding-severity">${finding.severity}</span>
            </div>
            <p class="finding-desc">${finding.description}</p>
            ${finding.mitre ? `<p class="finding-mitre">🎯 MITRE ATT&CK: ${finding.mitre}</p>` : ''}
        `;
        findingsList.appendChild(card);
    });

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth' });
}

function addSummaryCard(label, value) {
    const card = document.createElement('div');
    card.className = 'summary-card';
    card.innerHTML = `
        <div class="card-value">${value}</div>
        <div class="card-label">${label}</div>
    `;
    summaryCards.appendChild(card);
}

// ============================================
// Copy Report
// ============================================
copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(reportContent.textContent)
        .then(() => {
            copyBtn.textContent = '✅ Copied!';
            setTimeout(() => {
                copyBtn.textContent = '📋 Copy Report';
            }, 2000);
        });
});
