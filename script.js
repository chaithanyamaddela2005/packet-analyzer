// Global Variables
let currentPackets = [];
let filteredPackets = [];
let currentPage = 1;
let packetsPerPage = 50;
let currentStats = null;
let protocolChart = null;
let appProtocolChart = null;
let availableSessions = [];

// DOM Elements
const fileInput = document.getElementById('fileInput');
const browseBtn = document.getElementById('browseBtn');
const uploadArea = document.getElementById('uploadArea');
const fileInfo = document.getElementById('fileInfo');
const fileName = document.getElementById('fileName');
const fileSize = document.getElementById('fileSize');
const analyzeBtn = document.getElementById('analyzeBtn');
const clearBtn = document.getElementById('clearBtn');
const loadingSection = document.getElementById('loadingSection');
const dashboardSection = document.getElementById('dashboardSection');
const errorSection = document.getElementById('errorSection');
const errorText = document.getElementById('errorText');
const retryBtn = document.getElementById('retryBtn');
const packetsBody = document.getElementById('packetsBody');
const searchFilter = document.getElementById('searchFilter');
const protocolFilter = document.getElementById('protocolFilter');
const appProtocolFilter = document.getElementById('appProtocolFilter');
const exportBtn = document.getElementById('exportBtn');
const exportJsonBtn = document.getElementById('exportJsonBtn');
const prevBtn = document.getElementById('prevBtn');
const nextBtn = document.getElementById('nextBtn');
const pageInfo = document.getElementById('pageInfo');
const sessionsBtn = document.getElementById('sessionsBtn');
const sessionModal = document.getElementById('sessionModal');
const closeModal = document.getElementById('closeModal');
const sessionsList = document.getElementById('sessionsList');

// Initialize
document.addEventListener('DOMContentLoaded', initializeApp);

function initializeApp() {
    // Existing event listeners
    browseBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', handleFileSelect);
    uploadArea.addEventListener('dragover', handleDragOver);
    uploadArea.addEventListener('dragleave', handleDragLeave);
    uploadArea.addEventListener('drop', handleDrop);
    uploadArea.addEventListener('click', () => fileInput.click());
    analyzeBtn.addEventListener('click', () => handleFileUpload());
    clearBtn.addEventListener('click', clearSelection);
    retryBtn.addEventListener('click', resetInterface);
    exportBtn.addEventListener('click', exportCSV);
    exportJsonBtn.addEventListener('click', exportJSON);
    searchFilter.addEventListener('input', debounce(applyFilters, 300));
    protocolFilter.addEventListener('change', applyFilters);
    appProtocolFilter.addEventListener('change', applyFilters);
    prevBtn.addEventListener('click', () => changePage(-1));
    nextBtn.addEventListener('click', () => changePage(1));
    
    // New session management listeners
    sessionsBtn.addEventListener('click', openSessionModal);
    closeModal.addEventListener('click', closeSessionModal);
    window.addEventListener('click', (e) => {
        if (e.target === sessionModal) closeSessionModal();
    });
    
    // Fetch sessions on page load
    fetchSessions();
}

// ==================== SESSION MANAGEMENT ====================

/**
 * Fetch available sessions from backend
 * Backend returns: { "success": true, "sessions": [...] }
 */
async function fetchSessions() {
    try {
        const response = await fetch('/sessions');
        
        if (!response.ok) {
            console.error('Failed to fetch sessions:', response.statusText);
            return;
        }
        
        const result = await response.json();
        console.log('Sessions response:', result);
        
        // Backend wraps sessions in "sessions" field
        if (result.success && result.sessions) {
            availableSessions = Array.isArray(result.sessions) ? result.sessions : [];
        } else {
            availableSessions = [];
        }
        
        console.log('✓ Fetched sessions:', availableSessions.length);
        
        // Update UI to show sessions button if sessions exist
        updateSessionsButtonVisibility();
        
    } catch (error) {
        console.error('Error fetching sessions:', error);
        availableSessions = [];
    }
}

/**
 * Update sessions button visibility based on available sessions
 */
function updateSessionsButtonVisibility() {
    if (availableSessions.length > 0) {
        sessionsBtn.style.display = 'inline-block';
        sessionsBtn.innerHTML = `📋 Previous Uploads (${availableSessions.length})`;
    } else {
        sessionsBtn.style.display = 'none';
    }
}

/**
 * Open session modal and render sessions
 */
function openSessionModal() {
    renderSessionDropdown(availableSessions);
    sessionModal.style.display = 'flex';
    sessionModal.classList.add('fade-in');
}

/**
 * Close session modal
 */
function closeSessionModal() {
    sessionModal.style.display = 'none';
}

/**
 * Render sessions in the modal
 */
function renderSessionDropdown(sessions) {
    if (!sessions || sessions.length === 0) {
        sessionsList.innerHTML = `
            <div class="no-sessions">
                <p>📭 No previous sessions found</p>
                <p class="no-sessions-hint">Upload a PCAP file to create your first session</p>
            </div>
        `;
        return;
    }
    
    const sessionsHTML = sessions.map(session => `
        <div class="session-item" data-session-id="${session.id}">
            <div class="session-info">
                <div class="session-name">📄 ${session.session_name}</div>
                <div class="session-time">🕒 ${formatDateTime(session.upload_time)}</div>
            </div>
            <button class="btn-load" onclick="handleSessionSelect(${session.id})">
                Load Session
            </button>
        </div>
    `).join('');
    
    sessionsList.innerHTML = sessionsHTML;
}

/**
 * Handle session selection
 * Backend returns: { "success": true, "packets": [...], "ip_stats": [...], "protocol_stats": [...] }
 */
async function handleSessionSelect(sessionId) {
    console.log('Loading session:', sessionId);
    
    closeSessionModal();
    showLoading();
    
    try {
        const response = await fetch(`/analyze/${sessionId}`);
        
        if (!response.ok) {
            throw new Error(`Failed to load session: ${response.statusText}`);
        }
        
        const result = await response.json();
        console.log('Session data received:', result);
        
        if (!result.success) {
            throw new Error(result.error || 'Failed to load session');
        }
        
        // Find session name for display
        const session = availableSessions.find(s => s.id === sessionId);
        const sessionName = session ? session.session_name : `Session ${sessionId}`;
        
        // Transform backend response to match upload format
        const transformedResult = transformSessionData(result, sessionName);
        
        displayResults(transformedResult);
        
    } catch (error) {
        console.error('Error loading session:', error);
        showError('Failed to load session: ' + error.message);
    }
}

/**
 * Transform session data from C++ backend to match frontend format
 * Backend format: { packets: [...], ip_stats: [...], protocol_stats: [...] }
 * Frontend expects: { success: true, packets: [...], stats: {...} }
 */
function transformSessionData(sessionData, sessionName) {
    const packets = sessionData.packets || [];
    const ipStats = sessionData.ip_stats || [];
    const protocolStats = sessionData.protocol_stats || [];
    
    // Build protocol distribution from protocol_stats
    const protocolDistribution = {};
    const appProtocolDistribution = {};
    
    protocolStats.forEach(stat => {
        if (stat.protocol_name) {
            protocolDistribution[stat.protocol_name] = stat.count || 0;
        }
    });
    
    // Count app protocols from packets
    packets.forEach(packet => {
        if (packet.app_protocol && packet.app_protocol !== 'Unknown') {
            appProtocolDistribution[packet.app_protocol] = 
                (appProtocolDistribution[packet.app_protocol] || 0) + 1;
        }
    });
    
    // Calculate total bytes
    const totalBytes = packets.reduce((sum, p) => sum + (p.length || 0), 0);
    
    // Get top sources and destinations from ip_stats
    // Backend format: { ip: "...", type: "SOURCE" or "DEST", packet_count: ... }
    const sourceIPs = ipStats
        .filter(ip => ip.type === 'SOURCE')
        .sort((a, b) => b.packet_count - a.packet_count)
        .slice(0, 5);
    
    const destIPs = ipStats
        .filter(ip => ip.type === 'DEST')
        .sort((a, b) => b.packet_count - a.packet_count)
        .slice(0, 5);
    
    const topSources = sourceIPs.map(ip => ({
        ip: ip.ip,
        count: ip.packet_count
    }));
    
    const topDestinations = destIPs.map(ip => ({
        ip: ip.ip,
        count: ip.packet_count
    }));
    
    // Count unique IPs
    const uniqueSourceIPs = new Set(packets.map(p => p.source ? p.source.split(':')[0] : null).filter(Boolean)).size;
    const uniqueDestIPs = new Set(packets.map(p => p.destination ? p.destination.split(':')[0] : null).filter(Boolean)).size;
    
    return {
        success: true,
        session_name: sessionName,
        packets: packets,
        stats: {
            TotalPackets: packets.length,
            TotalBytes: totalBytes,
            UniqueSourceIPs: uniqueSourceIPs,
            UniqueDestIPs: uniqueDestIPs,
            ProtocolDistribution: protocolDistribution,
            AppProtocolDistribution: appProtocolDistribution,
            TopSources: topSources,
            TopDestinations: topDestinations
        }
    };
}

/**
 * Format date/time for display
 */
function formatDateTime(datetime) {
    if (!datetime) return 'Unknown';
    
    try {
        const date = new Date(datetime);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins} min ago`;
        if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
        if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
        
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { 
            hour: '2-digit', 
            minute: '2-digit' 
        });
    } catch (e) {
        return datetime;
    }
}

// ==================== FILE HANDLING ====================

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) showFileInfo(file);
}

function handleDragOver(e) {
    e.preventDefault();
    uploadArea.classList.add('dragover');
}

function handleDragLeave(e) {
    e.preventDefault();
    uploadArea.classList.remove('dragover');
}

function handleDrop(e) {
    e.preventDefault();
    uploadArea.classList.remove('dragover');
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        fileInput.files = files;
        showFileInfo(files[0]);
    }
}

function showFileInfo(file) {
    if (!file.name.toLowerCase().match(/\.(pcap|pcapng)$/)) {
        showError('Please select a valid PCAP file (.pcap or .pcapng)');
        return;
    }
    fileName.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);
    uploadArea.style.display = 'none';
    fileInfo.style.display = 'flex';
}

function clearSelection() {
    fileInput.value = '';
    uploadArea.style.display = 'block';
    fileInfo.style.display = 'none';
    resetInterface();
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ==================== FILE UPLOAD & ANALYSIS ====================

/**
 * Handle new file upload
 * C++ backend expects raw binary data with Content-Type: application/octet-stream
 */
async function handleFileUpload() {
    const file = fileInput.files[0];
    if (!file) {
        showError('Please select a file first');
        return;
    }
    
    // Check if this file was previously uploaded by comparing name
    const matchingSession = availableSessions.find(session => 
        session.session_name.toLowerCase().includes(file.name.toLowerCase()) ||
        file.name.toLowerCase().includes(session.session_name.toLowerCase())
    );
    
    if (matchingSession) {
        const useExisting = confirm(
            `This file "${file.name}" appears to match an existing session:\n` +
            `"${matchingSession.session_name}" uploaded ${formatDateTime(matchingSession.upload_time)}\n\n` +
            `Would you like to load the existing analysis instead of re-uploading?\n\n` +
            `✓ Load Existing (faster, uses cached analysis)\n` +
            `✗ Upload New (re-analyzes the file)`
        );
        
        if (useExisting) {
            console.log('User chose to load existing session:', matchingSession.id);
            handleSessionSelect(matchingSession.id);
            return;
        }
    }
    
    showLoading();
    
    try {
        // Read file as binary and send as raw body (matching C++ backend expectation)
        const response = await fetch('/upload', {
            method: 'POST',
            body: file,
            headers: { 'Content-Type': 'application/octet-stream' }
        });
        
        const result = await response.json();
        console.log('Upload response:', result);
        
        if (result.success) {
            displayResults(result);
            // Refresh sessions list after successful upload
            await fetchSessions();
        } else {
            showError(result.error || 'Analysis failed: Unknown error');
        }
    } catch (error) {
        console.error('Upload error:', error);
        showError('Failed to analyze file: ' + (error.message || 'Network error'));
    }
}

// ==================== DISPLAY RESULTS ====================

function displayResults(result) {
    destroyCharts();
    hideAllSections();
    
    currentPackets = Array.isArray(result.packets) ? result.packets : [];
    filteredPackets = [...currentPackets];
    currentStats = result.stats || {};
    currentPage = 1;
    
    console.log('Stats received:', currentStats);
    console.log('Packets count:', currentPackets.length);
    
    if (currentPackets.length === 0) {
        showError('No packets found in PCAP file');
        return;
    }
    
    updateStatCards();
    renderCharts();
    displayTopIPs();
    populateFilters();
    displayPackets();
    
    dashboardSection.style.display = 'block';
    dashboardSection.classList.add('fade-in');
}

function destroyCharts() {
    if (protocolChart) {
        protocolChart.destroy();
        protocolChart = null;
    }
    if (appProtocolChart) {
        appProtocolChart.destroy();
        appProtocolChart = null;
    }
}

function updateStatCards() {
    const totalPackets = currentStats.TotalPackets || 0;
    document.getElementById('statTotalPackets').textContent = totalPackets.toLocaleString();
    
    const totalBytes = currentStats.TotalBytes || 0;
    document.getElementById('statTotalBytes').textContent = formatFileSize(totalBytes);
    
    const uniqueSourceIPs = currentStats.UniqueSourceIPs || 0;
    const uniqueDestIPs = currentStats.UniqueDestIPs || 0;
    const uniqueIPs = uniqueSourceIPs + uniqueDestIPs;
    document.getElementById('statUniqueIPs').textContent = uniqueIPs.toLocaleString();
    
    const protocolDist = currentStats.ProtocolDistribution || {};
    const protocolCount = Object.keys(protocolDist).length;
    document.getElementById('statProtocols').textContent = protocolCount;
}

function renderCharts() {
    const protocolDist = currentStats.ProtocolDistribution || {};
    const appProtocolDist = currentStats.AppProtocolDistribution || {};
    
    const protocolCtx = document.getElementById('protocolChart').getContext('2d');
    const protocolLabels = Object.keys(protocolDist);
    const protocolValues = Object.values(protocolDist);
    
    if (protocolLabels.length === 0) {
        protocolLabels.push('No Data');
        protocolValues.push(1);
    }
    
    protocolChart = new Chart(protocolCtx, {
        type: 'doughnut',
        data: {
            labels: protocolLabels,
            datasets: [{
                data: protocolValues,
                backgroundColor: [
                    '#3b82f6', '#10b981', '#f59e0b', '#ef4444', 
                    '#8b5cf6', '#06b6d4', '#ec4899', '#6366f1'
                ],
                borderWidth: 2,
                borderColor: 'rgba(255,255,255,0.1)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { 
                        color: '#e2e8f0',
                        padding: 15,
                        font: { size: 12 }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0,0,0,0.8)',
                    padding: 12,
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((context.parsed / total) * 100).toFixed(1);
                            return `${context.label}: ${context.parsed} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
    
    const appProtocolCtx = document.getElementById('appProtocolChart').getContext('2d');
    const appLabels = Object.keys(appProtocolDist);
    const appValues = Object.values(appProtocolDist);
    
    if (appLabels.length === 0) {
        appLabels.push('No Data');
        appValues.push(0);
    }
    
    appProtocolChart = new Chart(appProtocolCtx, {
        type: 'bar',
        data: {
            labels: appLabels,
            datasets: [{
                label: 'Packets',
                data: appValues,
                backgroundColor: 'rgba(59, 130, 246, 0.6)',
                borderColor: 'rgba(59, 130, 246, 1)',
                borderWidth: 2,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: 'rgba(0,0,0,0.8)',
                    padding: 12
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: '#94a3b8' },
                    grid: { color: 'rgba(255,255,255,0.05)' }
                },
                x: {
                    ticks: { color: '#94a3b8' },
                    grid: { color: 'rgba(255,255,255,0.05)' }
                }
            }
        }
    });
}

function displayTopIPs() {
    const topSources = currentStats.TopSources || [];
    const topDests = currentStats.TopDestinations || [];
    
    const sourcesHTML = topSources.map((item, index) => `
        <div class="top-ip-item">
            <span class="ip-rank">#${index + 1}</span>
            <span class="ip-address">${item.ip}</span>
            <span class="ip-count">${item.count} packets</span>
        </div>
    `).join('');
    
    const destsHTML = topDests.map((item, index) => `
        <div class="top-ip-item">
            <span class="ip-rank">#${index + 1}</span>
            <span class="ip-address">${item.ip}</span>
            <span class="ip-count">${item.count} packets</span>
        </div>
    `).join('');
    
    document.getElementById('topSourcesList').innerHTML = sourcesHTML || '<p class="no-data">No data available</p>';
    document.getElementById('topDestsList').innerHTML = destsHTML || '<p class="no-data">No data available</p>';
}

function populateFilters() {
    const l4Protocols = [...new Set(currentPackets.map(p => p.protocol))].filter(p => p).sort();
    const appProtocols = [...new Set(currentPackets.map(p => p.app_protocol))].filter(p => p).sort();
    
    protocolFilter.innerHTML = '<option value="">All L4 Protocols</option>' +
        l4Protocols.map(p => `<option value="${p}">${p}</option>`).join('');
    
    appProtocolFilter.innerHTML = '<option value="">All App Protocols</option>' +
        appProtocols.map(p => `<option value="${p}">${p}</option>`).join('');
}

function displayPackets() {
    const startIndex = (currentPage - 1) * packetsPerPage;
    const endIndex = startIndex + packetsPerPage;
    const pagePackets = filteredPackets.slice(startIndex, endIndex);
    
    packetsBody.innerHTML = pagePackets.map(packet => `
        <tr>
            <td>${packet.number || 'N/A'}</td>
            <td><strong>${packet.source || 'N/A'}</strong></td>
            <td><strong>${packet.destination || 'N/A'}</strong></td>
            <td><span class="protocol-badge protocol-${getProtocolClass(packet.protocol || 'unknown')}">${packet.protocol || 'Unknown'}</span></td>
            <td><span class="app-protocol-badge">${packet.app_protocol || 'Unknown'}</span></td>
            <td>${packet.length || 0} bytes</td>
            <td>${packet.summary || 'No summary'}</td>
        </tr>
    `).join('');
    
    updatePaginationInfo();
}

function getProtocolClass(protocol) {
    return protocol.toLowerCase().replace(/[^a-z0-9]/g, '-');
}

function updatePaginationInfo() {
    const totalPages = Math.max(1, Math.ceil(filteredPackets.length / packetsPerPage));
    pageInfo.textContent = `Page ${currentPage} of ${totalPages}`;
    prevBtn.disabled = currentPage <= 1;
    nextBtn.disabled = currentPage >= totalPages;
}

// ==================== FILTERING ====================

function applyFilters() {
    const searchTerm = searchFilter.value.toLowerCase();
    const selectedProtocol = protocolFilter.value;
    const selectedAppProtocol = appProtocolFilter.value;
    
    filteredPackets = currentPackets.filter(packet => {
        const matchesSearch = !searchTerm || 
            (packet.source && packet.source.toLowerCase().includes(searchTerm)) ||
            (packet.destination && packet.destination.toLowerCase().includes(searchTerm)) ||
            (packet.protocol && packet.protocol.toLowerCase().includes(searchTerm)) ||
            (packet.app_protocol && packet.app_protocol.toLowerCase().includes(searchTerm));
        
        const matchesProtocol = !selectedProtocol || packet.protocol === selectedProtocol;
        const matchesAppProtocol = !selectedAppProtocol || packet.app_protocol === selectedAppProtocol;
        
        return matchesSearch && matchesProtocol && matchesAppProtocol;
    });
    
    currentPage = 1;
    displayPackets();
}

// ==================== PAGINATION ====================

function changePage(direction) {
    const totalPages = Math.ceil(filteredPackets.length / packetsPerPage);
    const newPage = currentPage + direction;
    
    if (newPage >= 1 && newPage <= totalPages) {
        currentPage = newPage;
        displayPackets();
        document.querySelector('.table-container').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

// ==================== EXPORT ====================

function exportCSV() {
    const headers = ['No.', 'Source', 'Destination', 'L4 Protocol', 'App Protocol', 'Length', 'Summary'];
    const csvData = [headers, ...filteredPackets.map(p => [
        p.number || '', 
        p.source || '', 
        p.destination || '', 
        p.protocol || '', 
        p.app_protocol || 'Unknown', 
        p.length || 0, 
        p.summary || ''
    ])];
    
    const csvContent = csvData.map(row => 
        row.map(field => `"${String(field).replace(/"/g, '""')}"`).join(',')
    ).join('\n');
    
    downloadFile(csvContent, `pcap_analysis_${Date.now()}.csv`, 'text/csv');
}

function exportJSON() {
    const exportData = {
        stats: currentStats,
        packets: filteredPackets,
        exportDate: new Date().toISOString()
    };
    
    const jsonContent = JSON.stringify(exportData, null, 2);
    downloadFile(jsonContent, `pcap_analysis_${Date.now()}.json`, 'application/json');
}

function downloadFile(content, filename, type) {
    const blob = new Blob([content], { type });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 100);
}

// ==================== UI STATE MANAGEMENT ====================

function showLoading() {
    hideAllSections();
    loadingSection.style.display = 'block';
}

function showError(message) {
    hideAllSections();
    errorText.textContent = message;
    errorSection.style.display = 'block';
}

function hideAllSections() {
    loadingSection.style.display = 'none';
    dashboardSection.style.display = 'none';
    errorSection.style.display = 'none';
}

function resetInterface() {
    fileInput.value = '';
    uploadArea.style.display = 'block';
    fileInfo.style.display = 'none';
    hideAllSections();
    destroyCharts();
    currentPackets = [];
    filteredPackets = [];
    currentStats = null;
    currentPage = 1;
    searchFilter.value = '';
    if (protocolFilter) protocolFilter.innerHTML = '<option value="">All L4 Protocols</option>';
    if (appProtocolFilter) appProtocolFilter.innerHTML = '<option value="">All App Protocols</option>';
    console.log('✓ Interface reset - ready for new upload');
}

// ==================== UTILITIES ====================

function debounce(func, wait) {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func(...args), wait);
    };
}

console.log('✓ NetScope Analyzer initialized - Compatible with C++ Crow Backend!');
