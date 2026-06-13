// DeepShield XAI - Forensic Suite Front-end Engine

let activeRadarChart = null;

document.addEventListener('DOMContentLoaded', function () {
    // 1. File Uploads Handle & Previews
    setupPreviews('imageFiles', 'imagePreviews', 'imageSubmitBtn', 'image');
    setupPreviews('videoFiles', 'videoPreviews', 'videoSubmitBtn', 'video');
    setupPreviews('audioFiles', 'audioPreviews', 'audioSubmitBtn', 'audio');

    // Drag-and-drop triggers
    setupDragDrop('imageDropZone', 'imageFiles');
    setupDragDrop('videoDropZone', 'videoFiles');
    setupDragDrop('audioDropZone', 'audioFiles');

    // 2. Form Submissions
    document.getElementById('imageForm').addEventListener('submit', (e) => handleForensicForm(e, 'imageForm'));
    document.getElementById('videoForm').addEventListener('submit', (e) => handleForensicForm(e, 'videoForm'));
    document.getElementById('audioForm').addEventListener('submit', (e) => handleForensicForm(e, 'audioForm'));
    document.getElementById('urlForm').addEventListener('submit', (e) => handleUrlScan(e));

    // 3. Webcam Operations
    setupWebcam();
});

// Setup File drag and drop visual indicators
function setupDragDrop(zoneId, inputId) {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    if (!zone || !input) return;

    ['dragenter', 'dragover'].forEach(eventName => {
        zone.addEventListener(eventName, (e) => {
            e.preventDefault();
            zone.classList.add('drop-zone-active');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        zone.addEventListener(eventName, (e) => {
            e.preventDefault();
            zone.classList.remove('drop-zone-active');
        }, false);
    });

    zone.addEventListener('drop', (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        input.files = files;
        // Trigger manually the preview render
        input.dispatchEvent(new Event('change'));
    });
}

// Generate interactive file thumbnails dynamically
function setupPreviews(inputId, previewFolderId, submitBtnId, mediaClass) {
    const input = document.getElementById(inputId);
    const dest = document.getElementById(previewFolderId);
    const btn = document.getElementById(submitBtnId);
    if (!input || !dest) return;

    input.addEventListener('change', function () {
        dest.innerHTML = '';
        const files = Array.from(input.files);

        if (files.length === 0) {
            btn.disabled = true;
            return;
        }
        btn.disabled = false;

        files.forEach((file, index) => {
            const wrapper = document.createElement('div');
            wrapper.className = 'col-sm-6 col-md-4';

            const card = document.createElement('div');
            card.className = 'file-preview-card d-flex align-items-center gap-2 border p-2';

            // Create appropriate preview indicator
            let previewElement;
            if (file.type.startsWith('image/')) {
                previewElement = document.createElement('img');
                previewElement.className = 'preview-thumbnail';
                const reader = new FileReader();
                reader.onload = (e) => { previewElement.src = e.target.result; };
                reader.readAsDataURL(file);
            } else if (file.type.startsWith('video/')) {
                previewElement = document.createElement('div');
                previewElement.className = 'preview-thumbnail d-flex align-items-center justify-content-center bg-secondary-subtle';
                previewElement.innerHTML = '<i class="bi bi-camera-video text-muted"></i>';
            } else if (file.type.startsWith('audio/')) {
                previewElement = document.createElement('div');
                previewElement.className = 'preview-thumbnail d-flex align-items-center justify-content-center bg-info-subtle';
                previewElement.innerHTML = '<i class="bi bi-mic text-info"></i>';
            } else {
                previewElement = document.createElement('div');
                previewElement.className = 'preview-thumbnail d-flex align-items-center justify-content-center bg-light';
                previewElement.innerHTML = '<i class="bi bi-file-earmark text-muted"></i>';
            }

            const textWrap = document.createElement('div');
            textWrap.className = 'overflow-hidden';
            
            const title = document.createElement('div');
            title.className = 'text-xs fw-semibold text-truncate';
            title.textContent = file.name;

            const sub = document.createElement('div');
            sub.className = 'text-xs text-muted';
            sub.textContent = (file.size / (1024 * 1024)).toFixed(2) + ' MB';

            textWrap.appendChild(title);
            textWrap.appendChild(sub);

            card.appendChild(previewElement);
            card.appendChild(textWrap);
            wrapper.appendChild(card);
            dest.appendChild(wrapper);
        });
    });
}

// Handle Form uploads logically and step loaders
async function handleForensicForm(e, formId) {
    e.preventDefault();
    const form = document.getElementById(formId);
    if (!form) return;

    const formData = new FormData(form);
    
    // Inject global forensic calibration setting (for easy mock vector testing)
    const calEl = document.getElementById('globalForensicCalibration');
    if (calEl) {
        formData.append('forensic_calibration', calEl.value);
    }
    
    // Hide Idle, Show Loading Progress
    toggleReportState('loading');
    startProgressAnimation();

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        if (result.success) {
            setTimeout(() => {
                renderReport(result.data, formData.get('media_type'));
            }, 400); // Super fast report rendering
        } else {
            alert('Forensics Analysis Failed: ' + (result.message || 'Unknown network error.'));
            toggleReportState('idle');
        }
    } catch (err) {
        console.error(err);
        alert('Server connection failed. Could not process multi-modal check.');
        toggleReportState('idle');
    }
}

// URL platform check
async function handleUrlScan(e) {
    e.preventDefault();
    const urlVal = document.getElementById('urlInput').value.trim();
    if (!urlVal) return;

    toggleReportState('loading');
    startProgressAnimation();

    const calEl = document.getElementById('globalForensicCalibration');
    const calVal = calEl ? calEl.value : 'auto';

    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ media_type: 'url', url: urlVal, forensic_calibration: calVal })
        });

        const result = await response.json();
        if (result.success) {
            setTimeout(() => {
                renderReport(result.data, 'url');
            }, 400);
        } else {
            alert('URL scan failed: ' + result.message);
            toggleReportState('idle');
        }
    } catch (err) {
        console.error(err);
        toggleReportState('idle');
    }
}

// Simulated stepped progress loaders
function startProgressAnimation() {
    const stages = [
        { progress: 15, text: "COMPUTING FOURIER FFT TRANSFORM..." },
        { progress: 45, text: "EXTRACTING COMPOSITE FACE COORDINATES..." },
        { progress: 75, text: "INTERPOLATING ENSEMBLE CLASSIFICATION..." },
        { progress: 95, text: "GENERATING EXPLAINABLE RADAR HEATMAP..." }
    ];

    const bar = document.getElementById('loaderBar');
    const label = document.getElementById('loaderSubText');
    if (!bar || !label) return;

    bar.style.width = '5%';
    label.textContent = "INITIALIZING HIGH ACCURACY ANALYST...";

    stages.forEach((stage, index) => {
        setTimeout(() => {
            bar.style.width = stage.progress + '%';
            label.textContent = stage.text;
        }, (index + 1) * 80);
    });
}

// Switch Right sidebar report panels
function toggleReportState(state) {
    const idle = document.getElementById('idleReport');
    const loading = document.getElementById('loadingReport');
    const active = document.getElementById('activeReport');

    idle.classList.add('d-none');
    loading.classList.add('d-none');
    active.classList.add('d-none');

    if (state === 'idle') idle.classList.remove('d-none');
    if (state === 'loading') loading.classList.remove('d-none');
    if (state === 'active') active.classList.remove('d-none');
}

// Render dynamic results report of deepfake analysis
function renderReport(report, mediaType) {
    toggleReportState('active');

    const vFake = document.getElementById('verdictFake');
    const vReal = document.getElementById('verdictReal');

    const confFake = document.getElementById('confValueFake');
    const confReal = document.getElementById('confValueReal');

    const summaryFake = document.getElementById('verdictSummaryFake');
    const summaryReal = document.getElementById('verdictSummaryReal');

    // Update active classification model badge
    const engineBadge = document.getElementById('activeEngineBadge');
    if (engineBadge) {
        const engineName = report.engine || 'Local Heuristics Engine';
        let badgeIcon = '<i class="bi bi-cpu text-info"></i>';
        if (engineName.includes('Gemini')) {
            badgeIcon = '<i class="bi bi-stars text-warning"></i>';
        } else if (engineName.includes('Sandbox') || engineName.includes('Adaptive')) {
            badgeIcon = '<i class="bi bi-shield-check text-success"></i>';
        }
        engineBadge.innerHTML = `${badgeIcon} ACTIVE PIPELINE: <strong class="text-dark ms-1">${engineName}</strong>`;
    }

    // 1. Set Verdict Banners based on prediction verdict
    vFake.classList.add('d-none');
    vReal.classList.add('d-none');

    if (report.verdict === 'FAKE') {
        vFake.classList.remove('d-none');
        confFake.textContent = `FAKE (${report.confidence}% Probability)`;
        summaryFake.textContent = report.explanation || 'Visual noise checks point to generative adversarial adjustments.';
    } else {
        vReal.classList.remove('d-none');
        confReal.textContent = `REAL (${report.confidence}% Authentic)`;
        summaryReal.textContent = report.explanation || 'Verified consistent pixel gradient limits, indicating genuine footage.';
    }

    // 2. Load and overlay Grad-CAM canvas
    renderGradcamCanvas(report, mediaType);

    // 3. Slide sub-weights
    updateSlideBar('weightBar1', 'weightVal1', report.metrics.blending);
    updateSlideBar('weightBar2', 'weightVal2', report.metrics.gan);
    updateSlideBar('weightBar3', 'weightVal3', report.metrics.anomaly);

    // 4. Radar diagnostis Chart
    renderRadarChart(report.metrics);
}

function updateSlideBar(barId, valId, score) {
    const bar = document.getElementById(barId);
    const val = document.getElementById(valId);
    if (!bar || !val) return;

    bar.style.width = score + '%';
    val.textContent = score + '%';
    
    // Change bar color based on danger margins
    bar.className = 'progress-bar rounded-pill';
    if (score >= 75) {
        bar.classList.add('bg-danger');
    } else if (score >= 45) {
        bar.classList.add('bg-warning');
    } else {
        bar.classList.add('bg-success');
    }
}

// Draw Gradient Heatmap Mockups using Canvas Overlays (Explainable AI)
function renderGradcamCanvas(report, mediaType) {
    const canvas = document.getElementById('gradcamCanvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    canvas.width = 300;
    canvas.height = 220;

    // Clear Canvas first
    ctx.clearRect(0,0, canvas.width, canvas.height);

    // Draw dark techno visual layout overlay
    ctx.fillStyle = "#0f172a";
    ctx.fillRect(0,0, canvas.width, canvas.height);

    // Draw Face grid outline helper
    ctx.strokeStyle = "rgba(16, 185, 129, 0.15)";
    ctx.lineWidth = 1;
    for(let i = 20; i < canvas.width; i+=20) {
        ctx.beginPath();
        ctx.moveTo(i, 0);
        ctx.lineTo(i, canvas.height);
        ctx.stroke();
    }
    for(let i = 20; i < canvas.height; i+=20) {
        ctx.beginPath();
        ctx.moveTo(0, i);
        ctx.lineTo(canvas.width, i);
        ctx.stroke();
    }

    // Draw bounding box silhouette of facial scanning
    ctx.strokeStyle = report.verdict === 'FAKE' ? "rgba(239, 68, 68, 0.4)" : "rgba(16, 185, 129, 0.4)";
    ctx.lineWidth = 2;
    ctx.strokeRect(100, 40, 100, 120);

    // Bounding corners list
    const cropX = 100, cropY = 40, cropW = 100, cropH = 120;
    ctx.fillStyle = report.verdict === 'FAKE' ? "#ef4444" : "#10b981";
    ctx.fillRect(cropX-2, cropY-2, 8, 2);
    ctx.fillRect(cropX-2, cropY-2, 2, 8);
    ctx.fillRect(cropX+cropW-6, cropY-2, 8, 2);
    ctx.fillRect(cropX+cropW, cropY-2, 2, 8);
    ctx.fillRect(cropX-2, cropY+cropH, 8, 2);
    ctx.fillRect(cropX-2, cropY+cropH-6, 2, 8);
    ctx.fillRect(cropX+cropW-6, cropY+cropH, 8, 2);
    ctx.fillRect(cropX+cropW, cropY+cropH-6, 2, 8);

    // Eye hotspots or blending boundary anomalies heat spots
    if (report.verdict === 'FAKE') {
        // Red Hotspot 1 (Eyes matching right side coordinates)
        let grad = ctx.createRadialGradient(130, 75, 2, 130, 75, 30);
        grad.addColorStop(0, 'rgba(239, 68, 68, 1)');
        grad.addColorStop(0.3, 'rgba(239, 68, 68, 0.6)');
        grad.addColorStop(0.6, 'rgba(245, 158, 11, 0.3)');
        grad.addColorStop(1, 'rgba(239, 68, 68, 0)');
        ctx.fillStyle = grad;
        ctx.beginPath(); ctx.arc(130, 75, 30, 0, Math.PI*2); ctx.fill();

        // Warning circle tags text
        ctx.fillStyle = "rgba(239, 68, 68, 0.85)";
        ctx.font = "8px JetBrains Mono";
        ctx.fillText("SEAM_TRACE_92.4%", 150, 150);

        // Orange Hotspot 2 (Mouth/Chin area coordinates)
        let grad2 = ctx.createRadialGradient(150, 125, 2, 150, 125, 45);
        grad2.addColorStop(0, 'rgba(245, 158, 11, 1)');
        grad2.addColorStop(0.4, 'rgba(239, 68, 68, 0.4)');
        grad2.addColorStop(1, 'rgba(245, 158, 11, 0)');
        ctx.fillStyle = grad2;
        ctx.beginPath(); ctx.arc(150, 125, 45, 0, Math.PI*2); ctx.fill();
        
        ctx.fillStyle = "rgba(245, 158, 11, 0.9)";
        ctx.fillText("GRAD_ANOMALY_84.5%", 105, 175);
    } else {
        // Green Hotspots for authentic vectors
        // Eye hotspots standard alignments
        let grad1 = ctx.createRadialGradient(130, 75, 1, 130, 75, 15);
        grad1.addColorStop(0, 'rgba(16, 185, 129, 0.7)');
        grad1.addColorStop(1, 'rgba(16, 185, 129, 0)');
        ctx.fillStyle = grad1;
        ctx.beginPath(); ctx.arc(130, 75, 15, 0, Math.PI*2); ctx.fill();

        let grad2 = ctx.createRadialGradient(170, 75, 1, 170, 75, 15);
        grad2.addColorStop(0, 'rgba(16, 185, 129, 0.7)');
        grad2.addColorStop(1, 'rgba(16, 185, 129, 0)');
        ctx.fillStyle = grad2;
        ctx.beginPath(); ctx.arc(170, 75, 15, 0, Math.PI*2); ctx.fill();

        ctx.fillStyle = "rgba(16, 185, 129, 0.8)";
        ctx.font = "8px JetBrains Mono";
        ctx.fillText("ALIGNED_VECTORS: MATCH", 102, 175);
    }
}

// Diagnostic Radar profiles via Chart.js
function renderRadarChart(metrics) {
    const canvas = document.getElementById('forensicRadarCanvas');
    if (!canvas) return;

    if (activeRadarChart) {
        activeRadarChart.destroy();
    }

    const ctx = canvas.getContext('2d');
    activeRadarChart = new Chart(ctx, {
        type: 'radar',
        data: {
            labels: ['Boundary Blend', 'CNN Artifacts', 'Freq Anomaly', 'Moire Noise', 'Stitching Alignment'],
            datasets: [{
                label: 'Sensing Matrix %',
                data: [metrics.blending, metrics.gan, metrics.anomaly, Math.round(metrics.blending*0.6 + metrics.gan*0.4), Math.round(metrics.anomaly*0.7)],
                backgroundColor: 'rgba(16, 185, 129, 0.2)',
                borderColor: '#10b981',
                borderWidth: 2,
                pointBackgroundColor: '#047857',
            }]
        },
        options: {
            plugins: {
                legend: { display: false }
            },
            scales: {
                r: {
                    angleLines: { color: 'rgba(0,0,0,0.06)' },
                    grid: { color: 'rgba(0,0,0,0.06)' },
                    suggestedMin: 0,
                    suggestedMax: 100,
                    ticks: { display: false }
                }
            },
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

function resetForensic() {
    toggleReportState('idle');
}

// 4. Multi-media Webcam handling (Page 33 & 51 parameters)
let streamInstance = null;

function setupWebcam() {
    const activateBtn = document.getElementById('activateCamBtn');
    const captureBtn = document.getElementById('captureScanBtn');
    const video = document.getElementById('webcamVideo');
    const promptBox = document.querySelector('.webcam-disconnected');
    const gridOverlay = document.querySelector('.webcam-scan-overlay');

    if (!activateBtn) return;

    activateBtn.addEventListener('click', async function() {
        promptBox.innerHTML = '<div class="spinner-border text-mint small mb-2"></div><p class="small text-muted mb-0">Connecting camera frame feeds...</p>';
        
        try {
            const stream = await navigator.mediaDevices.getUserMedia({
                video: { width: 640, height: 480 },
                audio: false
            });

            streamInstance = stream;
            video.srcObject = stream;
            video.classList.remove('d-none');
            
            promptBox.classList.add('d-none');
            gridOverlay.classList.remove('d-none');
            captureBtn.classList.remove('d-none');
        } catch (err) {
            console.error(err);
            promptBox.innerHTML = '<i class="bi bi-exclamation-octagon-fill text-danger fs-3 mb-2"></i><p class="small text-danger mb-0">Webcam feed entry blocked or unsupported by sandbox preview. Use tab file-drops instead.</p>';
        }
    });

    if (captureBtn) {
        captureBtn.addEventListener('click', async function() {
            if (!streamInstance) return;

            // Flash video to capture a canvas image tag representing camera frames
            const canvas = document.createElement('canvas');
            canvas.width = video.videoWidth || 640;
            canvas.height = video.videoHeight || 480;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

            // Convert raw frame to JPEG Base64 payload
            const rawFrame = canvas.toDataURL('image/jpeg');

            toggleReportState('loading');
            startProgressAnimation();

            const calEl = document.getElementById('globalForensicCalibration');
            const calVal = calEl ? calEl.value : 'auto';

            const spoofEl = document.getElementById('webcamSimulateSpoof');
            const spoofVal = spoofEl ? spoofEl.checked : false;

            try {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        media_type: 'webcam',
                        frame: rawFrame,
                        forensic_calibration: calVal,
                        webcam_simulate_spoof: spoofVal
                    })
                });

                const result = await response.json();
                if (result.success) {
                    setTimeout(() => {
                        renderReport(result.data, 'webcam');
                    }, 400);
                } else {
                    alert('Camera verification failed: ' + result.message);
                    toggleReportState('idle');
                }
            } catch (err) {
                console.error(err);
                toggleReportState('idle');
            }
        });
    }
}

// Interactive Forensic Test Deck controllers (Page 44 dataset helpers)
function setTestFilename(filename, tabType) {
    // 1. Switch Bootstrap pill active state
    const tabEl = document.getElementById(`pills-${tabType}-tab`);
    if (tabEl) {
        const tab = new bootstrap.Tab(tabEl);
        tab.show();
    }

    // 2. Generate a valid simulated File instance
    let mime = "video/mp4";
    if (tabType === 'image') mime = "image/jpeg";
    if (tabType === 'audio') mime = "audio/wav";

    const testFile = new File([new Uint8Array(200)], filename, { type: mime });

    // 3. Inject mock file into actual input element using DataTransfer container API
    const inputEl = document.getElementById(`${tabType}Files`);
    if (inputEl) {
        const dataTransfer = new DataTransfer();
        dataTransfer.items.add(testFile);
        inputEl.files = dataTransfer.files;

        // Dispatch state change events to refresh previews & enable submittal button
        inputEl.dispatchEvent(new Event('change'));
    }
}

function setTestUrl(url) {
    // Switch to URL scanning tab
    const tabEl = document.getElementById('pills-url-tab');
    if (tabEl) {
        const tab = new bootstrap.Tab(tabEl);
        tab.show();
    }

    // Pre-populate input URL field
    const inputEl = document.getElementById('urlInput');
    if (inputEl) {
        inputEl.value = url;
    }
}

