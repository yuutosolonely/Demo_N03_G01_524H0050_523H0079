/**
 * Digital Signature Tool — Frontend JavaScript
 * ==============================================
 * Handles file uploads, API calls, SweetAlert2 notifications,
 * and character-level hash diff visualization.
 */

// Global: stores the last verification result for audit report download
let lastVerificationResult = null;

// ═══════════════════════════════════════════════════════════
//  File Upload Handlers
// ═══════════════════════════════════════════════════════════

function handleDragOver(e) {
    e.preventDefault();
    e.currentTarget.classList.add('drag-over');
}

function handleDragLeave(e) {
    e.preventDefault();
    e.currentTarget.classList.remove('drag-over');
}

function handleDrop(e, inputId) {
    e.preventDefault();
    e.currentTarget.classList.remove('drag-over');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        const input = document.getElementById(inputId);
        input.files = files;
        
        // Determine context from input id
        const context = inputId.replace('-file-input', '');
        handleFileSelect(input, context);
    }
}

function handleFileSelect(input, context) {
    const file = input.files[0];
    if (!file) return;
    
    // Show file preview
    const preview = document.getElementById(`${context}-file-preview`);
    const nameEl = document.getElementById(`${context}-file-name`);
    const sizeEl = document.getElementById(`${context}-file-size`);
    const uploadZone = document.getElementById(`${context}-upload-zone`);
    
    if (preview && nameEl && sizeEl) {
        nameEl.textContent = file.name;
        sizeEl.textContent = formatFileSize(file.size);
        preview.style.display = 'flex';
        if (uploadZone) uploadZone.style.display = 'none';
    }
    
    // Enable relevant button
    if (context === 'sign') {
        updateSignButton();
    } else if (context === 'verify') {
        const btn = document.getElementById('btn-verify');
        if (btn) btn.disabled = false;
    } else if (context === 'demo') {
        const btn = document.getElementById('btn-attack');
        if (btn) btn.disabled = false;
    }
}

function clearFile(context) {
    const input = document.getElementById(`${context}-file-input`);
    const preview = document.getElementById(`${context}-file-preview`);
    const uploadZone = document.getElementById(`${context}-upload-zone`);
    
    if (input) input.value = '';
    if (preview) preview.style.display = 'none';
    if (uploadZone) uploadZone.style.display = '';
    
    if (context === 'sign') {
        updateSignButton();
    } else if (context === 'verify') {
        document.getElementById('btn-verify').disabled = true;
    } else if (context === 'demo') {
        document.getElementById('btn-attack').disabled = true;
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}


// ═══════════════════════════════════════════════════════════
//  Key Management
// ═══════════════════════════════════════════════════════════

function selectKey(element, keyName) {
    document.querySelectorAll('.key-item').forEach(el => el.classList.remove('selected'));
    element.classList.add('selected');
    selectedKeyName = keyName;
    
    const display = document.getElementById('selected-key-name');
    if (display) display.textContent = keyName;
    
    if (typeof updateSignButton === 'function') updateSignButton();
}

async function generateKeys() {
    const algorithm = document.getElementById('algo-select').value;
    const keyName = document.getElementById('key-name-input').value.trim() || null;
    
    const body = { algorithm, key_name: keyName };
    
    if (algorithm === 'RSA') {
        body.key_size = parseInt(document.getElementById('key-size-select').value);
    } else {
        body.curve = document.getElementById('curve-select').value;
    }
    
    const btn = document.getElementById('btn-generate-key');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner"></span> Generating...';
    btn.disabled = true;
    
    try {
        const resp = await fetch('/sender/generate-keys', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        
        const data = await resp.json();
        
        if (data.success) {
            Swal.fire({
                icon: 'success',
                title: 'Key Pair Generated!',
                html: `
                    <div style="text-align:left; font-size:0.9rem;">
                        <p><strong>Algorithm:</strong> ${data.key.algorithm}</p>
                        <p><strong>Name:</strong> ${data.key.key_name}</p>
                        <p><strong>Fingerprint:</strong> <code>${data.key.fingerprint}</code></p>
                    </div>
                `,
                background: '#111827',
                color: '#f1f5f9',
                confirmButtonColor: '#06b6d4',
            });
            
            // Reload to show new key
            setTimeout(() => location.reload(), 1500);
        } else {
            throw new Error(data.error || 'Key generation failed');
        }
    } catch (err) {
        Swal.fire({
            icon: 'error',
            title: 'Error',
            text: err.message,
            background: '#111827',
            color: '#f1f5f9',
            confirmButtonColor: '#ef4444',
        });
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

function copyHash(elementId) {
    const hash = document.getElementById(elementId).textContent;
    navigator.clipboard.writeText(hash).then(() => {
        Swal.fire({
            toast: true,
            position: 'top-end',
            icon: 'success',
            title: 'Hash copied!',
            showConfirmButton: false,
            timer: 1500,
            background: '#111827',
            color: '#f1f5f9',
        });
    });
}


// ═══════════════════════════════════════════════════════════
//  Signing
// ═══════════════════════════════════════════════════════════

async function signFile() {
    const fileInput = document.getElementById('sign-file-input');
    if (!fileInput.files[0] || !selectedKeyName) return;
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    formData.append('key_name', selectedKeyName);
    
    const btn = document.getElementById('btn-sign');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner"></span> Signing...';
    btn.disabled = true;
    
    try {
        const resp = await fetch('/sender/sign', {
            method: 'POST',
            body: formData
        });
        
        const data = await resp.json();
        
        if (data.success) {
            // Show result card
            const resultCard = document.getElementById('step-result');
            resultCard.style.display = '';
            
            document.getElementById('result-file-name').textContent = data.file_name;
            document.getElementById('result-algorithm').textContent = `${data.algorithm} (${data.key_size}-bit)`;
            document.getElementById('result-hash').textContent = data.file_hash;
            document.getElementById('result-signature').textContent = data.signature_hex;
            document.getElementById('result-timestamp').textContent = new Date(data.signed_at).toLocaleString();
            
            const downloadBtn = document.getElementById('btn-download-bundle');
            downloadBtn.href = `/sender/download/${data.bundle_name}`;
            
            // SweetAlert success
            Swal.fire({
                icon: 'success',
                title: 'Document Signed! ✍️',
                html: `
                    <p style="font-size:0.9rem; color:#94a3b8;">
                        <strong>${data.file_name}</strong> has been signed with ${data.algorithm}.<br>
                        Download the <code>.sigbundle</code> to send to the receiver.
                    </p>
                `,
                background: '#111827',
                color: '#f1f5f9',
                confirmButtonColor: '#06b6d4',
            });
            
            // Scroll to result
            resultCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
        } else {
            throw new Error(data.error || 'Signing failed');
        }
    } catch (err) {
        Swal.fire({
            icon: 'error',
            title: 'Signing Failed',
            text: err.message,
            background: '#111827',
            color: '#f1f5f9',
            confirmButtonColor: '#ef4444',
        });
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}


// ═══════════════════════════════════════════════════════════
//  Verification
// ═══════════════════════════════════════════════════════════

async function verifyBundle() {
    const fileInput = document.getElementById('verify-file-input');
    if (!fileInput.files[0]) return;
    
    const formData = new FormData();
    formData.append('bundle', fileInput.files[0]);
    
    const btn = document.getElementById('btn-verify');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner"></span> Verifying...';
    btn.disabled = true;
    
    try {
        const resp = await fetch('/receiver/verify', {
            method: 'POST',
            body: formData
        });
        
        const data = await resp.json();
        
        if (data.success) {
            showVerificationResult(data);
        } else {
            throw new Error(data.verification_error || 'Verification failed');
        }
    } catch (err) {
        Swal.fire({
            icon: 'error',
            title: 'Verification Error',
            text: err.message,
            background: '#111827',
            color: '#f1f5f9',
            confirmButtonColor: '#ef4444',
        });
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

function showVerificationResult(data) {
    // Store globally for audit report download
    lastVerificationResult = data;

    const resultCard = document.getElementById('verify-result-card');
    resultCard.style.display = '';
    
    // Status banner
    const banner = document.getElementById('verify-status-banner');
    const statusIcon = document.getElementById('verify-status-icon');
    const statusText = document.getElementById('verify-status-text');
    
    if (data.signature_valid) {
        banner.className = 'status-banner status-valid';
        statusIcon.textContent = '✓';
        statusText.textContent = 'Signature Valid — File Integrity Confirmed';
        
        Swal.fire({
            icon: 'success',
            title: '✓ Signature Valid',
            text: 'The file has not been modified since it was signed.',
            background: '#111827',
            color: '#f1f5f9',
            confirmButtonColor: '#10b981',
        });
    } else {
        banner.className = 'status-banner status-invalid';
        statusIcon.textContent = '✗';
        statusText.textContent = 'ALERT: Signature Invalid — File Tampered!';
        
        Swal.fire({
            icon: 'error',
            title: '✗ SIGNATURE INVALID',
            html: `<p style="color:#ef4444; font-weight:600;">The file has been tampered with!</p>
                   <p style="color:#94a3b8; font-size:0.85rem; margin-top:8px;">${data.verification_error || 'Hash mismatch detected.'}</p>`,
            background: '#111827',
            color: '#f1f5f9',
            confirmButtonColor: '#ef4444',
        });
    }
    
    // Details
    document.getElementById('verify-result-filename').textContent = data.file_name || '-';
    document.getElementById('verify-result-filesize').textContent = formatFileSize(data.file_size || 0);
    document.getElementById('verify-result-algo').textContent = data.algorithm || '-';
    document.getElementById('verify-result-keysize').textContent = (data.key_size || '-') + '-bit';
    document.getElementById('verify-result-time').textContent = data.signed_at ? new Date(data.signed_at).toLocaleString() : '-';
    document.getElementById('verify-result-sig').textContent = data.signature_hex || '-';
    
    // Hash comparison with character-level highlighting
    renderHashComparison(
        'verify-hash-original', 
        'verify-hash-recomputed', 
        data.original_hash, 
        data.recomputed_hash,
        data.hash_comparison
    );

    // Metadata binding notice (v2.0)
    if (data.metadata_signed) {
        const tbs = document.getElementById('verify-tbs-notice');
        if (tbs) {
            tbs.style.display = '';
            document.getElementById('verify-tbs-text').innerHTML =
                '<strong>Metadata Bound (v2.0):</strong> The signature covers both file content AND metadata (timestamp, algorithm). Modifying any manifest field will invalidate the signature.';
        }
    }
    
    // PKI notice
    if (data.pki_notice) {
        const pki = document.getElementById('verify-pki-notice');
        pki.style.display = '';
        document.getElementById('verify-pki-text').innerHTML = `<strong>PKI Notice:</strong> ${data.pki_notice}`;
    }

    // Show audit report download button
    const reportSection = document.getElementById('verify-report-section');
    if (reportSection) reportSection.style.display = '';
    
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderHashComparison(origId, recompId, hash1, hash2, comparison) {
    const origEl = document.getElementById(origId);
    const recompEl = document.getElementById(recompId);
    
    if (!comparison || !comparison.diff_positions) {
        origEl.textContent = hash1;
        recompEl.textContent = hash2;
        return;
    }
    
    const diffSet = new Set(comparison.diff_positions);
    
    // Render with character-level highlighting
    origEl.innerHTML = renderHashChars(hash1, diffSet);
    recompEl.innerHTML = renderHashChars(hash2, diffSet);
}

function renderHashChars(hash, diffPositions) {
    let html = '';
    for (let i = 0; i < hash.length; i++) {
        const isDiff = diffPositions.has(i);
        const cls = isDiff ? 'hash-char-diff' : 'hash-char-match';
        html += `<span class="hash-char ${cls}">${hash[i]}</span>`;
    }
    return `<div class="hash-diff-chars">${html}</div>`;
}


// ═══════════════════════════════════════════════════════════
//  Attack Demo
// ═══════════════════════════════════════════════════════════

async function runAttack() {
    const fileInput = document.getElementById('demo-file-input');
    if (!fileInput.files[0]) return;
    
    const tamperType = document.querySelector('input[name="attack_type"]:checked').value;
    
    const formData = new FormData();
    formData.append('bundle', fileInput.files[0]);
    formData.append('tamper_type', tamperType);
    
    const btn = document.getElementById('btn-attack');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner"></span> Attacking...';
    btn.disabled = true;
    
    try {
        const resp = await fetch('/demo/tamper', {
            method: 'POST',
            body: formData
        });
        
        const data = await resp.json();
        
        if (data.tamper_result && data.tamper_result.success) {
            showDemoResults(data);
        } else {
            throw new Error(data.tamper_result?.error || 'Attack simulation failed');
        }
    } catch (err) {
        Swal.fire({
            icon: 'error',
            title: 'Demo Error',
            text: err.message,
            background: '#111827',
            color: '#f1f5f9',
            confirmButtonColor: '#ef4444',
        });
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

function showDemoResults(data) {
    const orig = data.original_verification;
    const tamper = data.tamper_result;
    const tamperVerify = tamper.verification_result;
    
    // Show results section
    document.getElementById('demo-results').style.display = '';
    
    // Original hash
    document.getElementById('demo-original-hash').textContent = orig.original_hash;
    
    // Tampered hash
    document.getElementById('demo-tampered-hash').textContent = tamper.tampered_hash;
    
    // Attack details
    const details = tamper.tamper_details;
    document.getElementById('demo-attack-details').textContent = details.description;
    
    // Hash diff visualization
    buildHashDiffGrid(orig.original_hash, tamper.tampered_hash);
    
    // SweetAlert notification
    Swal.fire({
        icon: 'warning',
        title: '⚔️ Attack Executed',
        html: `
            <div style="text-align:left; font-size:0.85rem; color:#94a3b8;">
                <p><strong style="color:#ef4444;">Attack Type:</strong> ${details.tamper_type}</p>
                <p style="margin-top:8px;">${details.description}</p>
                <hr style="border-color:#1e293b; margin:12px 0;">
                <p><strong style="color:#10b981;">Original:</strong> ✓ Signature Valid</p>
                <p><strong style="color:#ef4444;">Tampered:</strong> ✗ SIGNATURE INVALID</p>
            </div>
        `,
        background: '#111827',
        color: '#f1f5f9',
        confirmButtonColor: '#8b5cf6',
        confirmButtonText: 'View Hash Diff',
    }).then(() => {
        document.getElementById('hash-diff-card').scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
}

function buildHashDiffGrid(hash1, hash2) {
    const container = document.getElementById('hash-diff-grid');
    const card = document.getElementById('hash-diff-card');
    card.style.display = '';
    
    // Find diff positions
    const diffs = new Set();
    for (let i = 0; i < Math.max(hash1.length, hash2.length); i++) {
        if (hash1[i] !== hash2[i]) diffs.add(i);
    }
    
    // Build original row
    let origHtml = '<div class="hash-diff-row"><span class="hash-diff-row-label">Original</span><div class="hash-diff-chars">';
    for (let i = 0; i < hash1.length; i++) {
        const cls = diffs.has(i) ? 'hash-char-diff' : 'hash-char-match';
        origHtml += `<span class="hash-char ${cls}" style="animation-delay:${i * 30}ms">${hash1[i]}</span>`;
    }
    origHtml += '</div></div>';
    
    // Build tampered row
    let tampHtml = '<div class="hash-diff-row"><span class="hash-diff-row-label">Tampered</span><div class="hash-diff-chars">';
    for (let i = 0; i < hash2.length; i++) {
        const cls = diffs.has(i) ? 'hash-char-diff' : 'hash-char-match';
        tampHtml += `<span class="hash-char ${cls}" style="animation-delay:${i * 30}ms">${hash2[i]}</span>`;
    }
    tampHtml += '</div></div>';
    
    container.innerHTML = origHtml + tampHtml;
    
    // Stats
    const statsEl = document.getElementById('hash-diff-stats-text');
    const total = Math.max(hash1.length, hash2.length);
    const pct = ((diffs.size / total) * 100).toFixed(1);
    statsEl.textContent = `${diffs.size}/${total} characters differ (${pct}%) — This is the SHA-256 Avalanche Effect`;
}


// ═══════════════════════════════════════════════════════════
//  Audit Report Download
// ═══════════════════════════════════════════════════════════

async function downloadAuditReport() {
    if (!lastVerificationResult) {
        Swal.fire({
            icon: 'warning',
            title: 'No Verification Data',
            text: 'Please verify a bundle first before downloading the report.',
            background: '#111827',
            color: '#f1f5f9',
            confirmButtonColor: '#06b6d4',
        });
        return;
    }

    const btn = document.getElementById('btn-download-report');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner"></span> Generating Report...';
    btn.disabled = true;

    try {
        const resp = await fetch('/receiver/report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(lastVerificationResult)
        });

        if (!resp.ok) throw new Error('Failed to generate report');

        // Get the filename from Content-Disposition header
        const disposition = resp.headers.get('Content-Disposition');
        let filename = 'verification_report.txt';
        if (disposition) {
            const match = disposition.match(/filename=(.+)/);
            if (match) filename = match[1];
        }

        // Download the file
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        Swal.fire({
            toast: true,
            position: 'top-end',
            icon: 'success',
            title: 'Report downloaded!',
            showConfirmButton: false,
            timer: 2000,
            background: '#111827',
            color: '#f1f5f9',
        });
    } catch (err) {
        Swal.fire({
            icon: 'error',
            title: 'Report Error',
            text: err.message,
            background: '#111827',
            color: '#f1f5f9',
            confirmButtonColor: '#ef4444',
        });
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}
