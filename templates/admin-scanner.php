<?php
/**
 * Admin Scanner Template — Dark glassmorphism UI with Scanner + Quarantine tabs.
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) exit;
?>
<div class="wrap bestdid-scanner-wrap">
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

.bestdid-scanner-wrap {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    margin-left: -20px;
    padding: 30px;
    min-height: 100vh;
}

/* Header */
.scanner-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 30px;
}
.scanner-header-left {
    display: flex;
    align-items: center;
    gap: 20px;
}
.scanner-logo {
    width: 60px;
    height: 60px;
    background: linear-gradient(135deg, #8b5cf6, #6366f1);
    border-radius: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 28px;
    box-shadow: 0 10px 30px rgba(139, 92, 246, 0.3);
}
.scanner-title h1 {
    margin: 0;
    font-size: 28px;
    font-weight: 700;
    color: #fff;
}
.scanner-title p {
    margin: 5px 0 0;
    color: rgba(255,255,255,0.6);
    font-size: 14px;
}

/* Tabs */
.scanner-tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 24px;
    background: rgba(255,255,255,0.05);
    border-radius: 14px;
    padding: 4px;
    display: inline-flex;
}
.scanner-tab {
    padding: 10px 24px;
    border-radius: 10px;
    color: rgba(255,255,255,0.5);
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    border: none;
    background: none;
    transition: all 0.3s;
}
.scanner-tab:hover {
    color: rgba(255,255,255,0.8);
}
.scanner-tab.active {
    background: rgba(255,255,255,0.1);
    color: #fff;
    box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}
.tab-content { display: none; }
.tab-content.active { display: block; }

/* Stats Row */
.stats-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 24px;
}
.mini-stat {
    background: rgba(255,255,255,0.05);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 16px;
    padding: 20px;
    text-align: center;
}
.mini-stat-value {
    font-size: 28px;
    font-weight: 700;
    color: #fff;
}
.mini-stat-label {
    font-size: 12px;
    color: rgba(255,255,255,0.5);
    margin-top: 4px;
}

/* Card */
.scanner-card {
    background: rgba(255,255,255,0.05);
    backdrop-filter: blur(10px);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 20px;
    overflow: hidden;
    margin-bottom: 20px;
}
.scanner-card-header {
    padding: 20px 25px;
    border-bottom: 1px solid rgba(255,255,255,0.1);
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.scanner-card-header h3 {
    margin: 0;
    font-size: 16px;
    font-weight: 600;
    color: #fff;
}
.scanner-card-body { padding: 25px; }

/* Scan controls */
.scan-btn {
    background: linear-gradient(135deg, #8b5cf6, #6366f1);
    color: white;
    border: none;
    padding: 14px 32px;
    border-radius: 12px;
    cursor: pointer;
    font-size: 15px;
    font-weight: 600;
    transition: all 0.3s;
    display: inline-flex;
    align-items: center;
    gap: 8px;
}
.scan-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 30px rgba(99, 102, 241, 0.4);
}
.scan-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    transform: none;
    box-shadow: none;
}
.scan-btn.cancel {
    background: linear-gradient(135deg, #ef4444, #dc2626);
}

/* Progress */
.scan-progress {
    display: none;
    margin-top: 24px;
}
.progress-bar-outer {
    width: 100%;
    height: 12px;
    background: rgba(255,255,255,0.1);
    border-radius: 6px;
    overflow: hidden;
}
.progress-bar-inner {
    height: 100%;
    background: linear-gradient(90deg, #8b5cf6, #06b6d4);
    border-radius: 6px;
    transition: width 0.3s;
    width: 0%;
}
.progress-info {
    display: flex;
    justify-content: space-between;
    margin-top: 10px;
    font-size: 13px;
    color: rgba(255,255,255,0.6);
}
.progress-file {
    font-size: 12px;
    color: rgba(255,255,255,0.4);
    margin-top: 6px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}

/* Results table */
.results-table {
    width: 100%;
    border-collapse: collapse;
}
.results-table th {
    text-align: left;
    padding: 12px 16px;
    color: rgba(255,255,255,0.5);
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid rgba(255,255,255,0.1);
}
.results-table td {
    padding: 14px 16px;
    color: rgba(255,255,255,0.8);
    font-size: 13px;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    vertical-align: middle;
}
.results-table tr:hover td {
    background: rgba(255,255,255,0.03);
}
.results-table .file-path {
    font-family: 'SF Mono', Monaco, monospace;
    font-size: 12px;
    word-break: break-all;
    max-width: 300px;
}

/* Badges */
.severity-badge {
    display: inline-block;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.severity-badge.critical { background: rgba(239,68,68,0.2); color: #f87171; }
.severity-badge.high { background: rgba(245,158,11,0.2); color: #fbbf24; }
.severity-badge.medium { background: rgba(59,130,246,0.2); color: #60a5fa; }
.severity-badge.low { background: rgba(34,197,94,0.2); color: #4ade80; }

.threat-badge {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 11px;
    background: rgba(255,255,255,0.08);
    color: rgba(255,255,255,0.6);
}

/* Action buttons */
.action-btn {
    padding: 6px 14px;
    border-radius: 6px;
    border: none;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
    margin-right: 4px;
}
.action-btn.quarantine {
    background: rgba(245,158,11,0.2);
    color: #fbbf24;
}
.action-btn.quarantine:hover {
    background: rgba(245,158,11,0.4);
}
.action-btn.ignore {
    background: rgba(255,255,255,0.08);
    color: rgba(255,255,255,0.5);
}
.action-btn.ignore:hover {
    background: rgba(255,255,255,0.15);
}
.action-btn.restore {
    background: rgba(34,197,94,0.2);
    color: #4ade80;
}
.action-btn.restore:hover {
    background: rgba(34,197,94,0.4);
}
.action-btn.delete-perm {
    background: rgba(239,68,68,0.2);
    color: #f87171;
}
.action-btn.delete-perm:hover {
    background: rgba(239,68,68,0.4);
}

/* Empty state */
.empty-state {
    padding: 60px 20px;
    text-align: center;
    color: rgba(255,255,255,0.4);
}
.empty-state-icon { font-size: 48px; margin-bottom: 15px; opacity: 0.5; }
.empty-state h4 { margin: 0 0 5px; color: rgba(255,255,255,0.6); font-size: 16px; }
.empty-state p { margin: 0; font-size: 13px; }

@media (max-width: 1024px) {
    .stats-row { grid-template-columns: repeat(2, 1fr); }
}
</style>

<!-- Header -->
<div class="scanner-header">
    <div class="scanner-header-left">
        <div class="scanner-logo">🔍</div>
        <div class="scanner-title">
            <h1>Malware Scanner</h1>
            <p>Deep file scanning for malware, backdoors, and core integrity</p>
        </div>
    </div>
</div>

<!-- Tabs -->
<div class="scanner-tabs">
    <button class="scanner-tab active" data-tab="scanner">Scanner</button>
    <button class="scanner-tab" data-tab="quarantine">Quarantine <span id="quarantine-badge" style="background:rgba(239,68,68,0.3);color:#f87171;padding:2px 8px;border-radius:10px;font-size:11px;margin-left:4px;"><?php echo intval( $quarantine_count ); ?></span></button>
</div>

<!-- ═══════════════════ SCANNER TAB ═══════════════════ -->
<div class="tab-content active" id="tab-scanner">

    <!-- Stats -->
    <div class="stats-row">
        <div class="mini-stat">
            <div class="mini-stat-value"><?php echo $last_scan ? esc_html( human_time_diff( strtotime( $last_scan['finished_at'] ), current_time( 'timestamp' ) ) ) : '—'; ?></div>
            <div class="mini-stat-label">Last Scan</div>
        </div>
        <div class="mini-stat">
            <div class="mini-stat-value"><?php echo $last_scan ? number_format( $last_scan['total'] ) : '0'; ?></div>
            <div class="mini-stat-label">Files Scanned</div>
        </div>
        <div class="mini-stat">
            <div class="mini-stat-value"><?php echo $last_scan ? number_format( $last_scan['findings'] ) : '0'; ?></div>
            <div class="mini-stat-label">Threats Found</div>
        </div>
        <div class="mini-stat">
            <div class="mini-stat-value"><?php echo intval( $quarantine_count ); ?></div>
            <div class="mini-stat-label">Quarantined</div>
        </div>
    </div>

    <!-- Scan Controls -->
    <div class="scanner-card">
        <div class="scanner-card-header">
            <h3>File Scanner</h3>
        </div>
        <div class="scanner-card-body">
            <button id="btn-start-scan" class="scan-btn">
                <span>🔍</span> Start Full Scan
            </button>
            <button id="btn-cancel-scan" class="scan-btn cancel" style="display:none;">
                <span>✕</span> Cancel Scan
            </button>

            <div class="scan-progress" id="scan-progress">
                <div class="progress-bar-outer">
                    <div class="progress-bar-inner" id="progress-bar"></div>
                </div>
                <div class="progress-info">
                    <span id="progress-text">Initializing...</span>
                    <span id="progress-percent">0%</span>
                </div>
                <div class="progress-file" id="progress-file">&nbsp;</div>
            </div>
        </div>
    </div>

    <!-- Results -->
    <div class="scanner-card" id="results-card" style="display:none;">
        <div class="scanner-card-header">
            <h3>Scan Results</h3>
            <span id="results-count" style="color:rgba(255,255,255,0.5);font-size:13px;"></span>
        </div>
        <div class="scanner-card-body" style="padding:0;">
            <table class="results-table">
                <thead>
                    <tr>
                        <th>File Path</th>
                        <th>Threat Type</th>
                        <th>Severity</th>
                        <th>Signature</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="results-body"></tbody>
            </table>
            <div class="empty-state" id="results-empty" style="display:none;">
                <div class="empty-state-icon">✅</div>
                <h4>No Threats Found</h4>
                <p>Your site looks clean. No malware or suspicious files detected.</p>
            </div>
        </div>
    </div>
</div>

<!-- ═══════════════════ QUARANTINE TAB ═══════════════════ -->
<div class="tab-content" id="tab-quarantine">
    <div class="scanner-card">
        <div class="scanner-card-header">
            <h3>Quarantined Files</h3>
            <span style="color:rgba(255,255,255,0.5);font-size:13px;"><?php echo count( $quarantined_files ); ?> file(s)</span>
        </div>
        <div class="scanner-card-body" style="padding:0;">
            <?php if ( empty( $quarantined_files ) ) : ?>
                <div class="empty-state">
                    <div class="empty-state-icon">📁</div>
                    <h4>No Quarantined Files</h4>
                    <p>Files moved to quarantine will appear here.</p>
                </div>
            <?php else : ?>
                <table class="results-table">
                    <thead>
                        <tr>
                            <th>Original Path</th>
                            <th>Date</th>
                            <th>Size</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ( $quarantined_files as $qf ) : ?>
                            <tr id="qrow-<?php echo intval( $qf->id ); ?>">
                                <td class="file-path"><?php echo esc_html( str_replace( ABSPATH, '', $qf->original_path ) ); ?></td>
                                <td><?php echo esc_html( date( 'M j, Y g:i A', strtotime( $qf->quarantined_at ) ) ); ?></td>
                                <td><?php echo esc_html( size_format( $qf->file_size ) ); ?></td>
                                <td>
                                    <button class="action-btn restore" onclick="bdsecRestoreFile(<?php echo intval( $qf->id ); ?>)">Restore</button>
                                    <button class="action-btn delete-perm" onclick="bdsecDeleteQuarantined(<?php echo intval( $qf->id ); ?>)">Delete</button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>
</div>

<script>
(function() {
    var nonce    = '<?php echo wp_create_nonce( 'bdsec_scanner_nonce' ); ?>';
    var ajaxUrl  = '<?php echo admin_url( 'admin-ajax.php' ); ?>';
    var scanId   = null;
    var scanning = false;

    /* ── Tab switching ──────────────────────────────────── */
    document.querySelectorAll('.scanner-tab').forEach(function(tab) {
        tab.addEventListener('click', function() {
            document.querySelectorAll('.scanner-tab').forEach(function(t) { t.classList.remove('active'); });
            document.querySelectorAll('.tab-content').forEach(function(c) { c.classList.remove('active'); });
            this.classList.add('active');
            document.getElementById('tab-' + this.dataset.tab).classList.add('active');
        });
    });

    /* ── AJAX helper ────────────────────────────────────── */
    function post(action, data, cb) {
        data.action = action;
        data._nonce = nonce;
        var fd = new FormData();
        for (var k in data) fd.append(k, data[k]);
        fetch(ajaxUrl, { method: 'POST', body: fd, credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(r) { cb(r.success ? r.data : null, r.success ? null : (r.data || 'Error')); })
            .catch(function(e) { cb(null, e.message); });
    }

    /* ── Start Scan ─────────────────────────────────────── */
    document.getElementById('btn-start-scan').addEventListener('click', function() {
        if (scanning) return;
        scanning = true;
        this.disabled = true;
        document.getElementById('btn-cancel-scan').style.display = 'inline-flex';
        document.getElementById('scan-progress').style.display = 'block';
        document.getElementById('results-card').style.display = 'none';
        updateProgress(0, 0, 'Collecting files...');

        post('bdsec_start_scan', {}, function(data, err) {
            if (err || !data) {
                alert('Failed to start scan: ' + (err || 'Unknown error'));
                resetUI();
                return;
            }
            scanId = data.scan_id;
            updateProgress(0, data.total_files, 'Scanning...');
            processNext();
        });
    });

    /* ── Process loop ───────────────────────────────────── */
    function processNext() {
        if (!scanning || !scanId) return;
        post('bdsec_process_chunk', { scan_id: scanId }, function(data, err) {
            if (err || !data) {
                alert('Scan error: ' + (err || 'Unknown'));
                resetUI();
                return;
            }
            if (data.error) {
                alert(data.error);
                resetUI();
                return;
            }
            updateProgress(data.processed, data.total, data.current_file || '');
            if (data.done) {
                scanComplete(data);
            } else {
                processNext();
            }
        });
    }

    /* ── Cancel ─────────────────────────────────────────── */
    document.getElementById('btn-cancel-scan').addEventListener('click', function() {
        post('bdsec_cancel_scan', {}, function() {});
        scanning = false;
        scanId = null;
        resetUI();
    });

    /* ── UI helpers ─────────────────────────────────────── */
    function updateProgress(processed, total, file) {
        var pct = total > 0 ? Math.round((processed / total) * 100) : 0;
        document.getElementById('progress-bar').style.width = pct + '%';
        document.getElementById('progress-percent').textContent = pct + '%';
        document.getElementById('progress-text').textContent = processed + ' / ' + total + ' files';
        if (file) document.getElementById('progress-file').textContent = file;
    }

    function resetUI() {
        scanning = false;
        scanId = null;
        document.getElementById('btn-start-scan').disabled = false;
        document.getElementById('btn-cancel-scan').style.display = 'none';
        document.getElementById('scan-progress').style.display = 'none';
    }

    function scanComplete(data) {
        resetUI();
        document.getElementById('progress-text').textContent = 'Scan complete!';

        // Fetch results
        post('bdsec_get_scan_state', {}, function() {});
        loadResults();
    }

    function loadResults() {
        post('bdsec_get_scan_results', {}, function(data, err) {
            var card  = document.getElementById('results-card');
            var tbody = document.getElementById('results-body');
            var empty = document.getElementById('results-empty');
            var count = document.getElementById('results-count');

            card.style.display = 'block';
            tbody.innerHTML = '';

            if (!data || !data.length) {
                empty.style.display = 'block';
                count.textContent = '0 findings';
                return;
            }

            empty.style.display = 'none';
            count.textContent = data.length + ' finding(s)';

            data.forEach(function(r) {
                var tr = document.createElement('tr');
                tr.id = 'row-' + r.id;
                tr.innerHTML =
                    '<td class="file-path">' + escHtml(r.file_path_relative) + '</td>' +
                    '<td><span class="threat-badge">' + escHtml(r.threat_type) + '</span></td>' +
                    '<td><span class="severity-badge ' + escHtml(r.severity) + '">' + escHtml(r.severity) + '</span></td>' +
                    '<td style="font-size:12px;color:rgba(255,255,255,0.5);">' + escHtml(r.matched_signature || r.details) + '</td>' +
                    '<td>' +
                        '<button class="action-btn quarantine" onclick="bdsecQuarantineFile(' + r.id + ')">Quarantine</button>' +
                        '<button class="action-btn ignore" onclick="bdsecIgnoreFinding(' + r.id + ')">Ignore</button>' +
                    '</td>';
                tbody.appendChild(tr);
            });
        });
    }

    function escHtml(s) {
        if (!s) return '';
        var d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    /* ── Action handlers (global scope) ─────────────────── */
    window.bdsecQuarantineFile = function(id) {
        if (!confirm('Move this file to quarantine?')) return;
        post('bdsec_quarantine_file', { finding_id: id }, function(data, err) {
            if (err) { alert('Error: ' + err); return; }
            var row = document.getElementById('row-' + id);
            if (row) row.remove();
        });
    };

    window.bdsecIgnoreFinding = function(id) {
        post('bdsec_ignore_finding', { finding_id: id }, function(data, err) {
            if (err) { alert('Error: ' + err); return; }
            var row = document.getElementById('row-' + id);
            if (row) row.remove();
        });
    };

    window.bdsecRestoreFile = function(id) {
        if (!confirm('Restore this file to its original location?')) return;
        post('bdsec_restore_file', { quarantine_id: id }, function(data, err) {
            if (err) { alert('Error: ' + err); return; }
            var row = document.getElementById('qrow-' + id);
            if (row) row.remove();
        });
    };

    window.bdsecDeleteQuarantined = function(id) {
        if (!confirm('Permanently delete this quarantined file? This cannot be undone.')) return;
        post('bdsec_delete_quarantined', { quarantine_id: id }, function(data, err) {
            if (err) { alert('Error: ' + err); return; }
            var row = document.getElementById('qrow-' + id);
            if (row) row.remove();
        });
    };

    /* ── Auto-load results if last scan exists ──────────── */
    <?php if ( $last_scan ) : ?>
    loadResults();
    <?php endif; ?>
})();
</script>
</div>
