<?php
/**
 * Admin File Integrity Monitor Template
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) exit;

$settings      = get_option( 'bestdid_security_settings' );
$baseline_info = get_option( 'bdsec_fim_baseline_info' );
$last_check    = get_option( 'bdsec_fim_last_check' );
$stats         = BDSEC_File_Integrity::get_stats();
$changes       = BDSEC_File_Integrity::get_changes( 100 );
?>
<div class="wrap bestdid-security-wrap">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

        .bestdid-security-wrap {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%) !important;
            margin-left: -20px !important;
            padding: 30px !important;
            min-height: 100vh;
        }
        .bestdid-security-wrap * { box-sizing: border-box; }

        /* Header */
        .bdsec-page-header {
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 30px;
        }
        .bdsec-page-icon {
            width: 60px; height: 60px;
            background: linear-gradient(135deg, #D97757, #E29578);
            border-radius: 16px;
            display: flex; align-items: center; justify-content: center;
            font-size: 28px;
            box-shadow: 0 10px 30px rgba(217, 119, 87, 0.3);
            flex-shrink: 0;
        }
        .bdsec-page-header h1 {
            margin: 0 !important; padding: 0 !important;
            font-size: 28px !important; font-weight: 700 !important; color: #fff !important;
        }
        .bdsec-page-header p {
            margin: 5px 0 0 !important;
            color: rgba(255,255,255,0.6) !important; font-size: 14px !important;
        }

        /* Card */
        .bdsec-card {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            padding: 30px;
            margin-bottom: 25px;
            color: #fff;
        }
        .bdsec-card h2 {
            margin: 0 0 20px !important; padding: 0 !important;
            font-size: 20px !important; font-weight: 600 !important; color: #fff !important;
        }

        /* Stats row */
        .bdsec-stats-row {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .bdsec-mini-stat {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 24px;
            text-align: center;
            transition: all 0.3s;
        }
        .bdsec-mini-stat:hover {
            transform: translateY(-3px);
            background: rgba(255,255,255,0.08);
            box-shadow: 0 15px 30px rgba(0,0,0,0.2);
        }
        .bdsec-mini-stat .num {
            font-size: 36px;
            font-weight: 700;
            line-height: 1;
        }
        .bdsec-mini-stat .num.ok { color: #00ff88; }
        .bdsec-mini-stat .num.warn { color: #fbbf24; }
        .bdsec-mini-stat .num.danger { color: #ff6b6b; }
        .bdsec-mini-stat .num.info { color: #4facfe; }
        .bdsec-mini-stat .lbl {
            color: rgba(255,255,255,0.5);
            font-size: 13px;
            margin-top: 8px;
            font-weight: 500;
        }

        /* Tabs — pill-style */
        .bdsec-tabs {
            display: inline-flex;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 4px;
            margin-bottom: 25px;
        }
        .bdsec-tab-btn {
            padding: 10px 28px;
            border: none;
            background: transparent;
            color: rgba(255,255,255,0.5);
            border-radius: 10px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            font-family: 'Inter', sans-serif;
            transition: all 0.2s;
        }
        .bdsec-tab-btn:hover {
            color: rgba(255,255,255,0.8);
        }
        .bdsec-tab-btn.active {
            background: linear-gradient(135deg, #D97757, #E29578);
            color: #fff;
            box-shadow: 0 4px 15px rgba(217, 119, 87, 0.3);
        }
        .bdsec-tab-content { display: none; }
        .bdsec-tab-content.active { display: block; }

        /* Progress bar */
        .bdsec-progress-wrap { margin: 20px 0; display: none; }
        .bdsec-progress-bar {
            height: 10px;
            background: rgba(255,255,255,0.1);
            border-radius: 5px;
            overflow: hidden;
        }
        .bdsec-progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #D97757, #E29578);
            border-radius: 5px;
            transition: width 0.3s;
            width: 0;
        }
        .bdsec-progress-text {
            color: rgba(255,255,255,0.5);
            font-size: 12px;
            margin-top: 8px;
            text-align: center;
        }

        /* Table */
        .bdsec-table {
            width: 100%;
            border-collapse: collapse;
        }
        .bdsec-table th {
            text-align: left;
            color: rgba(255,255,255,0.5) !important;
            font-size: 11px !important;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            padding: 12px 14px;
            border-bottom: 2px solid rgba(255,255,255,0.1);
            font-weight: 600 !important;
            background: transparent !important;
        }
        .bdsec-table td {
            padding: 12px 14px;
            color: rgba(255,255,255,0.8) !important;
            font-size: 13px !important;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            background: transparent !important;
        }
        .bdsec-table tr:hover td {
            background: rgba(255,255,255,0.03) !important;
        }

        .bdsec-status-pill {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }
        .bdsec-status-pill.modified { background: rgba(251,191,36,0.15); color: #fbbf24; }
        .bdsec-status-pill.new { background: rgba(0,255,136,0.15); color: #00ff88; }
        .bdsec-status-pill.deleted { background: rgba(255,107,107,0.15); color: #ff6b6b; }

        /* Buttons */
        .bdsec-btn {
            display: inline-flex; align-items: center; gap: 6px;
            padding: 10px 20px; border: none; border-radius: 10px;
            font-size: 14px; font-weight: 600; cursor: pointer;
            transition: all 0.3s; font-family: 'Inter', sans-serif;
            text-decoration: none !important;
        }
        .bdsec-btn-primary {
            background: linear-gradient(135deg, #D97757, #E29578) !important;
            color: #fff !important;
        }
        .bdsec-btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(217,119,87,0.3);
        }
        .bdsec-btn-secondary {
            background: rgba(255,255,255,0.08) !important;
            border: 1px solid rgba(255,255,255,0.15) !important;
            color: #fff !important;
        }
        .bdsec-btn-sm { padding: 8px 16px !important; font-size: 12px !important; border-radius: 8px !important; }
        .bdsec-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none !important; }

        .bdsec-hash-cell {
            font-family: 'Courier New', monospace;
            font-size: 11px;
            color: rgba(255,255,255,0.35);
            max-width: 140px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .bdsec-baseline-info {
            color: rgba(255,255,255,0.5);
            font-size: 14px;
            line-height: 1.8;
        }
        .bdsec-baseline-info strong {
            color: #fff;
        }
        .bdsec-card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .bdsec-card-header h2 { margin: 0 !important; }

        .bdsec-empty {
            text-align: center;
            color: rgba(255,255,255,0.3);
            padding: 40px 20px;
            font-size: 14px;
        }
    </style>

    <!-- Header -->
    <div class="bdsec-page-header">
        <div class="bdsec-page-icon">📁</div>
        <div>
            <h1>File Integrity Monitor</h1>
            <p>Detect unauthorized changes to core files, themes, and plugins</p>
        </div>
    </div>

    <!-- Stats -->
    <div class="bdsec-stats-row">
        <div class="bdsec-mini-stat">
            <div class="num info"><?php echo number_format( intval( $stats['total'] ) ); ?></div>
            <div class="lbl">Total Files</div>
        </div>
        <div class="bdsec-mini-stat">
            <div class="num warn"><?php echo intval( $stats['modified'] ); ?></div>
            <div class="lbl">Modified</div>
        </div>
        <div class="bdsec-mini-stat">
            <div class="num ok"><?php echo intval( $stats['new'] ); ?></div>
            <div class="lbl">Added</div>
        </div>
        <div class="bdsec-mini-stat">
            <div class="num danger"><?php echo intval( $stats['deleted'] ); ?></div>
            <div class="lbl">Deleted</div>
        </div>
    </div>

    <!-- Tabs -->
    <div class="bdsec-tabs">
        <button class="bdsec-tab-btn active" data-tab="monitor">Monitor</button>
        <button class="bdsec-tab-btn" data-tab="baseline">Baseline</button>
    </div>

    <!-- Monitor Tab -->
    <div class="bdsec-tab-content active" id="tab-monitor">
        <div class="bdsec-card">
            <div class="bdsec-card-header">
                <h2>Integrity Check</h2>
                <button class="bdsec-btn bdsec-btn-primary" id="checkNowBtn">Check Now</button>
            </div>

            <?php if ( $last_check ) : ?>
            <div class="bdsec-baseline-info" style="margin-bottom:20px;">
                Last check: <strong><?php echo esc_html( $last_check['checked_at'] ); ?></strong> &mdash;
                Modified: <strong><?php echo intval( $last_check['modified'] ); ?></strong>,
                Added: <strong><?php echo intval( $last_check['added'] ); ?></strong>,
                Deleted: <strong><?php echo intval( $last_check['deleted'] ); ?></strong>
            </div>
            <?php endif; ?>

            <div class="bdsec-progress-wrap" id="checkProgress">
                <div class="bdsec-progress-bar"><div class="bdsec-progress-fill" id="checkProgressFill"></div></div>
                <div class="bdsec-progress-text" id="checkProgressText">0 / 0 files</div>
            </div>

            <?php if ( ! empty( $changes ) ) : ?>
            <div style="display:flex;justify-content:flex-end;margin-bottom:15px;">
                <button class="bdsec-btn bdsec-btn-primary bdsec-btn-sm" id="acceptAllBtn">Accept All Changes (<?php echo count( $changes ); ?>)</button>
            </div>
            <table class="bdsec-table" id="changesTable">
                <thead>
                    <tr><th>File</th><th>Status</th><th>Hash</th><th>Action</th></tr>
                </thead>
                <tbody>
                    <?php foreach ( $changes as $c ) : ?>
                    <tr id="change-row-<?php echo intval( $c['id'] ); ?>">
                        <td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="<?php echo esc_attr( $c['file_path'] ); ?>"><?php echo esc_html( $c['file_path'] ); ?></td>
                        <td><span class="bdsec-status-pill <?php echo esc_attr( $c['status'] ); ?>"><?php echo esc_html( $c['status'] ); ?></span></td>
                        <td class="bdsec-hash-cell" title="<?php echo esc_attr( $c['file_hash'] ); ?>"><?php echo esc_html( substr( $c['file_hash'], 0, 16 ) ); ?>...</td>
                        <td><button class="bdsec-btn bdsec-btn-secondary bdsec-btn-sm" onclick="acceptChange(<?php echo intval( $c['id'] ); ?>)">Accept</button></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <?php else : ?>
            <p class="bdsec-empty"><?php echo $baseline_info ? 'No changes detected.' : 'No baseline exists yet. Create a baseline first.'; ?></p>
            <?php endif; ?>
        </div>
    </div>

    <!-- Baseline Tab -->
    <div class="bdsec-tab-content" id="tab-baseline">
        <div class="bdsec-card">
            <div class="bdsec-card-header">
                <h2>File Baseline</h2>
                <button class="bdsec-btn bdsec-btn-primary" id="createBaselineBtn">Create / Rebuild Baseline</button>
            </div>

            <?php if ( $baseline_info ) : ?>
            <div class="bdsec-baseline-info">
                Baseline created: <strong><?php echo esc_html( $baseline_info['created_at'] ); ?></strong><br>
                Files in baseline: <strong><?php echo number_format( intval( $baseline_info['file_count'] ) ); ?></strong>
            </div>
            <?php else : ?>
            <p class="bdsec-empty">No baseline exists yet. Click "Create / Rebuild Baseline" to hash all monitored files.</p>
            <?php endif; ?>

            <div class="bdsec-progress-wrap" id="baselineProgress">
                <div class="bdsec-progress-bar"><div class="bdsec-progress-fill" id="baselineProgressFill"></div></div>
                <div class="bdsec-progress-text" id="baselineProgressText">0 / 0 files</div>
            </div>
        </div>
    </div>
</div>

<script>
(function(){
    const nonce = '<?php echo wp_create_nonce( 'bdsec_nonce' ); ?>';
    const ajaxurl = '<?php echo admin_url( 'admin-ajax.php' ); ?>';

    // Tab switching
    document.querySelectorAll('.bdsec-tab-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var tab = this.getAttribute('data-tab');
            document.querySelectorAll('.bdsec-tab-btn').forEach(function(b) { b.classList.remove('active'); });
            document.querySelectorAll('.bdsec-tab-content').forEach(function(c) { c.classList.remove('active'); });
            this.classList.add('active');
            document.getElementById('tab-' + tab).classList.add('active');
        });
    });

    function post(action, extra) {
        extra = extra || {};
        var params = new URLSearchParams(Object.assign({action: action, nonce: nonce}, extra));
        return fetch(ajaxurl, {
            method: 'POST',
            headers: {'Content-Type':'application/x-www-form-urlencoded'},
            body: params.toString()
        }).then(function(r) { return r.json(); });
    }

    // Create Baseline
    document.getElementById('createBaselineBtn').addEventListener('click', function(){
        if (!confirm('This will rebuild the entire baseline. Continue?')) return;
        var btn = this;
        btn.disabled = true;
        document.getElementById('baselineProgress').style.display = 'block';

        post('bdsec_fim_create_baseline').then(function(res) {
            if (!res.success) { alert('Error starting baseline'); btn.disabled = false; return; }
            processBaselineChunks(res.data.total);
        });
    });

    function processBaselineChunks(total) {
        post('bdsec_fim_process_baseline').then(function(res) {
            if (!res.success) return;
            var d = res.data;
            var pct = total > 0 ? (d.processed / total * 100) : 100;
            document.getElementById('baselineProgressFill').style.width = pct + '%';
            document.getElementById('baselineProgressText').textContent = d.processed + ' / ' + total + ' files';

            if (!d.done) {
                processBaselineChunks(total);
            } else {
                document.getElementById('baselineProgressText').textContent = 'Baseline complete! ' + total + ' files hashed.';
                document.getElementById('createBaselineBtn').disabled = false;
                setTimeout(function() { location.reload(); }, 1500);
            }
        });
    }

    // Check Now
    document.getElementById('checkNowBtn').addEventListener('click', function(){
        var btn = this;
        btn.disabled = true;
        document.getElementById('checkProgress').style.display = 'block';

        post('bdsec_fim_start_check').then(function(res) {
            if (!res.success) { alert('Error starting check'); btn.disabled = false; return; }
            processCheckChunks(res.data.total);
        });
    });

    function processCheckChunks(total) {
        post('bdsec_fim_process_check').then(function(res) {
            if (!res.success) return;
            var d = res.data;
            var pct = total > 0 ? (d.processed / total * 100) : 100;
            document.getElementById('checkProgressFill').style.width = pct + '%';
            document.getElementById('checkProgressText').textContent = d.processed + ' / ' + total + ' files';

            if (!d.done) {
                processCheckChunks(total);
            } else {
                var r = d.results;
                document.getElementById('checkProgressText').textContent =
                    'Check complete! Modified: ' + r.modified + ', Added: ' + r.added + ', Deleted: ' + r.deleted;
                document.getElementById('checkNowBtn').disabled = false;
                setTimeout(function() { location.reload(); }, 2000);
            }
        });
    }

    // Accept single change
    window.acceptChange = function(id) {
        post('bdsec_fim_accept_change', {id: id}).then(function(res) {
            if (res.success) {
                var row = document.getElementById('change-row-' + id);
                if (row) row.remove();
            } else {
                alert(res.data || 'Error');
            }
        });
    };

    // Accept All changes
    var acceptAllBtn = document.getElementById('acceptAllBtn');
    if (acceptAllBtn) {
        acceptAllBtn.addEventListener('click', function() {
            if (!confirm('Accept ALL changes and update the baseline? This cannot be undone.')) return;
            var btn = this;
            btn.disabled = true;
            btn.textContent = 'Accepting all...';

            post('bdsec_fim_accept_all').then(function(res) {
                if (res.success) {
                    btn.textContent = 'Done! Reloading...';
                    setTimeout(function() { location.reload(); }, 1000);
                } else {
                    alert(res.data || 'Error');
                    btn.disabled = false;
                    btn.textContent = 'Accept All Changes';
                }
            });
        });
    }
})();
</script>
