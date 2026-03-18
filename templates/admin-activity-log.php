<?php
/**
 * Admin Activity Log Template
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) exit;

$settings = get_option( 'bestdid_security_settings' );
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
            margin: 0 0 24px !important; padding: 0 !important;
            font-size: 20px !important; font-weight: 600 !important; color: #fff !important;
        }

        /* Filters */
        .bdsec-filters {
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            align-items: flex-end;
            margin-bottom: 24px;
            padding-bottom: 24px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
        }
        .bdsec-filter-group {
            display: flex;
            flex-direction: column;
            gap: 6px;
        }
        .bdsec-filter-group .bdsec-filter-label {
            display: block !important;
            color: rgba(255,255,255,0.7) !important;
            font-size: 12px !important;
            font-weight: 600 !important;
            text-transform: uppercase !important;
            letter-spacing: 0.8px !important;
            margin: 0 !important;
            padding: 0 !important;
        }
        .bdsec-filter-group select,
        .bdsec-filter-group input[type="text"],
        .bdsec-filter-group input[type="date"] {
            background: rgba(255,255,255,0.08) !important;
            border: 1px solid rgba(255,255,255,0.15) !important;
            color: #fff !important;
            padding: 10px 14px !important;
            border-radius: 10px !important;
            font-size: 13px !important;
            font-family: 'Inter', sans-serif !important;
            min-width: 160px;
            height: auto !important;
            line-height: normal !important;
            outline: none !important;
            box-shadow: none !important;
            -webkit-appearance: none;
            transition: border-color 0.2s;
        }
        .bdsec-filter-group select:focus,
        .bdsec-filter-group input:focus {
            border-color: rgba(217, 119, 87, 0.5) !important;
            background: rgba(255,255,255,0.12) !important;
        }
        .bdsec-filter-group select option {
            background: #1a1a2e !important;
            color: #fff !important;
        }
        /* Date input color fix for dark theme */
        .bdsec-filter-group input[type="date"]::-webkit-calendar-picker-indicator {
            filter: invert(1);
        }

        /* Actions row */
        .bdsec-actions-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .bdsec-event-count {
            color: rgba(255,255,255,0.5);
            font-size: 13px;
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

        /* Event type badges */
        .bdsec-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            white-space: nowrap;
        }
        .bdsec-badge-login    { background: rgba(0,255,136,0.15); color: #00ff88; }
        .bdsec-badge-failed   { background: rgba(255,107,107,0.15); color: #ff6b6b; }
        .bdsec-badge-settings { background: rgba(79,172,254,0.15); color: #4facfe; }
        .bdsec-badge-content  { background: rgba(168,85,247,0.15); color: #a855f7; }
        .bdsec-badge-user     { background: rgba(251,191,36,0.15); color: #fbbf24; }
        .bdsec-badge-system   { background: rgba(255,255,255,0.1); color: rgba(255,255,255,0.6); }

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
        .bdsec-btn-danger {
            background: rgba(255,107,107,0.15) !important;
            border: 1px solid rgba(255,107,107,0.3) !important;
            color: #ff6b6b !important;
        }
        .bdsec-btn-secondary {
            background: rgba(255,255,255,0.08) !important;
            border: 1px solid rgba(255,255,255,0.15) !important;
            color: #fff !important;
        }
        .bdsec-btn-sm { padding: 8px 16px !important; font-size: 12px !important; border-radius: 8px !important; }

        .bdsec-pagination {
            display: flex; gap: 8px; justify-content: center; margin-top: 24px;
        }
        .bdsec-pagination button {
            background: rgba(255,255,255,0.08) !important;
            border: 1px solid rgba(255,255,255,0.1) !important;
            color: #fff !important;
            padding: 8px 14px !important;
            border-radius: 8px !important;
            cursor: pointer;
            font-family: 'Inter', sans-serif;
        }
        .bdsec-pagination button.active {
            background: linear-gradient(135deg, #D97757, #E29578) !important;
            border-color: transparent !important;
        }

        .bdsec-detail-json {
            max-width: 200px; overflow: hidden; text-overflow: ellipsis;
            white-space: nowrap; color: rgba(255,255,255,0.4); font-size: 12px; cursor: help;
        }

        /* Empty state */
        .bdsec-empty {
            text-align: center;
            color: rgba(255,255,255,0.3);
            padding: 40px 20px;
            font-size: 14px;
        }
    </style>

    <!-- Header -->
    <div class="bdsec-page-header">
        <div class="bdsec-page-icon">📋</div>
        <div>
            <h1>Activity Log</h1>
            <p>Audit trail of admin actions and security events</p>
        </div>
    </div>

    <div class="bdsec-card">
        <h2>Event History</h2>

        <!-- Filters -->
        <div class="bdsec-filters">
            <div class="bdsec-filter-group">
                <span class="bdsec-filter-label">Event Type</span>
                <select id="filterEvent">
                    <option value="">All Events</option>
                    <option value="login_success">Login Success</option>
                    <option value="login_failed">Login Failed</option>
                    <option value="logout">Logout</option>
                    <option value="password_changed">Password Changed</option>
                    <option value="password_reset">Password Reset</option>
                    <option value="user_created">User Created</option>
                    <option value="user_deleted">User Deleted</option>
                    <option value="role_changed">Role Changed</option>
                    <option value="plugin_activated">Plugin Activated</option>
                    <option value="plugin_deactivated">Plugin Deactivated</option>
                    <option value="theme_switched">Theme Switched</option>
                    <option value="post_published">Post Published</option>
                    <option value="post_trashed">Post Trashed</option>
                    <option value="post_deleted">Post Deleted</option>
                    <option value="settings_saved">Settings Saved</option>
                    <option value="option_updated">Option Updated</option>
                    <option value="core_updated">Core Updated</option>
                    <option value="plugin_updated">Plugin Updated</option>
                    <option value="theme_updated">Theme Updated</option>
                </select>
            </div>
            <div class="bdsec-filter-group">
                <span class="bdsec-filter-label">User</span>
                <input type="text" id="filterUser" placeholder="Username...">
            </div>
            <div class="bdsec-filter-group">
                <span class="bdsec-filter-label">Date From</span>
                <input type="date" id="filterFrom">
            </div>
            <div class="bdsec-filter-group">
                <span class="bdsec-filter-label">Date To</span>
                <input type="date" id="filterTo">
            </div>
            <div class="bdsec-filter-group" style="justify-content:flex-end;">
                <span class="bdsec-filter-label">&nbsp;</span>
                <button class="bdsec-btn bdsec-btn-primary bdsec-btn-sm" id="applyFilters">Filter</button>
            </div>
        </div>

        <!-- Actions -->
        <div class="bdsec-actions-row">
            <div id="logCount" class="bdsec-event-count"></div>
            <div style="display:flex;gap:10px;">
                <button class="bdsec-btn bdsec-btn-secondary bdsec-btn-sm" id="exportCsv">Export CSV</button>
                <button class="bdsec-btn bdsec-btn-danger bdsec-btn-sm" id="clearLog">Clear Log</button>
            </div>
        </div>

        <!-- Table -->
        <table class="bdsec-table">
            <thead>
                <tr>
                    <th>Time</th>
                    <th>User</th>
                    <th>Event</th>
                    <th>Object</th>
                    <th>Details</th>
                    <th>IP Address</th>
                </tr>
            </thead>
            <tbody id="activityLogBody">
                <tr><td colspan="6" class="bdsec-empty">Loading...</td></tr>
            </tbody>
        </table>
        <div class="bdsec-pagination" id="activityPagination"></div>
    </div>
</div>

<script>
(function(){
    const nonce = '<?php echo wp_create_nonce( 'bdsec_nonce' ); ?>';
    const ajaxurl = '<?php echo admin_url( 'admin-ajax.php' ); ?>';
    let currentPage = 1;

    function getEventBadgeClass(type) {
        if (type.includes('login_success') || type === 'logout') return 'login';
        if (type.includes('failed')) return 'failed';
        if (type.includes('settings') || type.includes('option')) return 'settings';
        if (type.includes('post') || type.includes('theme')) return 'content';
        if (type.includes('user') || type.includes('role') || type.includes('password')) return 'user';
        return 'system';
    }

    function getFilters() {
        return {
            event_type: document.getElementById('filterEvent').value,
            user_filter: document.getElementById('filterUser').value,
            date_from: document.getElementById('filterFrom').value,
            date_to: document.getElementById('filterTo').value,
        };
    }

    function loadLog(page) {
        currentPage = page;
        const f = getFilters();
        const params = new URLSearchParams({
            action: 'bdsec_activity_get_log', nonce, page,
            ...f
        });

        fetch(ajaxurl, {
            method: 'POST',
            headers: {'Content-Type':'application/x-www-form-urlencoded'},
            body: params.toString()
        }).then(r=>r.json()).then(res => {
            if (!res.success) return;
            const {rows, total, pages} = res.data;
            document.getElementById('logCount').textContent = total + ' events found';

            const body = document.getElementById('activityLogBody');
            if (!rows.length) {
                body.innerHTML = '<tr><td colspan="6" class="bdsec-empty">No events found.</td></tr>';
            } else {
                body.innerHTML = rows.map(r => {
                    const badge = getEventBadgeClass(r.event_type);
                    const details = r.details && r.details !== '[]' && r.details !== '{}' ? r.details : '';
                    return '<tr>' +
                        '<td style="white-space:nowrap;">' + r.created_at + '</td>' +
                        '<td><strong>' + (r.username || 'system') + '</strong></td>' +
                        '<td><span class="bdsec-badge bdsec-badge-' + badge + '">' + r.event_type.replace(/_/g, ' ') + '</span></td>' +
                        '<td>' + (r.object_name || '-') + '</td>' +
                        '<td><span class="bdsec-detail-json" title="' + (details ? details.replace(/"/g, '&quot;') : '') + '">' + (details || '-') + '</span></td>' +
                        '<td style="font-family:monospace;font-size:12px;">' + (r.ip_address || '-') + '</td>' +
                    '</tr>';
                }).join('');
            }

            const pag = document.getElementById('activityPagination');
            if (pages > 1) {
                let btns = '';
                for (let i = 1; i <= Math.min(pages, 10); i++) {
                    btns += '<button class="' + (i === page ? 'active' : '') + '" onclick="loadActivityLog(' + i + ')">' + i + '</button>';
                }
                pag.innerHTML = btns;
            } else {
                pag.innerHTML = '';
            }
        });
    }
    window.loadActivityLog = loadLog;

    document.getElementById('applyFilters').addEventListener('click', function() { loadLog(1); });
    loadLog(1);

    // Export CSV
    document.getElementById('exportCsv').addEventListener('click', function(){
        const f = getFilters();
        const params = new URLSearchParams({
            action: 'bdsec_activity_export_csv', nonce, ...f
        });
        window.location.href = ajaxurl + '?' + params.toString();
    });

    // Clear log
    document.getElementById('clearLog').addEventListener('click', function(){
        const days = prompt('Delete entries older than how many days? (0 = clear all)', '0');
        if (days === null) return;
        fetch(ajaxurl, {
            method: 'POST',
            headers: {'Content-Type':'application/x-www-form-urlencoded'},
            body: 'action=bdsec_activity_clear_log&nonce=' + nonce + '&days=' + (parseInt(days) || 0)
        }).then(r => r.json()).then(function() { loadLog(1); });
    });
})();
</script>
