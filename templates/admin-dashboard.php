<?php
/**
 * Admin Dashboard Template
 * 
 * @package BestDid_Security
 */

if (!defined('ABSPATH')) exit;

// Handle unblock action
if (isset($_POST['unblock_ip']) && wp_verify_nonce($_POST['unblock_nonce'], 'bestdid_unblock_ip')) {
    global $wpdb;
    $ip_to_unblock = sanitize_text_field($_POST['unblock_ip']);
    $rate_table = $wpdb->prefix . 'bestdid_rate_limits';
    $wpdb->delete($rate_table, array('ip_address' => $ip_to_unblock));
    echo '<div class="notice notice-success" style="margin: 20px 20px 0;"><p>✅ IP <strong>' . esc_html($ip_to_unblock) . '</strong> has been unblocked.</p></div>';
    $blocked_ips = $wpdb->get_var("SELECT COUNT(DISTINCT ip_address) FROM $rate_table WHERE blocked_until > NOW()");
}

// Handle unblock all
if (isset($_POST['unblock_all']) && wp_verify_nonce($_POST['unblock_all_nonce'], 'bestdid_unblock_all')) {
    global $wpdb;
    $rate_table = $wpdb->prefix . 'bestdid_rate_limits';
    $wpdb->query("DELETE FROM $rate_table WHERE blocked_until > NOW()");
    echo '<div class="notice notice-success" style="margin: 20px 20px 0;"><p>✅ All blocked IPs have been unblocked.</p></div>';
    $blocked_ips = 0;
}

// Get currently blocked IPs
global $wpdb;
$rate_table = $wpdb->prefix . 'bestdid_rate_limits';
$table_exists = $wpdb->get_var("SHOW TABLES LIKE '$rate_table'");
$blocked_ip_list = array();
if ($table_exists === $rate_table) {
    $blocked_ip_list = $wpdb->get_results("SELECT DISTINCT ip_address, blocked_until, attempts FROM $rate_table WHERE blocked_until > NOW() ORDER BY blocked_until DESC LIMIT 20");
}

$settings = get_option('bestdid_security_settings');
?>
<div class="wrap bestdid-security-wrap">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
        
        .bestdid-security-wrap {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            margin-left: -20px;
            padding: 30px;
            min-height: 100vh;
        }
        
        /* Header */
        .security-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        .security-header-left {
            display: flex;
            align-items: center;
            gap: 20px;
        }
        .security-logo {
            width: 60px;
            height: 60px;
            background: linear-gradient(135deg, #D97757, #E29578);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 28px;
            box-shadow: 0 10px 30px rgba(217, 119, 87, 0.3);
        }
        .security-title h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 700;
            color: #fff;
        }
        .security-title p {
            margin: 5px 0 0;
            color: rgba(255,255,255,0.6);
            font-size: 14px;
        }
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 20px;
            background: rgba(0, 255, 136, 0.15);
            border: 1px solid rgba(0, 255, 136, 0.3);
            color: #00ff88;
            border-radius: 30px;
            font-size: 13px;
            font-weight: 600;
        }
        .status-badge .pulse {
            width: 8px;
            height: 8px;
            background: #00ff88;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(0, 255, 136, 0.4); }
            50% { opacity: 0.8; box-shadow: 0 0 0 10px rgba(0, 255, 136, 0); }
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            padding: 25px;
            position: relative;
            overflow: hidden;
            transition: all 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            background: rgba(255,255,255,0.08);
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
        }
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            border-radius: 20px 20px 0 0;
        }
        .stat-card.danger::before { background: linear-gradient(90deg, #ff6b6b, #ee5a5a); }
        .stat-card.warning::before { background: linear-gradient(90deg, #ffd93d, #f9c74f); }
        .stat-card.success::before { background: linear-gradient(90deg, #00ff88, #00cc6a); }
        .stat-card.info::before { background: linear-gradient(90deg, #4facfe, #00f2fe); }
        
        .stat-icon {
            width: 50px;
            height: 50px;
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            margin-bottom: 15px;
        }
        .stat-card.danger .stat-icon { background: rgba(255, 107, 107, 0.2); }
        .stat-card.warning .stat-icon { background: rgba(255, 217, 61, 0.2); }
        .stat-card.success .stat-icon { background: rgba(0, 255, 136, 0.2); }
        .stat-card.info .stat-icon { background: rgba(79, 172, 254, 0.2); }
        
        .stat-value {
            font-size: 36px;
            font-weight: 700;
            color: #fff;
            line-height: 1;
            margin-bottom: 5px;
        }
        .stat-label {
            font-size: 13px;
            color: rgba(255,255,255,0.5);
            font-weight: 500;
        }
        
        /* Cards */
        .content-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px;
            overflow: hidden;
        }
        .card-header {
            padding: 20px 25px;
            border-bottom: 1px solid rgba(255,255,255,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .card-header h3 {
            margin: 0;
            font-size: 16px;
            font-weight: 600;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .card-body {
            padding: 0;
        }
        
        /* Blocked IPs Card */
        .blocked-ips-card {
            grid-column: span 2;
        }
        .blocked-ip-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 16px 25px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            transition: background 0.2s;
        }
        .blocked-ip-item:hover {
            background: rgba(255,255,255,0.03);
        }
        .blocked-ip-item:last-child {
            border-bottom: none;
        }
        .ip-info {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .ip-icon {
            width: 40px;
            height: 40px;
            background: rgba(255, 107, 107, 0.2);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }
        .ip-details code {
            background: rgba(255,255,255,0.1);
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 14px;
            color: #fff;
            font-family: 'SF Mono', Monaco, monospace;
        }
        .ip-meta {
            font-size: 12px;
            color: rgba(255,255,255,0.4);
            margin-top: 4px;
        }
        .unblock-btn {
            background: linear-gradient(135deg, #ff6b6b, #ee5a5a);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 600;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .unblock-btn:hover {
            transform: scale(1.05);
            box-shadow: 0 5px 20px rgba(255, 107, 107, 0.4);
        }
        .unblock-all-btn {
            background: rgba(255, 107, 107, 0.2);
            color: #ff6b6b;
            border: 1px solid rgba(255, 107, 107, 0.3);
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            transition: all 0.3s;
        }
        .unblock-all-btn:hover {
            background: #ff6b6b;
            color: white;
        }
        
        /* Threat List */
        .threat-item {
            display: flex;
            align-items: center;
            gap: 15px;
            padding: 16px 25px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            transition: background 0.2s;
        }
        .threat-item:hover {
            background: rgba(255,255,255,0.03);
        }
        .threat-item:last-child {
            border-bottom: none;
        }
        .threat-icon {
            width: 40px;
            height: 40px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }
        .threat-icon.critical { background: rgba(255, 107, 107, 0.2); }
        .threat-icon.high { background: rgba(255, 193, 7, 0.2); }
        .threat-icon.medium { background: rgba(255, 193, 7, 0.15); }
        .threat-icon.low { background: rgba(0, 255, 136, 0.15); }
        
        .threat-info {
            flex: 1;
        }
        .threat-type {
            font-weight: 600;
            font-size: 14px;
            color: #fff;
        }
        .threat-details {
            font-size: 12px;
            color: rgba(255,255,255,0.4);
            margin-top: 2px;
        }
        .threat-meta {
            text-align: right;
        }
        .severity-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .severity-badge.critical { background: rgba(255, 107, 107, 0.2); color: #ff6b6b; }
        .severity-badge.high { background: rgba(255, 193, 7, 0.2); color: #ffc107; }
        .severity-badge.medium { background: rgba(255, 193, 7, 0.15); color: #f9c74f; }
        .severity-badge.low { background: rgba(0, 255, 136, 0.15); color: #00ff88; }
        .threat-time {
            font-size: 11px;
            color: rgba(255,255,255,0.3);
            margin-top: 4px;
        }
        
        /* Protection Status */
        .protection-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 14px 25px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .protection-item:last-child {
            border-bottom: none;
        }
        .protection-name {
            font-size: 14px;
            color: rgba(255,255,255,0.8);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .protection-status {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #00ff88;
            box-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
        }
        .protection-status.inactive {
            background: #ff6b6b;
            box-shadow: 0 0 10px rgba(255, 107, 107, 0.5);
        }
        
        /* Empty State */
        .empty-state {
            padding: 40px;
            text-align: center;
            color: rgba(255,255,255,0.4);
        }
        .empty-state-icon {
            font-size: 48px;
            margin-bottom: 15px;
            opacity: 0.5;
        }
        .empty-state h4 {
            margin: 0 0 5px;
            color: rgba(255,255,255,0.6);
            font-size: 16px;
        }
        .empty-state p {
            margin: 0;
            font-size: 13px;
        }
        
        /* View All Button */
        .view-all-btn {
            background: rgba(255,255,255,0.1);
            color: rgba(255,255,255,0.7);
            border: none;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.3s;
        }
        .view-all-btn:hover {
            background: rgba(255,255,255,0.2);
            color: #fff;
        }
        
        @media (max-width: 1200px) {
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
            .content-grid { grid-template-columns: 1fr; }
            .blocked-ips-card { grid-column: span 1; }
        }
    </style>
    
    <div class="security-header">
        <div class="security-header-left">
            <div class="security-logo">🛡️</div>
            <div class="security-title">
                <h1>Security Firewall</h1>
                <p>Real-time protection for your WordPress site</p>
            </div>
        </div>
        <div class="status-badge">
            <span class="pulse"></span>
            Protection Active
        </div>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card danger">
            <div class="stat-icon">🚫</div>
            <div class="stat-value"><?php echo number_format($blocked_today); ?></div>
            <div class="stat-label">Threats Blocked Today</div>
        </div>
        
        <div class="stat-card success">
            <div class="stat-icon">🛡️</div>
            <div class="stat-value"><?php echo number_format($total_blocked); ?></div>
            <div class="stat-label">Total Threats Blocked</div>
        </div>
        
        <div class="stat-card warning">
            <div class="stat-icon">⚠️</div>
            <div class="stat-value"><?php echo number_format($critical_threats); ?></div>
            <div class="stat-label">Critical Threats Today</div>
        </div>
        
        <div class="stat-card info">
            <div class="stat-icon">🔒</div>
            <div class="stat-value"><?php echo number_format($blocked_ips); ?></div>
            <div class="stat-label">IPs Currently Blocked</div>
        </div>
    </div>
    
    <!-- Blocked IPs Management -->
    <div class="card blocked-ips-card" style="margin-bottom: 20px;">
        <div class="card-header">
            <h3>🔒 Blocked IPs</h3>
            <?php if (!empty($blocked_ip_list)) : ?>
                <form method="post" style="display: inline;">
                    <?php wp_nonce_field('bestdid_unblock_all', 'unblock_all_nonce'); ?>
                    <button type="submit" name="unblock_all" class="unblock-all-btn" onclick="return confirm('Unblock ALL IPs? This will allow previously blocked addresses to access your site.');">
                        🔓 Unblock All
                    </button>
                </form>
            <?php endif; ?>
        </div>
        <div class="card-body">
            <?php if (empty($blocked_ip_list)) : ?>
                <div class="empty-state">
                    <div class="empty-state-icon">✅</div>
                    <h4>No Blocked IPs</h4>
                    <p>All IP addresses are currently allowed to access your site.</p>
                </div>
            <?php else : ?>
                <?php foreach ($blocked_ip_list as $blocked) : ?>
                    <div class="blocked-ip-item">
                        <div class="ip-info">
                            <div class="ip-icon">🚫</div>
                            <div class="ip-details">
                                <code><?php echo esc_html($blocked->ip_address); ?></code>
                                <div class="ip-meta">
                                    Blocked until <?php echo date('M j, Y \a\t g:i A', strtotime($blocked->blocked_until)); ?>
                                    <?php if (isset($blocked->attempts)) : ?>
                                        • <?php echo intval($blocked->attempts); ?> requests
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                        <form method="post" style="display: inline;">
                            <?php wp_nonce_field('bestdid_unblock_ip', 'unblock_nonce'); ?>
                            <input type="hidden" name="unblock_ip" value="<?php echo esc_attr($blocked->ip_address); ?>">
                            <button type="submit" class="unblock-btn">
                                🔓 Unblock
                            </button>
                        </form>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>
    
    <div class="content-grid">
        <div class="card">
            <div class="card-header">
                <h3>⚡ Recent Threats</h3>
                <a href="<?php echo admin_url('admin.php?page=bestdid-security-logs'); ?>" class="view-all-btn">View All</a>
            </div>
            <div class="card-body">
                <?php if (empty($recent_threats)) : ?>
                    <div class="empty-state">
                        <div class="empty-state-icon">🎉</div>
                        <h4>All Clear!</h4>
                        <p>No threats detected recently. Your site is secure.</p>
                    </div>
                <?php else : ?>
                    <?php foreach (array_slice($recent_threats, 0, 6) as $threat) : ?>
                        <div class="threat-item">
                            <div class="threat-icon <?php echo esc_attr($threat->severity); ?>">
                                <?php 
                                $icons = array('critical' => '🚨', 'high' => '⚠️', 'medium' => '⚡', 'low' => '📋');
                                echo isset($icons[$threat->severity]) ? $icons[$threat->severity] : '📋';
                                ?>
                            </div>
                            <div class="threat-info">
                                <div class="threat-type"><?php echo esc_html(ucwords(str_replace('_', ' ', $threat->threat_type))); ?></div>
                                <div class="threat-details">IP: <?php echo esc_html($threat->ip_address); ?></div>
                            </div>
                            <div class="threat-meta">
                                <span class="severity-badge <?php echo esc_attr($threat->severity); ?>"><?php echo esc_html($threat->severity); ?></span>
                                <div class="threat-time"><?php echo esc_html(human_time_diff(strtotime($threat->timestamp), current_time('timestamp'))); ?> ago</div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h3>🔐 Protection Status</h3>
            </div>
            <div class="card-body">
                <?php
                $protections = array(
                    'two_factor_enabled' => array('Two-Factor Auth', '🔐'),
                    'scanner_enabled' => array('Malware Scanner', '🔍'),
                    'geo_blocking_enabled' => array('Geo-Blocking', '🌍'),
                    'activity_logging_enabled' => array('Activity Logging', '📋'),
                    'file_integrity_enabled' => array('File Integrity', '📁'),
                    'sql_injection_protection' => array('SQL Injection', '💉'),
                    'xss_protection' => array('XSS Prevention', '🔰'),
                    'brute_force_protection' => array('Brute Force', '🔨'),
                    'rate_limiting' => array('Rate Limiting', '⏱️'),
                    'block_bad_bots' => array('Bad Bot Blocking', '🤖'),
                    'disable_xmlrpc' => array('XML-RPC Disabled', '📡'),
                    'hide_wp_version' => array('Version Hidden', '🙈'),
                );
                foreach ($protections as $key => $data) :
                    $active = !empty($settings[$key]);
                ?>
                    <div class="protection-item">
                        <span class="protection-name">
                            <span><?php echo $data[1]; ?></span>
                            <?php echo esc_html($data[0]); ?>
                        </span>
                        <span class="protection-status <?php echo $active ? '' : 'inactive'; ?>"></span>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <?php if ( ! empty( $settings['two_factor_enabled'] ) && class_exists( 'BDSEC_Two_Factor' ) ) :
        $tfa_roles = $settings['two_factor_roles'] ?? array( 'administrator' );
        $tfa_stats = BDSEC_Two_Factor::get_2fa_user_stats( $tfa_roles );
    ?>
    <div class="card blocked-ips-card" style="margin-top: 0;">
        <div class="card-header">
            <h3>🔐 Two-Factor Authentication</h3>
            <a href="<?php echo admin_url( 'admin.php?page=bestdid-security-settings' ); ?>" class="view-all-btn">Settings</a>
        </div>
        <div class="card-body">
            <div class="protection-item">
                <span class="protection-name">
                    <span>👤</span>
                    Users with 2FA active
                </span>
                <span style="color:#fff;font-weight:600;font-size:16px;">
                    <?php echo intval( $tfa_stats['enabled'] ); ?> / <?php echo intval( $tfa_stats['total'] ); ?>
                </span>
            </div>
            <div class="protection-item">
                <span class="protection-name">
                    <span>🔒</span>
                    Forced setup
                </span>
                <span class="protection-status <?php echo empty( $settings['two_factor_forced'] ) ? 'inactive' : ''; ?>"></span>
            </div>
            <div class="protection-item">
                <span class="protection-name">
                    <span>👥</span>
                    Enforced roles
                </span>
                <span style="color:rgba(255,255,255,0.7);font-size:13px;">
                    <?php echo esc_html( implode( ', ', array_map( 'ucfirst', $tfa_roles ) ) ); ?>
                </span>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <?php
    // Scanner status card.
    $bdsec_last_scan    = get_option( 'bdsec_last_scan' );
    $bdsec_scanner_on   = ! empty( $settings['scanner_enabled'] );
    if ( $bdsec_scanner_on || $bdsec_last_scan ) :
        $scan_counts = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0 );
        if ( $bdsec_last_scan && class_exists( 'BDSEC_Scanner_Engine' ) ) {
            $tmp_scanner = new BDSEC_Scanner_Engine();
            $scan_counts = $tmp_scanner->count_by_severity();
        }
    ?>
    <div class="card blocked-ips-card" style="margin-top: 0;">
        <div class="card-header">
            <h3>🔍 Malware Scanner</h3>
            <a href="<?php echo admin_url( 'admin.php?page=bestdid-security-scanner' ); ?>" class="view-all-btn">Scan Now</a>
        </div>
        <div class="card-body">
            <div class="protection-item">
                <span class="protection-name">
                    <span>📅</span>
                    Last scan
                </span>
                <span style="color:rgba(255,255,255,0.7);font-size:13px;">
                    <?php echo $bdsec_last_scan ? esc_html( human_time_diff( strtotime( $bdsec_last_scan['finished_at'] ), current_time( 'timestamp' ) ) ) . ' ago' : 'Never'; ?>
                </span>
            </div>
            <div class="protection-item">
                <span class="protection-name">
                    <span>📁</span>
                    Files scanned
                </span>
                <span style="color:#fff;font-weight:600;font-size:16px;">
                    <?php echo $bdsec_last_scan ? number_format( $bdsec_last_scan['total'] ) : '0'; ?>
                </span>
            </div>
            <?php if ( $scan_counts['critical'] > 0 ) : ?>
            <div class="protection-item">
                <span class="protection-name">
                    <span>🚨</span>
                    Critical threats
                </span>
                <span style="color:#f87171;font-weight:600;font-size:16px;">
                    <?php echo $scan_counts['critical']; ?>
                </span>
            </div>
            <?php endif; ?>
            <?php if ( $scan_counts['high'] > 0 ) : ?>
            <div class="protection-item">
                <span class="protection-name">
                    <span>⚠️</span>
                    High threats
                </span>
                <span style="color:#fbbf24;font-weight:600;font-size:16px;">
                    <?php echo $scan_counts['high']; ?>
                </span>
            </div>
            <?php endif; ?>
            <div class="protection-item">
                <span class="protection-name">
                    <span>🛡️</span>
                    Total findings
                </span>
                <span style="color:#fff;font-weight:600;font-size:16px;">
                    <?php echo $bdsec_last_scan ? intval( $bdsec_last_scan['findings'] ) : '0'; ?>
                </span>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <?php
    // ── Geo-Blocking card ──
    if ( ! empty( $settings['geo_blocking_enabled'] ) ) :
        $geo_blocked_today = BDSEC_Geo_Blocking::get_blocked_today();
        $geo_top = BDSEC_Geo_Blocking::get_country_stats();
    ?>
    <div class="card blocked-ips-card" style="margin-top: 0;">
        <div class="card-header">
            <h3>🌍 Geo-Blocking</h3>
            <a href="<?php echo admin_url( 'admin.php?page=bestdid-security-geo-blocking' ); ?>" class="view-all-btn">Manage</a>
        </div>
        <div class="card-body">
            <div class="protection-item">
                <span class="protection-name"><span>🚫</span> Blocked today</span>
                <span style="color:#ff6b6b;font-weight:600;font-size:16px;"><?php echo intval( $geo_blocked_today ); ?></span>
            </div>
            <div class="protection-item">
                <span class="protection-name"><span>⚙️</span> Mode</span>
                <span style="color:rgba(255,255,255,0.7);font-size:13px;"><?php echo esc_html( ucfirst( $settings['geo_mode'] ?? 'disabled' ) ); ?></span>
            </div>
            <?php if ( ! empty( $geo_top ) ) : $top = $geo_top[0]; ?>
            <div class="protection-item">
                <span class="protection-name"><span>🏆</span> Top blocked country</span>
                <span style="color:rgba(255,255,255,0.7);font-size:13px;"><?php echo esc_html( $top['country_name'] . ' (' . $top['total'] . ')' ); ?></span>
            </div>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>

    <?php
    // ── Activity Log card ──
    if ( ! empty( $settings['activity_logging_enabled'] ) ) :
        global $wpdb;
        $act_table = $wpdb->prefix . 'bestdid_activity_log';
        $recent_events = $wpdb->get_results( "SELECT event_type, username, object_name, created_at FROM {$act_table} ORDER BY created_at DESC LIMIT 5", ARRAY_A );
    ?>
    <div class="card blocked-ips-card" style="margin-top: 0;">
        <div class="card-header">
            <h3>📋 Activity Log</h3>
            <a href="<?php echo admin_url( 'admin.php?page=bestdid-security-activity-log' ); ?>" class="view-all-btn">View All</a>
        </div>
        <div class="card-body">
            <?php if ( empty( $recent_events ) ) : ?>
                <div class="protection-item"><span class="protection-name" style="color:rgba(255,255,255,0.4);">No events recorded yet.</span></div>
            <?php else : foreach ( $recent_events as $evt ) : ?>
                <div class="protection-item">
                    <span class="protection-name">
                        <span style="font-size:11px;">●</span>
                        <?php echo esc_html( str_replace( '_', ' ', $evt['event_type'] ) ); ?>
                        <?php if ( $evt['username'] ) : ?><span style="color:rgba(255,255,255,0.4);font-size:12px;">by <?php echo esc_html( $evt['username'] ); ?></span><?php endif; ?>
                    </span>
                    <span style="color:rgba(255,255,255,0.4);font-size:12px;"><?php echo esc_html( human_time_diff( strtotime( $evt['created_at'] ), current_time( 'timestamp' ) ) ); ?> ago</span>
                </div>
            <?php endforeach; endif; ?>
        </div>
    </div>
    <?php endif; ?>

    <?php
    // ── File Integrity card ──
    if ( ! empty( $settings['file_integrity_enabled'] ) ) :
        $fim_last = get_option( 'bdsec_fim_last_check' );
        $fim_stats = BDSEC_File_Integrity::get_stats();
    ?>
    <div class="card blocked-ips-card" style="margin-top: 0;">
        <div class="card-header">
            <h3>📁 File Integrity</h3>
            <a href="<?php echo admin_url( 'admin.php?page=bestdid-security-file-integrity' ); ?>" class="view-all-btn">Details</a>
        </div>
        <div class="card-body">
            <div class="protection-item">
                <span class="protection-name"><span>📅</span> Last check</span>
                <span style="color:rgba(255,255,255,0.7);font-size:13px;">
                    <?php echo $fim_last ? esc_html( human_time_diff( strtotime( $fim_last['checked_at'] ), current_time( 'timestamp' ) ) ) . ' ago' : 'Never'; ?>
                </span>
            </div>
            <div class="protection-item">
                <span class="protection-name"><span>📄</span> Files monitored</span>
                <span style="color:#fff;font-weight:600;font-size:16px;"><?php echo number_format( $fim_stats['total'] ); ?></span>
            </div>
            <?php $changes_count = $fim_stats['modified'] + $fim_stats['new'] + $fim_stats['deleted']; ?>
            <div class="protection-item">
                <span class="protection-name"><span>⚠️</span> Changes detected</span>
                <span style="color:<?php echo $changes_count > 0 ? '#fbbf24' : '#00ff88'; ?>;font-weight:600;font-size:16px;"><?php echo $changes_count; ?></span>
            </div>
        </div>
    </div>
    <?php endif; ?>
</div>
