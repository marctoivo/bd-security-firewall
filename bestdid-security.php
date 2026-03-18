<?php
/**
 * Plugin Name: BD Security Firewall
 * Plugin URI: https://getbdshield.com
 * Description: Enterprise-grade WordPress security firewall. Protects against SQL injection, XSS, brute force, geo-blocking, activity logging, file integrity monitoring, and unauthorized access.
 * Version: 1.1.1
 * Author: BD Shield
 * Author URI: https://getbdshield.com
 * License: GPL v2 or later
 * Text Domain: bestdid-security
 * 
 * @package BestDid_Security
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

define('BESTDID_SECURITY_VERSION', '1.1.1');
define('BESTDID_SECURITY_PATH', plugin_dir_path(__FILE__));
define('BESTDID_SECURITY_URL', plugin_dir_url(__FILE__));

// License gate helper.
require_once BESTDID_SECURITY_PATH . 'includes/class-bdsec-license.php';
require_once BESTDID_SECURITY_PATH . 'includes/class-bdsec-totp.php';
require_once BESTDID_SECURITY_PATH . 'includes/class-bdsec-qr.php';
require_once BESTDID_SECURITY_PATH . 'includes/class-bdsec-two-factor.php';
require_once BESTDID_SECURITY_PATH . 'includes/class-bdsec-malware-signatures.php';
require_once BESTDID_SECURITY_PATH . 'includes/class-bdsec-quarantine.php';
require_once BESTDID_SECURITY_PATH . 'includes/class-bdsec-scanner-engine.php';
require_once BESTDID_SECURITY_PATH . 'includes/class-bdsec-geo-blocking.php';
require_once BESTDID_SECURITY_PATH . 'includes/class-bdsec-activity-logger.php';
require_once BESTDID_SECURITY_PATH . 'includes/class-bdsec-file-integrity.php';

/**
 * Main Security Class
 */
class BestDid_Security_Firewall {
    
    private static $instance = null;
    private $blocked_ips = array();
    private $rate_limit_table = 'bestdid_rate_limits';
    private $security_log_table = 'bestdid_security_logs';
    
    /**
     * Get singleton instance
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        // Initialize on WordPress init
        add_action('plugins_loaded', array($this, 'init'));
        
        // Activation/Deactivation hooks
        register_activation_hook(__FILE__, array($this, 'activate'));
        register_deactivation_hook(__FILE__, array($this, 'deactivate'));
    }
    
    /**
     * Initialize the firewall
     */
    public function init() {
        // Always add admin menu (so users can manage settings & activate license)
        add_action('admin_menu', array($this, 'add_admin_menu'));

        // ── Safe hardening (always active, no license required) ─────
        // These are passive, non-breaking protections that should run
        // regardless of license status to provide baseline security.

        // Disable XML-RPC (prevents brute force via xmlrpc.php)
        add_filter('xmlrpc_enabled', '__return_false');
        add_action('init', array($this, 'block_xmlrpc_access'), 1);

        // Hide WordPress version from all sources
        remove_action('wp_head', 'wp_generator');
        add_filter('the_generator', '__return_empty_string');
        add_filter('style_loader_src', array($this, 'remove_version_query'), 10, 2);
        add_filter('script_loader_src', array($this, 'remove_version_query'), 10, 2);
        add_action('wp_head', array($this, 'remove_wp_version_meta'), 1);
        add_filter('style_loader_src', array($this, 'remove_version_strings'), 9999);
        add_filter('script_loader_src', array($this, 'remove_version_strings'), 9999);

        // Protect REST API user enumeration
        add_filter('rest_authentication_errors', array($this, 'protect_rest_api'), 1);
        add_filter('rest_endpoints', array($this, 'disable_user_endpoints'));

        // Block user enumeration via ?author=1 queries
        if ( ! is_admin() && ! is_user_logged_in() && isset( $_GET['author'] ) ) {
            unset( $_GET['author'] );
            unset( $_REQUEST['author'] );
        }
        add_action('parse_request', array($this, 'block_author_enumeration_early'));
        add_action('template_redirect', array($this, 'block_author_enumeration'));
        add_filter('redirect_canonical', array($this, 'block_author_redirect'), 10, 2);

        // Block access to sensitive files (readme.html, readme.txt, install.php)
        add_action('template_redirect', array($this, 'block_sensitive_files'));
        add_action('admin_init', array($this, 'block_install_php'));

        // Strip CORS headers from REST API (prevents cross-origin WP fingerprinting)
        // Priority 999 ensures this runs AFTER WP's rest_send_cors_headers (priority 10)
        add_filter('rest_pre_serve_request', array($this, 'strip_rest_cors_headers'), 999);

        // Filter REST API namespace index to hide sensitive namespaces
        add_filter('rest_index', array($this, 'filter_rest_index'));
        add_filter('rest_endpoints', array($this, 'filter_sensitive_rest_routes'));

        // Restrict REST API index for unauthenticated users
        add_filter('rest_pre_dispatch', array($this, 'restrict_rest_api_index'), 10, 3);

        // Add security headers (X-Frame-Options, HSTS, etc.)
        add_action('send_headers', array($this, 'add_security_headers'));

        // ── License gate ──────────────────────────────────────────────
        // Active protection features (firewall, WAF, brute force, etc.)
        // require a valid license. Admin UI is always accessible.
        if ( ! BDSEC_License::is_active() ) {
            add_action( 'admin_notices', array( $this, 'license_inactive_notice' ) );
            return;
        }

        // ========== NEW FEATURES ==========

        // Custom Login URL - must initialize early
        add_action('init', array($this, 'custom_login_init'), 1);
        add_action('wp_loaded', array($this, 'custom_login_redirect'));
        add_filter('site_url', array($this, 'custom_login_site_url'), 10, 4);
        add_filter('wp_redirect', array($this, 'custom_login_wp_redirect'), 10, 2);
        add_filter('login_url', array($this, 'custom_login_url'), 10, 3);
        add_filter('logout_url', array($this, 'custom_logout_url'), 10, 2);
        add_filter('register_url', array($this, 'custom_register_url'));
        add_filter('lostpassword_url', array($this, 'custom_lostpassword_url'), 10, 2);

        // Hide login errors (don't reveal if username exists)
        $settings = get_option('bestdid_security_settings');
        if (!empty($settings['hide_login_errors'])) {
            add_filter('login_errors', array($this, 'hide_login_error_messages'));
        }

        // Disable file editor
        if (!empty($settings['disable_file_editor'])) {
            if (!defined('DISALLOW_FILE_EDIT')) {
                define('DISALLOW_FILE_EDIT', true);
            }
        }

        // Disable RSS feeds
        if (!empty($settings['disable_rss_feeds'])) {
            add_action('do_feed', array($this, 'disable_feeds'), 1);
            add_action('do_feed_rdf', array($this, 'disable_feeds'), 1);
            add_action('do_feed_rss', array($this, 'disable_feeds'), 1);
            add_action('do_feed_rss2', array($this, 'disable_feeds'), 1);
            add_action('do_feed_atom', array($this, 'disable_feeds'), 1);
            remove_action('wp_head', 'feed_links', 2);
            remove_action('wp_head', 'feed_links_extra', 3);
        }

        // Force strong passwords
        if (!empty($settings['force_strong_passwords'])) {
            add_action('user_profile_update_errors', array($this, 'validate_strong_password'), 10, 3);
        }

        // Auto logout
        if (!empty($settings['auto_logout_minutes']) && $settings['auto_logout_minutes'] > 0) {
            add_filter('auth_cookie_expiration', array($this, 'set_auto_logout_time'), 10, 3);
        }

        // Block PHP in uploads
        if (!empty($settings['block_php_uploads'])) {
            add_filter('wp_handle_upload_prefilter', array($this, 'block_dangerous_uploads'));
        }

        // Two-Factor Authentication.
        if ( ! empty( $settings['two_factor_enabled'] ) ) {
            BDSEC_Two_Factor::instance();
        }

        // Malware Scanner — AJAX handlers + cron.
        add_action( 'wp_ajax_bdsec_start_scan',        array( $this, 'ajax_start_scan' ) );
        add_action( 'wp_ajax_bdsec_process_chunk',      array( $this, 'ajax_process_chunk' ) );
        add_action( 'wp_ajax_bdsec_cancel_scan',        array( $this, 'ajax_cancel_scan' ) );
        add_action( 'wp_ajax_bdsec_get_scan_state',     array( $this, 'ajax_get_scan_state' ) );
        add_action( 'wp_ajax_bdsec_get_scan_results',   array( $this, 'ajax_get_scan_results' ) );
        add_action( 'wp_ajax_bdsec_quarantine_file',    array( $this, 'ajax_quarantine_file' ) );
        add_action( 'wp_ajax_bdsec_restore_file',       array( $this, 'ajax_restore_file' ) );
        add_action( 'wp_ajax_bdsec_delete_quarantined', array( $this, 'ajax_delete_quarantined' ) );
        add_action( 'wp_ajax_bdsec_ignore_finding',     array( $this, 'ajax_ignore_finding' ) );

        // Cron: weekly schedule + scheduled scan hooks.
        add_filter( 'cron_schedules', array( $this, 'add_weekly_cron_schedule' ) );
        add_action( 'bdsec_scheduled_scan',          array( $this, 'run_scheduled_scan' ) );
        add_action( 'bdsec_scheduled_scan_continue', array( $this, 'run_scheduled_scan_continue' ) );

        if ( ! empty( $settings['scanner_enabled'] ) && $settings['scanner_schedule'] !== 'manual' ) {
            if ( ! wp_next_scheduled( 'bdsec_scheduled_scan' ) ) {
                $interval = $settings['scanner_schedule'] === 'daily' ? 'daily' : 'weekly';
                wp_schedule_event( time() + 60, $interval, 'bdsec_scheduled_scan' );
            }
        } else {
            // If scanner disabled or manual, clear any existing schedule.
            wp_clear_scheduled_hook( 'bdsec_scheduled_scan' );
        }

        // ── Geo-Blocking ────────────────────────────────────────
        if ( ! empty( $settings['geo_blocking_enabled'] ) ) {
            add_action( 'init', array( 'BDSEC_Geo_Blocking', 'check_request' ), 1 );
        }
        // Geo-Blocking AJAX.
        add_action( 'wp_ajax_bdsec_geo_get_log',   array( $this, 'ajax_geo_get_log' ) );
        add_action( 'wp_ajax_bdsec_geo_clear_log',  array( $this, 'ajax_geo_clear_log' ) );
        add_action( 'wp_ajax_bdsec_geo_test_ip',    array( $this, 'ajax_geo_test_ip' ) );

        // ── Activity Logger ─────────────────────────────────────
        if ( ! empty( $settings['activity_logging_enabled'] ) ) {
            add_action( 'wp_login',             array( 'BDSEC_Activity_Logger', 'on_login_success' ), 10, 2 );
            add_action( 'wp_login_failed',      array( 'BDSEC_Activity_Logger', 'on_login_failed' ) );
            add_action( 'wp_logout',            array( 'BDSEC_Activity_Logger', 'on_logout' ) );
            add_action( 'profile_update',       array( 'BDSEC_Activity_Logger', 'on_profile_update' ), 10, 3 );
            add_action( 'after_password_reset', array( 'BDSEC_Activity_Logger', 'on_password_reset' ) );
            add_action( 'user_register',        array( 'BDSEC_Activity_Logger', 'on_user_register' ) );
            add_action( 'delete_user',          array( 'BDSEC_Activity_Logger', 'on_delete_user' ) );
            add_action( 'set_user_role',        array( 'BDSEC_Activity_Logger', 'on_set_user_role' ), 10, 3 );
            add_action( 'activated_plugin',     array( 'BDSEC_Activity_Logger', 'on_activate_plugin' ) );
            add_action( 'deactivated_plugin',   array( 'BDSEC_Activity_Logger', 'on_deactivate_plugin' ) );
            add_action( 'switch_theme',         array( 'BDSEC_Activity_Logger', 'on_switch_theme' ), 10, 2 );
            add_action( 'transition_post_status', array( 'BDSEC_Activity_Logger', 'on_transition_post_status' ), 10, 3 );
            add_action( 'delete_post',          array( 'BDSEC_Activity_Logger', 'on_delete_post' ) );
            add_action( 'upgrader_process_complete', array( 'BDSEC_Activity_Logger', 'on_upgrader_complete' ), 10, 2 );
            add_action( 'updated_option',       array( 'BDSEC_Activity_Logger', 'on_update_option' ), 10, 3 );
        }
        // Activity Log AJAX.
        add_action( 'wp_ajax_bdsec_activity_get_log',    array( $this, 'ajax_activity_get_log' ) );
        add_action( 'wp_ajax_bdsec_activity_export_csv', array( $this, 'ajax_activity_export_csv' ) );
        add_action( 'wp_ajax_bdsec_activity_clear_log',  array( $this, 'ajax_activity_clear_log' ) );

        // Activity Log Cleanup Cron.
        if ( ! empty( $settings['activity_logging_enabled'] ) ) {
            if ( ! wp_next_scheduled( 'bdsec_activity_log_cleanup' ) ) {
                wp_schedule_event( time() + 60, 'daily', 'bdsec_activity_log_cleanup' );
            }
            add_action( 'bdsec_activity_log_cleanup', array( $this, 'run_activity_log_cleanup' ) );
        } else {
            wp_clear_scheduled_hook( 'bdsec_activity_log_cleanup' );
        }

        // ── File Integrity Monitor ──────────────────────────────
        add_action( 'wp_ajax_bdsec_fim_create_baseline',  array( $this, 'ajax_fim_create_baseline' ) );
        add_action( 'wp_ajax_bdsec_fim_process_baseline', array( $this, 'ajax_fim_process_baseline' ) );
        add_action( 'wp_ajax_bdsec_fim_start_check',      array( $this, 'ajax_fim_start_check' ) );
        add_action( 'wp_ajax_bdsec_fim_process_check',    array( $this, 'ajax_fim_process_check' ) );
        add_action( 'wp_ajax_bdsec_fim_accept_change',    array( $this, 'ajax_fim_accept_change' ) );
        add_action( 'wp_ajax_bdsec_fim_accept_all',      array( $this, 'ajax_fim_accept_all' ) );

        // File Integrity Cron.
        if ( ! empty( $settings['file_integrity_enabled'] ) && ( $settings['fim_schedule'] ?? 'manual' ) !== 'manual' ) {
            if ( ! wp_next_scheduled( 'bdsec_file_integrity_check' ) ) {
                $fim_interval = $settings['fim_schedule'] === 'weekly' ? 'weekly' : 'daily';
                wp_schedule_event( time() + 60, $fim_interval, 'bdsec_file_integrity_check' );
            }
            add_action( 'bdsec_file_integrity_check', array( 'BDSEC_File_Integrity', 'cron_check' ) );
        } else {
            wp_clear_scheduled_hook( 'bdsec_file_integrity_check' );
        }

        // ========== END NEW FEATURES ==========

        // Schedule cleanup
        if (!wp_next_scheduled('bestdid_security_cleanup')) {
            wp_schedule_event(time(), 'daily', 'bestdid_security_cleanup');
        }
        add_action('bestdid_security_cleanup', array($this, 'cleanup_old_logs'));

        // Check if plugin is properly installed before running blocking checks
        if (!$this->is_plugin_ready()) {
            return;
        }

        // Skip blocking security checks in admin to prevent lockouts
        if (is_admin() && !wp_doing_ajax()) {
            return;
        }

        // Skip for WP-CLI
        if ($this->is_wp_cli()) {
            return;
        }

        // Get settings - if protection is disabled, skip
        if (empty($settings)) {
            return;
        }

        // Run security checks on frontend only, with safe priority
        add_action('wp', array($this, 'run_security_checks'), 99);

        // Sanitize inputs (lightweight — null byte stripping only, no superglobal mutation)
        add_action('init', array($this, 'sanitize_global_inputs'), 99);

        // Protect login
        add_action('wp_login_failed', array($this, 'track_failed_login'));
        add_filter('authenticate', array($this, 'check_brute_force'), 30, 3);

        // Protect AJAX contact form
        add_action('wp_ajax_nopriv_bestdid_contact', array($this, 'validate_contact_form'), 1);
        add_action('wp_ajax_bestdid_contact', array($this, 'validate_contact_form'), 1);
    }
    
    // ==========================================
    // VERSION AND AUTHOR PROTECTION
    // ==========================================
    
    /**
     * Remove version query strings from scripts and styles
     */
    public function remove_version_query($src, $handle) {
        if (strpos($src, 'ver=') !== false) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    }
    
    /**
     * Remove version strings from scripts/styles
     */
    public function remove_version_strings($src) {
        if (strpos($src, 'ver=') !== false) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    }
    
    /**
     * Remove WP version meta tag
     */
    public function remove_wp_version_meta() {
        // This runs early to catch any remaining generator tags
        return;
    }
    
    /**
     * Block ?author=N BEFORE WordPress resolves it to /author/username/.
     * Hooked to parse_request (fires before redirect_canonical).
     */
    public function block_author_enumeration_early( $wp ) {
        if ( ! is_user_logged_in() && isset( $wp->query_vars['author'] ) ) {
            unset( $wp->query_vars['author'] );
            $wp->query_vars['error'] = '404';
        }
    }

    public function block_author_enumeration() {
        if ( is_author() && ! is_user_logged_in() ) {
            global $wp_query;
            $wp_query->set_404();
            status_header( 404 );
        }
    }

    /**
     * Block redirect_canonical from leaking author username in the 301 redirect URL.
     * WordPress redirects ?author=1 to /author/username/ — this kills the redirect.
     */
    public function block_author_redirect( $redirect_url, $requested_url ) {
        if ( ! is_user_logged_in() && isset( $_GET['author'] ) ) {
            return false;
        }
        if ( ! is_user_logged_in() && $redirect_url && preg_match( '#/author/#i', $redirect_url ) ) {
            return false;
        }
        return $redirect_url;
    }

    /**
     * Block access to sensitive files:
     * - readme.html (WP version leak)
     * - wp-admin/install.php (reinstall vector)
     * - Plugin readme.txt files (version leaks)
     */
    public function block_sensitive_files() {
        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
        $path        = parse_url( $request_uri, PHP_URL_PATH );

        if ( ! $path ) {
            return;
        }

        $blocked_paths = array(
            '/readme.html',
            '/readme.txt',
            '/license.txt',
            '/wp-admin/install.php',
        );

        // Exact match on known files
        foreach ( $blocked_paths as $blocked ) {
            if ( strtolower( $path ) === $blocked ) {
                status_header( 404 );
                nocache_headers();
                exit;
            }
        }

        // Block all plugin/theme readme.txt and changelog files (version leaks)
        if ( preg_match( '#/wp-content/(plugins|themes)/[^/]+/(readme\.txt|readme\.md|changelog\.txt|changelog\.md)$#i', $path ) ) {
            if ( ! is_user_logged_in() ) {
                status_header( 404 );
                nocache_headers();
                exit;
            }
        }
    }

    /**
     * Block direct access to wp-admin/install.php.
     */
    public function block_install_php() {
        $script = isset( $_SERVER['SCRIPT_NAME'] ) ? $_SERVER['SCRIPT_NAME'] : '';
        if ( stripos( $script, 'install.php' ) !== false && ! current_user_can( 'manage_options' ) ) {
            status_header( 403 );
            nocache_headers();
            exit( 'Forbidden' );
        }
    }

    /**
     * Strip CORS headers from REST API responses to prevent cross-origin
     * WordPress fingerprinting. Logged-in users are not affected since
     * they access the API same-origin.
     */
    public function strip_rest_cors_headers( $served ) {
        header_remove('Access-Control-Allow-Origin');
        header_remove('Access-Control-Allow-Methods');
        header_remove('Access-Control-Allow-Credentials');
        header_remove('Access-Control-Allow-Headers');
        header_remove('Access-Control-Expose-Headers');
        return $served;
    }

    /**
     * Filter the REST API index to hide sensitive namespaces from unauthenticated users.
     */
    public function filter_rest_index( $response ) {
        if ( is_user_logged_in() ) {
            return $response;
        }

        // Namespaces to hide from public view
        $hidden_namespaces = array(
            'wc-admin',
            'wc-analytics',
            'wc/private',
            'wc-admin-email',
            'wc-telemetry',
            'wccom-site/v3',
            'bdls/v1',
            'wp-abilities/v1',
            'fluent-smtp',
            'litespeed/v1',
            'litespeed/v3',
            'jetpack/v4',
            'wc/pos/v1/catalog',
        );

        $data = $response->get_data();

        // Filter namespaces list
        if ( isset( $data['namespaces'] ) && is_array( $data['namespaces'] ) ) {
            $data['namespaces'] = array_values( array_filter( $data['namespaces'], function( $ns ) use ( $hidden_namespaces ) {
                return ! in_array( $ns, $hidden_namespaces, true );
            }));
        }

        // Filter routes
        if ( isset( $data['routes'] ) && is_array( $data['routes'] ) ) {
            foreach ( array_keys( $data['routes'] ) as $route ) {
                foreach ( $hidden_namespaces as $ns ) {
                    if ( strpos( $route, '/' . $ns ) === 0 ) {
                        unset( $data['routes'][ $route ] );
                        break;
                    }
                }
            }
        }

        $response->set_data( $data );
        return $response;
    }

    /**
     * Remove sensitive REST endpoints for non-authenticated users.
     */
    public function filter_sensitive_rest_routes( $endpoints ) {
        if ( is_user_logged_in() ) {
            return $endpoints;
        }

        // Patterns to block for unauthenticated users
        $blocked_patterns = array(
            '#^/wc-admin#',
            '#^/wc-analytics#',
            '#^/wc/private#',
            '#^/wc-admin-email#',
            '#^/wc-telemetry#',
            '#^/wccom-site#',
            '#^/wp-abilities#',
            '#^/jetpack/v4/connection#',
            '#^/fluent-smtp#',
            '#^/litespeed#',
            '#^/jetpack/v4$#',
            '#^/wc/pos#',
        );

        foreach ( array_keys( $endpoints ) as $route ) {
            foreach ( $blocked_patterns as $pattern ) {
                if ( preg_match( $pattern, $route ) ) {
                    unset( $endpoints[ $route ] );
                    break;
                }
            }
        }

        return $endpoints;
    }

    /**
     * Block direct access to xmlrpc.php with a 403 response.
     * The xmlrpc_enabled filter only disables methods but the file still returns 200.
     * This actively blocks the request at the WordPress level.
     */
    public function block_xmlrpc_access() {
        $request_uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
        $path        = parse_url( $request_uri, PHP_URL_PATH );

        if ( $path && basename( $path ) === 'xmlrpc.php' ) {
            status_header( 403 );
            nocache_headers();
            header( 'Content-Type: text/plain' );
            exit( 'XML-RPC is disabled.' );
        }
    }

    /**
     * Restrict REST API root index (/wp-json/) for unauthenticated users.
     * Returns a minimal response instead of the full namespace/route listing.
     */
    public function restrict_rest_api_index( $result, $server, $request ) {
        if ( is_user_logged_in() ) {
            return $result;
        }

        $route = $request->get_route();

        /* Only block the root index — individual endpoints are handled by other filters */
        if ( $route === '/' ) {
            return new WP_Error(
                'rest_disabled',
                'The REST API root index is not available.',
                array( 'status' => 403 )
            );
        }

        return $result;
    }

    // ==========================================
    // CUSTOM LOGIN URL FUNCTIONS
    // ==========================================
    
    /**
     * Get custom login slug
     */
    private function get_custom_login_slug() {
        $settings = get_option('bestdid_security_settings');
        return isset($settings['custom_login_slug']) ? sanitize_title($settings['custom_login_slug']) : '';
    }
    
    /**
     * Initialize custom login
     */
    public function custom_login_init() {
        $slug = $this->get_custom_login_slug();
        if (empty($slug)) return;
        
        // Add rewrite rule for custom login
        add_rewrite_rule(
            '^' . $slug . '/?$',
            'index.php?bestdid_custom_login=1',
            'top'
        );
        add_rewrite_tag('%bestdid_custom_login%', '1');
    }
    
    /**
     * Handle custom login redirect
     */
    public function custom_login_redirect() {
        $slug = $this->get_custom_login_slug();
        if (empty($slug)) return;
        
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $request_path = parse_url($request_uri, PHP_URL_PATH);
        $request_path = rtrim($request_path, '/');
        
        // Check if accessing custom login URL
        if ($request_path === '/' . $slug || $request_path === '/' . $slug . '/') {
            // Set cookie to remember valid access
            setcookie('bestdid_login_access', wp_hash($slug), time() + 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
            
            // Load wp-login.php
            require_once ABSPATH . 'wp-login.php';
            exit;
        }
        
        // Block direct access to wp-login.php if custom URL is set
        $blocked_paths = array('/wp-login.php', '/wp-login', '/login');
        $is_blocked_path = false;
        
        foreach ($blocked_paths as $blocked) {
            if (strpos($request_path, $blocked) !== false) {
                $is_blocked_path = true;
                break;
            }
        }
        
        if ($is_blocked_path && !is_user_logged_in()) {
            // Check if they have valid cookie (came from custom login)
            $valid_cookie = isset($_COOKIE['bestdid_login_access']) && 
                           $_COOKIE['bestdid_login_access'] === wp_hash($slug);
            
            // Allow POST requests (login form submission)
            $is_post = isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST';
            
            // Allow specific actions
            $allowed_actions = array('logout', 'postpass', 'rp', 'resetpass', 'lostpassword', 'confirmaction');
            $action = isset($_GET['action']) ? $_GET['action'] : '';
            $is_allowed_action = in_array($action, $allowed_actions);
            
            if (!$valid_cookie && !$is_post && !$is_allowed_action) {
                // Log the attempt
                $ip = $this->get_client_ip();
                $this->log_threat($ip, 'hidden_login_access', 'low', 'Attempted to access hidden wp-login.php');
                
                // Redirect to 404
                wp_redirect(home_url('/404'), 302);
                exit;
            }
        }
        
        // Also block wp-admin for non-logged-in users (redirect to 404, not login)
        if (strpos($request_path, '/wp-admin') !== false && !is_user_logged_in()) {
            // Allow admin-ajax.php
            if (strpos($request_path, 'admin-ajax.php') !== false) {
                return;
            }
            // Allow admin-post.php
            if (strpos($request_path, 'admin-post.php') !== false) {
                return;
            }
            
            wp_redirect(home_url('/404'), 302);
            exit;
        }
    }
    
    /**
     * Filter site_url for login
     */
    public function custom_login_site_url($url, $path, $scheme, $blog_id) {
        $slug = $this->get_custom_login_slug();
        if (empty($slug)) return $url;
        
        if (strpos($url, 'wp-login.php') !== false && !is_user_logged_in()) {
            $url = str_replace('wp-login.php', $slug, $url);
        }
        
        return $url;
    }
    
    /**
     * Filter redirects
     */
    public function custom_login_wp_redirect($location, $status) {
        $slug = $this->get_custom_login_slug();
        if (empty($slug)) return $location;
        
        if (strpos($location, 'wp-login.php') !== false) {
            $location = str_replace('wp-login.php', $slug, $location);
        }
        
        return $location;
    }
    
    /**
     * Filter login_url
     */
    public function custom_login_url($login_url, $redirect, $force_reauth) {
        $slug = $this->get_custom_login_slug();
        if (empty($slug)) return $login_url;
        
        $login_url = home_url('/' . $slug . '/');
        
        if (!empty($redirect)) {
            $login_url = add_query_arg('redirect_to', urlencode($redirect), $login_url);
        }
        
        if ($force_reauth) {
            $login_url = add_query_arg('reauth', '1', $login_url);
        }
        
        return $login_url;
    }
    
    /**
     * Filter logout_url  
     */
    public function custom_logout_url($logout_url, $redirect) {
        $slug = $this->get_custom_login_slug();
        if (empty($slug)) return $logout_url;
        
        $logout_url = home_url('/' . $slug . '/?action=logout');
        $logout_url = wp_nonce_url($logout_url, 'log-out');
        
        if (!empty($redirect)) {
            $logout_url = add_query_arg('redirect_to', urlencode($redirect), $logout_url);
        }
        
        return $logout_url;
    }
    
    /**
     * Filter register_url
     */
    public function custom_register_url($register_url) {
        $slug = $this->get_custom_login_slug();
        if (empty($slug)) return $register_url;
        
        return home_url('/' . $slug . '/?action=register');
    }
    
    /**
     * Filter lostpassword_url
     */
    public function custom_lostpassword_url($lostpassword_url, $redirect) {
        $slug = $this->get_custom_login_slug();
        if (empty($slug)) return $lostpassword_url;
        
        $lostpassword_url = home_url('/' . $slug . '/?action=lostpassword');
        
        if (!empty($redirect)) {
            $lostpassword_url = add_query_arg('redirect_to', urlencode($redirect), $lostpassword_url);
        }
        
        return $lostpassword_url;
    }
    
    // ==========================================
    // OTHER NEW SECURITY FUNCTIONS
    // ==========================================
    
    /**
     * Hide login error messages
     */
    public function hide_login_error_messages($error) {
        return __('Invalid login credentials. Please try again.', 'bestdid-security');
    }
    
    /**
     * Disable RSS feeds
     */
    public function disable_feeds() {
        wp_die(
            __('RSS feeds are disabled on this site.', 'bestdid-security'),
            __('Feeds Disabled', 'bestdid-security'),
            array('response' => 403)
        );
    }
    
    /**
     * Validate strong password
     */
    public function validate_strong_password($errors, $update, $user) {
        if (!isset($_POST['pass1']) || empty($_POST['pass1'])) {
            return $errors;
        }
        
        $password = $_POST['pass1'];
        
        // Check minimum length
        if (strlen($password) < 12) {
            $errors->add('weak_password', __('Password must be at least 12 characters long.', 'bestdid-security'));
            return $errors;
        }
        
        // Check for uppercase
        if (!preg_match('/[A-Z]/', $password)) {
            $errors->add('weak_password', __('Password must contain at least one uppercase letter.', 'bestdid-security'));
        }
        
        // Check for lowercase
        if (!preg_match('/[a-z]/', $password)) {
            $errors->add('weak_password', __('Password must contain at least one lowercase letter.', 'bestdid-security'));
        }
        
        // Check for number
        if (!preg_match('/[0-9]/', $password)) {
            $errors->add('weak_password', __('Password must contain at least one number.', 'bestdid-security'));
        }
        
        // Check for special character
        if (!preg_match('/[^a-zA-Z0-9]/', $password)) {
            $errors->add('weak_password', __('Password must contain at least one special character.', 'bestdid-security'));
        }
        
        return $errors;
    }
    
    /**
     * Set auto logout time
     */
    public function set_auto_logout_time($expiration, $user_id, $remember) {
        $settings = get_option('bestdid_security_settings');
        $minutes = isset($settings['auto_logout_minutes']) ? intval($settings['auto_logout_minutes']) : 0;
        
        if ($minutes > 0) {
            return $minutes * 60; // Convert to seconds
        }
        
        return $expiration;
    }
    
    /**
     * Block dangerous file uploads
     */
    public function block_dangerous_uploads($file) {
        $dangerous_extensions = array(
            'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar',
            'exe', 'sh', 'bash', 'bat', 'cmd', 'com', 'cgi',
            'pl', 'py', 'rb', 'asp', 'aspx', 'jsp', 'htaccess'
        );
        
        $filename = isset($file['name']) ? $file['name'] : '';
        $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        
        if (in_array($extension, $dangerous_extensions)) {
            $ip = $this->get_client_ip();
            $this->log_threat($ip, 'dangerous_upload', 'high', 'Attempted to upload: ' . $filename);
            
            $file['error'] = __('This file type is not allowed for security reasons.', 'bestdid-security');
        }
        
        // Also check for double extensions like file.php.jpg
        if (preg_match('/\.(php|phtml|exe|sh|bash)[.\s]/i', $filename)) {
            $ip = $this->get_client_ip();
            $this->log_threat($ip, 'dangerous_upload', 'high', 'Attempted double extension upload: ' . $filename);
            
            $file['error'] = __('This file type is not allowed for security reasons.', 'bestdid-security');
        }
        
        return $file;
    }
    
    /**
     * Check if plugin is ready (tables exist)
     */
    private function is_plugin_ready() {
        global $wpdb;
        
        // Check if settings exist
        $settings = get_option('bestdid_security_settings');
        if (empty($settings)) {
            return false;
        }
        
        // Simple check - don't query DB if we don't need to
        return true;
    }
    
    /**
     * Check if running in WP-CLI
     */
    private function is_wp_cli() {
        return defined('WP_CLI') && WP_CLI;
    }
    
    /**
     * Plugin activation
     */
    public function activate() {
        global $wpdb;
        
        $charset_collate = $wpdb->get_charset_collate();
        
        // Create rate limits table
        $sql1 = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}{$this->rate_limit_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL,
            action_type VARCHAR(50) NOT NULL,
            attempts INT(11) NOT NULL DEFAULT 1,
            first_attempt DATETIME NOT NULL,
            last_attempt DATETIME NOT NULL,
            blocked_until DATETIME DEFAULT NULL,
            PRIMARY KEY (id),
            KEY ip_action (ip_address, action_type),
            KEY blocked_until (blocked_until)
        ) $charset_collate;";
        
        // Create security logs table
        $sql2 = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}{$this->security_log_table} (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            timestamp DATETIME NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            threat_type VARCHAR(100) NOT NULL,
            severity ENUM('low', 'medium', 'high', 'critical') NOT NULL,
            details TEXT,
            request_uri TEXT,
            user_agent TEXT,
            blocked TINYINT(1) NOT NULL DEFAULT 1,
            PRIMARY KEY (id),
            KEY timestamp (timestamp),
            KEY ip_address (ip_address),
            KEY threat_type (threat_type)
        ) $charset_collate;";
        
        // Create scan results table
        $sql3 = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bestdid_scan_results (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            scan_id VARCHAR(32) NOT NULL,
            file_path TEXT NOT NULL,
            file_hash VARCHAR(64) DEFAULT '',
            threat_type VARCHAR(50) NOT NULL,
            severity ENUM('low','medium','high','critical') NOT NULL DEFAULT 'medium',
            details TEXT,
            matched_signature VARCHAR(100) DEFAULT '',
            file_size BIGINT(20) UNSIGNED DEFAULT 0,
            file_modified DATETIME DEFAULT NULL,
            status ENUM('detected','quarantined','ignored','resolved') NOT NULL DEFAULT 'detected',
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY scan_id (scan_id),
            KEY status (status)
        ) $charset_collate;";

        // Create quarantine log table
        $sql4 = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bestdid_quarantine_log (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            scan_result_id BIGINT(20) UNSIGNED DEFAULT NULL,
            original_path TEXT NOT NULL,
            quarantine_path TEXT NOT NULL,
            file_hash VARCHAR(64) DEFAULT '',
            file_size BIGINT(20) UNSIGNED DEFAULT 0,
            file_permissions VARCHAR(10) DEFAULT '',
            quarantined_by BIGINT(20) UNSIGNED DEFAULT 0,
            quarantined_at DATETIME NOT NULL,
            restored_at DATETIME DEFAULT NULL,
            deleted_at DATETIME DEFAULT NULL,
            status ENUM('quarantined','restored','deleted') NOT NULL DEFAULT 'quarantined',
            notes TEXT,
            PRIMARY KEY (id)
        ) $charset_collate;";

        // Geo-blocking cache table.
        $sql5 = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bestdid_geo_cache (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL,
            country_code VARCHAR(2) NOT NULL DEFAULT '',
            country_name VARCHAR(100) NOT NULL DEFAULT '',
            resolved_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY ip_address (ip_address)
        ) $charset_collate;";

        // Geo-blocking log table.
        $sql6 = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bestdid_geo_log (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL,
            country_code VARCHAR(2) NOT NULL DEFAULT '',
            country_name VARCHAR(100) NOT NULL DEFAULT '',
            action VARCHAR(10) NOT NULL DEFAULT 'blocked',
            request_uri TEXT,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY created_at (created_at),
            KEY country_code (country_code)
        ) $charset_collate;";

        // Activity log table.
        $sql7 = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bestdid_activity_log (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            username VARCHAR(60) NOT NULL DEFAULT '',
            user_role VARCHAR(50) NOT NULL DEFAULT '',
            event_type VARCHAR(50) NOT NULL,
            object_type VARCHAR(50) NOT NULL DEFAULT '',
            object_id BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            object_name VARCHAR(255) NOT NULL DEFAULT '',
            details TEXT,
            ip_address VARCHAR(45) NOT NULL DEFAULT '',
            user_agent TEXT,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY event_type (event_type),
            KEY user_id (user_id),
            KEY created_at (created_at)
        ) $charset_collate;";

        // File integrity baselines table.
        $sql8 = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}bestdid_file_baselines (
            id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            file_path TEXT NOT NULL,
            file_hash VARCHAR(64) NOT NULL DEFAULT '',
            file_size BIGINT(20) UNSIGNED NOT NULL DEFAULT 0,
            file_modified DATETIME DEFAULT NULL,
            baseline_created DATETIME NOT NULL,
            last_checked DATETIME DEFAULT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'ok',
            PRIMARY KEY (id),
            KEY status (status)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql1);
        dbDelta($sql2);
        dbDelta($sql3);
        dbDelta($sql4);
        dbDelta($sql5);
        dbDelta($sql6);
        dbDelta($sql7);
        dbDelta($sql8);

        // Set default options
        add_option('bestdid_security_settings', array(
            'sql_injection_protection' => true,
            'xss_protection' => true,
            'brute_force_protection' => true,
            'rate_limiting' => true,
            'max_login_attempts' => 5,
            'lockout_duration' => 30, // minutes
            'rate_limit_requests' => 60, // per minute
            'log_retention_days' => 30,
            'block_bad_bots' => true,
            'hide_wp_version' => true,
            'disable_xmlrpc' => true,
            // New features
            'custom_login_slug' => '',  // Empty = disabled, e.g., 'my-secret-login'
            'hide_login_errors' => true,
            'disable_file_editor' => true,
            'block_php_uploads' => true,
            'disable_rss_feeds' => false,
            'force_strong_passwords' => true,
            'auto_logout_minutes' => 0, // 0 = disabled
            'two_factor_enabled' => false,
            'two_factor_roles' => array( 'administrator' ),
            'two_factor_forced' => false,
            // Malware Scanner
            'scanner_enabled' => false,
            'scanner_schedule' => 'manual',
            'scanner_check_core' => true,
            'scanner_check_malware' => true,
            'scanner_check_uploads' => true,
            'scanner_email_alerts' => false,
            'scanner_auto_quarantine' => false,
            // Geo-Blocking
            'geo_blocking_enabled' => false,
            'geo_mode'             => 'disabled',
            'geo_countries'        => '',
            'geo_log_blocked'      => true,
            // Activity Logging
            'activity_logging_enabled' => false,
            'activity_retention_days'  => 90,
            // File Integrity Monitor
            'file_integrity_enabled' => false,
            'fim_schedule'           => 'daily',
            'fim_email_alerts'       => false,
            // HSTS
            'enable_hsts'            => false,
        ));
        
        flush_rewrite_rules();
    }
    
    /**
     * Plugin deactivation
     */
    public function deactivate() {
        wp_clear_scheduled_hook('bestdid_security_cleanup');
        wp_clear_scheduled_hook('bdsec_scheduled_scan');
        wp_clear_scheduled_hook('bdsec_scheduled_scan_continue');
        wp_clear_scheduled_hook('bdsec_file_integrity_check');
        wp_clear_scheduled_hook('bdsec_activity_log_cleanup');
        flush_rewrite_rules();
    }
    
    /**
     * Run all security checks
     */
    public function run_security_checks() {
        // Don't run on admin, AJAX, or cron
        if (is_admin() || wp_doing_ajax() || wp_doing_cron()) {
            return;
        }
        
        try {
            $ip = $this->get_client_ip();
            
            // Skip localhost/development
            if ($ip === '127.0.0.1' || $ip === '::1' || strpos($ip, '192.168.') === 0) {
                return;
            }
            
            // Check if IP is blocked
            if ($this->is_ip_blocked($ip)) {
                $this->block_request('IP temporarily blocked due to suspicious activity');
            }
            
            // Rate limiting (but be generous)
            if ($this->is_rate_limited($ip)) {
                $this->log_threat($ip, 'rate_limit_exceeded', 'medium', 'Too many requests');
                $this->block_request('Rate limit exceeded. Please slow down.');
            }
            
            // Only run attack detection on non-standard requests
            $this->check_sql_injection();
            $this->check_xss_attacks();
            $this->check_path_traversal();
            $this->check_bad_bots();
            
        } catch (Exception $e) {
            // Fail open - never break the site
            error_log('BD Security Error: ' . $e->getMessage());
        }
    }
    
    /**
     * SQL Injection Protection
     */
    private function check_sql_injection() {
        $settings = get_option('bestdid_security_settings');
        if (empty($settings['sql_injection_protection'])) return;
        
        try {
            $ip = $this->get_client_ip();
            
            // Only check query strings and specific POST fields, not all data
            $check_data = '';
            if (isset($_SERVER['QUERY_STRING'])) {
                $check_data .= urldecode($_SERVER['QUERY_STRING']) . ' ';
            }
            if (isset($_GET)) {
                $check_data .= http_build_query($_GET) . ' ';
            }
            
            // Skip if empty
            if (empty(trim($check_data))) return;
            
            // More targeted patterns - only the most dangerous
            $dangerous_patterns = array(
                '/\bunion\s+select\b/i',
                '/\bselect\s+.*\bfrom\s+.*\bwhere\b/i',
                '/\bdrop\s+(table|database)\b/i',
                '/\btruncate\s+table\b/i',
                '/\bexec\s*\(/i',
                '/\bwaitfor\s+delay\b/i',
                '/\bload_file\s*\(/i',
                '/\binto\s+outfile\b/i',
                '/\binformation_schema\b/i',
            );
            
            foreach ($dangerous_patterns as $pattern) {
                if (preg_match($pattern, $check_data)) {
                    $this->log_threat($ip, 'sql_injection', 'critical', "Pattern matched: $pattern");
                    $this->increment_rate_limit($ip, 'sql_injection');
                    $this->block_request('Potential SQL injection detected');
                }
            }
        } catch (Exception $e) {
            // Fail open - don't break the site
            error_log('BD Security: SQL check error - ' . $e->getMessage());
        }
    }
    
    /**
     * XSS Protection
     */
    private function check_xss_attacks() {
        $settings = get_option('bestdid_security_settings');
        if (empty($settings['xss_protection'])) return;

        try {
            $ip = $this->get_client_ip();

            // Check GET query string + REQUEST_URI (covers path-based XSS)
            $check_parts = array();
            if ( ! empty( $_SERVER['QUERY_STRING'] ) ) {
                $check_parts[] = urldecode( $_SERVER['QUERY_STRING'] );
            }
            if ( ! empty( $_SERVER['REQUEST_URI'] ) ) {
                $check_parts[] = urldecode( $_SERVER['REQUEST_URI'] );
            }
            // Also check GET values (double-decoded)
            foreach ( $_GET as $val ) {
                if ( is_string( $val ) ) {
                    $check_parts[] = urldecode( $val );
                }
            }

            $check_data = implode( ' ', $check_parts );
            if (empty($check_data)) return;

            $xss_patterns = array(
                // Script tags
                '/<script\b[^>]*>/i',
                '/<\/script>/i',
                // Javascript protocol
                '/javascript\s*:/i',
                '/vbscript\s*:/i',
                '/data\s*:\s*text\/html/i',
                // Event handlers (comprehensive)
                '/\bon(error|load|click|mouseover|mouseout|mousemove|mousedown|mouseup|focus|blur|change|submit|reset|select|input|keydown|keyup|keypress|contextmenu|dblclick|drag|drop|copy|paste|cut|wheel|scroll|touchstart|touchend|touchmove|animationend|animationstart|beforeunload|hashchange|message|popstate|resize|storage|unload|pointerdown|pointerup)\s*=/i',
                // SVG-based XSS
                '/<svg\b[^>]*\bon\w+\s*=/i',
                '/<svg\b[^>]*>/i',
                // Iframe injection
                '/<iframe\b[^>]*>/i',
                // Object/embed/applet tags
                '/<(object|embed|applet)\b[^>]*>/i',
                // Expression (IE CSS XSS)
                '/expression\s*\(/i',
                // Import (CSS-based)
                '/@import\s/i',
                // Base tag hijacking
                '/<base\b[^>]*>/i',
                // Form action hijacking
                '/<form\b[^>]*action\s*=/i',
                // Meta refresh
                '/<meta\b[^>]*http-equiv\s*=\s*["\']?refresh/i',
                // HTML entity encoded script
                '/&#\d{2,};.*&#\d{2,};/i',
                // Template literal injection
                '/\$\{.*\}/i',
            );

            foreach ($xss_patterns as $pattern) {
                if (@preg_match($pattern, $check_data)) {
                    $this->log_threat($ip, 'xss_attack', 'high', "XSS pattern matched in request");
                    $this->increment_rate_limit($ip, 'xss_attack');
                    $this->block_request('Potential XSS attack detected');
                }
            }
        } catch (Exception $e) {
            error_log('BD Security: XSS check error - ' . $e->getMessage());
        }
    }
    
    /**
     * Path Traversal Protection
     */
    private function check_path_traversal() {
        $ip = $this->get_client_ip();
        $traversal_patterns = array(
            '/\.\.\//i',
            '/\.\.\\\/i',
            '/%2e%2e%2f/i',
            '/%2e%2e\//i',
            '/\.%2e\//i',
            '/%2e\.\//i',
            '/etc\/passwd/i',
            '/etc\/shadow/i',
            '/proc\/self/i',
            '/wp-config\.php/i',
        );
        
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $request_data = $this->get_all_request_data();
        $combined = $request_uri . ' ' . $request_data;
        
        foreach ($traversal_patterns as $pattern) {
            if (preg_match($pattern, $combined)) {
                $this->log_threat($ip, 'path_traversal', 'high', "Path traversal attempt: $pattern");
                $this->block_request('Path traversal attempt blocked');
            }
        }
    }
    
    /**
     * Bad Bot Detection
     */
    private function check_bad_bots() {
        $settings = get_option('bestdid_security_settings');
        if (empty($settings['block_bad_bots'])) return;
        
        $ip = $this->get_client_ip();
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? strtolower($_SERVER['HTTP_USER_AGENT']) : '';
        
        $bad_bots = array(
            'sqlmap', 'nikto', 'nmap', 'masscan', 'acunetix', 'nessus',
            'havij', 'sqlninja', 'pangolin', 'burpsuite', 'owasp',
            'dirbuster', 'gobuster', 'wfuzz', 'hydra', 'medusa',
            'brutus', 'scrapy', 'python-requests', 'curl/', 'wget/',
            'libwww', 'lwp-trivial', 'winhttp', 'harvest', 'grabber',
            'extract', 'stripper', 'sucker', 'webwhacker', 'teleport',
        );
        
        foreach ($bad_bots as $bot) {
            if (strpos($user_agent, $bot) !== false) {
                $this->log_threat($ip, 'bad_bot', 'medium', "Bad bot detected: $bot");
                $this->block_request('Access denied');
            }
        }
        
        // Block empty user agents on non-API requests
        if (empty($user_agent) && !$this->is_api_request()) {
            $this->log_threat($ip, 'empty_user_agent', 'low', 'Empty user agent');
        }
    }
    
    /**
     * Check request method
     */
    private function check_request_method() {
        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper($_SERVER['REQUEST_METHOD']) : 'GET';
        $allowed_methods = array('GET', 'POST', 'HEAD', 'OPTIONS');
        
        if (!in_array($method, $allowed_methods)) {
            $ip = $this->get_client_ip();
            $this->log_threat($ip, 'invalid_method', 'medium', "Invalid HTTP method: $method");
            $this->block_request('Invalid request method');
        }
    }
    
    /**
     * Filter database queries for additional protection
     */
    /**
     * Sanitize global inputs — null byte stripping only.
     * Does NOT modify superglobal values to avoid breaking WooCommerce/plugins.
     */
    public function sanitize_global_inputs() {
        // Only strip null bytes — the one universally dangerous character.
        // We do NOT run sanitize_text_field() or strip leading chars,
        // as that breaks WooCommerce, page builders, and other plugins.
        $this->strip_null_bytes( $_GET );
        $this->strip_null_bytes( $_POST );
        $this->strip_null_bytes( $_COOKIE );
        $this->strip_null_bytes( $_REQUEST );
    }

    /**
     * Recursively strip null bytes from an array of values (by reference).
     */
    private function strip_null_bytes( &$data ) {
        if ( is_array( $data ) ) {
            foreach ( $data as &$value ) {
                $this->strip_null_bytes( $value );
            }
        } elseif ( is_string( $data ) ) {
            $data = str_replace( chr( 0 ), '', $data );
        }
    }
    
    /**
     * Add security headers
     */
    public function add_security_headers() {
        if (headers_sent()) return;
        
        // Prevent clickjacking (DENY blocks all iframing, including same-origin)
        header('X-Frame-Options: DENY');
        
        // Prevent MIME type sniffing
        header('X-Content-Type-Options: nosniff');
        
        // XSS Protection
        header('X-XSS-Protection: 1; mode=block');
        
        // Referrer Policy
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // Permissions Policy
        header("Permissions-Policy: geolocation=(), microphone=(), camera=()");
        
        // HSTS — force HTTPS
        $settings = get_option('bestdid_security_settings');
        if ( ! empty( $settings['enable_hsts'] ) ) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }

        // Content Security Policy (adjust as needed for your site)
        $csp = "default-src 'self'; ";
        $csp .= "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: https://fonts.googleapis.com https://cdnjs.cloudflare.com; ";
        $csp .= "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; ";
        $csp .= "font-src 'self' data: https://fonts.gstatic.com; ";
        $csp .= "img-src 'self' data: https:; ";
        $csp .= "connect-src 'self' https:; ";
        $csp .= "frame-src 'self' https://www.youtube-nocookie.com https://www.youtube.com; ";
        $csp .= "frame-ancestors 'none';";
        header("Content-Security-Policy: $csp");
    }
    
    /**
     * Track failed login attempts
     */
    public function track_failed_login($username) {
        $ip = $this->get_client_ip();
        $this->increment_rate_limit($ip, 'failed_login');
        $this->log_threat($ip, 'failed_login', 'low', "Failed login attempt for user: $username");
    }
    
    /**
     * Check brute force before authentication
     */
    public function check_brute_force($user, $username, $password) {
        if (empty($username) || empty($password)) {
            return $user;
        }
        
        $settings = get_option('bestdid_security_settings');
        if (empty($settings['brute_force_protection'])) return $user;
        
        $ip = $this->get_client_ip();
        
        if ($this->is_ip_blocked($ip)) {
            $this->log_threat($ip, 'brute_force_blocked', 'high', "Brute force attempt blocked for user: $username");
            return new WP_Error('too_many_attempts', 
                __('<strong>Error</strong>: Too many failed login attempts. Please try again later.', 'bestdid-security')
            );
        }
        
        return $user;
    }
    
    /**
     * Validate contact form submissions
     */
    public function validate_contact_form() {
        $ip = $this->get_client_ip();
        
        // Check rate limit for contact form
        if ($this->is_rate_limited($ip, 'contact_form', 5, 60)) { // 5 submissions per minute max
            $this->log_threat($ip, 'contact_form_spam', 'medium', 'Contact form rate limit exceeded');
            wp_send_json_error(array('message' => __('Please wait before submitting again.', 'bestdid-security')));
            exit;
        }
        
        $this->increment_rate_limit($ip, 'contact_form');
        
        // Honeypot check (if implemented in form)
        if (!empty($_POST['website']) || !empty($_POST['url']) || !empty($_POST['honeypot'])) {
            $this->log_threat($ip, 'honeypot_triggered', 'medium', 'Bot detected via honeypot');
            wp_send_json_error(array('message' => __('Invalid submission.', 'bestdid-security')));
            exit;
        }
        
        // Time-based protection (form should take at least 3 seconds to fill)
        if (isset($_POST['_form_timestamp'])) {
            $submitted = intval($_POST['_form_timestamp']);
            if (time() - $submitted < 3) {
                $this->log_threat($ip, 'form_too_fast', 'low', 'Form submitted too quickly');
            }
        }
    }
    
    /**
     * Protect REST API
     */
    public function protect_rest_api($errors) {
        // If there's already an error, pass it through
        if (is_wp_error($errors)) {
            return $errors;
        }
        
        // Get the current REST route
        $rest_route = '';
        if (isset($GLOBALS['wp']->query_vars['rest_route'])) {
            $rest_route = $GLOBALS['wp']->query_vars['rest_route'];
        }
        if (empty($rest_route) && isset($_SERVER['REQUEST_URI'])) {
            // Try to extract from URL
            $rest_route = $_SERVER['REQUEST_URI'];
        }
        
        // Block user enumeration for non-logged-in users
        if (!is_user_logged_in()) {
            // Check if this is a users endpoint request
            if (preg_match('/\/wp\/v2\/users/i', $rest_route) || 
                preg_match('/\/wp-json\/wp\/v2\/users/i', $rest_route)) {
                
                $ip = $this->get_client_ip();
                $this->log_threat($ip, 'user_enumeration', 'medium', 'User enumeration attempt via REST API blocked');
                
                return new WP_Error(
                    'rest_forbidden',
                    __('Access denied.', 'bestdid-security'),
                    array('status' => 403)
                );
            }
        }
        
        return $errors;
    }
    
    /**
     * Disable user endpoints completely for non-logged-in users
     */
    public function disable_user_endpoints($endpoints) {
        if (!is_user_logged_in()) {
            // Remove all user-related endpoints
            if (isset($endpoints['/wp/v2/users'])) {
                unset($endpoints['/wp/v2/users']);
            }
            if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
                unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
            }
            if (isset($endpoints['/wp/v2/users/me'])) {
                unset($endpoints['/wp/v2/users/me']);
            }
        }
        return $endpoints;
    }
    
    /**
     * Rate limit REST API requests
     */
    public function rate_limit_rest_api($errors) {
        try {
            $ip = $this->get_client_ip();
            
            // Skip localhost
            if ($ip === '127.0.0.1' || $ip === '::1') {
                return $errors;
            }
            
            // Check if IP is blocked
            if ($this->is_ip_blocked($ip)) {
                return new WP_Error('rest_forbidden', __('Access denied.', 'bestdid-security'), array('status' => 403));
            }
        } catch (Exception $e) {
            error_log('BD Security REST API error: ' . $e->getMessage());
        }
        
        return $errors;
    }
    
    /**
     * Check if IP is whitelisted
     */
    private function is_ip_whitelisted($ip) {
        $settings = get_option('bestdid_security_settings');
        
        // Check if admins are whitelisted and user is admin
        if (!empty($settings['whitelist_admins']) && current_user_can('manage_options')) {
            return true;
        }
        
        // Check IP whitelist
        if (!empty($settings['whitelisted_ips'])) {
            $whitelisted = array_filter(array_map('trim', explode("\n", $settings['whitelisted_ips'])));
            if (in_array($ip, $whitelisted)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check if IP is blocked
     */
    private function is_ip_blocked($ip) {
        global $wpdb;
        
        // Check whitelist first
        if ($this->is_ip_whitelisted($ip)) {
            return false;
        }
        
        try {
            $table = $wpdb->prefix . $this->rate_limit_table;
            
            // Check if table exists first
            $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table'");
            if ($table_exists !== $table) {
                return false;
            }
            
            $blocked = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM $table WHERE ip_address = %s AND blocked_until > NOW()",
                $ip
            ));
            
            return $blocked > 0;
        } catch (Exception $e) {
            return false; // Fail open
        }
    }
    
    /**
     * Check rate limiting
     */
    private function is_rate_limited($ip, $action = 'general', $max_requests = null, $time_window = 60) {
        global $wpdb;
        
        // Check whitelist first
        if ($this->is_ip_whitelisted($ip)) {
            return false;
        }
        
        try {
            $settings = get_option('bestdid_security_settings');
            if (empty($settings['rate_limiting'])) return false;
            
            $table = $wpdb->prefix . $this->rate_limit_table;
            
            // Check if table exists
            $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table'");
            if ($table_exists !== $table) {
                return false;
            }
            
            if ($max_requests === null) {
                $max_requests = isset($settings['rate_limit_requests']) ? $settings['rate_limit_requests'] : 100;
            }
            
            $attempts = $wpdb->get_var($wpdb->prepare(
                "SELECT attempts FROM $table 
                 WHERE ip_address = %s AND action_type = %s 
                 AND last_attempt > DATE_SUB(NOW(), INTERVAL %d SECOND)",
                $ip, $action, $time_window
            ));
            
            return $attempts >= $max_requests;
        } catch (Exception $e) {
            return false; // Fail open
        }
    }
    
    /**
     * Increment rate limit counter
     */
    private function increment_rate_limit($ip, $action = 'general') {
        global $wpdb;
        
        try {
            $table = $wpdb->prefix . $this->rate_limit_table;
            
            // Check if table exists
            $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table'");
            if ($table_exists !== $table) {
                return;
            }
            
            $settings = get_option('bestdid_security_settings');
            $max_attempts = isset($settings['max_login_attempts']) ? $settings['max_login_attempts'] : 5;
            $lockout = isset($settings['lockout_duration']) ? $settings['lockout_duration'] : 30;
            
            $existing = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM $table WHERE ip_address = %s AND action_type = %s AND last_attempt > DATE_SUB(NOW(), INTERVAL 1 HOUR)",
                $ip, $action
            ));
            
            if ($existing) {
                $new_attempts = $existing->attempts + 1;
                $blocked_until = ($new_attempts >= $max_attempts) ? 
                    date('Y-m-d H:i:s', strtotime("+{$lockout} minutes")) : null;
                
                $wpdb->update(
                    $table,
                    array(
                        'attempts' => $new_attempts,
                        'last_attempt' => current_time('mysql'),
                        'blocked_until' => $blocked_until
                    ),
                    array('id' => $existing->id),
                    array('%d', '%s', '%s'),
                    array('%d')
                );
            } else {
                $wpdb->insert(
                    $table,
                    array(
                        'ip_address' => $ip,
                        'action_type' => $action,
                        'attempts' => 1,
                        'first_attempt' => current_time('mysql'),
                        'last_attempt' => current_time('mysql'),
                    ),
                    array('%s', '%s', '%d', '%s', '%s')
                );
            }
        } catch (Exception $e) {
            error_log('BD Security: Rate limit error - ' . $e->getMessage());
        }
    }
    
    /**
     * Log security threat
     */
    private function log_threat($ip, $type, $severity, $details) {
        global $wpdb;
        
        try {
            $table = $wpdb->prefix . $this->security_log_table;
            
            // Check if table exists
            $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table'");
            if ($table_exists !== $table) {
                error_log("BestDid Security: $type from $ip - $details");
                return;
            }
            
            $wpdb->insert(
                $table,
                array(
                    'timestamp' => current_time('mysql'),
                    'ip_address' => $ip,
                    'threat_type' => $type,
                    'severity' => $severity,
                    'details' => $details,
                    'request_uri' => isset($_SERVER['REQUEST_URI']) ? substr($_SERVER['REQUEST_URI'], 0, 500) : '',
                    'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 500) : '',
                    'blocked' => 1
                ),
                array('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d')
            );
        } catch (Exception $e) {
            error_log("BestDid Security: $type from $ip - $details (log failed)");
        }
    }
    
    /**
     * Block request and exit
     */
    private function block_request($message = 'Access Denied') {
        status_header(403);
        
        if ($this->is_api_request()) {
            wp_send_json_error(array('message' => $message), 403);
        }
        
        // Show a professional block page
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Access Denied - Security Alert</title>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="robots" content="noindex, nofollow">
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: #fff;
                }
                .container {
                    text-align: center;
                    padding: 40px;
                    max-width: 500px;
                }
                .shield {
                    font-size: 80px;
                    margin-bottom: 20px;
                    animation: pulse 2s ease-in-out infinite;
                }
                @keyframes pulse {
                    0%, 100% { transform: scale(1); }
                    50% { transform: scale(1.1); }
                }
                h1 {
                    font-size: 28px;
                    margin-bottom: 15px;
                    color: #e94560;
                }
                p {
                    color: #a0a0a0;
                    line-height: 1.6;
                    margin-bottom: 30px;
                }
                .code {
                    font-family: monospace;
                    background: rgba(255,255,255,0.1);
                    padding: 10px 20px;
                    border-radius: 5px;
                    display: inline-block;
                    color: #00ff88;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="shield">🛡️</div>
                <h1>Access Denied</h1>
                <p><?php echo esc_html($message); ?></p>
                <p>Your request has been blocked by our security system. If you believe this is an error, please contact the site administrator.</p>
                <div class="code">Error Code: SEC-<?php echo esc_html(time()); ?></div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
    
    /**
     * Get client IP address
     */
    private function get_client_ip() {
        $ip_headers = array(
            'HTTP_CF_CONNECTING_IP', // Cloudflare
            'HTTP_X_REAL_IP',
            'HTTP_X_FORWARDED_FOR',
            'REMOTE_ADDR'
        );
        
        foreach ($ip_headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                // Handle comma-separated IPs
                if (strpos($ip, ',') !== false) {
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }
                // Validate IP
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return '0.0.0.0';
    }
    
    /**
     * Get all request data as string for pattern matching
     */
    private function get_all_request_data() {
        $data = array();
        
        if (!empty($_GET)) {
            $data[] = http_build_query($_GET);
        }
        if (!empty($_POST)) {
            $data[] = http_build_query($_POST);
        }
        if (!empty($_COOKIE)) {
            $data[] = http_build_query($_COOKIE);
        }
        if (isset($_SERVER['REQUEST_URI'])) {
            $data[] = urldecode($_SERVER['REQUEST_URI']);
        }
        if (isset($_SERVER['QUERY_STRING'])) {
            $data[] = urldecode($_SERVER['QUERY_STRING']);
        }
        
        return implode(' ', $data);
    }
    
    /**
     * Check if this is an API request
     */
    private function is_api_request() {
        if (defined('REST_REQUEST') && REST_REQUEST) {
            return true;
        }
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return true;
        }
        if (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
            return true;
        }
        return false;
    }
    
    /**
     * Cleanup old logs
     */
    public function cleanup_old_logs() {
        global $wpdb;
        
        $settings = get_option('bestdid_security_settings');
        $retention = isset($settings['log_retention_days']) ? intval($settings['log_retention_days']) : 30;
        
        // Clean rate limits
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->prefix}{$this->rate_limit_table} WHERE last_attempt < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $retention
        ));
        
        // Clean security logs
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->prefix}{$this->security_log_table} WHERE timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $retention
        ));
    }
    
    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        add_menu_page(
            __('Security Firewall', 'bestdid-security'),
            __('Security', 'bestdid-security'),
            'manage_options',
            'bestdid-security',
            array($this, 'render_admin_page'),
            'dashicons-shield',
            80
        );
        
        add_submenu_page(
            'bestdid-security',
            __('Malware Scanner', 'bestdid-security'),
            __('Scanner', 'bestdid-security'),
            'manage_options',
            'bestdid-security-scanner',
            array($this, 'render_scanner_page')
        );

        add_submenu_page(
            'bestdid-security',
            __('Geo-Blocking', 'bestdid-security'),
            __('Geo-Blocking', 'bestdid-security'),
            'manage_options',
            'bestdid-security-geo-blocking',
            array($this, 'render_geo_blocking_page')
        );

        add_submenu_page(
            'bestdid-security',
            __('Activity Log', 'bestdid-security'),
            __('Activity Log', 'bestdid-security'),
            'manage_options',
            'bestdid-security-activity-log',
            array($this, 'render_activity_log_page')
        );

        add_submenu_page(
            'bestdid-security',
            __('File Integrity', 'bestdid-security'),
            __('File Integrity', 'bestdid-security'),
            'manage_options',
            'bestdid-security-file-integrity',
            array($this, 'render_file_integrity_page')
        );

        add_submenu_page(
            'bestdid-security',
            __('Security Logs', 'bestdid-security'),
            __('Logs', 'bestdid-security'),
            'manage_options',
            'bestdid-security-logs',
            array($this, 'render_logs_page')
        );
        
        add_submenu_page(
            'bestdid-security',
            __('Settings', 'bestdid-security'),
            __('Settings', 'bestdid-security'),
            'manage_options',
            'bestdid-security-settings',
            array($this, 'render_settings_page')
        );
    }
    
    /**
     * Render admin dashboard page
     */
    public function render_admin_page() {
        global $wpdb;
        
        // Get stats
        $log_table = $wpdb->prefix . $this->security_log_table;
        $rate_table = $wpdb->prefix . $this->rate_limit_table;
        
        $total_blocked = $wpdb->get_var("SELECT COUNT(*) FROM $log_table WHERE blocked = 1");
        $blocked_today = $wpdb->get_var("SELECT COUNT(*) FROM $log_table WHERE blocked = 1 AND DATE(timestamp) = CURDATE()");
        $critical_threats = $wpdb->get_var("SELECT COUNT(*) FROM $log_table WHERE severity = 'critical' AND DATE(timestamp) = CURDATE()");
        $blocked_ips = $wpdb->get_var("SELECT COUNT(DISTINCT ip_address) FROM $rate_table WHERE blocked_until > NOW()");
        
        $recent_threats = $wpdb->get_results("SELECT * FROM $log_table ORDER BY timestamp DESC LIMIT 10");
        
        include BESTDID_SECURITY_PATH . 'templates/admin-dashboard.php';
    }
    
    /**
     * Render logs page
     */
    public function render_logs_page() {
        global $wpdb;
        $log_table = $wpdb->prefix . $this->security_log_table;
        
        $page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $per_page = 50;
        $offset = ($page - 1) * $per_page;
        
        $total = $wpdb->get_var("SELECT COUNT(*) FROM $log_table");
        $logs = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM $log_table ORDER BY timestamp DESC LIMIT %d OFFSET %d",
            $per_page, $offset
        ));
        
        $total_pages = ceil($total / $per_page);
        
        include BESTDID_SECURITY_PATH . 'templates/admin-logs.php';
    }
    
    /**
     * Render settings page
     */
    public function render_settings_page() {
        if (isset($_POST['bestdid_security_settings_nonce']) && 
            wp_verify_nonce($_POST['bestdid_security_settings_nonce'], 'bestdid_security_save_settings')) {
            
            // Sanitize custom login slug
            $custom_login_slug = '';
            if (!empty($_POST['custom_login_slug'])) {
                $custom_login_slug = sanitize_title($_POST['custom_login_slug']);
                // Remove any reserved WordPress slugs
                $reserved = array('wp-admin', 'wp-login', 'login', 'admin', 'dashboard', 'wp-content', 'wp-includes');
                if (in_array($custom_login_slug, $reserved)) {
                    $custom_login_slug = '';
                }
            }
            
            $settings = array(
                'sql_injection_protection' => !empty($_POST['sql_injection_protection']),
                'xss_protection' => !empty($_POST['xss_protection']),
                'brute_force_protection' => !empty($_POST['brute_force_protection']),
                'rate_limiting' => !empty($_POST['rate_limiting']),
                'max_login_attempts' => intval($_POST['max_login_attempts']),
                'lockout_duration' => intval($_POST['lockout_duration']),
                'rate_limit_requests' => intval($_POST['rate_limit_requests']),
                'log_retention_days' => intval($_POST['log_retention_days']),
                'block_bad_bots' => !empty($_POST['block_bad_bots']),
                'hide_wp_version' => !empty($_POST['hide_wp_version']),
                'disable_xmlrpc' => !empty($_POST['disable_xmlrpc']),
                // New settings
                'custom_login_slug' => $custom_login_slug,
                'hide_login_errors' => !empty($_POST['hide_login_errors']),
                'disable_file_editor' => !empty($_POST['disable_file_editor']),
                'block_php_uploads' => !empty($_POST['block_php_uploads']),
                'disable_rss_feeds' => !empty($_POST['disable_rss_feeds']),
                'force_strong_passwords' => !empty($_POST['force_strong_passwords']),
                'auto_logout_minutes' => intval($_POST['auto_logout_minutes']),
                // Two-Factor Authentication
                'two_factor_enabled' => !empty($_POST['two_factor_enabled']),
                'two_factor_roles' => isset($_POST['two_factor_roles']) ? array_map('sanitize_text_field', (array) $_POST['two_factor_roles']) : array('administrator'),
                'two_factor_forced' => !empty($_POST['two_factor_forced']),
                // IP Whitelist
                'whitelisted_ips' => sanitize_textarea_field($_POST['whitelisted_ips'] ?? ''),
                'whitelist_admins' => !empty($_POST['whitelist_admins']),
                // Malware Scanner
                'scanner_enabled' => !empty($_POST['scanner_enabled']),
                'scanner_schedule' => in_array($_POST['scanner_schedule'] ?? 'manual', array('manual','daily','weekly')) ? $_POST['scanner_schedule'] : 'manual',
                'scanner_check_core' => !empty($_POST['scanner_check_core']),
                'scanner_check_malware' => !empty($_POST['scanner_check_malware']),
                'scanner_check_uploads' => !empty($_POST['scanner_check_uploads']),
                'scanner_email_alerts' => !empty($_POST['scanner_email_alerts']),
                'scanner_auto_quarantine' => !empty($_POST['scanner_auto_quarantine']),
                // Geo-Blocking
                'geo_blocking_enabled' => !empty($_POST['geo_blocking_enabled']),
                'geo_mode'             => in_array($_POST['geo_mode'] ?? 'disabled', array('disabled','blacklist','whitelist')) ? $_POST['geo_mode'] : 'disabled',
                'geo_countries'        => sanitize_text_field($_POST['geo_countries'] ?? ''),
                'geo_log_blocked'      => !empty($_POST['geo_log_blocked']),
                // Activity Logging
                'activity_logging_enabled' => !empty($_POST['activity_logging_enabled']),
                'activity_retention_days'  => max(1, intval($_POST['activity_retention_days'] ?? 90)),
                // File Integrity Monitor
                'file_integrity_enabled' => !empty($_POST['file_integrity_enabled']),
                'fim_schedule'           => in_array($_POST['fim_schedule'] ?? 'daily', array('manual','daily','weekly')) ? $_POST['fim_schedule'] : 'daily',
                'fim_email_alerts'       => !empty($_POST['fim_email_alerts']),
                // HSTS
                'enable_hsts'            => !empty($_POST['enable_hsts']),
            );

            // Log settings save in activity logger if enabled.
            if ( ! empty( $settings['activity_logging_enabled'] ) ) {
                BDSEC_Activity_Logger::on_settings_saved();
            }

            update_option('bestdid_security_settings', $settings);
            
            // Flush rewrite rules when custom login slug changes
            flush_rewrite_rules();
            
            $updated = true;
        }
        
        $settings = get_option('bestdid_security_settings');

        include BESTDID_SECURITY_PATH . 'templates/admin-settings.php';
    }

    // ==========================================
    // GEO-BLOCKING
    // ==========================================

    public function render_geo_blocking_page() {
        $settings = get_option( 'bestdid_security_settings' );
        include BESTDID_SECURITY_PATH . 'templates/admin-geo-blocking.php';
    }

    public function ajax_geo_get_log() {
        check_ajax_referer( 'bdsec_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( 'Unauthorized' ); }

        global $wpdb;
        $table  = $wpdb->prefix . 'bestdid_geo_log';
        $page   = max( 1, intval( $_POST['page'] ?? 1 ) );
        $limit  = 50;
        $offset = ( $page - 1 ) * $limit;

        $total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );
        $rows  = $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM {$table} ORDER BY created_at DESC LIMIT %d OFFSET %d",
            $limit, $offset
        ), ARRAY_A );

        wp_send_json_success( array( 'rows' => $rows, 'total' => $total, 'pages' => ceil( $total / $limit ) ) );
    }

    public function ajax_geo_clear_log() {
        check_ajax_referer( 'bdsec_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( 'Unauthorized' ); }

        global $wpdb;
        $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}bestdid_geo_log" );
        wp_send_json_success();
    }

    public function ajax_geo_test_ip() {
        check_ajax_referer( 'bdsec_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( 'Unauthorized' ); }

        $ip = sanitize_text_field( $_POST['ip'] ?? '' );
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            wp_send_json_error( 'Invalid IP address' );
        }

        wp_send_json_success( BDSEC_Geo_Blocking::test_ip( $ip ) );
    }

    // ==========================================
    // ACTIVITY LOG
    // ==========================================

    public function render_activity_log_page() {
        $settings = get_option( 'bestdid_security_settings' );
        include BESTDID_SECURITY_PATH . 'templates/admin-activity-log.php';
    }

    public function ajax_activity_get_log() {
        check_ajax_referer( 'bdsec_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( 'Unauthorized' ); }

        global $wpdb;
        $table  = $wpdb->prefix . 'bestdid_activity_log';
        $page   = max( 1, intval( $_POST['page'] ?? 1 ) );
        $limit  = 50;
        $offset = ( $page - 1 ) * $limit;

        $where = '1=1';
        $params = array();

        if ( ! empty( $_POST['event_type'] ) ) {
            $where .= ' AND event_type = %s';
            $params[] = sanitize_text_field( $_POST['event_type'] );
        }
        if ( ! empty( $_POST['user_filter'] ) ) {
            $where .= ' AND username = %s';
            $params[] = sanitize_text_field( $_POST['user_filter'] );
        }
        if ( ! empty( $_POST['date_from'] ) ) {
            $where .= ' AND created_at >= %s';
            $params[] = sanitize_text_field( $_POST['date_from'] ) . ' 00:00:00';
        }
        if ( ! empty( $_POST['date_to'] ) ) {
            $where .= ' AND created_at <= %s';
            $params[] = sanitize_text_field( $_POST['date_to'] ) . ' 23:59:59';
        }

        $count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where}";
        $data_sql  = "SELECT * FROM {$table} WHERE {$where} ORDER BY created_at DESC LIMIT %d OFFSET %d";
        $params_count = $params;
        $params[] = $limit;
        $params[] = $offset;

        $total = empty( $params_count )
            ? (int) $wpdb->get_var( $count_sql )
            : (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $params_count ) );

        $rows = empty( $params )
            ? $wpdb->get_results( $data_sql, ARRAY_A )
            : $wpdb->get_results( $wpdb->prepare( $data_sql, $params ), ARRAY_A );

        wp_send_json_success( array( 'rows' => $rows, 'total' => $total, 'pages' => ceil( $total / $limit ) ) );
    }

    public function ajax_activity_export_csv() {
        check_ajax_referer( 'bdsec_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) { wp_die( 'Unauthorized' ); }

        global $wpdb;
        $table = $wpdb->prefix . 'bestdid_activity_log';

        $where  = '1=1';
        $params = array();

        if ( ! empty( $_GET['event_type'] ) ) {
            $where .= ' AND event_type = %s';
            $params[] = sanitize_text_field( $_GET['event_type'] );
        }
        if ( ! empty( $_GET['date_from'] ) ) {
            $where .= ' AND created_at >= %s';
            $params[] = sanitize_text_field( $_GET['date_from'] ) . ' 00:00:00';
        }
        if ( ! empty( $_GET['date_to'] ) ) {
            $where .= ' AND created_at <= %s';
            $params[] = sanitize_text_field( $_GET['date_to'] ) . ' 23:59:59';
        }

        $sql  = "SELECT * FROM {$table} WHERE {$where} ORDER BY created_at DESC LIMIT 10000";
        $rows = empty( $params ) ? $wpdb->get_results( $sql, ARRAY_A ) : $wpdb->get_results( $wpdb->prepare( $sql, $params ), ARRAY_A );

        header( 'Content-Type: text/csv; charset=utf-8' );
        header( 'Content-Disposition: attachment; filename=activity-log-' . gmdate( 'Y-m-d' ) . '.csv' );

        $out = fopen( 'php://output', 'w' );
        fputcsv( $out, array( 'Time', 'User', 'Role', 'Event', 'Object Type', 'Object', 'Details', 'IP', 'User Agent' ) );
        foreach ( $rows as $r ) {
            fputcsv( $out, array(
                $r['created_at'], $r['username'], $r['user_role'], $r['event_type'],
                $r['object_type'], $r['object_name'], $r['details'], $r['ip_address'], $r['user_agent'],
            ) );
        }
        fclose( $out );
        exit;
    }

    public function ajax_activity_clear_log() {
        check_ajax_referer( 'bdsec_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( 'Unauthorized' ); }

        $days = max( 0, intval( $_POST['days'] ?? 0 ) );
        if ( $days > 0 ) {
            BDSEC_Activity_Logger::cleanup( $days );
        } else {
            global $wpdb;
            $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}bestdid_activity_log" );
        }

        wp_send_json_success();
    }

    public function run_activity_log_cleanup() {
        $settings = get_option( 'bestdid_security_settings' );
        $days = intval( $settings['activity_retention_days'] ?? 90 );
        BDSEC_Activity_Logger::cleanup( $days );
    }

    // ==========================================
    // FILE INTEGRITY MONITOR
    // ==========================================

    public function render_file_integrity_page() {
        $settings = get_option( 'bestdid_security_settings' );
        include BESTDID_SECURITY_PATH . 'templates/admin-file-integrity.php';
    }

    public function ajax_fim_create_baseline() {
        check_ajax_referer( 'bdsec_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( 'Unauthorized' ); }

        // Clear old baselines first.
        global $wpdb;
        $wpdb->query( "TRUNCATE TABLE {$wpdb->prefix}bestdid_file_baselines" );

        wp_send_json_success( BDSEC_File_Integrity::start_baseline() );
    }

    public function ajax_fim_process_baseline() {
        check_ajax_referer( 'bdsec_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( 'Unauthorized' ); }

        wp_send_json_success( BDSEC_File_Integrity::process_baseline_chunk() );
    }

    public function ajax_fim_start_check() {
        check_ajax_referer( 'bdsec_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( 'Unauthorized' ); }

        wp_send_json_success( BDSEC_File_Integrity::start_check() );
    }

    public function ajax_fim_process_check() {
        check_ajax_referer( 'bdsec_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( 'Unauthorized' ); }

        wp_send_json_success( BDSEC_File_Integrity::process_check_chunk() );
    }

    public function ajax_fim_accept_change() {
        check_ajax_referer( 'bdsec_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( 'Unauthorized' ); }

        $id = intval( $_POST['id'] ?? 0 );
        if ( ! $id ) { wp_send_json_error( 'Invalid ID' ); }

        $result = BDSEC_File_Integrity::accept_change( $id );
        $result ? wp_send_json_success() : wp_send_json_error( 'Failed to accept change' );
    }

    public function ajax_fim_accept_all() {
        check_ajax_referer( 'bdsec_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( 'Unauthorized' ); }

        BDSEC_File_Integrity::accept_all_changes();
        wp_send_json_success();
    }

    // ==========================================
    // MALWARE SCANNER
    // ==========================================

    /**
     * Render scanner admin page.
     */
    public function render_scanner_page() {
        $scanner          = new BDSEC_Scanner_Engine();
        $quarantine       = new BDSEC_Quarantine();
        $last_scan        = get_option( 'bdsec_last_scan' );
        $quarantine_count = $quarantine->get_quarantine_count();
        $quarantined_files = $quarantine->get_quarantined_files();

        include BESTDID_SECURITY_PATH . 'templates/admin-scanner.php';
    }

    /**
     * Add weekly cron schedule.
     */
    public function add_weekly_cron_schedule( $schedules ) {
        $schedules['weekly'] = array(
            'interval' => 604800,
            'display'  => __( 'Once Weekly', 'bestdid-security' ),
        );
        return $schedules;
    }

    /* ─── Scanner AJAX Handlers ─────────────────────────────────── */

    private function verify_scanner_nonce() {
        if ( ! current_user_can( 'manage_options' ) || ! check_ajax_referer( 'bdsec_scanner_nonce', '_nonce', false ) ) {
            wp_send_json_error( 'Unauthorized', 403 );
        }
        if ( ! BDSEC_License::is_active() ) {
            wp_send_json_error( 'License inactive', 403 );
        }
    }

    public function ajax_start_scan() {
        $this->verify_scanner_nonce();
        $settings = get_option( 'bestdid_security_settings' );
        $scanner  = new BDSEC_Scanner_Engine();
        $result   = $scanner->start_scan( array(
            'check_core'    => ! empty( $settings['scanner_check_core'] ),
            'check_malware' => ! empty( $settings['scanner_check_malware'] ),
            'check_uploads' => ! empty( $settings['scanner_check_uploads'] ),
            'check_perms'   => true,
        ) );
        wp_send_json_success( $result );
    }

    public function ajax_process_chunk() {
        $this->verify_scanner_nonce();
        $scan_id = isset( $_POST['scan_id'] ) ? sanitize_text_field( $_POST['scan_id'] ) : '';
        $scanner = new BDSEC_Scanner_Engine();
        $result  = $scanner->process_chunk( $scan_id );
        wp_send_json_success( $result );
    }

    public function ajax_cancel_scan() {
        $this->verify_scanner_nonce();
        $scanner = new BDSEC_Scanner_Engine();
        $scanner->cancel_scan();
        wp_send_json_success( true );
    }

    public function ajax_get_scan_state() {
        $this->verify_scanner_nonce();
        $scanner = new BDSEC_Scanner_Engine();
        wp_send_json_success( $scanner->get_scan_state() );
    }

    public function ajax_get_scan_results() {
        $this->verify_scanner_nonce();
        $scanner = new BDSEC_Scanner_Engine();
        $results = $scanner->get_results();

        // Add relative path for display.
        $base = wp_normalize_path( ABSPATH );
        foreach ( $results as &$r ) {
            $normalized = wp_normalize_path( $r->file_path );
            $r->file_path_relative = 0 === strpos( $normalized, $base )
                ? substr( $normalized, strlen( $base ) )
                : $r->file_path;
        }
        unset( $r );

        wp_send_json_success( $results );
    }

    public function ajax_quarantine_file() {
        $this->verify_scanner_nonce();
        $finding_id = isset( $_POST['finding_id'] ) ? intval( $_POST['finding_id'] ) : 0;

        global $wpdb;
        $table   = $wpdb->prefix . 'bestdid_scan_results';
        $finding = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table WHERE id = %d", $finding_id ) );

        if ( ! $finding ) {
            wp_send_json_error( 'Finding not found' );
        }

        $quarantine = new BDSEC_Quarantine();
        $qid = $quarantine->quarantine_file( $finding->file_path, $finding_id );

        if ( ! $qid ) {
            wp_send_json_error( 'Failed to quarantine file' );
        }

        $scanner = new BDSEC_Scanner_Engine();
        $scanner->mark_quarantined( $finding_id );

        wp_send_json_success( array( 'quarantine_id' => $qid ) );
    }

    public function ajax_restore_file() {
        $this->verify_scanner_nonce();
        $quarantine_id = isset( $_POST['quarantine_id'] ) ? intval( $_POST['quarantine_id'] ) : 0;
        $quarantine    = new BDSEC_Quarantine();
        $ok            = $quarantine->restore_file( $quarantine_id );

        if ( ! $ok ) {
            wp_send_json_error( 'Restore failed' );
        }
        wp_send_json_success( true );
    }

    public function ajax_delete_quarantined() {
        $this->verify_scanner_nonce();
        $quarantine_id = isset( $_POST['quarantine_id'] ) ? intval( $_POST['quarantine_id'] ) : 0;
        $quarantine    = new BDSEC_Quarantine();
        $ok            = $quarantine->delete_quarantined( $quarantine_id );

        if ( ! $ok ) {
            wp_send_json_error( 'Delete failed' );
        }
        wp_send_json_success( true );
    }

    public function ajax_ignore_finding() {
        $this->verify_scanner_nonce();
        $finding_id = isset( $_POST['finding_id'] ) ? intval( $_POST['finding_id'] ) : 0;
        $scanner    = new BDSEC_Scanner_Engine();
        $scanner->ignore_finding( $finding_id );
        wp_send_json_success( true );
    }

    /* ─── Scheduled Scan (Cron) ─────────────────────────────────── */

    /**
     * Start a scheduled background scan.
     */
    public function run_scheduled_scan() {
        $settings = get_option( 'bestdid_security_settings' );
        if ( empty( $settings['scanner_enabled'] ) ) {
            return;
        }

        $scanner = new BDSEC_Scanner_Engine();
        $result  = $scanner->start_scan( array(
            'check_core'    => ! empty( $settings['scanner_check_core'] ),
            'check_malware' => ! empty( $settings['scanner_check_malware'] ),
            'check_uploads' => ! empty( $settings['scanner_check_uploads'] ),
            'check_perms'   => true,
        ) );

        // Process first cron chunk, then chain.
        $this->process_cron_chunk( $result['scan_id'] );
    }

    /**
     * Continue a scheduled scan from where it left off.
     */
    public function run_scheduled_scan_continue() {
        $state = get_transient( 'bdsec_scan_state' );
        if ( ! $state || $state['status'] !== 'running' ) {
            return;
        }
        $this->process_cron_chunk( $state['scan_id'] );
    }

    /**
     * Process a cron-sized chunk and self-chain if not done.
     */
    private function process_cron_chunk( $scan_id ) {
        $scanner = new BDSEC_Scanner_Engine();
        $result  = $scanner->process_chunk( $scan_id, BDSEC_Scanner_Engine::CRON_CHUNK );

        if ( empty( $result['done'] ) ) {
            // Chain another cron event in 30 seconds.
            wp_schedule_single_event( time() + 30, 'bdsec_scheduled_scan_continue' );
            return;
        }

        // Scan finished — handle post-scan actions.
        $settings = get_option( 'bestdid_security_settings' );

        // Auto-quarantine critical threats.
        if ( ! empty( $settings['scanner_auto_quarantine'] ) ) {
            $all = $scanner->get_results( $scan_id );
            $quarantine = new BDSEC_Quarantine();
            foreach ( $all as $finding ) {
                if ( $finding->severity === 'critical' && $finding->status === 'detected' ) {
                    $qid = $quarantine->quarantine_file( $finding->file_path, $finding->id );
                    if ( $qid ) {
                        $scanner->mark_quarantined( $finding->id );
                    }
                }
            }
        }

        // Email alert.
        if ( ! empty( $settings['scanner_email_alerts'] ) && $result['findings'] > 0 ) {
            $admin_email = get_option( 'admin_email' );
            $site_name   = get_bloginfo( 'name' );
            $counts      = $scanner->count_by_severity();
            $subject     = sprintf( '[%s] Malware Scan: %d threats found', $site_name, $result['findings'] );

            $body  = "Scheduled malware scan completed.\n\n";
            $body .= "Files scanned: " . $result['total'] . "\n";
            $body .= "Threats found: " . $result['findings'] . "\n\n";
            $body .= "Critical: " . $counts['critical'] . "\n";
            $body .= "High: " . $counts['high'] . "\n";
            $body .= "Medium: " . $counts['medium'] . "\n";
            $body .= "Low: " . $counts['low'] . "\n\n";
            $body .= "Review results: " . admin_url( 'admin.php?page=bestdid-security-scanner' ) . "\n";

            wp_mail( $admin_email, $subject, $body );
        }
    }

    // ==========================================
    // LICENSE ENFORCEMENT
    // ==========================================

    /**
     * Show a prominent admin notice when the license is not active.
     * All security features are disabled in this state.
     */
    public function license_inactive_notice() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $license_url = admin_url( 'admin.php?page=bdsec-license' );
        ?>
        <div style="display:flex;align-items:flex-start;gap:14px;background:linear-gradient(135deg,#451a03,#78350f);border:1px solid #92400e;border-radius:10px;padding:18px 22px;margin:20px 20px 0 0;color:#fef3c7;">
            <span class="dashicons dashicons-warning" style="font-size:24px;width:24px;height:24px;margin-top:2px;color:#fbbf24;"></span>
            <div>
                <strong style="display:block;font-size:15px;color:#fff;margin-bottom:4px;">BD Security Firewall &mdash; License Required</strong>
                <p style="margin:0;font-size:13px;color:#fde68a;line-height:1.5;">
                    All security features (firewall, WAF, brute force, SQL injection, XSS, rate limiting, security headers) are <strong style="color:#fff;">currently disabled</strong> because no valid license is active.
                    <a href="<?php echo esc_url( $license_url ); ?>" style="color:#fbbf24;text-decoration:underline;">Activate your license</a> |
                    <a href="https://getbdshield.com/shop/" target="_blank" style="color:#fbbf24;text-decoration:underline;">Purchase a license</a>
                </p>
            </div>
        </div>
        <?php
    }
}

// Initialize the firewall
BestDid_Security_Firewall::get_instance();

// BD License Client — auto-updates & license activation.
if ( file_exists( __DIR__ . '/includes/class-bd-license-client.php' ) ) {
    require_once __DIR__ . '/includes/class-bd-license-client.php';
    new BD_License_Client( array(
        'api_url'         => 'https://getbdshield.com',
        'product_slug'    => 'bestdid-security',
        'plugin_basename' => 'bestdid-security/bestdid-security.php',
        'plugin_version'  => defined( 'BESTDID_SECURITY_VERSION' ) ? BESTDID_SECURITY_VERSION : '1.0.0',
        'option_prefix'   => 'bdsec',
        'plugin_name'     => 'BD Security Firewall',
        'menu_parent'     => 'bestdid-security',
        'text_domain'     => 'bestdid-security',
    ) );
}

