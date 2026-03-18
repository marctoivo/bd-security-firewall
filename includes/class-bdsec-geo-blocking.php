<?php
/**
 * Geo-Blocking — Country-based IP blocking using ip-api.com.
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class BDSEC_Geo_Blocking {

    /** Cache TTL in seconds (24 hours). */
    const CACHE_TTL = 86400;

    /**
     * Resolve country for an IP address (DB cache → ip-api.com).
     *
     * @param string $ip
     * @return array|false  { country_code, country_name } or false on failure.
     */
    public static function resolve_country( $ip ) {
        global $wpdb;

        $cache_table = $wpdb->prefix . 'bestdid_geo_cache';

        // 1. Check DB cache.
        $cached = $wpdb->get_row( $wpdb->prepare(
            "SELECT country_code, country_name FROM {$cache_table}
             WHERE ip_address = %s AND resolved_at > %s LIMIT 1",
            $ip,
            gmdate( 'Y-m-d H:i:s', time() - self::CACHE_TTL )
        ), ARRAY_A );

        if ( $cached ) {
            return $cached;
        }

        // 2. Query ip-api.com (free tier — http only, 45 req/min).
        $response = wp_remote_get( "http://ip-api.com/json/{$ip}?fields=status,countryCode,country", array(
            'timeout' => 5,
        ) );

        if ( is_wp_error( $response ) ) {
            return false;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $body ) || $body['status'] !== 'success' ) {
            return false;
        }

        $result = array(
            'country_code' => sanitize_text_field( $body['countryCode'] ),
            'country_name' => sanitize_text_field( $body['country'] ),
        );

        // 3. Upsert cache.
        $wpdb->replace( $cache_table, array(
            'ip_address'   => $ip,
            'country_code' => $result['country_code'],
            'country_name' => $result['country_name'],
            'resolved_at'  => current_time( 'mysql', true ),
        ) );

        return $result;
    }

    /**
     * Check whether an IP should be blocked.
     *
     * @param string $ip
     * @return bool  True if the IP should be blocked.
     */
    public static function is_blocked( $ip ) {
        $settings = get_option( 'bestdid_security_settings' );

        $mode = $settings['geo_mode'] ?? 'disabled';
        if ( $mode === 'disabled' ) {
            return false;
        }

        // Bypass for whitelisted IPs.
        $whitelist = array_filter( array_map( 'trim', explode( "\n", $settings['whitelisted_ips'] ?? '' ) ) );
        if ( in_array( $ip, $whitelist, true ) ) {
            return false;
        }

        // Bypass for logged-in admins.
        if ( ! empty( $settings['whitelist_admins'] ) && current_user_can( 'manage_options' ) ) {
            return false;
        }

        $country = self::resolve_country( $ip );
        if ( ! $country ) {
            return false; // Can't resolve — allow.
        }

        $countries = array_filter( array_map( 'trim', explode( ',', $settings['geo_countries'] ?? '' ) ) );
        if ( empty( $countries ) ) {
            return false;
        }

        $code = strtoupper( $country['country_code'] );

        if ( $mode === 'blacklist' ) {
            return in_array( $code, $countries, true );
        }

        // Whitelist mode — block if NOT in the list.
        if ( $mode === 'whitelist' ) {
            return ! in_array( $code, $countries, true );
        }

        return false;
    }

    /**
     * Run the geo-block check (hooked to `init` priority 1).
     */
    public static function check_request() {
        $settings = get_option( 'bestdid_security_settings' );
        if ( empty( $settings['geo_blocking_enabled'] ) || ( $settings['geo_mode'] ?? 'disabled' ) === 'disabled' ) {
            return;
        }

        $ip = self::get_client_ip();
        if ( ! $ip ) {
            return;
        }

        if ( ! self::is_blocked( $ip ) ) {
            return;
        }

        // Log the block.
        if ( ! empty( $settings['geo_log_blocked'] ) ) {
            self::log_request( $ip, 'blocked' );
        }

        // Return 403.
        status_header( 403 );
        nocache_headers();
        wp_die(
            '<h1>403 Forbidden</h1><p>Access from your country is not permitted.</p>',
            'Access Denied',
            array( 'response' => 403 )
        );
    }

    /**
     * Log a geo-blocking event.
     */
    public static function log_request( $ip, $action ) {
        global $wpdb;

        $country = self::resolve_country( $ip );

        $wpdb->insert( $wpdb->prefix . 'bestdid_geo_log', array(
            'ip_address'   => $ip,
            'country_code' => $country ? $country['country_code'] : '',
            'country_name' => $country ? $country['country_name'] : '',
            'action'       => $action,
            'request_uri'  => isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
            'created_at'   => current_time( 'mysql', true ),
        ) );
    }

    /**
     * Get aggregated country stats from the geo log.
     *
     * @return array
     */
    public static function get_country_stats() {
        global $wpdb;

        $table = $wpdb->prefix . 'bestdid_geo_log';

        return $wpdb->get_results(
            "SELECT country_code, country_name, COUNT(*) as total
             FROM {$table}
             WHERE action = 'blocked'
             GROUP BY country_code
             ORDER BY total DESC
             LIMIT 20",
            ARRAY_A
        );
    }

    /**
     * Get blocked-today count.
     */
    public static function get_blocked_today() {
        global $wpdb;
        $table = $wpdb->prefix . 'bestdid_geo_log';

        return (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM {$table} WHERE action = 'blocked' AND DATE(created_at) = CURDATE()"
        );
    }

    /**
     * Get client IP.
     */
    public static function get_client_ip() {
        $headers = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR' );
        foreach ( $headers as $header ) {
            if ( ! empty( $_SERVER[ $header ] ) ) {
                $ip = trim( explode( ',', $_SERVER[ $header ] )[0] );
                if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
                    return $ip;
                }
            }
        }
        return isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';
    }

    /**
     * Test an IP: resolve country + check blocked status.
     *
     * @param string $ip
     * @return array
     */
    public static function test_ip( $ip ) {
        $country = self::resolve_country( $ip );
        $blocked = self::is_blocked( $ip );

        return array(
            'ip'           => $ip,
            'country_code' => $country ? $country['country_code'] : 'N/A',
            'country_name' => $country ? $country['country_name'] : 'Unknown',
            'blocked'      => $blocked,
        );
    }
}
