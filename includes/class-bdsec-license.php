<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * License gate helper for BD Security Firewall.
 *
 * Reads the options written by BD_License_Client (option_prefix = 'bdsec')
 * and provides a simple static API to check whether the licence is active.
 *
 * Option keys (set by BD_License_Client):
 *   bdsec_license_key    – the raw license key
 *   bdsec_license_status – 'active' | 'inactive' | 'expired' | 'invalid'
 *   bdsec_license_data   – array returned by license server
 *
 * @package BestDid_Security
 */
class BDSEC_License {

    /** @var string Transient key for caching a periodic remote re-validation. */
    const CACHE_KEY = 'bdsec_license_valid';

    /** @var int How long to trust the cached result (24 hours). */
    const CACHE_TTL = DAY_IN_SECONDS;

    /** @var bool|null Per-request static cache to avoid multiple checks. */
    private static $is_active_cache = null;

    /**
     * Check whether this site has a valid, active license.
     *
     * Fast path: if the stored status is 'active' AND the transient cache
     * says it was recently validated, return true immediately (no HTTP).
     *
     * Slow path (at most once per CACHE_TTL): re-validate via the license
     * server so expired / revoked keys get caught.
     *
     * @return bool
     */
    public static function is_active() {
        if ( null !== self::$is_active_cache ) {
            return self::$is_active_cache;
        }

        $key = get_option( 'bdsec_license_key', '' );
        if ( empty( $key ) ) {
            self::$is_active_cache = false;
            return false;
        }

        $status = get_option( 'bdsec_license_status', 'inactive' );
        if ( 'active' !== $status ) {
            self::$is_active_cache = false;
            return false;
        }

        // Fast path – recently validated.
        $cached = get_transient( self::CACHE_KEY );
        if ( $cached ) {
            self::$is_active_cache = true;
            return true;
        }

        // Slow path – ask the server (non-blocking on failure).
        $valid = self::remote_validate( $key );

        if ( $valid ) {
            set_transient( self::CACHE_KEY, 1, self::CACHE_TTL );
        } else {
            // Cache failure for 1 hour to avoid hammering the server.
            set_transient( self::CACHE_KEY, 0, HOUR_IN_SECONDS );
        }

        self::$is_active_cache = $valid;
        return $valid;
    }

    /**
     * Lightweight remote validation via BD_License_Client's API endpoint.
     *
     * @param  string $key License key.
     * @return bool   True when the server confirms the license is valid.
     */
    private static function remote_validate( $key ) {
        $url = 'https://getbdshield.com/wp-json/bdls/v1/validate';

        $response = wp_remote_post( $url, array(
            'timeout'   => 5,
            'sslverify' => true,
            'body'      => array(
                'license_key'  => sanitize_text_field( $key ),
                'site_url'     => home_url(),
                'action'       => 'check',
                'product_slug' => 'bestdid-security',
            ),
        ) );

        if ( is_wp_error( $response ) ) {
            // Network failure – trust the locally stored 'active' status
            // to avoid disabling security when the license server is unreachable.
            set_transient( self::CACHE_KEY, 1, HOUR_IN_SECONDS );
            return true;
        }

        $code = wp_remote_retrieve_response_code( $response );
        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        // Server error (500, 502, etc.) — trust local status, cache for 1 hour.
        if ( $code >= 500 ) {
            set_transient( self::CACHE_KEY, 1, HOUR_IN_SECONDS );
            return true;
        }

        return is_array( $body ) && ! empty( $body['valid'] );
    }
}
