<?php
/**
 * TOTP (Time-based One-Time Password) Engine
 *
 * Pure PHP implementation of RFC 6238 TOTP — no external dependencies.
 * Compatible with Google Authenticator, Authy, and other TOTP apps.
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class BDSEC_TOTP {

    /** TOTP time step in seconds. */
    const PERIOD = 30;

    /** Number of digits in the generated code. */
    const DIGITS = 6;

    /** Base32 alphabet (RFC 4648). */
    const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Generate a random 20-byte (160-bit) secret, base32-encoded.
     *
     * @return string 32-character base32 string.
     */
    public static function generate_secret() {
        $bytes = random_bytes( 20 );
        return self::base32_encode( $bytes );
    }

    /**
     * Compute the current TOTP code for a given secret.
     *
     * @param string   $secret Base32-encoded secret.
     * @param int|null $time   Unix timestamp (defaults to now).
     * @return string  Zero-padded 6-digit code.
     */
    public static function get_code( $secret, $time = null ) {
        if ( null === $time ) {
            $time = time();
        }

        $time_counter = floor( $time / self::PERIOD );
        $secret_bytes = self::base32_decode( $secret );

        // Pack counter as 8-byte big-endian.
        $time_bytes = pack( 'N*', 0, $time_counter );

        // HMAC-SHA1.
        $hash = hash_hmac( 'sha1', $time_bytes, $secret_bytes, true );

        // Dynamic truncation (RFC 4226 s5.4).
        $offset = ord( $hash[19] ) & 0x0F;
        $code   = (
            ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 ) |
            ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 ) |
            ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 ) |
            ( ord( $hash[ $offset + 3 ] ) & 0xFF )
        ) % pow( 10, self::DIGITS );

        return str_pad( (string) $code, self::DIGITS, '0', STR_PAD_LEFT );
    }

    /**
     * Verify a user-supplied code against the secret.
     *
     * Checks the current time step plus ±$window steps (default 1 = 90 s tolerance).
     *
     * @param string $secret Base32-encoded secret.
     * @param string $code   User-supplied code.
     * @param int    $window Number of adjacent time steps to check.
     * @return bool
     */
    public static function verify_code( $secret, $code, $window = 1 ) {
        $code = trim( $code );
        if ( strlen( $code ) !== self::DIGITS || ! ctype_digit( $code ) ) {
            return false;
        }

        $now = time();

        for ( $i = -$window; $i <= $window; $i++ ) {
            $check_time = $now + ( $i * self::PERIOD );
            if ( hash_equals( self::get_code( $secret, $check_time ), $code ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Build an otpauth:// provisioning URI for QR code generation.
     *
     * @param string $secret  Base32-encoded secret.
     * @param string $email   User's email (account label).
     * @param string $issuer  Issuer name shown in the authenticator app.
     * @return string
     */
    public static function get_provisioning_uri( $secret, $email, $issuer = 'BD Security' ) {
        return sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d',
            rawurlencode( $issuer ),
            rawurlencode( $email ),
            $secret,
            rawurlencode( $issuer ),
            self::DIGITS,
            self::PERIOD
        );
    }

    // ------------------------------------------------------------------
    // Base32 helpers (RFC 4648)
    // ------------------------------------------------------------------

    /**
     * Encode raw bytes to base32.
     *
     * @param string $data Raw binary string.
     * @return string
     */
    public static function base32_encode( $data ) {
        $binary = '';
        foreach ( str_split( $data ) as $char ) {
            $binary .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
        }

        $encoded = '';
        $chunks  = str_split( $binary, 5 );
        foreach ( $chunks as $chunk ) {
            $chunk    = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
            $encoded .= self::BASE32_CHARS[ bindec( $chunk ) ];
        }

        return $encoded;
    }

    /**
     * Decode a base32 string to raw bytes.
     *
     * @param string $data Base32-encoded string.
     * @return string Raw binary string.
     */
    public static function base32_decode( $data ) {
        $data   = strtoupper( trim( $data ) );
        $binary = '';

        for ( $i = 0, $len = strlen( $data ); $i < $len; $i++ ) {
            $pos = strpos( self::BASE32_CHARS, $data[ $i ] );
            if ( false === $pos ) {
                continue; // skip invalid chars / padding
            }
            $binary .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
        }

        $bytes = '';
        $octets = str_split( $binary, 8 );
        foreach ( $octets as $octet ) {
            if ( strlen( $octet ) === 8 ) {
                $bytes .= chr( bindec( $octet ) );
            }
        }

        return $bytes;
    }
}
