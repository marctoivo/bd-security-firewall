<?php
/**
 * Scanner Engine — chunked AJAX file scanner (shared-hosting compatible).
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class BDSEC_Scanner_Engine {

    const CHUNK_SIZE    = 50;
    const MAX_FILE_SIZE = 2097152; // 2 MB
    const CRON_CHUNK    = 200;

    /** @var string DB table (no prefix). */
    private $table = 'bestdid_scan_results';

    /** @var BDSEC_Quarantine */
    private $quarantine;

    public function __construct() {
        $this->quarantine = new BDSEC_Quarantine();
    }

    /* ================================================================
     *  START SCAN — collect file list, store as transient
     * ================================================================ */

    /**
     * Initialize a new scan.
     *
     * @param  array $options  Which checks to enable.
     * @return array { scan_id, total_files }
     */
    public function start_scan( $options = array() ) {
        $scan_id = substr( md5( uniqid( wp_rand(), true ) ), 0, 16 );

        $files = $this->collect_files();

        $state = array(
            'scan_id'     => $scan_id,
            'files'       => $files,
            'total'       => count( $files ),
            'processed'   => 0,
            'findings'    => 0,
            'options'     => wp_parse_args( $options, array(
                'check_core'      => true,
                'check_malware'   => true,
                'check_uploads'   => true,
                'check_perms'     => true,
            ) ),
            'started_at'  => current_time( 'mysql' ),
            'status'      => 'running',
        );

        set_transient( 'bdsec_scan_state', $state, HOUR_IN_SECONDS );

        return array(
            'scan_id'     => $scan_id,
            'total_files' => $state['total'],
        );
    }

    /* ================================================================
     *  PROCESS CHUNK — scan the next N files
     * ================================================================ */

    /**
     * Process the next chunk of files.
     *
     * @param  string $scan_id
     * @param  int    $chunk_size  Override chunk size (cron uses larger).
     * @return array  { done, processed, total, findings, current_file }
     */
    public function process_chunk( $scan_id, $chunk_size = 0 ) {
        $state = get_transient( 'bdsec_scan_state' );

        if ( ! $state || $state['scan_id'] !== $scan_id || $state['status'] !== 'running' ) {
            return array( 'done' => true, 'error' => 'Invalid or expired scan.' );
        }

        if ( $chunk_size <= 0 ) {
            $chunk_size = self::CHUNK_SIZE;
        }

        $offset = $state['processed'];
        $chunk  = array_slice( $state['files'], $offset, $chunk_size );

        if ( empty( $chunk ) ) {
            return $this->finish_scan( $state );
        }

        $new_findings  = 0;
        $current_file  = '';
        $checksums     = null;
        $options       = $state['options'];

        // Lazy-load WP core checksums.
        if ( ! empty( $options['check_core'] ) ) {
            $checksums = $this->get_core_checksums();
        }

        $signatures = array();
        if ( ! empty( $options['check_malware'] ) ) {
            $signatures = BDSEC_Malware_Signatures::get_signatures();
        }

        foreach ( $chunk as $file ) {
            $current_file = $file;

            // ── Core integrity check ───────────────────────────
            if ( $checksums && ! empty( $options['check_core'] ) ) {
                $relative = $this->relative_path( $file );
                if ( isset( $checksums[ $relative ] ) ) {
                    $actual = md5_file( $file );
                    if ( $actual !== $checksums[ $relative ] ) {
                        $this->save_finding( $scan_id, $file, 'core_modified', 'high',
                            'Core file checksum mismatch', '', $actual );
                        $new_findings++;
                    }
                }
            }

            // ── Malware pattern scan ───────────────────────────
            if ( ! empty( $options['check_malware'] ) && $this->is_scannable( $file ) ) {
                $content = $this->read_file_safe( $file );
                if ( $content !== false ) {
                    foreach ( $signatures as $sig ) {
                        if ( @preg_match( $sig['pattern'], $content ) ) {
                            $this->save_finding( $scan_id, $file, 'malware_pattern',
                                $sig['severity'], 'Matched: ' . $sig['name'], $sig['name'] );
                            $new_findings++;
                            break; // one hit per file per chunk is enough
                        }
                    }
                }
            }

            // ── Suspicious location: PHP in uploads ────────────
            if ( ! empty( $options['check_uploads'] ) ) {
                $upload_dir = wp_upload_dir();
                $uploads    = realpath( $upload_dir['basedir'] );
                $real_file  = realpath( $file );

                if ( $uploads && $real_file && 0 === strpos( $real_file, $uploads ) ) {
                    $ext = strtolower( pathinfo( $file, PATHINFO_EXTENSION ) );
                    if ( in_array( $ext, array( 'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar' ), true ) ) {
                        $this->save_finding( $scan_id, $file, 'suspicious_location', 'critical',
                            'PHP file inside uploads directory', 'php_in_uploads' );
                        $new_findings++;
                    }
                }

                // Double extension: file.php.jpg etc.
                if ( preg_match( '/\.(php|phtml|phar)\.[a-z]{2,4}$/i', $file ) ) {
                    $this->save_finding( $scan_id, $file, 'suspicious_location', 'high',
                        'Double extension detected', 'double_extension' );
                    $new_findings++;
                }
            }

            // ── PHP in non-PHP extensions ──────────────────────
            if ( ! empty( $options['check_malware'] ) ) {
                $ext = strtolower( pathinfo( $file, PATHINFO_EXTENSION ) );
                $suspicious_exts = BDSEC_Malware_Signatures::get_suspicious_extensions();
                if ( in_array( $ext, $suspicious_exts, true ) && filesize( $file ) < self::MAX_FILE_SIZE ) {
                    $content = isset( $content ) ? $content : $this->read_file_safe( $file );
                    if ( $content !== false && preg_match( '/<\?php/i', $content ) ) {
                        $this->save_finding( $scan_id, $file, 'malware_pattern', 'high',
                            'PHP code inside .' . $ext . ' file', 'php_in_non_php' );
                        $new_findings++;
                    }
                }
                unset( $content ); // Free memory.
            }

            // ── Bad permissions ─────────────────────────────────
            if ( ! empty( $options['check_perms'] ) && function_exists( 'fileperms' ) ) {
                $perms = @fileperms( $file );
                if ( false !== $perms && ( $perms & 0x0002 ) ) { // world-writable
                    $this->save_finding( $scan_id, $file, 'bad_permissions', 'medium',
                        'World-writable file: ' . substr( sprintf( '%o', $perms ), -4 ), 'world_writable' );
                    $new_findings++;
                }
            }
        }

        // Update state.
        $state['processed'] += count( $chunk );
        $state['findings']  += $new_findings;
        set_transient( 'bdsec_scan_state', $state, HOUR_IN_SECONDS );

        $done = $state['processed'] >= $state['total'];
        if ( $done ) {
            return $this->finish_scan( $state );
        }

        return array(
            'done'         => false,
            'processed'    => $state['processed'],
            'total'        => $state['total'],
            'findings'     => $state['findings'],
            'current_file' => $this->relative_path( $current_file ),
        );
    }

    /* ================================================================
     *  CANCEL SCAN
     * ================================================================ */

    public function cancel_scan() {
        delete_transient( 'bdsec_scan_state' );
        return true;
    }

    /* ================================================================
     *  GET CURRENT STATE
     * ================================================================ */

    public function get_scan_state() {
        $state = get_transient( 'bdsec_scan_state' );
        if ( ! $state ) {
            return array( 'status' => 'idle' );
        }
        return array(
            'status'    => $state['status'],
            'scan_id'   => $state['scan_id'],
            'processed' => $state['processed'],
            'total'     => $state['total'],
            'findings'  => $state['findings'],
        );
    }

    /* ================================================================
     *  INTERNAL HELPERS
     * ================================================================ */

    /**
     * Finish a scan: save summary, delete transient.
     */
    private function finish_scan( $state ) {
        $summary = array(
            'scan_id'    => $state['scan_id'],
            'total'      => $state['total'],
            'findings'   => $state['findings'],
            'started_at' => $state['started_at'],
            'finished_at'=> current_time( 'mysql' ),
        );

        update_option( 'bdsec_last_scan', $summary );
        delete_transient( 'bdsec_scan_state' );

        return array(
            'done'      => true,
            'processed' => $state['total'],
            'total'     => $state['total'],
            'findings'  => $state['findings'],
        );
    }

    /**
     * Collect all file paths under ABSPATH, skipping excluded directories.
     *
     * @return array  List of absolute file paths.
     */
    private function collect_files() {
        $skip_paths = BDSEC_Malware_Signatures::get_skip_paths();
        $files      = array();

        $iterator = new RecursiveDirectoryIterator(
            ABSPATH,
            RecursiveDirectoryIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS
        );

        $recursive = new RecursiveIteratorIterator( $iterator, RecursiveIteratorIterator::SELF_FIRST );

        foreach ( $recursive as $item ) {
            if ( $item->isDir() ) {
                continue;
            }

            $path     = $item->getPathname();
            $relative = $this->relative_path( $path );

            // Skip excluded directories.
            $skip = false;
            foreach ( $skip_paths as $sp ) {
                if ( 0 === strpos( $relative, $sp ) ) {
                    $skip = true;
                    break;
                }
            }
            if ( $skip ) {
                continue;
            }

            $files[] = $path;
        }

        return $files;
    }

    /**
     * Determine whether a file should have its content scanned.
     */
    private function is_scannable( $file ) {
        if ( ! is_file( $file ) || ! is_readable( $file ) ) {
            return false;
        }

        $ext = strtolower( pathinfo( $file, PATHINFO_EXTENSION ) );
        $scannable = array( 'php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar', 'inc', 'module' );

        if ( ! in_array( $ext, $scannable, true ) ) {
            return false;
        }

        if ( filesize( $file ) > self::MAX_FILE_SIZE ) {
            return false;
        }

        return true;
    }

    /**
     * Read file content safely (limited size).
     */
    private function read_file_safe( $file ) {
        if ( ! is_readable( $file ) ) {
            return false;
        }
        $size = filesize( $file );
        if ( $size > self::MAX_FILE_SIZE ) {
            return false;
        }
        return @file_get_contents( $file, false, null, 0, self::MAX_FILE_SIZE );
    }

    /**
     * Get WP core checksums from api.wordpress.org (cached 24 h).
     *
     * @return array|false  Relative-path → md5 hash.
     */
    private function get_core_checksums() {
        $cached = get_transient( 'bdsec_core_checksums' );
        if ( is_array( $cached ) ) {
            return $cached;
        }

        global $wp_version;
        $locale = get_locale();

        $url = add_query_arg( array(
            'version' => $wp_version,
            'locale'  => $locale,
        ), 'https://api.wordpress.org/core/checksums/1.0/' );

        $response = wp_remote_get( $url, array( 'timeout' => 15 ) );

        if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
            return false;
        }

        $body = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( empty( $body['checksums'] ) || ! is_array( $body['checksums'] ) ) {
            return false;
        }

        $checksums = $body['checksums'];
        set_transient( 'bdsec_core_checksums', $checksums, DAY_IN_SECONDS );

        return $checksums;
    }

    /**
     * Save a finding to the database.
     */
    private function save_finding( $scan_id, $file, $threat_type, $severity, $details, $signature = '', $hash = '' ) {
        global $wpdb;
        $table = $wpdb->prefix . $this->table;

        // Don't duplicate — same scan, same file, same threat type.
        $exists = $wpdb->get_var( $wpdb->prepare(
            "SELECT id FROM $table WHERE scan_id = %s AND file_path = %s AND threat_type = %s",
            $scan_id, $file, $threat_type
        ) );
        if ( $exists ) {
            return;
        }

        $file_hash = $hash ?: ( is_file( $file ) ? md5_file( $file ) : '' );
        $file_size = is_file( $file ) ? filesize( $file ) : 0;
        $file_mod  = is_file( $file ) ? gmdate( 'Y-m-d H:i:s', filemtime( $file ) ) : null;

        $wpdb->insert( $table, array(
            'scan_id'          => $scan_id,
            'file_path'        => $file,
            'file_hash'        => $file_hash,
            'threat_type'      => $threat_type,
            'severity'         => $severity,
            'details'          => $details,
            'matched_signature'=> $signature,
            'file_size'        => $file_size,
            'file_modified'    => $file_mod,
            'status'           => 'detected',
            'created_at'       => current_time( 'mysql' ),
        ) );
    }

    /**
     * Convert absolute path to ABSPATH-relative.
     */
    private function relative_path( $path ) {
        $path = wp_normalize_path( $path );
        $base = wp_normalize_path( ABSPATH );
        if ( 0 === strpos( $path, $base ) ) {
            return substr( $path, strlen( $base ) );
        }
        return $path;
    }

    /* ================================================================
     *  QUERY HELPERS (used by AJAX handlers in main plugin file)
     * ================================================================ */

    /**
     * Get scan results for a given scan_id or the latest scan.
     */
    public function get_results( $scan_id = '' ) {
        global $wpdb;
        $table = $wpdb->prefix . $this->table;

        if ( empty( $scan_id ) ) {
            $last = get_option( 'bdsec_last_scan' );
            if ( ! $last ) {
                return array();
            }
            $scan_id = $last['scan_id'];
        }

        return $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM $table WHERE scan_id = %s AND status != 'ignored' ORDER BY FIELD(severity,'critical','high','medium','low'), created_at DESC",
            $scan_id
        ) );
    }

    /**
     * Get all results including ignored.
     */
    public function get_all_results( $scan_id = '' ) {
        global $wpdb;
        $table = $wpdb->prefix . $this->table;

        if ( empty( $scan_id ) ) {
            $last = get_option( 'bdsec_last_scan' );
            if ( ! $last ) {
                return array();
            }
            $scan_id = $last['scan_id'];
        }

        return $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM $table WHERE scan_id = %s ORDER BY FIELD(severity,'critical','high','medium','low'), created_at DESC",
            $scan_id
        ) );
    }

    /**
     * Mark a finding as ignored.
     */
    public function ignore_finding( $finding_id ) {
        global $wpdb;
        $table = $wpdb->prefix . $this->table;

        return $wpdb->update( $table,
            array( 'status' => 'ignored' ),
            array( 'id' => $finding_id ),
            array( '%s' ),
            array( '%d' )
        );
    }

    /**
     * Mark a finding as quarantined.
     */
    public function mark_quarantined( $finding_id ) {
        global $wpdb;
        $table = $wpdb->prefix . $this->table;

        return $wpdb->update( $table,
            array( 'status' => 'quarantined' ),
            array( 'id' => $finding_id ),
            array( '%s' ),
            array( '%d' )
        );
    }

    /**
     * Count findings by severity for the last scan.
     */
    public function count_by_severity() {
        global $wpdb;
        $table = $wpdb->prefix . $this->table;

        $last = get_option( 'bdsec_last_scan' );
        if ( ! $last ) {
            return array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0 );
        }

        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT severity, COUNT(*) as cnt FROM $table WHERE scan_id = %s AND status = 'detected' GROUP BY severity",
            $last['scan_id']
        ) );

        $counts = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0 );
        foreach ( $rows as $r ) {
            $counts[ $r->severity ] = (int) $r->cnt;
        }

        return $counts;
    }
}
