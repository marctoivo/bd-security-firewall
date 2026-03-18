<?php
/**
 * File Integrity Monitor — Baseline hashing and change detection.
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class BDSEC_File_Integrity {

    /** Files processed per AJAX chunk. */
    const CHUNK_SIZE = 200;

    /**
     * Collect all files that should be monitored.
     *
     * Scoped to: wp-includes/, wp-admin/, active theme, active plugins.
     * Skips: uploads, cache, backups.
     *
     * @return array  List of absolute file paths.
     */
    public static function collect_files() {
        $dirs = array(
            ABSPATH . 'wp-includes',
            ABSPATH . 'wp-admin',
            get_template_directory(),
            WP_PLUGIN_DIR,
        );

        // If child theme, add parent too.
        if ( get_template_directory() !== get_stylesheet_directory() ) {
            $dirs[] = get_stylesheet_directory();
        }

        $extensions = array( 'php', 'js', 'css' );
        $skip_dirs  = array( 'uploads', 'cache', 'backups', 'backups-bdbk', 'upgrade', 'wflogs' );
        $files      = array();

        foreach ( $dirs as $dir ) {
            if ( ! is_dir( $dir ) ) {
                continue;
            }
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator( $dir, RecursiveDirectoryIterator::SKIP_DOTS ),
                RecursiveIteratorIterator::SELF_FIRST
            );

            foreach ( $iterator as $file ) {
                if ( ! $file->isFile() ) {
                    continue;
                }

                $path = $file->getPathname();

                // Skip excluded directories.
                $skip = false;
                foreach ( $skip_dirs as $sd ) {
                    if ( strpos( $path, DIRECTORY_SEPARATOR . $sd . DIRECTORY_SEPARATOR ) !== false ) {
                        $skip = true;
                        break;
                    }
                }
                if ( $skip ) {
                    continue;
                }

                $ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
                if ( in_array( $ext, $extensions, true ) ) {
                    $files[] = wp_normalize_path( $path );
                }
            }
        }

        // Critical configuration files — these have no extension or non-standard
        // extensions, so they must be added explicitly rather than via the loop.
        $critical_configs = array(
            ABSPATH . '.htaccess',
            ABSPATH . 'wp-config.php',
            ABSPATH . '.user.ini',
            ABSPATH . 'php.ini',
            get_template_directory() . '/.htaccess',
            WP_CONTENT_DIR . '/.htaccess',
        );

        foreach ( $critical_configs as $config_path ) {
            $normalized = wp_normalize_path( $config_path );
            if ( file_exists( $config_path ) && ! in_array( $normalized, $files, true ) ) {
                $files[] = $normalized;
            }
        }

        return $files;
    }

    /**
     * Start baseline creation — store file list in transient, return total.
     *
     * @return array { total: int }
     */
    public static function start_baseline() {
        $files = self::collect_files();
        set_transient( 'bdsec_fim_files', $files, HOUR_IN_SECONDS );
        set_transient( 'bdsec_fim_offset', 0, HOUR_IN_SECONDS );

        return array( 'total' => count( $files ) );
    }

    /**
     * Process a chunk of baseline creation.
     *
     * @return array { processed, total, done }
     */
    public static function process_baseline_chunk() {
        global $wpdb;

        $table  = $wpdb->prefix . 'bestdid_file_baselines';
        $files  = get_transient( 'bdsec_fim_files' );
        $offset = (int) get_transient( 'bdsec_fim_offset' );

        if ( ! $files ) {
            return array( 'processed' => 0, 'total' => 0, 'done' => true );
        }

        $total = count( $files );
        $chunk = array_slice( $files, $offset, self::CHUNK_SIZE );
        $now   = current_time( 'mysql', true );

        foreach ( $chunk as $filepath ) {
            if ( ! file_exists( $filepath ) ) {
                continue;
            }

            $hash     = hash_file( 'sha256', $filepath );
            $size     = filesize( $filepath );
            $modified = gmdate( 'Y-m-d H:i:s', filemtime( $filepath ) );
            $rel_path = self::relative_path( $filepath );

            // Upsert.
            $existing = $wpdb->get_var( $wpdb->prepare(
                "SELECT id FROM {$table} WHERE file_path = %s LIMIT 1",
                $rel_path
            ) );

            if ( $existing ) {
                $wpdb->update( $table, array(
                    'file_hash'        => $hash,
                    'file_size'        => $size,
                    'file_modified'    => $modified,
                    'baseline_created' => $now,
                    'last_checked'     => $now,
                    'status'           => 'ok',
                ), array( 'id' => $existing ) );
            } else {
                $wpdb->insert( $table, array(
                    'file_path'        => $rel_path,
                    'file_hash'        => $hash,
                    'file_size'        => $size,
                    'file_modified'    => $modified,
                    'baseline_created' => $now,
                    'last_checked'     => $now,
                    'status'           => 'ok',
                ) );
            }
        }

        $new_offset = $offset + self::CHUNK_SIZE;
        $done       = $new_offset >= $total;

        if ( $done ) {
            // Mark files no longer present as deleted.
            $wpdb->query( $wpdb->prepare(
                "UPDATE {$table} SET status = 'deleted', last_checked = %s WHERE baseline_created < %s",
                $now, $now
            ) );

            delete_transient( 'bdsec_fim_files' );
            delete_transient( 'bdsec_fim_offset' );
            update_option( 'bdsec_fim_baseline_info', array(
                'created_at' => $now,
                'file_count' => $total,
            ) );
        } else {
            set_transient( 'bdsec_fim_offset', $new_offset, HOUR_IN_SECONDS );
        }

        return array(
            'processed' => min( $new_offset, $total ),
            'total'     => $total,
            'done'      => $done,
        );
    }

    /**
     * Start integrity check — collect files and return total.
     *
     * @return array { total }
     */
    public static function start_check() {
        $files = self::collect_files();
        set_transient( 'bdsec_fim_check_files', $files, HOUR_IN_SECONDS );
        set_transient( 'bdsec_fim_check_offset', 0, HOUR_IN_SECONDS );
        // Reset results.
        delete_transient( 'bdsec_fim_check_results' );

        return array( 'total' => count( $files ) );
    }

    /**
     * Process a chunk of the integrity check.
     *
     * @return array { processed, total, done, results: { modified, added, deleted } }
     */
    public static function process_check_chunk() {
        global $wpdb;

        $table  = $wpdb->prefix . 'bestdid_file_baselines';
        $files  = get_transient( 'bdsec_fim_check_files' );
        $offset = (int) get_transient( 'bdsec_fim_check_offset' );

        if ( ! $files ) {
            return array( 'processed' => 0, 'total' => 0, 'done' => true, 'results' => array() );
        }

        $total   = count( $files );
        $chunk   = array_slice( $files, $offset, self::CHUNK_SIZE );
        $now     = current_time( 'mysql', true );
        $results = get_transient( 'bdsec_fim_check_results' ) ?: array( 'modified' => 0, 'added' => 0, 'deleted' => 0 );

        $checked_paths = array();

        foreach ( $chunk as $filepath ) {
            $rel_path = self::relative_path( $filepath );
            $checked_paths[] = $rel_path;

            if ( ! file_exists( $filepath ) ) {
                continue;
            }

            $hash = hash_file( 'sha256', $filepath );

            $baseline = $wpdb->get_row( $wpdb->prepare(
                "SELECT id, file_hash FROM {$table} WHERE file_path = %s LIMIT 1",
                $rel_path
            ) );

            if ( $baseline ) {
                if ( $baseline->file_hash !== $hash ) {
                    $wpdb->update( $table, array(
                        'status'       => 'modified',
                        'last_checked' => $now,
                    ), array( 'id' => $baseline->id ) );
                    $results['modified']++;
                } else {
                    $wpdb->update( $table, array(
                        'status'       => 'ok',
                        'last_checked' => $now,
                    ), array( 'id' => $baseline->id ) );
                }
            } else {
                // New file — not in baseline.
                $wpdb->insert( $table, array(
                    'file_path'        => $rel_path,
                    'file_hash'        => $hash,
                    'file_size'        => filesize( $filepath ),
                    'file_modified'    => gmdate( 'Y-m-d H:i:s', filemtime( $filepath ) ),
                    'baseline_created' => $now,
                    'last_checked'     => $now,
                    'status'           => 'new',
                ) );
                $results['added']++;
            }
        }

        $new_offset = $offset + self::CHUNK_SIZE;
        $done       = $new_offset >= $total;

        if ( $done ) {
            // Mark files in baseline that weren't found as deleted.
            $deleted = (int) $wpdb->get_var( $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table} WHERE last_checked < %s AND status != 'deleted'",
                $now
            ) );
            if ( $deleted > 0 ) {
                $wpdb->query( $wpdb->prepare(
                    "UPDATE {$table} SET status = 'deleted', last_checked = %s WHERE last_checked < %s AND status != 'deleted'",
                    $now, $now
                ) );
            }
            $results['deleted'] = $deleted;

            delete_transient( 'bdsec_fim_check_files' );
            delete_transient( 'bdsec_fim_check_offset' );
            delete_transient( 'bdsec_fim_check_results' );

            update_option( 'bdsec_fim_last_check', array(
                'checked_at' => $now,
                'modified'   => $results['modified'],
                'added'      => $results['added'],
                'deleted'    => $results['deleted'],
            ) );
        } else {
            set_transient( 'bdsec_fim_check_offset', $new_offset, HOUR_IN_SECONDS );
            set_transient( 'bdsec_fim_check_results', $results, HOUR_IN_SECONDS );
        }

        return array(
            'processed' => min( $new_offset, $total ),
            'total'     => $total,
            'done'      => $done,
            'results'   => $results,
        );
    }

    /**
     * Accept a changed file — update its baseline hash to current.
     *
     * @param int $id  Baseline row ID.
     * @return bool
     */
    public static function accept_change( $id ) {
        global $wpdb;

        $table = $wpdb->prefix . 'bestdid_file_baselines';
        $row   = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d", $id ) );

        if ( ! $row ) {
            return false;
        }

        $abs_path = self::absolute_path( $row->file_path );

        if ( $row->status === 'deleted' ) {
            $wpdb->delete( $table, array( 'id' => $id ) );
            return true;
        }

        if ( ! file_exists( $abs_path ) ) {
            return false;
        }

        $wpdb->update( $table, array(
            'file_hash'        => hash_file( 'sha256', $abs_path ),
            'file_size'        => filesize( $abs_path ),
            'file_modified'    => gmdate( 'Y-m-d H:i:s', filemtime( $abs_path ) ),
            'baseline_created' => current_time( 'mysql', true ),
            'status'           => 'ok',
        ), array( 'id' => $id ) );

        return true;
    }

    /**
     * Accept ALL changes — update modified/new to current hash, remove deleted.
     */
    public static function accept_all_changes() {
        global $wpdb;

        $table = $wpdb->prefix . 'bestdid_file_baselines';
        $now   = current_time( 'mysql', true );

        // Remove deleted entries.
        $wpdb->query( "DELETE FROM {$table} WHERE status = 'deleted'" );

        // Update modified and new files to current hashes.
        $changed = $wpdb->get_results(
            "SELECT id, file_path FROM {$table} WHERE status IN ('modified', 'new')",
            ARRAY_A
        );

        foreach ( $changed as $row ) {
            $abs_path = self::absolute_path( $row['file_path'] );
            if ( ! file_exists( $abs_path ) ) {
                $wpdb->delete( $table, array( 'id' => $row['id'] ) );
                continue;
            }

            $wpdb->update( $table, array(
                'file_hash'        => hash_file( 'sha256', $abs_path ),
                'file_size'        => filesize( $abs_path ),
                'file_modified'    => gmdate( 'Y-m-d H:i:s', filemtime( $abs_path ) ),
                'baseline_created' => $now,
                'status'           => 'ok',
            ), array( 'id' => $row['id'] ) );
        }
    }

    /**
     * Get summary stats from baselines table.
     *
     * @return array { total, ok, modified, new, deleted }
     */
    public static function get_stats() {
        global $wpdb;
        $table = $wpdb->prefix . 'bestdid_file_baselines';

        $rows = $wpdb->get_results(
            "SELECT status, COUNT(*) as cnt FROM {$table} GROUP BY status",
            ARRAY_A
        );

        $stats = array( 'total' => 0, 'ok' => 0, 'modified' => 0, 'new' => 0, 'deleted' => 0 );
        foreach ( $rows as $r ) {
            $stats[ $r['status'] ] = (int) $r['cnt'];
            $stats['total']       += (int) $r['cnt'];
        }

        return $stats;
    }

    /**
     * Get changed files (modified/new/deleted).
     *
     * @param int $limit
     * @param int $offset_num
     * @return array
     */
    public static function get_changes( $limit = 50, $offset_num = 0 ) {
        global $wpdb;
        $table = $wpdb->prefix . 'bestdid_file_baselines';

        return $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM {$table} WHERE status IN ('modified','new','deleted') ORDER BY last_checked DESC LIMIT %d OFFSET %d",
            $limit, $offset_num
        ), ARRAY_A );
    }

    /**
     * Run scheduled integrity check (cron).
     */
    public static function cron_check() {
        global $wpdb;

        $table = $wpdb->prefix . 'bestdid_file_baselines';
        $has_baseline = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

        if ( ! $has_baseline ) {
            return; // No baseline yet.
        }

        // Run full check synchronously.
        $files = self::collect_files();
        $now   = current_time( 'mysql', true );
        $modified = 0;
        $added   = 0;

        foreach ( $files as $filepath ) {
            $rel_path = self::relative_path( $filepath );
            if ( ! file_exists( $filepath ) ) {
                continue;
            }

            $hash     = hash_file( 'sha256', $filepath );
            $baseline = $wpdb->get_row( $wpdb->prepare(
                "SELECT id, file_hash FROM {$table} WHERE file_path = %s LIMIT 1",
                $rel_path
            ) );

            if ( $baseline ) {
                if ( $baseline->file_hash !== $hash ) {
                    $wpdb->update( $table, array( 'status' => 'modified', 'last_checked' => $now ), array( 'id' => $baseline->id ) );
                    $modified++;
                } else {
                    $wpdb->update( $table, array( 'status' => 'ok', 'last_checked' => $now ), array( 'id' => $baseline->id ) );
                }
            } else {
                $wpdb->insert( $table, array(
                    'file_path'        => $rel_path,
                    'file_hash'        => $hash,
                    'file_size'        => filesize( $filepath ),
                    'file_modified'    => gmdate( 'Y-m-d H:i:s', filemtime( $filepath ) ),
                    'baseline_created' => $now,
                    'last_checked'     => $now,
                    'status'           => 'new',
                ) );
                $added++;
            }
        }

        // Deleted files.
        $deleted = (int) $wpdb->get_var( $wpdb->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE last_checked < %s AND status != 'deleted'",
            $now
        ) );
        if ( $deleted > 0 ) {
            $wpdb->query( $wpdb->prepare(
                "UPDATE {$table} SET status = 'deleted', last_checked = %s WHERE last_checked < %s AND status != 'deleted'",
                $now, $now
            ) );
        }

        update_option( 'bdsec_fim_last_check', array(
            'checked_at' => $now,
            'modified'   => $modified,
            'added'      => $added,
            'deleted'    => $deleted,
        ) );

        // Email alert if changes found.
        $settings = get_option( 'bestdid_security_settings' );
        if ( ! empty( $settings['fim_email_alerts'] ) && ( $modified + $added + $deleted ) > 0 ) {
            $admin_email = get_option( 'admin_email' );
            $site_name   = get_bloginfo( 'name' );
            $total_changes = $modified + $added + $deleted;

            wp_mail(
                $admin_email,
                "[{$site_name}] File Integrity Alert — {$total_changes} change(s) detected",
                "The file integrity monitor detected changes on your site:\n\n"
                . "Modified: {$modified}\n"
                . "Added: {$added}\n"
                . "Deleted: {$deleted}\n\n"
                . "Review changes: " . admin_url( 'admin.php?page=bestdid-security-file-integrity' )
            );
        }
    }

    // ── Path helpers ───────────────────────────────────────────

    /**
     * Convert absolute path to relative (from ABSPATH).
     */
    public static function relative_path( $path ) {
        $path    = wp_normalize_path( $path );
        $abspath = wp_normalize_path( ABSPATH );
        if ( strpos( $path, $abspath ) === 0 ) {
            return substr( $path, strlen( $abspath ) );
        }
        return $path;
    }

    /**
     * Convert relative path back to absolute.
     */
    public static function absolute_path( $rel ) {
        return wp_normalize_path( ABSPATH . $rel );
    }
}
