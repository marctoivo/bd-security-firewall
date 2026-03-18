<?php
/**
 * Quarantine Manager — moves suspicious files out of the web root.
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class BDSEC_Quarantine {

    /** @var string Quarantine directory inside uploads. */
    private $quarantine_dir;

    /** @var string DB table (no prefix). */
    private $table = 'bestdid_quarantine_log';

    public function __construct() {
        $upload_dir          = wp_upload_dir();
        $this->quarantine_dir = trailingslashit( $upload_dir['basedir'] ) . 'bestdid-security-quarantine/';
    }

    /* ─── Directory bootstrap ───────────────────────────────────── */

    /**
     * Ensure quarantine folder exists with .htaccess + index.php.
     */
    public function ensure_directory() {
        if ( ! is_dir( $this->quarantine_dir ) ) {
            wp_mkdir_p( $this->quarantine_dir );
        }

        $htaccess = $this->quarantine_dir . '.htaccess';
        if ( ! file_exists( $htaccess ) ) {
            file_put_contents( $htaccess, "Order deny,allow\nDeny from all\n" );
        }

        $index = $this->quarantine_dir . 'index.php';
        if ( ! file_exists( $index ) ) {
            file_put_contents( $index, "<?php\n// Silence is golden.\n" );
        }
    }

    /* ─── Path validation ───────────────────────────────────────── */

    /**
     * Validate a path lives inside ABSPATH and is not a symlink/null-byte trick.
     *
     * @param  string $path Absolute file path.
     * @return bool
     */
    private function validate_path( $path ) {
        if ( strpos( $path, "\0" ) !== false ) {
            return false;
        }

        $real = realpath( $path );
        if ( false === $real ) {
            return false;
        }

        $abspath = realpath( ABSPATH );
        if ( false === $abspath ) {
            return false;
        }

        return 0 === strpos( $real, $abspath );
    }

    /* ─── Quarantine ────────────────────────────────────────────── */

    /**
     * Move a file into quarantine.
     *
     * @param  string   $file_path       Absolute path to the file.
     * @param  int|null $scan_result_id  FK to scan_results table.
     * @param  string   $notes           Optional notes.
     * @return int|false  Quarantine log ID on success.
     */
    public function quarantine_file( $file_path, $scan_result_id = null, $notes = '' ) {
        if ( ! $this->validate_path( $file_path ) ) {
            return false;
        }

        if ( ! file_exists( $file_path ) || ! is_file( $file_path ) ) {
            return false;
        }

        $this->ensure_directory();

        $hash       = md5_file( $file_path );
        $size       = filesize( $file_path );
        $perms      = substr( sprintf( '%o', fileperms( $file_path ) ), -4 );
        $safe_name  = $hash . '_' . time() . '.quarantined';
        $dest       = $this->quarantine_dir . $safe_name;

        if ( ! @rename( $file_path, $dest ) ) {
            // Fallback: copy + delete.
            if ( ! @copy( $file_path, $dest ) ) {
                return false;
            }
            @unlink( $file_path );
        }

        global $wpdb;
        $table = $wpdb->prefix . $this->table;

        $wpdb->insert( $table, array(
            'scan_result_id'   => $scan_result_id,
            'original_path'    => $file_path,
            'quarantine_path'  => $dest,
            'file_hash'        => $hash,
            'file_size'        => $size,
            'file_permissions' => $perms,
            'quarantined_by'   => get_current_user_id(),
            'quarantined_at'   => current_time( 'mysql' ),
            'status'           => 'quarantined',
            'notes'            => $notes,
        ), array( '%d', '%s', '%s', '%s', '%d', '%s', '%d', '%s', '%s', '%s' ) );

        return $wpdb->insert_id;
    }

    /* ─── Restore ───────────────────────────────────────────────── */

    /**
     * Restore a quarantined file to its original location.
     *
     * @param  int $quarantine_id Row ID in quarantine_log.
     * @return bool
     */
    public function restore_file( $quarantine_id ) {
        global $wpdb;
        $table = $wpdb->prefix . $this->table;

        $row = $wpdb->get_row( $wpdb->prepare(
            "SELECT * FROM $table WHERE id = %d AND status = 'quarantined'",
            $quarantine_id
        ) );

        if ( ! $row || ! file_exists( $row->quarantine_path ) ) {
            return false;
        }

        // Ensure target directory exists.
        $dir = dirname( $row->original_path );
        if ( ! is_dir( $dir ) ) {
            wp_mkdir_p( $dir );
        }

        if ( ! @rename( $row->quarantine_path, $row->original_path ) ) {
            if ( ! @copy( $row->quarantine_path, $row->original_path ) ) {
                return false;
            }
            @unlink( $row->quarantine_path );
        }

        // Restore original permissions.
        if ( ! empty( $row->file_permissions ) ) {
            @chmod( $row->original_path, octdec( $row->file_permissions ) );
        }

        $wpdb->update( $table, array(
            'status'      => 'restored',
            'restored_at' => current_time( 'mysql' ),
        ), array( 'id' => $quarantine_id ), array( '%s', '%s' ), array( '%d' ) );

        return true;
    }

    /* ─── Permanent delete ──────────────────────────────────────── */

    /**
     * Permanently delete a quarantined file.
     *
     * @param  int $quarantine_id Row ID.
     * @return bool
     */
    public function delete_quarantined( $quarantine_id ) {
        global $wpdb;
        $table = $wpdb->prefix . $this->table;

        $row = $wpdb->get_row( $wpdb->prepare(
            "SELECT * FROM $table WHERE id = %d AND status = 'quarantined'",
            $quarantine_id
        ) );

        if ( ! $row ) {
            return false;
        }

        if ( file_exists( $row->quarantine_path ) ) {
            @unlink( $row->quarantine_path );
        }

        $wpdb->update( $table, array(
            'status'     => 'deleted',
            'deleted_at' => current_time( 'mysql' ),
        ), array( 'id' => $quarantine_id ), array( '%s', '%s' ), array( '%d' ) );

        return true;
    }

    /* ─── Queries ───────────────────────────────────────────────── */

    /**
     * Get all quarantined files.
     *
     * @return array
     */
    public function get_quarantined_files() {
        global $wpdb;
        $table = $wpdb->prefix . $this->table;

        return $wpdb->get_results(
            "SELECT * FROM $table WHERE status = 'quarantined' ORDER BY quarantined_at DESC"
        );
    }

    /**
     * Get count of currently quarantined files.
     *
     * @return int
     */
    public function get_quarantine_count() {
        global $wpdb;
        $table = $wpdb->prefix . $this->table;

        return (int) $wpdb->get_var(
            "SELECT COUNT(*) FROM $table WHERE status = 'quarantined'"
        );
    }
}
