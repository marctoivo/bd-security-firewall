<?php
/**
 * Activity Logger — Audit trail for admin actions.
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class BDSEC_Activity_Logger {

    /**
     * Log an event.
     *
     * @param string $event_type   e.g. login_success, plugin_activated
     * @param string $object_type  e.g. user, plugin, post
     * @param int    $object_id
     * @param string $object_name
     * @param array  $details      Extra JSON-encodable data.
     */
    public static function log_event( $event_type, $object_type = '', $object_id = 0, $object_name = '', $details = array() ) {
        global $wpdb;

        $user    = wp_get_current_user();
        $user_id = $user->ID ?? 0;

        $wpdb->insert( $wpdb->prefix . 'bestdid_activity_log', array(
            'user_id'     => $user_id,
            'username'    => $user_id ? $user->user_login : 'system',
            'user_role'   => $user_id && ! empty( $user->roles ) ? implode( ', ', $user->roles ) : '',
            'event_type'  => sanitize_text_field( $event_type ),
            'object_type' => sanitize_text_field( $object_type ),
            'object_id'   => absint( $object_id ),
            'object_name' => sanitize_text_field( $object_name ),
            'details'     => wp_json_encode( $details ),
            'ip_address'  => self::get_ip(),
            'user_agent'  => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 512 ) : '',
            'created_at'  => current_time( 'mysql', true ),
        ) );
    }

    // ── Hook callbacks ─────────────────────────────────────────

    /** Login success. */
    public static function on_login_success( $user_login, $user ) {
        self::log_event( 'login_success', 'user', $user->ID, $user_login );
    }

    /** Login failure. */
    public static function on_login_failed( $username ) {
        self::log_event( 'login_failed', 'user', 0, $username );
    }

    /** Logout. */
    public static function on_logout() {
        $user = wp_get_current_user();
        if ( $user->ID ) {
            self::log_event( 'logout', 'user', $user->ID, $user->user_login );
        }
    }

    /** Password changed via profile. */
    public static function on_profile_update( $user_id, $old_user_data, $userdata ) {
        if ( isset( $userdata['user_pass'] ) && $old_user_data->user_pass !== $userdata['user_pass'] ) {
            $user = get_userdata( $user_id );
            self::log_event( 'password_changed', 'user', $user_id, $user->user_login );
        }
    }

    /** Password reset. */
    public static function on_password_reset( $user ) {
        self::log_event( 'password_reset', 'user', $user->ID, $user->user_login );
    }

    /** User created. */
    public static function on_user_register( $user_id ) {
        $user = get_userdata( $user_id );
        self::log_event( 'user_created', 'user', $user_id, $user ? $user->user_login : '' );
    }

    /** User deleted. */
    public static function on_delete_user( $user_id ) {
        $user = get_userdata( $user_id );
        self::log_event( 'user_deleted', 'user', $user_id, $user ? $user->user_login : '' );
    }

    /** Role changed. */
    public static function on_set_user_role( $user_id, $role, $old_roles ) {
        $user = get_userdata( $user_id );
        self::log_event( 'role_changed', 'user', $user_id, $user ? $user->user_login : '', array(
            'old_roles' => $old_roles,
            'new_role'  => $role,
        ) );
    }

    /** Plugin activated. */
    public static function on_activate_plugin( $plugin ) {
        self::log_event( 'plugin_activated', 'plugin', 0, $plugin );
    }

    /** Plugin deactivated. */
    public static function on_deactivate_plugin( $plugin ) {
        self::log_event( 'plugin_deactivated', 'plugin', 0, $plugin );
    }

    /** Theme switched. */
    public static function on_switch_theme( $new_name, $new_theme ) {
        self::log_event( 'theme_switched', 'theme', 0, $new_name );
    }

    /** Post status transition (publish, trash, delete). */
    public static function on_transition_post_status( $new_status, $old_status, $post ) {
        if ( $new_status === $old_status || wp_is_post_revision( $post ) || wp_is_post_autosave( $post ) ) {
            return;
        }

        $map = array(
            'publish' => 'post_published',
            'trash'   => 'post_trashed',
        );

        if ( isset( $map[ $new_status ] ) ) {
            self::log_event( $map[ $new_status ], 'post', $post->ID, $post->post_title, array(
                'post_type'  => $post->post_type,
                'old_status' => $old_status,
            ) );
        }
    }

    /** Post permanently deleted. */
    public static function on_delete_post( $post_id ) {
        $post = get_post( $post_id );
        if ( ! $post || wp_is_post_revision( $post ) ) {
            return;
        }
        self::log_event( 'post_deleted', 'post', $post_id, $post->post_title, array( 'post_type' => $post->post_type ) );
    }

    /** Core/plugin/theme updated. */
    public static function on_upgrader_complete( $upgrader, $options ) {
        $type = $options['type'] ?? '';
        $action = $options['action'] ?? '';

        if ( $action !== 'update' ) {
            return;
        }

        if ( $type === 'core' ) {
            self::log_event( 'core_updated', 'core', 0, 'WordPress', array( 'version' => get_bloginfo( 'version' ) ) );
        } elseif ( $type === 'plugin' && ! empty( $options['plugins'] ) ) {
            foreach ( (array) $options['plugins'] as $plugin ) {
                self::log_event( 'plugin_updated', 'plugin', 0, $plugin );
            }
        } elseif ( $type === 'theme' && ! empty( $options['themes'] ) ) {
            foreach ( (array) $options['themes'] as $theme ) {
                self::log_event( 'theme_updated', 'theme', 0, $theme );
            }
        }
    }

    /** BD Security settings saved. */
    public static function on_settings_saved() {
        self::log_event( 'settings_saved', 'settings', 0, 'bestdid_security_settings' );
    }

    /** Generic WP option update (limit to important ones). */
    public static function on_update_option( $option, $old_value, $value ) {
        $tracked = array( 'blogname', 'blogdescription', 'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role' );
        if ( in_array( $option, $tracked, true ) ) {
            self::log_event( 'option_updated', 'option', 0, $option );
        }
    }

    // ── Cleanup ────────────────────────────────────────────────

    /**
     * Delete entries older than retention days.
     */
    public static function cleanup( $days = 90 ) {
        global $wpdb;
        $table = $wpdb->prefix . 'bestdid_activity_log';
        $wpdb->query( $wpdb->prepare(
            "DELETE FROM {$table} WHERE created_at < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $days
        ) );
    }

    // ── Helpers ────────────────────────────────────────────────

    private static function get_ip() {
        $headers = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR' );
        foreach ( $headers as $h ) {
            if ( ! empty( $_SERVER[ $h ] ) ) {
                return trim( explode( ',', $_SERVER[ $h ] )[0] );
            }
        }
        return '';
    }
}
