<?php
/**
 * Two-Factor Authentication Controller
 *
 * Integrates TOTP into the WordPress login flow, user profile, and admin UI.
 * Supports backup codes, trusted devices, and per-role enforcement.
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class BDSEC_Two_Factor {

    /** Singleton instance. */
    private static $instance = null;

    /** Max 2FA verification failures before the pending session is invalidated. */
    const MAX_FAILURES = 5;

    /** Trusted device cookie TTL in seconds (30 days). */
    const TRUSTED_DEVICE_TTL = 2592000;

    /** Pending 2FA transient TTL in seconds (5 minutes). */
    const PENDING_TTL = 300;

    /**
     * Get / create singleton.
     */
    public static function instance() {
        if ( null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Constructor — register all hooks.
     */
    private function __construct() {
        $settings = get_option( 'bestdid_security_settings' );
        if ( empty( $settings['two_factor_enabled'] ) ) {
            return; // master switch off
        }

        // Login flow.
        add_filter( 'authenticate', array( $this, 'intercept_login' ), 99, 3 );
        add_action( 'login_form_bdsec_2fa', array( $this, 'handle_2fa_page' ) );
        add_action( 'login_form_bdsec_2fa_complete', array( $this, 'handle_2fa_complete_login' ) );

        // User profile.
        add_action( 'show_user_profile', array( $this, 'render_user_profile_section' ) );
        add_action( 'edit_user_profile', array( $this, 'render_user_profile_section' ) );

        // AJAX endpoints.
        add_action( 'wp_ajax_bdsec_verify_2fa_setup', array( $this, 'ajax_verify_setup' ) );
        add_action( 'wp_ajax_bdsec_disable_2fa', array( $this, 'ajax_disable_2fa' ) );
        add_action( 'wp_ajax_bdsec_regenerate_backup_codes', array( $this, 'ajax_regenerate_backup_codes' ) );

        // Force setup redirect for enforced roles.
        add_action( 'current_screen', array( $this, 'maybe_force_setup' ) );
    }

    // ------------------------------------------------------------------
    // LOGIN FLOW
    // ------------------------------------------------------------------

    /**
     * Priority-99 authenticate filter.
     *
     * If the user has 2FA enabled and the device is not trusted,
     * store pending state and halt login.
     */
    public function intercept_login( $user, $username, $password ) {
        // Only act on successful authentication.
        if ( is_wp_error( $user ) || ! ( $user instanceof WP_User ) ) {
            return $user;
        }

        $has_2fa = (bool) get_user_meta( $user->ID, '_bdsec_2fa_enabled', true );

        // If user already has 2FA set up and device is trusted, let them through.
        if ( $has_2fa && $this->is_device_trusted( $user->ID ) ) {
            return $user;
        }

        // If user does NOT have 2FA set up, check if their role requires it.
        if ( ! $has_2fa ) {
            $settings   = get_option( 'bestdid_security_settings' );
            $roles      = $settings['two_factor_roles'] ?? array( 'administrator' );
            $user_roles = (array) $user->roles;

            if ( ! array_intersect( $user_roles, $roles ) ) {
                return $user; // role not enforced
            }
        }

        // At this point either:
        // a) User has 2FA enabled but device is not trusted → verify code
        // b) User's role requires 2FA but they haven't set it up → setup flow
        $needs_setup = ! $has_2fa;

        // For setup flow, generate a secret now if they don't have one.
        if ( $needs_setup ) {
            $existing_secret = $this->get_user_secret( $user->ID );
            if ( ! $existing_secret ) {
                $secret = BDSEC_TOTP::generate_secret();
                $this->save_user_secret( $user->ID, $secret );
            }
        }

        // Create pending 2FA session.
        $token = wp_generate_password( 32, false );
        set_transient( 'bdsec_2fa_' . $token, array(
            'user_id'     => $user->ID,
            'expiry'      => time() + self::PENDING_TTL,
            'failures'    => 0,
            'needs_setup' => $needs_setup,
        ), self::PENDING_TTL );

        // Set cookie so the 2FA page can look up the token.
        setcookie( 'bdsec_2fa_token', $token, 0, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );

        $redirect = wp_login_url();
        $redirect = add_query_arg( array(
            'action'          => 'bdsec_2fa',
            'bdsec_2fa_token' => $token,
        ), $redirect );

        wp_safe_redirect( $redirect );
        exit;
    }

    /**
     * Handle the 2FA verification page (login_form_bdsec_2fa action).
     */
    public function handle_2fa_page() {
        // Retrieve token.
        $token = '';
        if ( ! empty( $_COOKIE['bdsec_2fa_token'] ) ) {
            $token = sanitize_text_field( $_COOKIE['bdsec_2fa_token'] );
        } elseif ( ! empty( $_REQUEST['bdsec_2fa_token'] ) ) {
            $token = sanitize_text_field( $_REQUEST['bdsec_2fa_token'] );
        }

        $pending = $token ? get_transient( 'bdsec_2fa_' . $token ) : false;

        if ( ! $pending || empty( $pending['user_id'] ) ) {
            wp_safe_redirect( wp_login_url() );
            exit;
        }

        // Check expiry.
        if ( time() > $pending['expiry'] ) {
            delete_transient( 'bdsec_2fa_' . $token );
            wp_safe_redirect( add_query_arg( 'bdsec_2fa_expired', '1', wp_login_url() ) );
            exit;
        }

        $error_message = '';
        $needs_setup   = ! empty( $pending['needs_setup'] );
        $backup_codes  = array(); // populated after successful setup

        // Process submission.
        if ( 'POST' === $_SERVER['REQUEST_METHOD'] && isset( $_POST['bdsec_2fa_nonce'] ) ) {
            if ( ! wp_verify_nonce( $_POST['bdsec_2fa_nonce'], 'bdsec_2fa_verify' ) ) {
                $error_message = __( 'Security check failed. Please try again.', 'bestdid-security' );
            } else {
                $code    = sanitize_text_field( $_POST['bdsec_2fa_code'] ?? '' );
                $user_id = $pending['user_id'];
                $secret  = $this->get_user_secret( $user_id );
                $is_backup = ! empty( $_POST['bdsec_2fa_use_backup'] );

                $verified = false;

                if ( $is_backup && ! $needs_setup ) {
                    $verified = $this->verify_backup_code( $user_id, $code );
                } else {
                    $verified = BDSEC_TOTP::verify_code( $secret, $code );
                }

                if ( $verified ) {
                    // If this was a setup flow, enable 2FA and generate backup codes.
                    if ( $needs_setup ) {
                        update_user_meta( $user_id, '_bdsec_2fa_enabled', true );
                        $backup_codes = $this->generate_backup_codes( $user_id );

                        // Show the backup codes page before completing login.
                        $user = get_userdata( $user_id );
                        // Store login completion data in a new short transient.
                        $login_token = wp_generate_password( 32, false );
                        set_transient( 'bdsec_2fa_login_' . $login_token, array(
                            'user_id' => $user_id,
                            'trust'   => ! empty( $_POST['bdsec_2fa_trust'] ),
                        ), 600 ); // 10 minutes to view backup codes
                        delete_transient( 'bdsec_2fa_' . $token );
                        setcookie( 'bdsec_2fa_token', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
                        include BESTDID_SECURITY_PATH . 'templates/2fa-backup-codes.php';
                        exit;
                    }

                    // Trust device if requested.
                    if ( ! empty( $_POST['bdsec_2fa_trust'] ) ) {
                        $this->trust_device( $user_id );
                    }

                    // Complete login.
                    delete_transient( 'bdsec_2fa_' . $token );
                    setcookie( 'bdsec_2fa_token', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );

                    wp_set_auth_cookie( $user_id, false );
                    wp_set_current_user( $user_id );

                    $redirect_to = admin_url();
                    if ( ! empty( $_POST['redirect_to'] ) ) {
                        $redirect_to = esc_url_raw( $_POST['redirect_to'] );
                    }

                    wp_safe_redirect( $redirect_to );
                    exit;
                }

                // Failed attempt.
                $pending['failures'] = ( $pending['failures'] ?? 0 ) + 1;

                if ( $pending['failures'] >= self::MAX_FAILURES ) {
                    delete_transient( 'bdsec_2fa_' . $token );
                    setcookie( 'bdsec_2fa_token', '', time() - 3600, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
                    wp_safe_redirect( add_query_arg( 'bdsec_2fa_locked', '1', wp_login_url() ) );
                    exit;
                }

                set_transient( 'bdsec_2fa_' . $token, $pending, self::PENDING_TTL );
                $remaining     = self::MAX_FAILURES - $pending['failures'];
                $error_message = sprintf(
                    __( 'Invalid code. %d attempt(s) remaining.', 'bestdid-security' ),
                    $remaining
                );
            }
        }

        // Render the appropriate form.
        $user = get_userdata( $pending['user_id'] );

        if ( $needs_setup ) {
            // Show QR code setup form during login.
            $secret = $this->get_user_secret( $pending['user_id'] );
            // If decryption failed or secret is empty, regenerate it.
            if ( empty( $secret ) || strlen( $secret ) < 16 ) {
                $secret = BDSEC_TOTP::generate_secret();
                $this->save_user_secret( $pending['user_id'], $secret );
            }
            $provisioning_uri = BDSEC_TOTP::get_provisioning_uri( $secret, $user->user_email );
            include BESTDID_SECURITY_PATH . 'templates/2fa-setup-form.php';
        } else {
            include BESTDID_SECURITY_PATH . 'templates/2fa-login-form.php';
        }
        exit;
    }

    /**
     * Complete login after the user has seen their backup codes.
     */
    public function handle_2fa_complete_login() {
        $login_token = sanitize_text_field( $_REQUEST['login_token'] ?? '' );
        if ( ! $login_token ) {
            wp_safe_redirect( wp_login_url() );
            exit;
        }

        $data = get_transient( 'bdsec_2fa_login_' . $login_token );
        if ( ! $data || empty( $data['user_id'] ) ) {
            wp_safe_redirect( wp_login_url() );
            exit;
        }

        delete_transient( 'bdsec_2fa_login_' . $login_token );

        if ( ! empty( $data['trust'] ) ) {
            $this->trust_device( $data['user_id'] );
        }

        wp_set_auth_cookie( $data['user_id'], false );
        wp_set_current_user( $data['user_id'] );
        wp_safe_redirect( admin_url() );
        exit;
    }

    // ------------------------------------------------------------------
    // USER PROFILE SECTION
    // ------------------------------------------------------------------

    /**
     * Render the 2FA setup / status section on the user profile page.
     */
    public function render_user_profile_section( $user ) {
        // Only show if user's role is in the allowed roles.
        $settings = get_option( 'bestdid_security_settings' );
        $roles    = $settings['two_factor_roles'] ?? array( 'administrator' );

        $user_roles = (array) $user->roles;
        if ( ! array_intersect( $user_roles, $roles ) ) {
            return;
        }

        $enabled      = (bool) get_user_meta( $user->ID, '_bdsec_2fa_enabled', true );
        $secret       = $this->get_user_secret( $user->ID );
        $backup_count = 0;

        if ( $enabled ) {
            $codes = get_user_meta( $user->ID, '_bdsec_2fa_backup_codes', true );
            if ( is_array( $codes ) ) {
                $backup_count = count( $codes );
            }
        }

        // Generate a new secret if the user hasn't set one up yet, or if decryption failed.
        if ( ( ! $secret || strlen( $secret ) < 16 ) && ! $enabled ) {
            $secret = BDSEC_TOTP::generate_secret();
            $this->save_user_secret( $user->ID, $secret );
        }

        $provisioning_uri = BDSEC_TOTP::get_provisioning_uri( $secret, $user->user_email );

        wp_nonce_field( 'bdsec_2fa_profile', 'bdsec_2fa_profile_nonce' );
        ?>
        <h2><?php esc_html_e( 'Two-Factor Authentication', 'bestdid-security' ); ?></h2>
        <table class="form-table" role="presentation" id="bdsec-2fa-section">
            <tr>
                <th scope="row"><?php esc_html_e( 'Status', 'bestdid-security' ); ?></th>
                <td>
                    <?php if ( $enabled ) : ?>
                        <span style="color:#00a32a;font-weight:600;">&#10003; <?php esc_html_e( 'Active', 'bestdid-security' ); ?></span>
                        <p class="description">
                            <?php
                            printf(
                                esc_html__( 'You have %d backup code(s) remaining.', 'bestdid-security' ),
                                $backup_count
                            );
                            ?>
                        </p>
                        <p style="margin-top:10px;">
                            <button type="button" class="button" id="bdsec-regenerate-backup-codes">
                                <?php esc_html_e( 'Regenerate Backup Codes', 'bestdid-security' ); ?>
                            </button>
                            <button type="button" class="button button-link-delete" id="bdsec-disable-2fa" style="margin-left:10px;">
                                <?php esc_html_e( 'Disable 2FA', 'bestdid-security' ); ?>
                            </button>
                        </p>
                        <div id="bdsec-backup-codes-display" style="display:none;margin-top:15px;padding:15px;background:#f0f0f1;border-radius:6px;">
                            <p><strong><?php esc_html_e( 'Save these backup codes in a safe place. Each code can only be used once.', 'bestdid-security' ); ?></strong></p>
                            <pre id="bdsec-backup-codes-list" style="background:#fff;padding:10px;border-radius:4px;font-family:monospace;font-size:14px;"></pre>
                        </div>
                    <?php else : ?>
                        <span style="color:#d63638;font-weight:600;"><?php esc_html_e( 'Not configured', 'bestdid-security' ); ?></span>
                    <?php endif; ?>
                </td>
            </tr>

            <?php if ( ! $enabled ) : ?>
            <tr>
                <th scope="row"><?php esc_html_e( 'Setup', 'bestdid-security' ); ?></th>
                <td>
                    <p class="description" style="margin-bottom:15px;">
                        <?php esc_html_e( 'Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.):', 'bestdid-security' ); ?>
                    </p>
                    <div style="margin-bottom:15px;" id="bdsec-profile-qr-code">
                        <?php
                        $qr_svg = BDSEC_QR::svg( $provisioning_uri, 200 );
                        if ( $qr_svg ) {
                            echo $qr_svg;
                        } else {
                            echo '<p class="description">' . esc_html__( 'QR code generation failed. Please enter the secret manually below.', 'bestdid-security' ) . '</p>';
                        }
                        ?>
                    </div>
                    <p class="description" style="margin-bottom:15px;">
                        <?php esc_html_e( 'Or enter this secret manually:', 'bestdid-security' ); ?>
                        <code style="font-size:14px;padding:4px 8px;user-select:all;"><?php echo esc_html( $secret ); ?></code>
                    </p>
                    <p style="margin-bottom:8px;">
                        <label for="bdsec-2fa-verify-code">
                            <strong><?php esc_html_e( 'Enter the 6-digit code from your app to verify:', 'bestdid-security' ); ?></strong>
                        </label>
                    </p>
                    <input type="text" id="bdsec-2fa-verify-code" maxlength="6" size="8" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" style="font-size:18px;letter-spacing:4px;text-align:center;padding:8px 12px;">
                    <button type="button" class="button button-primary" id="bdsec-verify-setup" style="margin-left:8px;">
                        <?php esc_html_e( 'Verify & Enable', 'bestdid-security' ); ?>
                    </button>
                    <span id="bdsec-2fa-setup-status" style="margin-left:10px;"></span>
                    <div id="bdsec-setup-backup-codes" style="display:none;margin-top:15px;padding:15px;background:#f0f0f1;border-radius:6px;">
                        <p><strong><?php esc_html_e( 'Save these backup codes in a safe place. Each code can only be used once.', 'bestdid-security' ); ?></strong></p>
                        <pre id="bdsec-setup-codes-list" style="background:#fff;padding:10px;border-radius:4px;font-family:monospace;font-size:14px;"></pre>
                    </div>
                </td>
            </tr>
            <?php endif; ?>
        </table>

        <script>
        (function($) {
            var userId = <?php echo (int) $user->ID; ?>;
            var nonce  = '<?php echo wp_create_nonce( 'bdsec_2fa_ajax' ); ?>';

            // Verify & Enable.
            $('#bdsec-verify-setup').on('click', function() {
                var code = $('#bdsec-2fa-verify-code').val().trim();
                if (code.length !== 6) {
                    $('#bdsec-2fa-setup-status').html('<span style="color:#d63638;">Enter a 6-digit code.</span>');
                    return;
                }
                var $btn = $(this).prop('disabled', true).text('<?php echo esc_js( __( 'Verifying...', 'bestdid-security' ) ); ?>');
                $.post(ajaxurl, {
                    action: 'bdsec_verify_2fa_setup',
                    code: code,
                    user_id: userId,
                    _ajax_nonce: nonce
                }, function(res) {
                    if (res.success) {
                        $('#bdsec-2fa-setup-status').html('<span style="color:#00a32a;">&#10003; 2FA enabled!</span>');
                        if (res.data.backup_codes) {
                            $('#bdsec-setup-codes-list').text(res.data.backup_codes.join('\n'));
                            $('#bdsec-setup-backup-codes').show();
                        }
                        $btn.text('<?php echo esc_js( __( 'Enabled', 'bestdid-security' ) ); ?>');
                    } else {
                        $('#bdsec-2fa-setup-status').html('<span style="color:#d63638;">' + (res.data || 'Verification failed.') + '</span>');
                        $btn.prop('disabled', false).text('<?php echo esc_js( __( 'Verify & Enable', 'bestdid-security' ) ); ?>');
                    }
                }).fail(function() {
                    $btn.prop('disabled', false).text('<?php echo esc_js( __( 'Verify & Enable', 'bestdid-security' ) ); ?>');
                    $('#bdsec-2fa-setup-status').html('<span style="color:#d63638;">Request failed.</span>');
                });
            });

            // Disable 2FA.
            $('#bdsec-disable-2fa').on('click', function() {
                if (!confirm('<?php echo esc_js( __( 'Are you sure you want to disable two-factor authentication?', 'bestdid-security' ) ); ?>')) return;
                $.post(ajaxurl, {
                    action: 'bdsec_disable_2fa',
                    user_id: userId,
                    _ajax_nonce: nonce
                }, function(res) {
                    if (res.success) { location.reload(); }
                });
            });

            // Regenerate backup codes.
            $('#bdsec-regenerate-backup-codes').on('click', function() {
                if (!confirm('<?php echo esc_js( __( 'This will invalidate all existing backup codes. Continue?', 'bestdid-security' ) ); ?>')) return;
                $.post(ajaxurl, {
                    action: 'bdsec_regenerate_backup_codes',
                    user_id: userId,
                    _ajax_nonce: nonce
                }, function(res) {
                    if (res.success && res.data.backup_codes) {
                        $('#bdsec-backup-codes-list').text(res.data.backup_codes.join('\n'));
                        $('#bdsec-backup-codes-display').show();
                    }
                });
            });
        })(jQuery);
        </script>
        <?php
    }

    // ------------------------------------------------------------------
    // AJAX HANDLERS
    // ------------------------------------------------------------------

    /**
     * AJAX: Verify initial 2FA setup code, enable 2FA, return backup codes.
     */
    public function ajax_verify_setup() {
        check_ajax_referer( 'bdsec_2fa_ajax' );

        $user_id = intval( $_POST['user_id'] ?? 0 );
        if ( ! $this->can_manage_2fa( $user_id ) ) {
            wp_send_json_error( __( 'Permission denied.', 'bestdid-security' ) );
        }

        $code   = sanitize_text_field( $_POST['code'] ?? '' );
        $secret = $this->get_user_secret( $user_id );

        if ( ! $secret || ! BDSEC_TOTP::verify_code( $secret, $code ) ) {
            wp_send_json_error( __( 'Invalid code. Make sure your authenticator app time is synced.', 'bestdid-security' ) );
        }

        update_user_meta( $user_id, '_bdsec_2fa_enabled', true );

        $backup_codes = $this->generate_backup_codes( $user_id );

        wp_send_json_success( array( 'backup_codes' => $backup_codes ) );
    }

    /**
     * AJAX: Disable 2FA for a user.
     */
    public function ajax_disable_2fa() {
        check_ajax_referer( 'bdsec_2fa_ajax' );

        $user_id = intval( $_POST['user_id'] ?? 0 );
        if ( ! $this->can_manage_2fa( $user_id ) ) {
            wp_send_json_error( __( 'Permission denied.', 'bestdid-security' ) );
        }

        delete_user_meta( $user_id, '_bdsec_2fa_enabled' );
        delete_user_meta( $user_id, '_bdsec_2fa_secret' );
        delete_user_meta( $user_id, '_bdsec_2fa_backup_codes' );
        delete_user_meta( $user_id, '_bdsec_2fa_trusted_devices' );

        wp_send_json_success();
    }

    /**
     * AJAX: Regenerate backup codes.
     */
    public function ajax_regenerate_backup_codes() {
        check_ajax_referer( 'bdsec_2fa_ajax' );

        $user_id = intval( $_POST['user_id'] ?? 0 );
        if ( ! $this->can_manage_2fa( $user_id ) ) {
            wp_send_json_error( __( 'Permission denied.', 'bestdid-security' ) );
        }

        $codes = $this->generate_backup_codes( $user_id );
        wp_send_json_success( array( 'backup_codes' => $codes ) );
    }

    // ------------------------------------------------------------------
    // FORCE SETUP
    // ------------------------------------------------------------------

    /**
     * Redirect users in enforced roles to their profile if 2FA is not set up.
     */
    public function maybe_force_setup( $screen ) {
        if ( ! is_admin() || wp_doing_ajax() ) {
            return;
        }

        $settings = get_option( 'bestdid_security_settings' );
        if ( empty( $settings['two_factor_forced'] ) ) {
            return;
        }

        $user  = wp_get_current_user();
        $roles = $settings['two_factor_roles'] ?? array( 'administrator' );

        if ( ! array_intersect( (array) $user->roles, $roles ) ) {
            return;
        }

        if ( get_user_meta( $user->ID, '_bdsec_2fa_enabled', true ) ) {
            return;
        }

        // Allow access to profile page and AJAX so they can complete setup.
        if ( 'profile' === $screen->id || 'user-edit' === $screen->id ) {
            add_action( 'admin_notices', function() {
                echo '<div class="notice notice-warning"><p><strong>';
                esc_html_e( 'Two-factor authentication is required for your role. Please set it up below.', 'bestdid-security' );
                echo '</strong></p></div>';
            });
            return;
        }

        wp_safe_redirect( admin_url( 'profile.php#bdsec-2fa-section' ) );
        exit;
    }

    // ------------------------------------------------------------------
    // TRUSTED DEVICES
    // ------------------------------------------------------------------

    /**
     * Check whether the current browser/device is trusted for a user.
     */
    private function is_device_trusted( $user_id ) {
        if ( empty( $_COOKIE['bdsec_trusted_device'] ) ) {
            return false;
        }

        $cookie_hash = sanitize_text_field( $_COOKIE['bdsec_trusted_device'] );
        $devices     = get_user_meta( $user_id, '_bdsec_2fa_trusted_devices', true );

        if ( ! is_array( $devices ) ) {
            return false;
        }

        $now             = time();
        $updated         = false;
        $found           = false;
        $active_devices  = array();

        foreach ( $devices as $device ) {
            if ( $device['expires'] < $now ) {
                $updated = true;
                continue; // expired — prune
            }
            $active_devices[] = $device;
            if ( hash_equals( $device['hash'], $cookie_hash ) ) {
                $found = true;
            }
        }

        if ( $updated ) {
            update_user_meta( $user_id, '_bdsec_2fa_trusted_devices', $active_devices );
        }

        return $found;
    }

    /**
     * Mark the current device as trusted for 30 days.
     */
    private function trust_device( $user_id ) {
        $hash = wp_generate_password( 64, false );

        $devices = get_user_meta( $user_id, '_bdsec_2fa_trusted_devices', true );
        if ( ! is_array( $devices ) ) {
            $devices = array();
        }

        $devices[] = array(
            'hash'    => $hash,
            'label'   => sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown' ),
            'expires' => time() + self::TRUSTED_DEVICE_TTL,
        );

        update_user_meta( $user_id, '_bdsec_2fa_trusted_devices', $devices );

        setcookie(
            'bdsec_trusted_device',
            $hash,
            time() + self::TRUSTED_DEVICE_TTL,
            COOKIEPATH,
            COOKIE_DOMAIN,
            is_ssl(),
            true
        );
    }

    // ------------------------------------------------------------------
    // BACKUP CODES
    // ------------------------------------------------------------------

    /**
     * Generate 10 single-use backup codes, store hashes, return plaintext.
     *
     * @param int $user_id
     * @return array Plaintext codes (for one-time display).
     */
    public function generate_backup_codes( $user_id ) {
        $codes  = array();
        $hashes = array();

        for ( $i = 0; $i < 10; $i++ ) {
            $code     = strtoupper( wp_generate_password( 8, false ) );
            $codes[]  = $code;
            $hashes[] = wp_hash( $code );
        }

        update_user_meta( $user_id, '_bdsec_2fa_backup_codes', $hashes );

        return $codes;
    }

    /**
     * Verify and consume a backup code.
     *
     * @param int    $user_id
     * @param string $code
     * @return bool
     */
    private function verify_backup_code( $user_id, $code ) {
        $code   = strtoupper( trim( $code ) );
        $hashes = get_user_meta( $user_id, '_bdsec_2fa_backup_codes', true );

        if ( ! is_array( $hashes ) || empty( $hashes ) ) {
            return false;
        }

        $code_hash = wp_hash( $code );

        foreach ( $hashes as $index => $stored_hash ) {
            if ( hash_equals( $stored_hash, $code_hash ) ) {
                // Consume — remove from list.
                unset( $hashes[ $index ] );
                update_user_meta( $user_id, '_bdsec_2fa_backup_codes', array_values( $hashes ) );
                return true;
            }
        }

        return false;
    }

    // ------------------------------------------------------------------
    // SECRET MANAGEMENT
    // ------------------------------------------------------------------

    /**
     * Get decrypted TOTP secret for a user.
     */
    private function get_user_secret( $user_id ) {
        $encrypted = get_user_meta( $user_id, '_bdsec_2fa_secret', true );
        if ( ! $encrypted ) {
            return '';
        }

        return $this->decrypt_secret( $encrypted );
    }

    /**
     * Encrypt and save a TOTP secret for a user.
     */
    private function save_user_secret( $user_id, $secret ) {
        $encrypted = $this->encrypt_secret( $secret );
        update_user_meta( $user_id, '_bdsec_2fa_secret', $encrypted );
    }

    /**
     * Encrypt a secret using WordPress salts.
     */
    private function encrypt_secret( $plaintext ) {
        $key = wp_hash( 'bdsec_2fa_key' );
        $iv  = substr( wp_hash( 'bdsec_2fa_iv' ), 0, 16 );

        if ( function_exists( 'openssl_encrypt' ) ) {
            // Use OPENSSL_RAW_DATA to get raw bytes, then single base64 encode.
            $encrypted = openssl_encrypt( $plaintext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv );
            if ( false === $encrypted ) {
                return '';
            }
            return 'v2:' . base64_encode( $encrypted );
        }

        // Fallback: XOR obfuscation.
        $result = '';
        for ( $i = 0, $len = strlen( $plaintext ); $i < $len; $i++ ) {
            $result .= chr( ord( $plaintext[ $i ] ) ^ ord( $key[ $i % strlen( $key ) ] ) );
        }
        return base64_encode( 'xor:' . $result );
    }

    /**
     * Decrypt a secret. Handles v2 (raw), legacy double-base64, and XOR formats.
     */
    private function decrypt_secret( $ciphertext ) {
        $key = wp_hash( 'bdsec_2fa_key' );
        $iv  = substr( wp_hash( 'bdsec_2fa_iv' ), 0, 16 );

        if ( empty( $ciphertext ) ) {
            return '';
        }

        // v2 format: "v2:" prefix + base64(raw_encrypted).
        if ( strpos( $ciphertext, 'v2:' ) === 0 ) {
            $raw = base64_decode( substr( $ciphertext, 3 ) );
            if ( false === $raw ) return '';
            $result = openssl_decrypt( $raw, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv );
            return ( false === $result ) ? '' : $result;
        }

        // Legacy format: base64( openssl_encrypt_base64_output ).
        $decoded = base64_decode( $ciphertext );
        if ( false === $decoded ) return '';

        // XOR fallback.
        if ( strpos( $decoded, 'xor:' ) === 0 ) {
            $data   = substr( $decoded, 4 );
            $result = '';
            for ( $i = 0, $len = strlen( $data ); $i < $len; $i++ ) {
                $result .= chr( ord( $data[ $i ] ) ^ ord( $key[ $i % strlen( $key ) ] ) );
            }
            return $result;
        }

        // Legacy openssl: $decoded is a base64 string from openssl_encrypt(flags=0).
        if ( function_exists( 'openssl_decrypt' ) ) {
            $result = openssl_decrypt( $decoded, 'AES-256-CBC', $key, 0, $iv );
            if ( false !== $result ) {
                return $result;
            }
        }

        return '';
    }

    // ------------------------------------------------------------------
    // HELPERS
    // ------------------------------------------------------------------

    /**
     * Check if the current user can manage 2FA for the given user ID.
     */
    private function can_manage_2fa( $user_id ) {
        if ( ! $user_id ) {
            return false;
        }
        // Users can manage their own 2FA; admins can manage anyone's.
        return ( get_current_user_id() === $user_id ) || current_user_can( 'edit_users' );
    }

    /**
     * Count users with 2FA enabled, optionally filtered by roles.
     *
     * @param array|null $roles Limit to these roles. Null = all.
     * @return array { enabled: int, total: int }
     */
    public static function get_2fa_user_stats( $roles = null ) {
        $args = array( 'fields' => 'ID' );
        if ( $roles ) {
            $args['role__in'] = $roles;
        }
        $users   = get_users( $args );
        $total   = count( $users );
        $enabled = 0;

        foreach ( $users as $uid ) {
            if ( get_user_meta( $uid, '_bdsec_2fa_enabled', true ) ) {
                $enabled++;
            }
        }

        return array( 'enabled' => $enabled, 'total' => $total );
    }
}
