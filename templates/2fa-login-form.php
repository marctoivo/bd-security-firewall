<?php
/**
 * Two-Factor Authentication Login Form
 *
 * Rendered during the 2FA verification step of the login flow.
 * Variables available: $user (WP_User), $token (string), $error_message (string).
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

// Use WordPress login page header/footer for consistent styling.
login_header(
    __( 'Two-Factor Authentication', 'bestdid-security' ),
    $error_message ? '<div id="login_error" role="alert">' . esc_html( $error_message ) . '</div>' : ''
);
?>

<style>
    #bdsec-2fa-form .input {
        font-size: 24px;
        letter-spacing: 8px;
        text-align: center;
        padding: 8px 12px;
        width: 100%;
        box-sizing: border-box;
    }
    #bdsec-2fa-form p.description {
        margin-bottom: 16px;
        color: #50575e;
        font-size: 14px;
    }
    #bdsec-2fa-form .backup-toggle {
        display: block;
        margin: 12px 0;
        font-size: 13px;
        color: #2271b1;
        cursor: pointer;
        text-decoration: underline;
        background: none;
        border: none;
        padding: 0;
    }
    #bdsec-2fa-form .backup-toggle:hover {
        color: #135e96;
    }
    #bdsec-2fa-form .trust-label {
        display: flex;
        align-items: center;
        gap: 6px;
        margin: 16px 0;
        font-size: 13px;
        color: #50575e;
    }
    #bdsec-2fa-form .trust-label input {
        margin: 0;
    }
    #bdsec-2fa-backup-input {
        display: none;
    }
    #bdsec-2fa-backup-input .input {
        font-size: 16px;
        letter-spacing: 2px;
    }
</style>

<form name="bdsec_2fa_form" id="bdsec-2fa-form" method="post" autocomplete="off">
    <?php wp_nonce_field( 'bdsec_2fa_verify', 'bdsec_2fa_nonce' ); ?>
    <input type="hidden" name="bdsec_2fa_token" value="<?php echo esc_attr( $token ); ?>">
    <input type="hidden" name="redirect_to" value="<?php echo esc_attr( admin_url() ); ?>">
    <input type="hidden" name="bdsec_2fa_use_backup" id="bdsec-2fa-use-backup" value="">

    <!-- TOTP code input -->
    <div id="bdsec-2fa-totp-input">
        <p class="description">
            <?php esc_html_e( 'Enter the 6-digit code from your authenticator app.', 'bestdid-security' ); ?>
        </p>
        <p>
            <label for="bdsec-2fa-code" class="screen-reader-text">
                <?php esc_html_e( 'Authentication Code', 'bestdid-security' ); ?>
            </label>
            <input type="text" name="bdsec_2fa_code" id="bdsec-2fa-code"
                   class="input" maxlength="8"
                   autocomplete="one-time-code" inputmode="numeric"
                   pattern="[0-9A-Za-z]{6,8}"
                   placeholder="000000" autofocus>
        </p>
    </div>

    <!-- Backup code input (hidden by default) -->
    <div id="bdsec-2fa-backup-input">
        <p class="description">
            <?php esc_html_e( 'Enter one of your 8-character backup codes.', 'bestdid-security' ); ?>
        </p>
        <p>
            <label for="bdsec-2fa-backup-code" class="screen-reader-text">
                <?php esc_html_e( 'Backup Code', 'bestdid-security' ); ?>
            </label>
            <input type="text" id="bdsec-2fa-backup-code"
                   class="input" maxlength="8"
                   autocomplete="off"
                   placeholder="XXXXXXXX">
        </p>
    </div>

    <button type="button" class="backup-toggle" id="bdsec-toggle-backup">
        <?php esc_html_e( 'Use a backup code instead', 'bestdid-security' ); ?>
    </button>

    <label class="trust-label">
        <input type="checkbox" name="bdsec_2fa_trust" value="1">
        <?php esc_html_e( 'Trust this device for 30 days', 'bestdid-security' ); ?>
    </label>

    <p class="submit">
        <input type="submit" name="wp-submit" id="wp-submit"
               class="button button-primary button-large"
               value="<?php esc_attr_e( 'Verify', 'bestdid-security' ); ?>">
    </p>
</form>

<script>
(function() {
    var totpWrap   = document.getElementById('bdsec-2fa-totp-input');
    var backupWrap = document.getElementById('bdsec-2fa-backup-input');
    var toggleBtn  = document.getElementById('bdsec-toggle-backup');
    var useBackup  = document.getElementById('bdsec-2fa-use-backup');
    var totpInput  = document.getElementById('bdsec-2fa-code');
    var backupInput= document.getElementById('bdsec-2fa-backup-code');
    var showingBackup = false;

    toggleBtn.addEventListener('click', function() {
        showingBackup = !showingBackup;
        if (showingBackup) {
            totpWrap.style.display   = 'none';
            backupWrap.style.display = 'block';
            useBackup.value          = '1';
            toggleBtn.textContent    = '<?php echo esc_js( __( 'Use authenticator code instead', 'bestdid-security' ) ); ?>';
            backupInput.focus();
        } else {
            totpWrap.style.display   = 'block';
            backupWrap.style.display = 'none';
            useBackup.value          = '';
            toggleBtn.textContent    = '<?php echo esc_js( __( 'Use a backup code instead', 'bestdid-security' ) ); ?>';
            totpInput.focus();
        }
    });

    // When backup mode is active, copy backup code into the main code field on submit.
    document.getElementById('bdsec-2fa-form').addEventListener('submit', function() {
        if (showingBackup && backupInput.value) {
            totpInput.name  = '';
            backupInput.name = 'bdsec_2fa_code';
        }
    });
})();
</script>

<?php
login_footer();
