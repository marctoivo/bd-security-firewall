<?php
/**
 * Two-Factor Authentication Setup Form (shown during login)
 *
 * Displayed when a user's role requires 2FA but they haven't set it up yet.
 * Variables: $user, $token, $error_message, $secret, $provisioning_uri.
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

login_header(
    __( 'Set Up Two-Factor Authentication', 'bestdid-security' ),
    $error_message ? '<div id="login_error" role="alert">' . esc_html( $error_message ) . '</div>' : ''
);
?>

<style>
    #bdsec-2fa-setup p.setup-intro {
        margin-bottom: 20px;
        color: #50575e;
        font-size: 14px;
        line-height: 1.6;
    }
    #bdsec-2fa-setup .qr-wrapper {
        text-align: center;
        margin: 20px 0;
    }
    #bdsec-2fa-setup .qr-wrapper img {
        border: 4px solid #fff;
        box-shadow: 0 2px 8px rgba(0,0,0,0.12);
        border-radius: 8px;
    }
    #bdsec-2fa-setup .secret-display {
        text-align: center;
        margin: 12px 0 20px;
    }
    #bdsec-2fa-setup .secret-display code {
        font-size: 14px;
        padding: 6px 12px;
        background: #f0f0f1;
        border-radius: 4px;
        letter-spacing: 2px;
        user-select: all;
    }
    #bdsec-2fa-setup .input {
        font-size: 24px;
        letter-spacing: 8px;
        text-align: center;
        padding: 8px 12px;
        width: 100%;
        box-sizing: border-box;
    }
    #bdsec-2fa-setup .trust-label {
        display: flex;
        align-items: center;
        gap: 6px;
        margin: 16px 0;
        font-size: 13px;
        color: #50575e;
    }
    #bdsec-2fa-setup .trust-label input {
        margin: 0;
    }
    #bdsec-2fa-setup .step-label {
        font-weight: 600;
        color: #1d2327;
        margin-bottom: 6px;
        font-size: 13px;
    }
</style>

<form name="bdsec_2fa_setup" id="bdsec-2fa-setup" method="post" autocomplete="off">
    <?php wp_nonce_field( 'bdsec_2fa_verify', 'bdsec_2fa_nonce' ); ?>
    <input type="hidden" name="bdsec_2fa_token" value="<?php echo esc_attr( $token ); ?>">
    <input type="hidden" name="redirect_to" value="<?php echo esc_attr( admin_url() ); ?>">

    <p class="setup-intro">
        <?php esc_html_e( 'Your account requires two-factor authentication. Scan the QR code below with an authenticator app like Google Authenticator or Authy.', 'bestdid-security' ); ?>
    </p>

    <div class="qr-wrapper">
        <?php
        $qr_svg = BDSEC_QR::svg( $provisioning_uri, 200 );
        if ( $qr_svg ) {
            echo $qr_svg;
        } else {
            echo '<p>' . esc_html__( 'QR code generation failed. Please enter the secret manually below.', 'bestdid-security' ) . '</p>';
        }
        ?>
    </div>

    <div class="secret-display">
        <p class="step-label"><?php esc_html_e( 'Or enter this secret manually:', 'bestdid-security' ); ?></p>
        <code><?php echo esc_html( $secret ); ?></code>
    </div>

    <p class="step-label"><?php esc_html_e( 'Enter the 6-digit code from your app to verify:', 'bestdid-security' ); ?></p>
    <p>
        <input type="text" name="bdsec_2fa_code" id="bdsec-2fa-code"
               class="input" maxlength="6"
               autocomplete="one-time-code" inputmode="numeric"
               pattern="[0-9]{6}" placeholder="000000" autofocus>
    </p>

    <label class="trust-label">
        <input type="checkbox" name="bdsec_2fa_trust" value="1">
        <?php esc_html_e( 'Trust this device for 30 days', 'bestdid-security' ); ?>
    </label>

    <p class="submit">
        <input type="submit" name="wp-submit" id="wp-submit"
               class="button button-primary button-large"
               value="<?php esc_attr_e( 'Verify & Enable 2FA', 'bestdid-security' ); ?>">
    </p>
</form>

<?php
login_footer();
