<?php
/**
 * Two-Factor Authentication — Backup Codes Display
 *
 * Shown after initial 2FA setup during login. User must save these codes
 * before continuing to wp-admin.
 *
 * Variables: $user, $backup_codes, $login_token.
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

login_header( __( '2FA Enabled — Save Your Backup Codes', 'bestdid-security' ) );
?>

<style>
    #bdsec-backup-page {
        text-align: center;
    }
    #bdsec-backup-page .success-icon {
        font-size: 48px;
        margin-bottom: 10px;
    }
    #bdsec-backup-page h2 {
        font-size: 18px;
        margin: 0 0 10px;
        color: #1d2327;
    }
    #bdsec-backup-page .description {
        color: #50575e;
        font-size: 13px;
        margin-bottom: 20px;
        line-height: 1.5;
    }
    #bdsec-backup-page .codes-box {
        background: #f6f7f7;
        border: 1px solid #c3c4c7;
        border-radius: 6px;
        padding: 16px;
        margin: 16px 0;
        text-align: left;
    }
    #bdsec-backup-page .codes-box pre {
        margin: 0;
        font-family: 'SF Mono', Monaco, 'Courier New', monospace;
        font-size: 14px;
        line-height: 2;
        white-space: pre-wrap;
        text-align: center;
    }
    #bdsec-backup-page .warning {
        background: #fcf9e8;
        border-left: 4px solid #dba617;
        padding: 10px 14px;
        font-size: 12px;
        color: #50575e;
        text-align: left;
        margin: 16px 0;
        line-height: 1.5;
    }
</style>

<div id="bdsec-backup-page">
    <div class="success-icon">&#9989;</div>
    <h2><?php esc_html_e( 'Two-Factor Authentication Enabled!', 'bestdid-security' ); ?></h2>
    <p class="description">
        <?php esc_html_e( 'Save these backup codes somewhere safe. Each code can only be used once if you lose access to your authenticator app.', 'bestdid-security' ); ?>
    </p>

    <div class="codes-box">
        <pre><?php echo esc_html( implode( "\n", $backup_codes ) ); ?></pre>
    </div>

    <div class="warning">
        <strong><?php esc_html_e( 'Important:', 'bestdid-security' ); ?></strong>
        <?php esc_html_e( 'These codes will NOT be shown again. Copy or print them now.', 'bestdid-security' ); ?>
    </div>

    <?php
    $continue_url = add_query_arg( array(
        'action'      => 'bdsec_2fa_complete',
        'login_token' => $login_token,
    ), wp_login_url() );
    ?>
    <p class="submit">
        <a href="<?php echo esc_url( $continue_url ); ?>" class="button button-primary button-large" style="width:100%;text-align:center;">
            <?php esc_html_e( 'I\'ve Saved My Codes — Continue', 'bestdid-security' ); ?>
        </a>
    </p>
</div>

<?php
login_footer();
