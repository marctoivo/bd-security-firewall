<?php
/**
 * BD License Client — handles license activation, validation, and auto-updates.
 *
 * Shared across BD Shield plugins. Each plugin instantiates with its own config.
 * Uses if(!class_exists) guard so only one copy is loaded.
 *
 * @package BD_License_Client
 * @version 1.0.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

if ( ! class_exists( 'BD_License_Client' ) ) :

class BD_License_Client {

    /** @var string License server URL */
    private $api_url = 'https://getbdshield.com';

    /** @var string Product slug on the license server */
    private $product_slug;

    /** @var string Plugin basename (e.g. "bd-antispam/bd-antispam.php") */
    private $plugin_basename;

    /** @var string Current plugin version */
    private $plugin_version;

    /** @var string wp_options key prefix (unique per plugin) */
    private $option_prefix;

    /** @var string Plugin display name */
    private $plugin_name;

    /** @var string Parent menu slug for submenu placement */
    private $menu_parent;

    /** @var string Text domain */
    private $text_domain;

    /**
     * Initialize the license client.
     *
     * @param array $config {
     *     @type string $api_url        License server URL.
     *     @type string $product_slug   Product slug on the license server.
     *     @type string $plugin_basename Plugin basename (folder/file.php).
     *     @type string $plugin_version Current plugin version.
     *     @type string $option_prefix  Unique prefix for wp_options keys.
     *     @type string $plugin_name    Plugin display name.
     *     @type string $menu_parent    Parent menu slug for submenu.
     *     @type string $text_domain    Text domain for i18n.
     * }
     */
    public function __construct( $config ) {
        $this->api_url         = rtrim( $config['api_url'] ?? $this->api_url, '/' );
        $this->product_slug    = $config['product_slug'];
        $this->plugin_basename = $config['plugin_basename'];
        $this->plugin_version  = $config['plugin_version'] ?? '1.0.0';
        $this->option_prefix   = $config['option_prefix'] ?? 'bdlc';
        $this->plugin_name     = $config['plugin_name'] ?? 'BD Plugin';
        $this->menu_parent     = $config['menu_parent'] ?? '';
        $this->text_domain     = $config['text_domain'] ?? 'bd-license-client';

        // Admin hooks.
        add_action( 'admin_menu', array( $this, 'add_license_menu' ), 20 );
        add_action( 'admin_init', array( $this, 'handle_license_actions' ) );
        add_action( 'admin_notices', array( $this, 'license_notices' ) );

        // Auto-update hooks.
        add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check_for_update' ) );
        add_filter( 'plugins_api', array( $this, 'plugin_info' ), 20, 3 );
        add_filter( 'plugin_action_links_' . $this->plugin_basename, array( $this, 'plugin_action_links' ) );

        // Post-install hooks (folder rename + cache clear).
        add_filter( 'upgrader_post_install', array( $this, 'post_install' ), 10, 3 );
        add_action( 'upgrader_process_complete', array( $this, 'after_update' ), 10, 2 );

        // Plugin row meta.
        add_filter( 'plugin_row_meta', array( $this, 'plugin_row_meta' ), 10, 2 );
    }

    // ========================================
    // OPTIONS HELPERS
    // ========================================

    private function opt( $key ) {
        return $this->option_prefix . '_license_' . $key;
    }

    public function get_license_key() {
        return get_option( $this->opt( 'key' ), '' );
    }

    public function get_license_status() {
        return get_option( $this->opt( 'status' ), 'inactive' );
    }

    private function set_license_key( $key ) {
        update_option( $this->opt( 'key' ), sanitize_text_field( $key ) );
    }

    private function set_license_status( $status ) {
        update_option( $this->opt( 'status' ), sanitize_text_field( $status ) );
    }

    private function set_license_data( $data ) {
        update_option( $this->opt( 'data' ), $data );
    }

    public function get_license_data() {
        return get_option( $this->opt( 'data' ), array() );
    }

    // ========================================
    // API COMMUNICATION
    // ========================================

    /**
     * Make a POST request to the license server.
     *
     * @param string $endpoint API endpoint (e.g. "activate").
     * @param array  $body     POST body.
     * @return array|WP_Error
     */
    private function api_request( $endpoint, $body = array() ) {
        $url = $this->api_url . '/wp-json/bdls/v1/' . $endpoint;

        $response = wp_remote_post( $url, array(
            'timeout'   => 30,
            'sslverify' => true,
            'body'      => $body,
            'headers'   => array(
                'Accept' => 'application/json',
            ),
        ) );

        if ( is_wp_error( $response ) ) {
            return $response;
        }

        $code = wp_remote_retrieve_response_code( $response );
        $json = json_decode( wp_remote_retrieve_body( $response ), true );

        if ( ! is_array( $json ) ) {
            return new WP_Error( 'invalid_response', 'Invalid response from license server.' );
        }

        return $json;
    }

    /**
     * Activate license on this site.
     */
    public function activate_license( $key ) {
        $result = $this->api_request( 'activate', array(
            'license_key' => $key,
            'site_url'    => home_url(),
            'product_slug' => $this->product_slug,
        ) );

        if ( is_wp_error( $result ) ) {
            return array( 'valid' => false, 'message' => $result->get_error_message() );
        }

        if ( ! empty( $result['valid'] ) ) {
            $this->set_license_key( $key );
            $this->set_license_status( 'active' );
            $this->set_license_data( $result );
        } else {
            $this->set_license_status( 'invalid' );
            $this->set_license_data( $result );
        }

        return $result;
    }

    /**
     * Deactivate license from this site.
     */
    public function deactivate_license() {
        $key = $this->get_license_key();

        if ( empty( $key ) ) {
            return array( 'valid' => false, 'message' => 'No license key found.' );
        }

        $result = $this->api_request( 'deactivate', array(
            'license_key' => $key,
            'site_url'    => home_url(),
        ) );

        $this->set_license_status( 'inactive' );
        $this->set_license_data( array() );

        return is_wp_error( $result ) ? array( 'message' => $result->get_error_message() ) : $result;
    }

    /**
     * Validate license (periodic check).
     */
    public function validate_license() {
        $key = $this->get_license_key();

        if ( empty( $key ) ) {
            return array( 'valid' => false );
        }

        $result = $this->api_request( 'validate', array(
            'license_key' => $key,
            'site_url'    => home_url(),
        ) );

        if ( is_wp_error( $result ) ) {
            return array( 'valid' => false, 'message' => $result->get_error_message() );
        }

        if ( ! empty( $result['valid'] ) ) {
            $this->set_license_status( 'active' );
        } else {
            $this->set_license_status( 'expired' );
        }

        $this->set_license_data( $result );
        return $result;
    }

    // ========================================
    // AUTO-UPDATE
    // ========================================

    /**
     * Check the license server for plugin updates.
     *
     * @param object $transient Update transient.
     * @return object
     */
    public function check_for_update( $transient ) {
        if ( empty( $transient->checked ) ) {
            return $transient;
        }

        $key = $this->get_license_key();

        // Skip API call if no license key is set.
        if ( empty( $key ) ) {
            return $transient;
        }

        $result = $this->api_request( 'check-update', array(
            'license_key'     => $key,
            'site_url'        => home_url(),
            'product_slug'    => $this->product_slug,
            'current_version' => $this->plugin_version,
        ) );

        if ( is_wp_error( $result ) || empty( $result['update'] ) ) {
            return $transient;
        }

        $plugin_data = new stdClass();
        $plugin_data->slug        = $this->product_slug;
        $plugin_data->plugin      = $this->plugin_basename;
        $plugin_data->new_version = $result['new_version'];
        $plugin_data->url         = $this->api_url;
        $plugin_data->package     = ! empty( $result['download_url'] ) ? $result['download_url'] : '';
        $plugin_data->tested      = $result['tested'] ?? '';
        $plugin_data->requires    = $result['requires'] ?? '';
        $plugin_data->requires_php = $result['requires_php'] ?? '';

        if ( ! empty( $result['icon_url'] ) ) {
            $plugin_data->icons = array( 'default' => $result['icon_url'] );
        }
        if ( ! empty( $result['banner_url'] ) ) {
            $plugin_data->banners = array( 'low' => $result['banner_url'] );
        }

        $transient->response[ $this->plugin_basename ] = $plugin_data;

        return $transient;
    }

    /**
     * Provide plugin info for the "View details" popup.
     */
    public function plugin_info( $result, $action, $args ) {
        if ( 'plugin_information' !== $action ) {
            return $result;
        }

        if ( ! isset( $args->slug ) || $args->slug !== $this->product_slug ) {
            return $result;
        }

        $key = $this->get_license_key();

        $info = $this->api_request( 'check-update', array(
            'license_key'     => $key,
            'site_url'        => home_url(),
            'product_slug'    => $this->product_slug,
            'current_version' => $this->plugin_version,
        ) );

        if ( is_wp_error( $info ) ) {
            return $result;
        }

        $plugin_info = new stdClass();
        $plugin_info->name          = $info['name'] ?? $this->plugin_name;
        $plugin_info->slug          = $this->product_slug;
        $plugin_info->version       = $info['new_version'] ?? $this->plugin_version;
        $plugin_info->tested        = $info['tested'] ?? '';
        $plugin_info->requires      = $info['requires'] ?? '';
        $plugin_info->requires_php  = $info['requires_php'] ?? '';
        $plugin_info->author        = '<a href="https://getbdshield.com">BD Shield</a>';
        $plugin_info->homepage      = $this->api_url;
        $plugin_info->download_link = ! empty( $info['download_url'] ) ? $info['download_url'] : '';

        if ( ! empty( $info['changelog'] ) ) {
            $plugin_info->sections = array(
                'changelog' => $info['changelog'],
            );
        }

        if ( ! empty( $info['banner_url'] ) ) {
            $plugin_info->banners = array( 'low' => $info['banner_url'] );
        }

        return $plugin_info;
    }

    /**
     * After WordPress extracts the update ZIP, rename the folder to match our plugin slug.
     * Without this, a ZIP with a mismatched top-level folder breaks the plugin.
     */
    public function post_install( $response, $hook_extra, $result ) {
        if ( empty( $hook_extra['plugin'] ) || $hook_extra['plugin'] !== $this->plugin_basename ) {
            return $result;
        }

        global $wp_filesystem;
        $expected_folder  = dirname( $this->plugin_basename );
        $installed_folder = isset( $result['destination_name'] ) ? $result['destination_name'] : '';

        if ( $installed_folder && $installed_folder !== $expected_folder ) {
            $plugins_dir = $wp_filesystem->wp_plugins_dir();
            $old_path    = trailingslashit( $plugins_dir ) . $installed_folder;
            $new_path    = trailingslashit( $plugins_dir ) . $expected_folder;

            if ( $wp_filesystem->move( $old_path, $new_path ) ) {
                $result['destination']      = $new_path;
                $result['destination_name'] = $expected_folder;
            }
        }

        return $result;
    }

    /**
     * After the plugin is updated, clear the update_plugins transient so WP
     * does not keep showing a stale "update available" notice.
     */
    public function after_update( $upgrader, $options ) {
        if ( 'update' !== ( $options['action'] ?? '' ) || 'plugin' !== ( $options['type'] ?? '' ) ) {
            return;
        }

        $plugins = $options['plugins'] ?? array();
        if ( in_array( $this->plugin_basename, $plugins, true ) ) {
            delete_site_transient( 'update_plugins' );
        }
    }

    // ========================================
    // ADMIN UI
    // ========================================

    /**
     * Add license submenu page.
     */
    public function add_license_menu() {
        if ( empty( $this->menu_parent ) ) {
            return;
        }

        add_submenu_page(
            $this->menu_parent,
            'License',
            'License',
            'manage_options',
            $this->option_prefix . '-license',
            array( $this, 'render_license_page' )
        );
    }

    /**
     * Handle license form submissions (activate/deactivate).
     */
    public function handle_license_actions() {
        if ( ! isset( $_POST[ $this->option_prefix . '_license_nonce' ] ) ) {
            return;
        }

        if ( ! wp_verify_nonce( $_POST[ $this->option_prefix . '_license_nonce' ], $this->option_prefix . '_license_action' ) ) {
            return;
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        if ( isset( $_POST[ $this->option_prefix . '_activate' ] ) ) {
            $key = sanitize_text_field( $_POST[ $this->option_prefix . '_license_key' ] ?? '' );
            if ( ! empty( $key ) ) {
                $result = $this->activate_license( $key );
                if ( ! empty( $result['valid'] ) ) {
                    add_settings_error( $this->option_prefix . '_license', 'activated', 'License activated successfully!', 'success' );
                } else {
                    $msg = $result['message'] ?? 'Activation failed.';
                    add_settings_error( $this->option_prefix . '_license', 'activation_failed', esc_html( $msg ), 'error' );
                }
            }
        }

        if ( isset( $_POST[ $this->option_prefix . '_deactivate' ] ) ) {
            $this->deactivate_license();
            add_settings_error( $this->option_prefix . '_license', 'deactivated', 'License deactivated.', 'updated' );
        }
    }

    /**
     * Show admin notice if license is not active.
     */
    public function license_notices() {
        $screen = get_current_screen();
        if ( ! $screen ) {
            return;
        }

        // Only show on this plugin's pages or the plugins list.
        $show_on = array( 'plugins', 'toplevel_page_' . $this->menu_parent );
        $dominated = false;
        foreach ( $show_on as $id ) {
            if ( false !== strpos( $screen->id, $id ) || $screen->id === $id ) {
                $dominated = true;
                break;
            }
        }

        if ( ! $dominated ) {
            return;
        }

        $status = $this->get_license_status();
        if ( 'active' === $status ) {
            return;
        }

        $license_url = admin_url( 'admin.php?page=' . $this->option_prefix . '-license' );
        $plugin_name = esc_html( $this->plugin_name );

        echo '<div style="display:flex;align-items:flex-start;gap:14px;background:linear-gradient(135deg,#451a03,#78350f);border:1px solid #92400e;border-radius:10px;padding:18px 22px;margin:20px 20px 0 0;color:#fef3c7;">';
        echo '<span class="dashicons dashicons-warning" style="font-size:24px;width:24px;height:24px;margin-top:2px;color:#fbbf24;"></span>';
        echo '<div>';
        echo '<strong style="display:block;font-size:15px;color:#fff;margin-bottom:4px;">' . $plugin_name . ' &mdash; License Required</strong>';
        echo '<p style="margin:0;font-size:13px;color:#fde68a;line-height:1.5;"><a href="' . esc_url( $license_url ) . '" style="color:#fbbf24;text-decoration:underline;">Enter your license key</a> to enable automatic updates.</p>';
        echo '</div></div>';
    }

    /**
     * Add "License" link to plugin action links.
     */
    public function plugin_action_links( $links ) {
        $license_url = admin_url( 'admin.php?page=' . $this->option_prefix . '-license' );
        $status = $this->get_license_status();
        $color = 'active' === $status ? '#46b450' : '#dc3232';
        $label = 'active' === $status ? 'Licensed' : 'Activate License';

        array_unshift( $links, '<a href="' . esc_url( $license_url ) . '" style="color:' . $color . ';font-weight:600;">' . $label . '</a>' );

        return $links;
    }

    /**
     * Plugin row meta.
     */
    public function plugin_row_meta( $links, $file ) {
        if ( $file !== $this->plugin_basename ) {
            return $links;
        }

        $links[] = '<a href="https://getbdshield.com/support/">Support</a>';
        return $links;
    }

    /**
     * Render the license admin page.
     */
    public function render_license_page() {
        $key    = $this->get_license_key();
        $status = $this->get_license_status();
        $data   = $this->get_license_data();
        $masked = '';
        if ( ! empty( $key ) ) {
            $masked = substr( $key, 0, 9 ) . str_repeat( '*', max( 0, strlen( $key ) - 13 ) ) . substr( $key, -4 );
        }

        $status_colors = array(
            'active'   => '#46b450',
            'inactive' => '#999',
            'expired'  => '#dc3232',
            'invalid'  => '#dc3232',
        );
        $status_color = $status_colors[ $status ] ?? '#999';
        $nonce_action = $this->option_prefix . '_license_action';
        $nonce_field  = $this->option_prefix . '_license_nonce';
        ?>
        <div class="wrap">
            <h1><?php echo esc_html( $this->plugin_name ); ?> — License</h1>

            <?php settings_errors( $this->option_prefix . '_license' ); ?>

            <div style="max-width:600px;background:#fff;border:1px solid #ccd0d4;border-radius:6px;padding:24px;margin-top:16px;">

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">Status</th>
                        <td>
                            <span style="display:inline-block;padding:4px 12px;border-radius:4px;background:<?php echo esc_attr( $status_color ); ?>;color:#fff;font-weight:600;text-transform:uppercase;font-size:12px;">
                                <?php echo esc_html( $status ); ?>
                            </span>
                            <?php if ( ! empty( $data['expires'] ) ) : ?>
                                <span style="margin-left:10px;color:#666;">Expires: <?php echo esc_html( $data['expires'] ); ?></span>
                            <?php endif; ?>
                            <?php if ( ! empty( $data['activations_left'] ) ) : ?>
                                <span style="margin-left:10px;color:#666;">Sites left: <?php echo esc_html( $data['activations_left'] ); ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                </table>

                <?php if ( 'active' === $status ) : ?>
                    <p style="color:#666;">License key: <code><?php echo esc_html( $masked ); ?></code></p>
                    <form method="post">
                        <?php wp_nonce_field( $nonce_action, $nonce_field ); ?>
                        <p>
                            <button type="submit" name="<?php echo esc_attr( $this->option_prefix ); ?>_deactivate" value="1" class="button">
                                Deactivate License
                            </button>
                        </p>
                    </form>
                <?php else : ?>
                    <form method="post">
                        <?php wp_nonce_field( $nonce_action, $nonce_field ); ?>
                        <table class="form-table" role="presentation">
                            <tr>
                                <th scope="row"><label for="license_key">License Key</label></th>
                                <td>
                                    <input type="text" id="license_key"
                                           name="<?php echo esc_attr( $this->option_prefix ); ?>_license_key"
                                           value="<?php echo esc_attr( $key ); ?>"
                                           class="regular-text" placeholder="BDSH-XXXX-XXXX-XXXX-XXXX"
                                           style="font-family:monospace;" />
                                </td>
                            </tr>
                        </table>
                        <p>
                            <button type="submit" name="<?php echo esc_attr( $this->option_prefix ); ?>_activate" value="1" class="button button-primary">
                                Activate License
                            </button>
                        </p>
                    </form>
                <?php endif; ?>

                <hr style="margin:20px 0;border-color:#eee;" />
                <p style="color:#999;font-size:12px;">
                    Your license key was emailed to you after purchase.
                    Need help? Visit <a href="https://getbdshield.com/support/" target="_blank">BD Shield Support</a>.
                </p>
            </div>
        </div>
        <?php
    }
}

endif;
