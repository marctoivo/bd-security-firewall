<?php
/**
 * Admin Settings Template
 * 
 * @package BestDid_Security
 */

if (!defined('ABSPATH')) exit;
?>
<div class="wrap">
    <h1>Security Settings</h1>
    
    <?php if (isset($updated) && $updated) : ?>
        <div class="notice notice-success is-dismissible">
            <p>Settings saved successfully!</p>
            <?php 
            $settings = get_option('bestdid_security_settings');
            if (!empty($settings['custom_login_slug'])) : 
            ?>
                <p><strong>✓ Custom Login URL is active.</strong> Go to Settings → Login Security to view your URL.</p>
                <p style="color: #d63638;">⚠️ <strong>Important:</strong> Make sure to bookmark your login URL! The old /wp-admin and /wp-login.php will show a 404 page.</p>
            <?php endif; ?>
        </div>
    <?php endif; ?>
    
    <style>
        .settings-form { background: white; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); padding: 30px; margin-top: 20px; max-width: 900px; }
        .settings-section { margin-bottom: 40px; }
        .settings-section:last-child { margin-bottom: 0; }
        .settings-section h2 { font-size: 18px; font-weight: 600; margin: 0 0 20px; padding-bottom: 10px; border-bottom: 1px solid #e0e0e0; }
        .setting-row { display: flex; align-items: flex-start; padding: 15px 0; border-bottom: 1px solid #f0f0f1; }
        .setting-row:last-child { border-bottom: none; }
        .setting-label { flex: 1; }
        .setting-label strong { display: block; margin-bottom: 4px; }
        .setting-label span { font-size: 13px; color: #646970; }
        .setting-control { width: 200px; text-align: right; }
        .setting-control.wide { width: 300px; }
        .toggle-switch { position: relative; width: 48px; height: 24px; display: inline-block; }
        .toggle-switch input { opacity: 0; width: 0; height: 0; }
        .toggle-slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: 0.3s; border-radius: 24px; }
        .toggle-slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; transition: 0.3s; border-radius: 50%; }
        .toggle-switch input:checked + .toggle-slider { background-color: #00a32a; }
        .toggle-switch input:checked + .toggle-slider:before { transform: translateX(24px); }
        .number-input { width: 80px; padding: 8px 12px; border: 1px solid #8c8f94; border-radius: 4px; font-size: 14px; }
        .text-input { width: 100%; padding: 8px 12px; border: 1px solid #8c8f94; border-radius: 4px; font-size: 14px; }
        .submit-row { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; }
        .new-badge { display: inline-block; background: #d63638; color: white; font-size: 10px; padding: 2px 6px; border-radius: 3px; margin-left: 8px; font-weight: 600; }
        .current-url { margin-top: 8px; padding: 10px; background: #f0f0f1; border-radius: 4px; font-family: monospace; font-size: 13px; }
        .warning-box { background: #fcf9e8; border-left: 4px solid #dba617; padding: 12px 16px; margin-top: 10px; font-size: 13px; }
    </style>
    
    <form method="post" class="settings-form">
        <?php wp_nonce_field('bestdid_security_save_settings', 'bestdid_security_settings_nonce'); ?>
        
        <div class="settings-section">
            <h2>🔐 Login Security <span class="new-badge">NEW</span></h2>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Custom Login URL</strong>
                    <span>Hide wp-login.php and wp-admin from bots. Leave empty to disable.</span>
                    <?php if (!empty($settings['custom_login_slug'])) : ?>
                        <div class="current-url" style="margin-top: 10px;">
                            <span style="color: #22c55e; font-weight: 600;">✓ Custom URL Active</span>
                        </div>
                    <?php endif; ?>
                    <div class="warning-box">⚠️ After setting this, bookmark your new login URL! You will not be able to access /wp-admin directly.</div>
                </div>
                <div class="setting-control wide">
                    <div style="position: relative; display: flex; gap: 10px; align-items: center;">
                        <input type="password" name="custom_login_slug" id="custom_login_slug" class="text-input" value="<?php echo esc_attr($settings['custom_login_slug'] ?? ''); ?>" placeholder="e.g., my-secret-login" style="flex: 1;">
                        <button type="button" id="toggle_login_url" style="background: #2271b1; border: none; color: #fff; padding: 10px 18px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 500; white-space: nowrap;">👁 Show</button>
                    </div>
                    <?php if (!empty($settings['custom_login_slug'])) : ?>
                        <div id="login_url_preview" style="margin-top: 12px; padding: 14px 18px; background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; display: none;">
                            <span style="color: #666; font-size: 12px; display: block; margin-bottom: 6px;">Your login URL:</span>
                            <code style="color: #16a34a; font-size: 14px; background: #dcfce7; padding: 6px 10px; border-radius: 4px; display: inline-block;"><?php echo esc_url(home_url('/' . $settings['custom_login_slug'] . '/')); ?></code>
                            <button type="button" id="copy_login_url" style="margin-left: 10px; background: #22c55e; border: none; color: #fff; padding: 6px 14px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 500;">📋 Copy</button>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
            
            <script>
            (function() {
                var toggleBtn = document.getElementById('toggle_login_url');
                var input = document.getElementById('custom_login_slug');
                var preview = document.getElementById('login_url_preview');
                var copyBtn = document.getElementById('copy_login_url');
                
                if (toggleBtn) {
                    toggleBtn.addEventListener('click', function() {
                        if (input.type === 'password') {
                            input.type = 'text';
                            this.innerHTML = '🙈 Hide';
                            this.style.background = '#dc2626';
                            if (preview) preview.style.display = 'block';
                        } else {
                            input.type = 'password';
                            this.innerHTML = '👁 Show';
                            this.style.background = '#2271b1';
                            if (preview) preview.style.display = 'none';
                        }
                    });
                }
                
                if (copyBtn) {
                    copyBtn.addEventListener('click', function() {
                        var url = '<?php echo esc_url(home_url('/' . ($settings['custom_login_slug'] ?? '') . '/')); ?>';
                        navigator.clipboard.writeText(url).then(function() {
                            copyBtn.innerHTML = '✓ Copied!';
                            copyBtn.style.background = '#16a34a';
                            setTimeout(function() {
                                copyBtn.innerHTML = '📋 Copy';
                                copyBtn.style.background = '#22c55e';
                            }, 2000);
                        });
                    });
                }
            })();
            </script>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Hide Login Error Messages</strong>
                    <span>Do not reveal whether username or password was wrong</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="hide_login_errors" value="1" <?php checked(!empty($settings['hide_login_errors'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Auto Logout (minutes)</strong>
                    <span>Automatically log out inactive users. 0 = disabled.</span>
                </div>
                <div class="setting-control">
                    <input type="number" name="auto_logout_minutes" class="number-input" value="<?php echo intval($settings['auto_logout_minutes'] ?? 0); ?>" min="0" max="1440">
                </div>
            </div>
        </div>
        
        <div class="settings-section">
            <h2>🔐 Two-Factor Authentication <span class="new-badge">NEW</span></h2>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Enable Two-Factor Authentication</strong>
                    <span>Require a TOTP code (Google Authenticator, Authy) after password login</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="two_factor_enabled" value="1" <?php checked(!empty($settings['two_factor_enabled'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Enforce for Roles</strong>
                    <span>Which user roles can use (or be required to use) 2FA</span>
                </div>
                <div class="setting-control wide">
                    <?php
                    $two_factor_roles = $settings['two_factor_roles'] ?? array('administrator');
                    $available_roles = array('administrator' => 'Administrator', 'editor' => 'Editor', 'author' => 'Author');
                    foreach ($available_roles as $role_key => $role_label) :
                    ?>
                        <label style="display:block;margin-bottom:6px;">
                            <input type="checkbox" name="two_factor_roles[]" value="<?php echo esc_attr($role_key); ?>" <?php checked(in_array($role_key, (array) $two_factor_roles)); ?>>
                            <?php echo esc_html($role_label); ?>
                        </label>
                    <?php endforeach; ?>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Force Setup</strong>
                    <span>Require users in selected roles to set up 2FA on next login. They cannot access wp-admin until 2FA is configured.</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="two_factor_forced" value="1" <?php checked(!empty($settings['two_factor_forced'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
        </div>

        <div class="settings-section">
            <h2>🛡️ Attack Prevention</h2>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>SQL Injection Protection</strong>
                    <span>Blocks attempts to inject malicious SQL queries</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="sql_injection_protection" value="1" <?php checked(!empty($settings['sql_injection_protection'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>XSS Attack Prevention</strong>
                    <span>Prevents cross-site scripting attacks</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="xss_protection" value="1" <?php checked(!empty($settings['xss_protection'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Block Bad Bots</strong>
                    <span>Blocks known malicious bots and scanners</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="block_bad_bots" value="1" <?php checked(!empty($settings['block_bad_bots'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Block Dangerous Uploads</strong>
                    <span>Prevents uploading PHP, EXE, and other dangerous files</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="block_php_uploads" value="1" <?php checked(!empty($settings['block_php_uploads'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
        </div>
        
        <div class="settings-section">
            <h2>🔒 Brute Force Protection</h2>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Enable Brute Force Protection</strong>
                    <span>Limits failed login attempts</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="brute_force_protection" value="1" <?php checked(!empty($settings['brute_force_protection'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Max Login Attempts</strong>
                    <span>Failed attempts before lockout</span>
                </div>
                <div class="setting-control">
                    <input type="number" name="max_login_attempts" class="number-input" value="<?php echo intval($settings['max_login_attempts'] ?? 5); ?>" min="1" max="20">
                </div>
            </div>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Lockout Duration (minutes)</strong>
                    <span>Minutes to block IP after max attempts</span>
                </div>
                <div class="setting-control">
                    <input type="number" name="lockout_duration" class="number-input" value="<?php echo intval($settings['lockout_duration'] ?? 30); ?>" min="5" max="1440">
                </div>
            </div>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Force Strong Passwords</strong>
                    <span>Require 12+ chars with mixed case, numbers, and symbols</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="force_strong_passwords" value="1" <?php checked(!empty($settings['force_strong_passwords'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
        </div>
        
        <div class="settings-section">
            <h2>⚡ Rate Limiting</h2>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Enable Rate Limiting</strong>
                    <span>Limits requests per IP to prevent abuse</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="rate_limiting" value="1" <?php checked(!empty($settings['rate_limiting'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Requests Per Minute</strong>
                    <span>Max requests per IP per minute</span>
                </div>
                <div class="setting-control">
                    <input type="number" name="rate_limit_requests" class="number-input" value="<?php echo intval($settings['rate_limit_requests'] ?? 60); ?>" min="10" max="500">
                </div>
            </div>
        </div>
        
        <div class="settings-section">
            <h2>✅ IP Whitelist</h2>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Whitelisted IP Addresses</strong>
                    <span>These IPs will never be blocked. One IP per line. <a href="https://whatismyip.com" target="_blank">Find your IP</a></span>
                    <div class="warning-box" style="background: #e7f5ea; border-color: #00a32a;">💡 Add your own IP address to prevent accidentally blocking yourself.</div>
                </div>
                <div class="setting-control wide">
                    <textarea name="whitelisted_ips" class="text-input" rows="4" style="width: 100%; font-family: monospace;" placeholder="e.g.&#10;192.168.1.1&#10;10.0.0.1"><?php echo esc_textarea($settings['whitelisted_ips'] ?? ''); ?></textarea>
                </div>
            </div>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Whitelist Logged-in Admins</strong>
                    <span>Never block logged-in administrators</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="whitelist_admins" value="1" <?php checked(!empty($settings['whitelist_admins'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
        </div>
        
        <div class="settings-section">
            <h2>🔧 Additional Hardening</h2>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Hide WordPress Version</strong>
                    <span>Removes WP version from source code and scripts</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="hide_wp_version" value="1" <?php checked(!empty($settings['hide_wp_version'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Disable XML-RPC</strong>
                    <span>Blocks XML-RPC which is often exploited</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="disable_xmlrpc" value="1" <?php checked(!empty($settings['disable_xmlrpc'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Disable File Editor</strong>
                    <span>Removes Theme/Plugin Editor from admin</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="disable_file_editor" value="1" <?php checked(!empty($settings['disable_file_editor'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Disable RSS Feeds</strong>
                    <span>Prevents content scraping via RSS</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="disable_rss_feeds" value="1" <?php checked(!empty($settings['disable_rss_feeds'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
            
            <div class="setting-row">
                <div class="setting-label">
                    <strong>Log Retention Days</strong>
                    <span>How long to keep security logs</span>
                </div>
                <div class="setting-control">
                    <input type="number" name="log_retention_days" class="number-input" value="<?php echo intval($settings['log_retention_days'] ?? 30); ?>" min="7" max="365">
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Enable HSTS</strong>
                    <span>Forces HTTPS via Strict-Transport-Security header (1 year). Only enable if your site fully supports HTTPS.</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="enable_hsts" value="1" <?php checked(!empty($settings['enable_hsts'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
        </div>
        
        <div class="settings-section">
            <h2>🔍 Malware Scanner <span class="new-badge">NEW</span></h2>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Enable Scanner</strong>
                    <span>Activate the malware scanner feature</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="scanner_enabled" value="1" <?php checked(!empty($settings['scanner_enabled'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Scan Schedule</strong>
                    <span>How often to run automated scans</span>
                </div>
                <div class="setting-control">
                    <select name="scanner_schedule" style="width:100%;padding:8px 12px;border:1px solid #8c8f94;border-radius:4px;font-size:14px;">
                        <option value="manual" <?php selected(($settings['scanner_schedule'] ?? 'manual'), 'manual'); ?>>Manual Only</option>
                        <option value="daily" <?php selected(($settings['scanner_schedule'] ?? 'manual'), 'daily'); ?>>Daily</option>
                        <option value="weekly" <?php selected(($settings['scanner_schedule'] ?? 'manual'), 'weekly'); ?>>Weekly</option>
                    </select>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Check Core Integrity</strong>
                    <span>Compare WordPress core files against official checksums</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="scanner_check_core" value="1" <?php checked($settings['scanner_check_core'] ?? true); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Check Malware Patterns</strong>
                    <span>Scan files for known malware signatures and obfuscated code</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="scanner_check_malware" value="1" <?php checked($settings['scanner_check_malware'] ?? true); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Check PHP in Uploads</strong>
                    <span>Detect PHP files in the uploads directory (common backdoor location)</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="scanner_check_uploads" value="1" <?php checked($settings['scanner_check_uploads'] ?? true); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Email Alerts on Critical Findings</strong>
                    <span>Send email to admin when scheduled scans find threats</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="scanner_email_alerts" value="1" <?php checked(!empty($settings['scanner_email_alerts'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Auto-Quarantine Critical Threats</strong>
                    <span>Automatically quarantine files rated critical during scheduled scans</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="scanner_auto_quarantine" value="1" <?php checked(!empty($settings['scanner_auto_quarantine'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
        </div>

        <div class="settings-section">
            <h2>🌍 Geo-Blocking</h2>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Enable Geo-Blocking</strong>
                    <span>Block or allow traffic based on country of origin</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="geo_blocking_enabled" value="1" <?php checked(!empty($settings['geo_blocking_enabled'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Mode</strong>
                    <span>Blacklist blocks listed countries; Whitelist allows only listed countries</span>
                </div>
                <div class="setting-control">
                    <select name="geo_mode" style="width:100%;padding:8px 12px;border:1px solid #8c8f94;border-radius:4px;font-size:14px;">
                        <option value="disabled" <?php selected(($settings['geo_mode'] ?? 'disabled'), 'disabled'); ?>>Disabled</option>
                        <option value="blacklist" <?php selected(($settings['geo_mode'] ?? 'disabled'), 'blacklist'); ?>>Blacklist</option>
                        <option value="whitelist" <?php selected(($settings['geo_mode'] ?? 'disabled'), 'whitelist'); ?>>Whitelist</option>
                    </select>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Log Blocked Requests</strong>
                    <span>Keep a log of geo-blocked requests</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="geo_log_blocked" value="1" <?php checked(!empty($settings['geo_log_blocked'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
        </div>

        <div class="settings-section">
            <h2>📋 Activity Logging</h2>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Enable Activity Logging</strong>
                    <span>Track admin actions (logins, settings changes, content edits)</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="activity_logging_enabled" value="1" <?php checked(!empty($settings['activity_logging_enabled'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Retention Days</strong>
                    <span>Automatically delete log entries older than this</span>
                </div>
                <div class="setting-control">
                    <input type="number" name="activity_retention_days" class="number-input" value="<?php echo intval($settings['activity_retention_days'] ?? 90); ?>" min="1" max="365">
                </div>
            </div>
        </div>

        <div class="settings-section">
            <h2>📁 File Integrity Monitor</h2>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Enable File Integrity Monitor</strong>
                    <span>Hash-based monitoring of core, theme, and plugin files</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="file_integrity_enabled" value="1" <?php checked(!empty($settings['file_integrity_enabled'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Check Schedule</strong>
                    <span>How often to run automated integrity checks</span>
                </div>
                <div class="setting-control">
                    <select name="fim_schedule" style="width:100%;padding:8px 12px;border:1px solid #8c8f94;border-radius:4px;font-size:14px;">
                        <option value="manual" <?php selected(($settings['fim_schedule'] ?? 'daily'), 'manual'); ?>>Manual Only</option>
                        <option value="daily" <?php selected(($settings['fim_schedule'] ?? 'daily'), 'daily'); ?>>Daily</option>
                        <option value="weekly" <?php selected(($settings['fim_schedule'] ?? 'daily'), 'weekly'); ?>>Weekly</option>
                    </select>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Email Alerts on Changes</strong>
                    <span>Send email to admin when scheduled checks detect file changes</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="fim_email_alerts" value="1" <?php checked(!empty($settings['fim_email_alerts'])); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>
        </div>

        <div class="submit-row">
            <button type="submit" class="button button-primary button-large">Save Settings</button>
        </div>
    </form>
</div>
