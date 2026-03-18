<?php
/**
 * Admin Geo-Blocking Template
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) exit;

$settings      = get_option( 'bestdid_security_settings' );
$blocked_today = BDSEC_Geo_Blocking::get_blocked_today();
$country_stats = BDSEC_Geo_Blocking::get_country_stats();
?>
<div class="wrap bestdid-security-wrap">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

        .bestdid-security-wrap {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%) !important;
            margin-left: -20px !important; padding: 30px !important; min-height: 100vh;
        }
        .bestdid-security-wrap * { box-sizing: border-box; }

        .bdsec-page-header {
            display: flex; align-items: center; gap: 20px; margin-bottom: 30px;
        }
        .bdsec-page-icon {
            width: 60px; height: 60px;
            background: linear-gradient(135deg, #D97757, #E29578);
            border-radius: 16px; display: flex; align-items: center; justify-content: center;
            font-size: 28px; box-shadow: 0 10px 30px rgba(217, 119, 87, 0.3); flex-shrink: 0;
        }
        .bdsec-page-header h1 { margin: 0 !important; padding: 0 !important; font-size: 28px !important; font-weight: 700 !important; color: #fff !important; }
        .bdsec-page-header p { margin: 5px 0 0 !important; color: rgba(255,255,255,0.6) !important; font-size: 14px !important; }

        .card {
            background: rgba(255,255,255,0.05); backdrop-filter: blur(10px);
            border: 1px solid rgba(255,255,255,0.1); border-radius: 20px;
            padding: 30px; margin-bottom: 25px; color: #fff;
        }
        .card h2 { margin:0 0 20px !important; padding:0 !important; font-size:20px !important; font-weight:600 !important; color:#fff !important; }

        .stats-row { display:grid; grid-template-columns:repeat(3,1fr); gap:20px; margin-bottom:30px; }
        .mini-stat {
            background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1);
            border-radius:16px; padding:24px; text-align:center; transition:all 0.3s;
        }
        .mini-stat:hover { transform:translateY(-3px); background:rgba(255,255,255,0.08); box-shadow:0 15px 30px rgba(0,0,0,0.2); }
        .mini-stat .num { font-size:36px; font-weight:700; color:#4facfe; line-height:1; }
        .mini-stat .lbl { color:rgba(255,255,255,0.5); font-size:13px; margin-top:8px; font-weight:500; }

        /* Settings form */
        .setting-row { display:flex; justify-content:space-between; align-items:center; padding:15px 0; border-bottom:1px solid rgba(255,255,255,0.06); }
        .setting-row:last-child { border-bottom:none; }
        .setting-label strong { color:#fff; display:block; margin-bottom:4px; }
        .setting-label span { color:rgba(255,255,255,0.5); font-size:12px; }
        .setting-control select, .setting-control input[type=text] {
            background:rgba(255,255,255,0.08) !important; border:1px solid rgba(255,255,255,0.15) !important;
            color:#fff !important; padding:10px 14px !important; border-radius:10px !important; font-size:14px !important; min-width:200px;
            height:auto !important; line-height:normal !important; box-shadow:none !important; -webkit-appearance:none;
            font-family:'Inter', sans-serif !important;
        }
        .setting-control select:focus, .setting-control input:focus {
            border-color:rgba(217,119,87,0.5) !important; background:rgba(255,255,255,0.12) !important; outline:none !important;
        }
        .setting-control select option { background:#1a1a2e !important; color:#fff !important; }
        .toggle-switch { position:relative; display:inline-block; width:50px; height:26px; }
        .toggle-switch input { opacity:0; width:0; height:0; }
        .toggle-slider {
            position:absolute; cursor:pointer; top:0; left:0; right:0; bottom:0;
            background:rgba(255,255,255,0.1); border-radius:26px; transition:.3s;
        }
        .toggle-slider::before {
            content:''; position:absolute; height:20px; width:20px; left:3px; bottom:3px;
            background:#fff; border-radius:50%; transition:.3s;
        }
        .toggle-switch input:checked + .toggle-slider { background:linear-gradient(135deg, #D97757, #E29578); }
        .toggle-switch input:checked + .toggle-slider::before { transform:translateX(24px); }

        /* Country select */
        .country-select-wrap { position:relative; }
        .country-search {
            width:100% !important; margin-bottom:8px;
            background:rgba(255,255,255,0.08) !important; border:1px solid rgba(255,255,255,0.15) !important;
            color:#fff !important; padding:10px 14px !important; border-radius:10px !important; font-size:14px !important;
            height:auto !important; box-shadow:none !important; outline:none !important;
        }
        .country-search::placeholder { color:rgba(255,255,255,0.4) !important; }
        .country-search:focus { border-color:rgba(217,119,87,0.5) !important; background:rgba(255,255,255,0.12) !important; }
        .country-list {
            max-height:200px; overflow-y:auto; background:rgba(0,0,0,0.4);
            border:1px solid rgba(255,255,255,0.1); border-radius:8px; padding:8px;
        }
        .country-list label {
            display:flex; align-items:center; gap:8px; padding:4px 8px; cursor:pointer;
            color:rgba(255,255,255,0.8); font-size:13px; border-radius:4px;
        }
        .country-list label:hover { background:rgba(255,255,255,0.05); }
        .country-list label.hidden { display:none; }
        .selected-countries { display:flex; flex-wrap:wrap; gap:6px; margin-top:8px; }
        .country-tag {
            background:rgba(217,119,87,0.2); border:1px solid rgba(217,119,87,0.4);
            color:#E29578; padding:4px 10px; border-radius:20px; font-size:12px; display:flex; align-items:center; gap:4px;
        }
        .country-tag .remove { cursor:pointer; font-weight:bold; }

        /* Table */
        .log-table { width:100%; border-collapse:collapse; }
        .log-table th { text-align:left; color:rgba(255,255,255,0.5) !important; font-size:11px !important; text-transform:uppercase; letter-spacing:0.8px; padding:12px 14px; border-bottom:2px solid rgba(255,255,255,0.1); font-weight:600 !important; background:transparent !important; }
        .log-table td { padding:12px 14px; color:rgba(255,255,255,0.8) !important; font-size:13px !important; border-bottom:1px solid rgba(255,255,255,0.04); background:transparent !important; }
        .log-table tr:hover td { background:rgba(255,255,255,0.03) !important; }

        /* Buttons */
        .btn { display:inline-flex; align-items:center; gap:6px; padding:10px 20px; border:none !important; border-radius:10px; font-size:14px; font-weight:600; cursor:pointer; transition:.3s; font-family:'Inter', sans-serif; text-decoration:none !important; }
        .btn-primary { background:linear-gradient(135deg, #D97757, #E29578) !important; color:#fff !important; }
        .btn-primary:hover { transform:translateY(-2px); box-shadow:0 10px 25px rgba(217,119,87,0.3); }
        .btn-danger { background:rgba(255,107,107,0.15) !important; border:1px solid rgba(255,107,107,0.3) !important; color:#ff6b6b !important; }
        .btn-secondary { background:rgba(255,255,255,0.08) !important; border:1px solid rgba(255,255,255,0.15) !important; color:#fff !important; }
        .btn-sm { padding:8px 16px !important; font-size:12px !important; border-radius:8px !important; }

        .pagination { display:flex; gap:8px; justify-content:center; margin-top:20px; }
        .pagination button { background:rgba(255,255,255,0.08); border:1px solid rgba(255,255,255,0.1); color:#fff; padding:6px 14px; border-radius:8px; cursor:pointer; }
        .pagination button.active { background:linear-gradient(135deg, #D97757, #E29578); }

        /* IP Test */
        .test-ip-row { display:flex; gap:10px; align-items:center; margin-top:20px; }
        .test-ip-row input {
            flex:1; background:rgba(255,255,255,0.08) !important; border:1px solid rgba(255,255,255,0.15) !important;
            color:#fff !important; padding:10px 14px !important; border-radius:10px !important; font-size:14px !important;
            height:auto !important; box-shadow:none !important; outline:none !important;
        }
        .test-ip-row input::placeholder { color:rgba(255,255,255,0.4) !important; }
        .test-ip-row input:focus { border-color:rgba(217,119,87,0.5) !important; }
        .test-result { margin-top:10px; padding:12px; border-radius:8px; font-size:13px; }
        .test-result.blocked { background:rgba(255,107,107,0.15); border:1px solid rgba(255,107,107,0.3); color:#ff6b6b; }
        .test-result.allowed { background:rgba(0,255,136,0.1); border:1px solid rgba(0,255,136,0.3); color:#00ff88; }

        .top-countries { display:flex; gap:10px; flex-wrap:wrap; }
        .top-country { background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); padding:8px 14px; border-radius:10px; font-size:13px; }
        .top-country .code { font-weight:600; color:#4facfe; }
        .top-country .count { color:rgba(255,255,255,0.5); margin-left:6px; }
    </style>

    <div class="bdsec-page-header">
        <div class="bdsec-page-icon">🌍</div>
        <div>
            <h1>Geo-Blocking</h1>
            <p>Block or allow traffic based on country of origin</p>
        </div>
    </div>

    <!-- Stats -->
    <div class="stats-row">
        <div class="mini-stat">
            <div class="num"><?php echo intval( $blocked_today ); ?></div>
            <div class="lbl">Blocked Today</div>
        </div>
        <div class="mini-stat">
            <div class="num"><?php echo count( $country_stats ); ?></div>
            <div class="lbl">Countries Blocked</div>
        </div>
        <div class="mini-stat">
            <div class="num"><?php echo esc_html( ucfirst( $settings['geo_mode'] ?? 'disabled' ) ); ?></div>
            <div class="lbl">Current Mode</div>
        </div>
    </div>

    <?php if ( ! empty( $country_stats ) ) : ?>
    <div class="card">
        <h2>Top Blocked Countries</h2>
        <div class="top-countries">
            <?php foreach ( array_slice( $country_stats, 0, 10 ) as $cs ) : ?>
                <div class="top-country">
                    <span class="code"><?php echo esc_html( $cs['country_code'] ); ?></span>
                    <?php echo esc_html( $cs['country_name'] ); ?>
                    <span class="count">(<?php echo intval( $cs['total'] ); ?>)</span>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>

    <!-- Settings -->
    <div class="card">
        <h2>Settings</h2>
        <form method="post" action="<?php echo admin_url( 'admin.php?page=bestdid-security-settings' ); ?>">
            <?php wp_nonce_field( 'bestdid_security_save_settings', 'bestdid_security_settings_nonce' ); ?>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Enable Geo-Blocking</strong>
                    <span>Turn on country-based IP filtering</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="geo_blocking_enabled" value="1" <?php checked( ! empty( $settings['geo_blocking_enabled'] ) ); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Mode</strong>
                    <span>Blacklist = block listed countries. Whitelist = allow ONLY listed countries.</span>
                </div>
                <div class="setting-control">
                    <select name="geo_mode">
                        <option value="disabled" <?php selected( $settings['geo_mode'] ?? 'disabled', 'disabled' ); ?>>Disabled</option>
                        <option value="blacklist" <?php selected( $settings['geo_mode'] ?? 'disabled', 'blacklist' ); ?>>Blacklist</option>
                        <option value="whitelist" <?php selected( $settings['geo_mode'] ?? 'disabled', 'whitelist' ); ?>>Whitelist</option>
                    </select>
                </div>
            </div>

            <div class="setting-row" style="flex-direction:column;align-items:stretch;gap:10px;">
                <div class="setting-label">
                    <strong>Countries</strong>
                    <span>Select countries to block or allow</span>
                </div>
                <div class="country-select-wrap">
                    <input type="text" class="country-search setting-control" placeholder="Search countries..." id="countrySearch">
                    <input type="hidden" name="geo_countries" id="geoCountries" value="<?php echo esc_attr( $settings['geo_countries'] ?? '' ); ?>">
                    <div class="selected-countries" id="selectedCountries"></div>
                    <div class="country-list" id="countryList"></div>
                </div>
            </div>

            <div class="setting-row">
                <div class="setting-label">
                    <strong>Log Blocked Requests</strong>
                    <span>Keep a log of blocked requests by country</span>
                </div>
                <div class="setting-control">
                    <label class="toggle-switch">
                        <input type="checkbox" name="geo_log_blocked" value="1" <?php checked( ! empty( $settings['geo_log_blocked'] ) ); ?>>
                        <span class="toggle-slider"></span>
                    </label>
                </div>
            </div>

            <!-- Pass through all existing settings as hidden fields so they don't get wiped -->
            <?php
            $passthrough = array(
                'sql_injection_protection','xss_protection','brute_force_protection','rate_limiting',
                'max_login_attempts','lockout_duration','rate_limit_requests','log_retention_days',
                'block_bad_bots','hide_wp_version','disable_xmlrpc','custom_login_slug',
                'hide_login_errors','disable_file_editor','block_php_uploads','disable_rss_feeds',
                'force_strong_passwords','auto_logout_minutes','two_factor_enabled','two_factor_forced',
                'whitelisted_ips','whitelist_admins','scanner_enabled','scanner_schedule',
                'scanner_check_core','scanner_check_malware','scanner_check_uploads',
                'scanner_email_alerts','scanner_auto_quarantine',
                'activity_logging_enabled','activity_retention_days',
                'file_integrity_enabled','fim_schedule','fim_email_alerts',
                'enable_hsts',
            );
            foreach ( $passthrough as $key ) :
                $val = $settings[ $key ] ?? '';
                if ( is_array( $val ) ) :
                    foreach ( $val as $v ) : ?>
                        <input type="hidden" name="<?php echo esc_attr( $key ); ?>[]" value="<?php echo esc_attr( $v ); ?>">
                    <?php endforeach;
                elseif ( is_bool( $val ) || $val === '1' || $val === true ) : ?>
                    <input type="hidden" name="<?php echo esc_attr( $key ); ?>" value="1">
                <?php else : ?>
                    <input type="hidden" name="<?php echo esc_attr( $key ); ?>" value="<?php echo esc_attr( $val ); ?>">
                <?php endif;
            endforeach; ?>

            <div style="margin-top:20px;">
                <button type="submit" class="btn btn-primary">Save Geo-Blocking Settings</button>
            </div>
        </form>
    </div>

    <!-- Test IP -->
    <div class="card">
        <h2>Test IP Address</h2>
        <div class="test-ip-row">
            <input type="text" id="testIpInput" placeholder="Enter an IP address..." class="setting-control">
            <button class="btn btn-secondary btn-sm" id="testIpBtn">Test</button>
        </div>
        <div id="testIpResult"></div>
    </div>

    <!-- Blocked Log -->
    <div class="card">
        <h2>Blocked Requests Log</h2>
        <div style="display:flex;justify-content:flex-end;margin-bottom:15px;">
            <button class="btn btn-danger btn-sm" id="clearGeoLog">Clear Log</button>
        </div>
        <table class="log-table">
            <thead>
                <tr><th>IP</th><th>Country</th><th>Request</th><th>Time</th></tr>
            </thead>
            <tbody id="geoLogBody">
                <tr><td colspan="4" style="text-align:center;color:rgba(255,255,255,0.4);">Loading...</td></tr>
            </tbody>
        </table>
        <div class="pagination" id="geoLogPagination"></div>
    </div>
</div>

<script>
(function(){
    const nonce = '<?php echo wp_create_nonce( 'bdsec_nonce' ); ?>';
    const ajaxurl = '<?php echo admin_url( 'admin-ajax.php' ); ?>';

    // ── Country list (ISO 3166-1) ──
    const countries = [
        {c:'AF',n:'Afghanistan'},{c:'AL',n:'Albania'},{c:'DZ',n:'Algeria'},{c:'AD',n:'Andorra'},{c:'AO',n:'Angola'},
        {c:'AG',n:'Antigua and Barbuda'},{c:'AR',n:'Argentina'},{c:'AM',n:'Armenia'},{c:'AU',n:'Australia'},{c:'AT',n:'Austria'},
        {c:'AZ',n:'Azerbaijan'},{c:'BS',n:'Bahamas'},{c:'BH',n:'Bahrain'},{c:'BD',n:'Bangladesh'},{c:'BB',n:'Barbados'},
        {c:'BY',n:'Belarus'},{c:'BE',n:'Belgium'},{c:'BZ',n:'Belize'},{c:'BJ',n:'Benin'},{c:'BT',n:'Bhutan'},
        {c:'BO',n:'Bolivia'},{c:'BA',n:'Bosnia and Herzegovina'},{c:'BW',n:'Botswana'},{c:'BR',n:'Brazil'},{c:'BN',n:'Brunei'},
        {c:'BG',n:'Bulgaria'},{c:'BF',n:'Burkina Faso'},{c:'BI',n:'Burundi'},{c:'KH',n:'Cambodia'},{c:'CM',n:'Cameroon'},
        {c:'CA',n:'Canada'},{c:'CV',n:'Cape Verde'},{c:'CF',n:'Central African Republic'},{c:'TD',n:'Chad'},{c:'CL',n:'Chile'},
        {c:'CN',n:'China'},{c:'CO',n:'Colombia'},{c:'KM',n:'Comoros'},{c:'CG',n:'Congo'},{c:'CR',n:'Costa Rica'},
        {c:'HR',n:'Croatia'},{c:'CU',n:'Cuba'},{c:'CY',n:'Cyprus'},{c:'CZ',n:'Czech Republic'},{c:'CD',n:'DR Congo'},
        {c:'DK',n:'Denmark'},{c:'DJ',n:'Djibouti'},{c:'DM',n:'Dominica'},{c:'DO',n:'Dominican Republic'},{c:'EC',n:'Ecuador'},
        {c:'EG',n:'Egypt'},{c:'SV',n:'El Salvador'},{c:'GQ',n:'Equatorial Guinea'},{c:'ER',n:'Eritrea'},{c:'EE',n:'Estonia'},
        {c:'SZ',n:'Eswatini'},{c:'ET',n:'Ethiopia'},{c:'FJ',n:'Fiji'},{c:'FI',n:'Finland'},{c:'FR',n:'France'},
        {c:'GA',n:'Gabon'},{c:'GM',n:'Gambia'},{c:'GE',n:'Georgia'},{c:'DE',n:'Germany'},{c:'GH',n:'Ghana'},
        {c:'GR',n:'Greece'},{c:'GD',n:'Grenada'},{c:'GT',n:'Guatemala'},{c:'GN',n:'Guinea'},{c:'GW',n:'Guinea-Bissau'},
        {c:'GY',n:'Guyana'},{c:'HT',n:'Haiti'},{c:'HN',n:'Honduras'},{c:'HU',n:'Hungary'},{c:'IS',n:'Iceland'},
        {c:'IN',n:'India'},{c:'ID',n:'Indonesia'},{c:'IR',n:'Iran'},{c:'IQ',n:'Iraq'},{c:'IE',n:'Ireland'},
        {c:'IL',n:'Israel'},{c:'IT',n:'Italy'},{c:'CI',n:'Ivory Coast'},{c:'JM',n:'Jamaica'},{c:'JP',n:'Japan'},
        {c:'JO',n:'Jordan'},{c:'KZ',n:'Kazakhstan'},{c:'KE',n:'Kenya'},{c:'KI',n:'Kiribati'},{c:'KW',n:'Kuwait'},
        {c:'KG',n:'Kyrgyzstan'},{c:'LA',n:'Laos'},{c:'LV',n:'Latvia'},{c:'LB',n:'Lebanon'},{c:'LS',n:'Lesotho'},
        {c:'LR',n:'Liberia'},{c:'LY',n:'Libya'},{c:'LI',n:'Liechtenstein'},{c:'LT',n:'Lithuania'},{c:'LU',n:'Luxembourg'},
        {c:'MG',n:'Madagascar'},{c:'MW',n:'Malawi'},{c:'MY',n:'Malaysia'},{c:'MV',n:'Maldives'},{c:'ML',n:'Mali'},
        {c:'MT',n:'Malta'},{c:'MH',n:'Marshall Islands'},{c:'MR',n:'Mauritania'},{c:'MU',n:'Mauritius'},{c:'MX',n:'Mexico'},
        {c:'FM',n:'Micronesia'},{c:'MD',n:'Moldova'},{c:'MC',n:'Monaco'},{c:'MN',n:'Mongolia'},{c:'ME',n:'Montenegro'},
        {c:'MA',n:'Morocco'},{c:'MZ',n:'Mozambique'},{c:'MM',n:'Myanmar'},{c:'NA',n:'Namibia'},{c:'NR',n:'Nauru'},
        {c:'NP',n:'Nepal'},{c:'NL',n:'Netherlands'},{c:'NZ',n:'New Zealand'},{c:'NI',n:'Nicaragua'},{c:'NE',n:'Niger'},
        {c:'NG',n:'Nigeria'},{c:'KP',n:'North Korea'},{c:'MK',n:'North Macedonia'},{c:'NO',n:'Norway'},{c:'OM',n:'Oman'},
        {c:'PK',n:'Pakistan'},{c:'PW',n:'Palau'},{c:'PS',n:'Palestine'},{c:'PA',n:'Panama'},{c:'PG',n:'Papua New Guinea'},
        {c:'PY',n:'Paraguay'},{c:'PE',n:'Peru'},{c:'PH',n:'Philippines'},{c:'PL',n:'Poland'},{c:'PT',n:'Portugal'},
        {c:'QA',n:'Qatar'},{c:'RO',n:'Romania'},{c:'RU',n:'Russia'},{c:'RW',n:'Rwanda'},{c:'KN',n:'Saint Kitts and Nevis'},
        {c:'LC',n:'Saint Lucia'},{c:'VC',n:'Saint Vincent'},{c:'WS',n:'Samoa'},{c:'SM',n:'San Marino'},
        {c:'ST',n:'Sao Tome and Principe'},{c:'SA',n:'Saudi Arabia'},{c:'SN',n:'Senegal'},{c:'RS',n:'Serbia'},
        {c:'SC',n:'Seychelles'},{c:'SL',n:'Sierra Leone'},{c:'SG',n:'Singapore'},{c:'SK',n:'Slovakia'},{c:'SI',n:'Slovenia'},
        {c:'SB',n:'Solomon Islands'},{c:'SO',n:'Somalia'},{c:'ZA',n:'South Africa'},{c:'KR',n:'South Korea'},
        {c:'SS',n:'South Sudan'},{c:'ES',n:'Spain'},{c:'LK',n:'Sri Lanka'},{c:'SD',n:'Sudan'},{c:'SR',n:'Suriname'},
        {c:'SE',n:'Sweden'},{c:'CH',n:'Switzerland'},{c:'SY',n:'Syria'},{c:'TW',n:'Taiwan'},{c:'TJ',n:'Tajikistan'},
        {c:'TZ',n:'Tanzania'},{c:'TH',n:'Thailand'},{c:'TL',n:'Timor-Leste'},{c:'TG',n:'Togo'},{c:'TO',n:'Tonga'},
        {c:'TT',n:'Trinidad and Tobago'},{c:'TN',n:'Tunisia'},{c:'TR',n:'Turkey'},{c:'TM',n:'Turkmenistan'},
        {c:'TV',n:'Tuvalu'},{c:'UG',n:'Uganda'},{c:'UA',n:'Ukraine'},{c:'AE',n:'United Arab Emirates'},
        {c:'GB',n:'United Kingdom'},{c:'US',n:'United States'},{c:'UY',n:'Uruguay'},{c:'UZ',n:'Uzbekistan'},
        {c:'VU',n:'Vanuatu'},{c:'VA',n:'Vatican City'},{c:'VE',n:'Venezuela'},{c:'VN',n:'Vietnam'},{c:'YE',n:'Yemen'},
        {c:'ZM',n:'Zambia'},{c:'ZW',n:'Zimbabwe'}
    ];

    let selected = ('<?php echo esc_js( $settings['geo_countries'] ?? '' ); ?>').split(',').filter(Boolean);

    function renderCountryList(filter = '') {
        const list = document.getElementById('countryList');
        const lower = filter.toLowerCase();
        list.innerHTML = countries.map(c => {
            const hidden = lower && !c.n.toLowerCase().includes(lower) && !c.c.toLowerCase().includes(lower);
            const checked = selected.includes(c.c);
            return `<label class="${hidden ? 'hidden' : ''}"><input type="checkbox" value="${c.c}" ${checked ? 'checked' : ''} onchange="toggleCountry('${c.c}')">${c.c} — ${c.n}</label>`;
        }).join('');
    }

    function renderTags() {
        const wrap = document.getElementById('selectedCountries');
        wrap.innerHTML = selected.map(code => {
            const c = countries.find(x => x.c === code);
            return `<span class="country-tag">${code} ${c ? c.n : ''} <span class="remove" onclick="toggleCountry('${code}')">&times;</span></span>`;
        }).join('');
        document.getElementById('geoCountries').value = selected.join(',');
    }

    window.toggleCountry = function(code) {
        const idx = selected.indexOf(code);
        if (idx > -1) selected.splice(idx, 1); else selected.push(code);
        renderTags();
        renderCountryList(document.getElementById('countrySearch').value);
    };

    document.getElementById('countrySearch').addEventListener('input', function(){ renderCountryList(this.value); });
    renderCountryList();
    renderTags();

    // ── Geo Log ──
    let geoPage = 1;
    function loadGeoLog(page) {
        geoPage = page;
        fetch(ajaxurl, {
            method: 'POST',
            headers: {'Content-Type':'application/x-www-form-urlencoded'},
            body: `action=bdsec_geo_get_log&nonce=${nonce}&page=${page}`
        }).then(r=>r.json()).then(res => {
            if (!res.success) return;
            const {rows, pages} = res.data;
            const body = document.getElementById('geoLogBody');
            if (!rows.length) {
                body.innerHTML = '<tr><td colspan="4" style="text-align:center;color:rgba(255,255,255,0.4);">No blocked requests yet.</td></tr>';
            } else {
                body.innerHTML = rows.map(r => `<tr><td>${r.ip_address}</td><td>${r.country_code} ${r.country_name}</td><td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${r.request_uri||''}</td><td>${r.created_at}</td></tr>`).join('');
            }
            const pag = document.getElementById('geoLogPagination');
            if (pages > 1) {
                let btns = '';
                for (let i=1;i<=Math.min(pages,10);i++) btns += `<button class="${i===page?'active':''}" onclick="loadGeoLog(${i})">${i}</button>`;
                pag.innerHTML = btns;
            } else { pag.innerHTML = ''; }
        });
    }
    window.loadGeoLog = loadGeoLog;
    loadGeoLog(1);

    // Clear log
    document.getElementById('clearGeoLog').addEventListener('click', function(){
        if (!confirm('Clear all geo-blocking logs?')) return;
        fetch(ajaxurl, {
            method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
            body:`action=bdsec_geo_clear_log&nonce=${nonce}`
        }).then(r=>r.json()).then(() => loadGeoLog(1));
    });

    // Test IP
    document.getElementById('testIpBtn').addEventListener('click', function(){
        const ip = document.getElementById('testIpInput').value.trim();
        if (!ip) return;
        fetch(ajaxurl, {
            method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
            body:`action=bdsec_geo_test_ip&nonce=${nonce}&ip=${encodeURIComponent(ip)}`
        }).then(r=>r.json()).then(res => {
            const el = document.getElementById('testIpResult');
            if (!res.success) { el.innerHTML = `<div class="test-result blocked">${res.data||'Error'}</div>`; return; }
            const d = res.data;
            el.innerHTML = `<div class="test-result ${d.blocked?'blocked':'allowed'}">
                <strong>${d.ip}</strong> — ${d.country_name} (${d.country_code}) — <strong>${d.blocked?'BLOCKED':'ALLOWED'}</strong>
            </div>`;
        });
    });
})();
</script>
