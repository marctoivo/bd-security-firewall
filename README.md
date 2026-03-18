# BestDid Security Firewall

🛡️ Enterprise-grade database protection and security hardening for your BestDid WordPress site.

## What This Plugin Protects Against

| Threat Type | Protection |
|-------------|------------|
| **SQL Injection** | Blocks malicious database queries (UNION, SELECT, DROP, etc.) |
| **XSS Attacks** | Prevents cross-site scripting via script tags, event handlers |
| **Brute Force** | Rate limits login attempts, auto-blocks repeat offenders |
| **Path Traversal** | Blocks `../` attacks trying to access system files |
| **Bad Bots** | Blocks known scanners (sqlmap, nikto, nmap, etc.) |
| **User Enumeration** | Blocks REST API user enumeration |
| **XML-RPC Exploits** | Disables XML-RPC completely |

## Installation

### Method 1: Upload via WordPress Admin (Recommended)

1. Download `bestdid-security.zip` from your files
2. Go to **WordPress Admin → Plugins → Add New → Upload Plugin**
3. Choose the zip file and click **Install Now**
4. Click **Activate Plugin**

### Method 2: FTP/File Manager Upload

1. Extract `bestdid-security.zip`
2. Upload the `bestdid-security` folder to `/wp-content/plugins/`
3. Go to **WordPress Admin → Plugins**
4. Find "BestDid Security Firewall" and click **Activate**

## Configuration

After activation:

1. Go to **WordPress Admin → Security** (shield icon in sidebar)
2. The dashboard shows real-time threat statistics
3. Click **Settings** to configure protection levels

### Recommended Settings

| Setting | Recommended Value |
|---------|-------------------|
| SQL Injection Protection | ✅ ON |
| XSS Protection | ✅ ON |
| Brute Force Protection | ✅ ON |
| Max Login Attempts | 5 |
| Lockout Duration | 30 minutes |
| Rate Limiting | ✅ ON |
| Requests Per Minute | 60 |
| Block Bad Bots | ✅ ON |

## Security Headers Added

The plugin automatically adds these HTTP security headers:

```
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: [configured for your site]
```

## Database Tables Created

The plugin creates two tables for logging and rate limiting:

- `wp_bestdid_rate_limits` - Tracks request rates per IP
- `wp_bestdid_security_logs` - Stores blocked threat details

## Features

### 🔒 Real-Time Protection
- Blocks attacks BEFORE they reach WordPress
- Runs at the earliest possible hook (`init` priority 1)
- Sanitizes all GET, POST, and COOKIE inputs

### 📊 Admin Dashboard
- View blocked threats in real-time
- See protection status at a glance
- Searchable security logs with pagination

### ⚡ Performance Optimized
- Minimal database queries
- Efficient regex patterns
- Automatic log cleanup (configurable retention)

### 🎨 Professional Block Page
- Shows custom "Access Denied" page to attackers
- Includes error code for support reference
- Doesn't reveal WordPress installation

## Viewing Security Logs

1. Go to **Security → Logs** in WordPress admin
2. View all blocked threats with:
   - Timestamp
   - IP address
   - Threat type
   - Severity level
   - Request details

## Troubleshooting

### "I got locked out!"

If your IP gets blocked:
1. Wait for the lockout duration to expire (default: 30 mins)
2. Or access your database and clear the `wp_bestdid_rate_limits` table

### "Legitimate form submissions are blocked"

Some forms may trigger false positives. You can:
1. Reduce rate limiting sensitivity in Settings
2. Check the logs to see what pattern matched

### "My API requests are failing"

The plugin allows 120 REST API requests per minute by default. If you need more:
1. Go to **Security → Settings**
2. Increase "Requests Per Minute"

## File Structure

```
bestdid-security/
├── bestdid-security.php      # Main plugin file
├── templates/
│   ├── admin-dashboard.php   # Dashboard template
│   ├── admin-logs.php        # Logs viewer template
│   └── admin-settings.php    # Settings page template
└── README.md                 # This file
```

## Uninstallation

1. Deactivate the plugin
2. Delete it from the Plugins page
3. The database tables will remain (for safety)
4. To fully remove, drop these tables:
   - `wp_bestdid_rate_limits`
   - `wp_bestdid_security_logs`

## Support

For issues or feature requests, contact your development team.

---

Built with ❤️ for BestDid | Version 1.0.0
