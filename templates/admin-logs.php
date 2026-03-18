<?php
/**
 * Admin Logs Template
 * 
 * @package BestDid_Security
 */

if (!defined('ABSPATH')) exit;
?>
<div class="wrap">
    <h1>Security Logs</h1>
    
    <style>
        .logs-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
            margin-top: 20px;
        }
        .logs-table th {
            background: #f6f7f7;
            padding: 12px 16px;
            text-align: left;
            font-weight: 600;
            font-size: 13px;
            color: #1d2327;
            border-bottom: 1px solid #e0e0e0;
        }
        .logs-table td {
            padding: 12px 16px;
            border-bottom: 1px solid #f0f0f1;
            font-size: 13px;
        }
        .logs-table tr:hover td {
            background: #f9f9f9;
        }
        .severity-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .severity-badge.critical { background: #d63638; color: white; }
        .severity-badge.high { background: #dba617; color: white; }
        .severity-badge.medium { background: #f0c33c; color: #1d2327; }
        .severity-badge.low { background: #00a32a; color: white; }
        
        .pagination-links {
            margin-top: 20px;
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .ip-address {
            font-family: monospace;
            background: #f0f0f1;
            padding: 2px 6px;
            border-radius: 4px;
        }
    </style>
    
    <table class="logs-table">
        <thead>
            <tr>
                <th>Time</th>
                <th>IP Address</th>
                <th>Threat Type</th>
                <th>Severity</th>
                <th>Details</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            <?php if (empty($logs)) : ?>
                <tr>
                    <td colspan="6" style="text-align: center; padding: 40px;">No security logs found.</td>
                </tr>
            <?php else : ?>
                <?php foreach ($logs as $log) : ?>
                    <tr>
                        <td><?php echo esc_html(date('M j, Y H:i:s', strtotime($log->timestamp))); ?></td>
                        <td><code class="ip-address"><?php echo esc_html($log->ip_address); ?></code></td>
                        <td><?php echo esc_html(ucwords(str_replace('_', ' ', $log->threat_type))); ?></td>
                        <td><span class="severity-badge <?php echo esc_attr($log->severity); ?>"><?php echo esc_html($log->severity); ?></span></td>
                        <td><?php echo esc_html(substr($log->details, 0, 100)); ?><?php echo strlen($log->details) > 100 ? '...' : ''; ?></td>
                        <td><?php echo $log->blocked ? '🚫 Blocked' : '⚠️ Logged'; ?></td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>
    
    <?php if ($total_pages > 1) : ?>
        <div class="pagination-links">
            <?php if ($page > 1) : ?>
                <a href="<?php echo add_query_arg('paged', $page - 1); ?>" class="button">← Previous</a>
            <?php endif; ?>
            
            <span>Page <?php echo $page; ?> of <?php echo $total_pages; ?></span>
            
            <?php if ($page < $total_pages) : ?>
                <a href="<?php echo add_query_arg('paged', $page + 1); ?>" class="button">Next →</a>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>
