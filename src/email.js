const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: process.env.SMTP_PORT == 465, // true for 465, false for other ports
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

/**
 * Original sendEmail function (kept for backwards compatibility)
 */
async function sendEmail(to, subject, text) {
  try {
    const info = await transporter.sendMail({
      from: `"HIDPS Alert" <${process.env.EMAIL_FROM}>`,
      to,
      subject,
      text,
    });
    console.log(`Email sent to ${to}: ${info.messageId}`);
  } catch (error) {
    console.error(`Error sending email to ${to}:`, error);
  }
}

/**
 * Get severity info for alerts
 */
function getSeverityInfo(severity) {
  switch(severity) {
    case 4: return { emoji: '🚨', color: '#ef4444', label: 'CRITICAL' };
    case 3: return { emoji: '⚠️', color: '#f97316', label: 'HIGH' };
    case 2: return { emoji: '⚡', color: '#eab308', label: 'MEDIUM' };
    default: return { emoji: 'ℹ️', color: '#3b82f6', label: 'LOW' };
  }
}

/**
 * Get alert type icon
 */
function getAlertTypeIcon(alertType) {
  const icons = {
    'network': '🌐',
    'security': '🔐',
    'integrity': '📁',
    'file_monitoring': '📝',
    'privilege_escalation': '⚡',
    'process': '⚙️',
    'system': '💻'
  };
  return icons[alertType] || '🔔';
}

/**
 * Send formatted alert email
 */
async function sendAlertEmail(alert, agentInfo, userEmail) {
  const severityInfo = getSeverityInfo(alert.severity);
  const typeIcon = getAlertTypeIcon(alert.alert_type);
  
  const subject = `${severityInfo.emoji} ${severityInfo.label}: ${alert.title}`;
  
  const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
      line-height: 1.6;
      color: #333;
      max-width: 600px;
      margin: 0 auto;
      padding: 20px;
      background-color: #f5f5f5;
    }
    .email-container {
      background: white;
      border-radius: 10px;
      overflow: hidden;
      box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .header {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      padding: 30px;
      text-align: center;
    }
    .header h1 {
      margin: 0;
      font-size: 24px;
    }
    .alert-badge {
      display: inline-block;
      background: ${severityInfo.color};
      color: white;
      padding: 8px 16px;
      border-radius: 20px;
      font-weight: bold;
      margin: 10px 0;
      font-size: 14px;
    }
    .content {
      padding: 30px;
    }
    .alert-title {
      font-size: 20px;
      font-weight: bold;
      color: #1f2937;
      margin-bottom: 15px;
    }
    .alert-message {
      background: #f9fafb;
      padding: 20px;
      border-radius: 8px;
      border-left: 4px solid ${severityInfo.color};
      margin: 20px 0;
      white-space: pre-wrap;
      color: #4b5563;
    }
    .info-grid {
      background: #f9fafb;
      padding: 20px;
      border-radius: 8px;
      margin: 20px 0;
    }
    .info-row {
      display: flex;
      padding: 8px 0;
      border-bottom: 1px solid #e5e7eb;
    }
    .info-row:last-child {
      border-bottom: none;
    }
    .info-label {
      font-weight: 600;
      color: #6b7280;
      width: 140px;
      flex-shrink: 0;
    }
    .info-value {
      color: #1f2937;
      flex: 1;
    }
    .button {
      display: inline-block;
      background: #667eea;
      color: white;
      padding: 12px 24px;
      text-decoration: none;
      border-radius: 6px;
      margin-top: 20px;
      font-weight: 600;
    }
    .footer {
      text-align: center;
      padding: 20px;
      color: #6b7280;
      font-size: 12px;
      background: #f9fafb;
    }
  </style>
</head>
<body>
  <div class="email-container">
    <div class="header">
      <h1>🛡️ HIDPS Security Alert</h1>
      <div class="alert-badge">${severityInfo.emoji} ${severityInfo.label} SEVERITY</div>
    </div>
    
    <div class="content">
      <div class="alert-title">
        ${typeIcon} ${alert.title}
      </div>
      
      <div class="alert-message">${alert.message || 'No additional details provided.'}</div>
      
      <div class="info-grid">
        <div class="info-row">
          <div class="info-label">Agent:</div>
          <div class="info-value">${agentInfo?.name || 'Unknown'}</div>
        </div>
        <div class="info-row">
          <div class="info-label">Alert Type:</div>
          <div class="info-value">${alert.alert_type}</div>
        </div>
        <div class="info-row">
          <div class="info-label">Time:</div>
          <div class="info-value">${new Date(alert.created_at).toLocaleString()}</div>
        </div>
        <div class="info-row">
          <div class="info-label">Severity:</div>
          <div class="info-value" style="color: ${severityInfo.color}; font-weight: bold;">
            ${severityInfo.label}
          </div>
        </div>
      </div>
      
      <a href="${process.env.FRONTEND_URL || 'https://hidps-frontend.vercel.app'}/dashboard/alerts" class="button">
        View in Dashboard →
      </a>
    </div>
    
    <div class="footer">
      <p>This is an automated alert from your HIDPS system.</p>
      <p>Monitored by agent: ${agentInfo?.name || 'Unknown'}</p>
    </div>
  </div>
</body>
</html>
  `;

  const textContent = `
🛡️ HIDPS SECURITY ALERT
${severityInfo.emoji} ${severityInfo.label} SEVERITY

${typeIcon} ${alert.title}

${alert.message || 'No additional details provided.'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Agent: ${agentInfo?.name || 'Unknown'}
Type: ${alert.alert_type}
Time: ${new Date(alert.created_at).toLocaleString()}
Severity: ${severityInfo.label}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━

View details: ${process.env.FRONTEND_URL || 'https://hidps-frontend.vercel.app'}/dashboard/alerts
  `;

  try {
    const info = await transporter.sendMail({
      from: `"HIDPS Alert" <${process.env.EMAIL_FROM}>`,
      to: userEmail,
      subject: subject,
      text: textContent,
      html: htmlContent
    });

    console.log(`Alert email sent to ${userEmail}: ${info.messageId}`);
    return true;
  } catch (error) {
    console.error('Failed to send alert email:', error);
    return false;
  }
}

/**
 * Send notification for critical alerts (severity 3+)
 */
async function notifyCriticalAlert(alert, agentInfo, userEmail) {
  // Only send emails for HIGH and CRITICAL severity
  if (alert.severity >= 3) {
    return await sendAlertEmail(alert, agentInfo, userEmail);
  }
  return false;
}

module.exports = {
  sendEmail,              // Original function (backwards compatible)
  sendAlertEmail,         // New formatted alert emails
  notifyCriticalAlert     // Auto-send for critical alerts
};