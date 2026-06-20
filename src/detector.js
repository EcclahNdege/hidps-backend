const { createAlert } = require('./supabase');
const { notifyCriticalAlert } = require('./email');
const { supabase } = require('./supabase');

// ========================
// PORT SCAN DETECTION
// ========================

const blockedIPs = new Map(); // IP -> { count, firstSeen, lastSeen, ports }

function analyzeFirewallBlock(message, agentId) {
  const srcMatch = message.match(/SRC=([0-9.]+)/);
  const dptMatch = message.match(/DPT=([0-9]+)/);
  const protoMatch = message.match(/PROTO=(\w+)/);

  if (!srcMatch || !dptMatch) return null;

  const sourceIP = srcMatch[1];
  const destPort = dptMatch[1];
  const protocol = protoMatch ? protoMatch[1] : 'TCP';
  const now = Date.now();

  if (!blockedIPs.has(sourceIP)) {
    blockedIPs.set(sourceIP, { count: 0, firstSeen: now, lastSeen: now, ports: new Set() });
  }

  const ipData = blockedIPs.get(sourceIP);
  ipData.count++;
  ipData.lastSeen = now;
  ipData.ports.add(destPort);

  for (const [ip, data] of blockedIPs.entries()) {
    if (now - data.lastSeen > 3600000) blockedIPs.delete(ip);
  }

  const timeWindow = now - ipData.firstSeen;
  const uniquePorts = ipData.ports.size;

  if (uniquePorts >= 5 && timeWindow < 60000) {
    return {
      type: 'port_scan_detected', severity: 4,
      title: '🚨 Port Scan Detected',
      description: `IP ${sourceIP} attempted to access ${uniquePorts} different ports in ${Math.round(timeWindow/1000)} seconds.`,
      details: `Ports scanned: ${Array.from(ipData.ports).join(', ')}`,
      mitre_technique: 'T1046', mitre_tactic: 'Discovery',
    };
  }
  if (ipData.count >= 20 && timeWindow < 300000) {
    return {
      type: 'slow_scan_detected', severity: 3,
      title: '⚠️ Slow Port Scan Detected',
      description: `IP ${sourceIP} made ${ipData.count} attempts to ${uniquePorts} ports over ${Math.round(timeWindow/60000)} minutes.`,
      details: `Ports targeted: ${Array.from(ipData.ports).join(', ')}`,
      mitre_technique: 'T1046', mitre_tactic: 'Discovery',
    };
  }
  if (ipData.count >= 10 && uniquePorts === 1) {
    return {
      type: 'brute_force_detected', severity: 4,
      title: '🔨 Brute Force Attack Detected',
      description: `IP ${sourceIP} made ${ipData.count} repeated attempts to port ${destPort}.`,
      details: `Target port: ${destPort} (${protocol})`,
      mitre_technique: 'T1110', mitre_tactic: 'Credential Access',
    };
  }
  const sensitivePorts = ['22', '3389', '445', '135', '1433', '3306', '5432', '27017'];
  if (sensitivePorts.includes(destPort) && ipData.count >= 3) {
    return {
      type: 'sensitive_port_probe', severity: 3,
      title: '🎯 Sensitive Port Probe',
      description: `IP ${sourceIP} is probing sensitive port ${destPort} (${getPortDescription(destPort)}).`,
      details: `Port ${destPort} is used for: ${getPortDescription(destPort)}`,
      mitre_technique: 'T1046', mitre_tactic: 'Discovery',
    };
  }
  return null;
}

function getPortDescription(port) {
  const portMap = {
    '22': 'SSH (Remote Access)', '3389': 'RDP (Windows Remote Desktop)',
    '445': 'SMB (Windows File Sharing)', '135': 'Windows RPC',
    '1433': 'MS SQL Server', '3306': 'MySQL Database',
    '5432': 'PostgreSQL Database', '27017': 'MongoDB Database',
    '80': 'HTTP Web Server', '443': 'HTTPS Web Server',
    '21': 'FTP File Transfer', '23': 'Telnet',
    '25': 'SMTP Email', '53': 'DNS',
    '110': 'POP3 Email', '143': 'IMAP Email'
  };
  return portMap[port] || 'Unknown Service';
}

// ========================
// FILE MONITORING HELPERS
// ========================

function extractMonitoredFileName(message) {
  const modifiedMatch = message.match(/Monitored file (?:MODIFIED|UPDATED|DELETED|MOVED): (.+?)(?:\s|$)/);
  if (modifiedMatch) return modifiedMatch[1];

  const pathMatch = message.match(/\/[\w\/.-]+/g);
  if (pathMatch) {
    const realFiles = pathMatch.filter(p =>
      !p.includes('.goutputstream') && !p.endsWith('~') &&
      !p.includes('.swp') && !p.includes('.tmp')
    );
    return realFiles[0] || pathMatch[0];
  }
  return null;
}

function formatFileAlert(message, monitoredFile) {
  const filename = monitoredFile.split('/').pop();
  if (message.includes('MODIFIED') || message.includes('modified'))
    return { title: `File Modified: ${filename}`, description: `The monitored file "${monitoredFile}" was modified.` };
  if (message.includes('UPDATED') || message.includes('saved by editor'))
    return { title: `File Saved: ${filename}`, description: `The monitored file "${monitoredFile}" was saved by an editor.` };
  if (message.includes('DELETED') || message.includes('deleted'))
    return { title: `🚨 File Deleted: ${filename}`, description: `CRITICAL: The monitored file "${monitoredFile}" was deleted!` };
  if (message.includes('MOVED') || message.includes('RENAMED'))
    return { title: `File Moved: ${filename}`, description: `The monitored file "${monitoredFile}" was moved or renamed.` };
  if (message.includes('created'))
    return { title: `File Created: ${filename}`, description: `A new file was created in the monitored location: "${monitoredFile}"` };
  return { title: `File Event: ${filename}`, description: message };
}

function shouldCreateFileAlert(message, monitoredFile) {
  if (message.includes('DELETED') || message.includes('deleted')) return true;
  if (message.includes('MOVED') || message.includes('RENAMED')) return true;
  if (monitoredFile.includes('/etc/passwd') || monitoredFile.includes('/etc/shadow') ||
      monitoredFile.includes('/etc/sudoers') || monitoredFile.includes('/etc/ssh/sshd_config')) return true;
  if (message.includes('MODIFIED') || message.includes('UPDATED')) return true;
  if (message.includes('being edited') || message.includes('File/Dir created') ||
      monitoredFile.includes('.goutputstream') || monitoredFile.includes('.swp')) return false;
  return true;
}

// ========================
// LOGIN MONITORING HELPERS
// ========================

function extractUsername(message) {
  let match = message.match(/for (\w+) from/);
  if (match) return match[1];
  match = message.match(/(\w+)\s*:/);
  if (match && match[1] !== 'pam_unix') return match[1];
  match = message.match(/session opened for user (\w+)/);
  if (match) return match[1];
  return 'unknown';
}

function extractIP(message) {
  const match = message.match(/from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/);
  return match ? match[1] : 'unknown';
}

// ========================
// AGENT ENRICHMENT HELPERS
// ========================

/**
 * Builds a MITRE ATT&CK context string from agent-supplied fields.
 * Appended to alert descriptions so the dashboard shows technique info
 * even before the frontend is updated to render dedicated fields.
 */
function formatMitreContext(log) {
  if (!log.mitre_technique) return '';
  return `\n\n🛡️ MITRE ATT&CK: ${log.mitre_tactic} — ${log.mitre_technique}` +
         (log.rule_id ? ` [${log.rule_id}]` : '') +
         (log.rule_description ? `\n${log.rule_description}` : '');
}

/**
 * Returns true when the agent has already classified this event with
 * meaningful severity (≥2) so we can skip redundant backend re-scoring
 * for that event type and just use the agent's verdict directly.
 *
 * The backend's own stateful detection (port scan tracking across IPs,
 * brute force counters) always runs regardless, because it requires
 * cross-event memory the agent doesn't have.
 */
function agentAlreadyScored(log) {
  return typeof log.severity === 'number' && log.severity >= 2 && !!log.rule_id;
}

// ========================
// MAIN LOG ANALYZER
// ========================

async function analyzeLog(agentId, log) {
  const { type, service, message } = log;

  // ========================
  // 1. FIREWALL & PORT SCAN DETECTION
  // Stateful cross-event analysis — always runs regardless of agent scoring
  // because the agent can only score individual events, not patterns across
  // multiple events from different source IPs over time.
  // ========================

  if (type === 'firewall') {
    if (message.includes('BLOCK') || message.includes('UFW BLOCK')) {
      const scanAlert = analyzeFirewallBlock(message, agentId);

      if (scanAlert) {
        const mitreContext = formatMitreContext({
          mitre_technique: scanAlert.mitre_technique,
          mitre_tactic: scanAlert.mitre_tactic,
        });
        const alert = await createAlert(
          agentId,
          scanAlert.title,
          `${scanAlert.description}\n\n${scanAlert.details}${mitreContext}`,
          'network',
          scanAlert.severity
        );

        if (alert && scanAlert.severity >= 3) {
          try {
            const { data: agentData } = await supabase
              .from('agents').select('name, owner_id').eq('id', agentId).single();
            if (agentData) {
              const { data: userData } = await supabase
                .from('auth.users').select('email').eq('id', agentData.owner_id).single();
              if (userData?.email) await notifyCriticalAlert(alert, agentData, userData.email);
            }
          } catch (emailError) {
            console.error('Failed to send email notification:', emailError);
          }
        }
      }

      // If the agent scored this firewall event (e.g. firewall disabled),
      // create an alert using the agent's verdict directly.
      if (agentAlreadyScored(log) && !message.includes('BLOCK')) {
        await createAlert(
          agentId,
          `🔥 Firewall Event [${log.rule_id}]`,
          `${message}${formatMitreContext(log)}`,
          'network',
          log.severity
        );
      }
    }
  }

  // ========================
  // 2. LOGIN MONITORING
  // Prefer agent severity when already scored; fall back to backend rules.
  // ========================

  if (type === 'login') {
    const username = extractUsername(message);
    const ip = extractIP(message);

    // If the agent already scored this login event, use its verdict directly
    // so we don't create a duplicate alert with a different severity.
    if (agentAlreadyScored(log)) {
      await createAlert(
        agentId,
        `🔐 Login Event [${log.rule_id}]`,
        `${message}\nUser: ${username} | IP: ${ip}${formatMitreContext(log)}`,
        'security',
        log.severity
      );
      return; // Don't also run backend rules for the same event
    }

    // Backend fallback rules (for events the agent scored as severity=1
    // or that arrived without enrichment from an older agent version)
    if (service === 'sshd' && (message.includes('Failed password') || message.includes('authentication failure'))) {
      await createAlert(agentId, '🔐 Failed SSH Login Attempt',
        `Failed SSH login for "${username}" from ${ip}.`, 'security', 4);
    }
    if (service === 'sudo' && message.includes('authentication failure')) {
      await createAlert(agentId, '⚠️ Failed Sudo Authentication',
        `User "${username}" failed sudo authentication.`, 'security', 4);
    }
    if (service === 'sudo' && message.includes('session opened for user root')) {
      await createAlert(agentId, '🔓 Root Access Granted',
        `User "${username}" gained root access via sudo.`, 'security', 3);
    }
    if (message.includes('Failed password') && message.includes('invalid user')) {
      await createAlert(agentId, '🚨 Invalid User Login Attempt',
        `Login attempt for non-existent user "${username}" from ${ip}.`, 'security', 4);
    }
    if (service === 'sshd' && message.includes('Accepted publickey')) {
      await createAlert(agentId, '✅ Successful SSH Login',
        `User "${username}" logged in via SSH from ${ip}.`, 'security', 2);
    }
    if (message.includes('account locked') || message.includes('maximum number of authentication failures')) {
      await createAlert(agentId, '🔒 Account Locked',
        `Account "${username}" locked after too many failed attempts.`, 'security', 3);
    }
  }

  // ========================
  // 3. FILE MONITORING
  // Agent severity takes precedence for file events since the agent has
  // direct knowledge of which specific file was touched.
  // ========================

  if (type === 'file_monitoring') {
    const monitoredFile = extractMonitoredFileName(message);
    if (!monitoredFile) return;
    if (!shouldCreateFileAlert(message, monitoredFile)) return;

    const formatted = formatFileAlert(message, monitoredFile);

    // Use agent's severity and MITRE tag if available
    if (agentAlreadyScored(log)) {
      await createAlert(
        agentId,
        formatted.title,
        `${formatted.description}${formatMitreContext(log)}`,
        'integrity',
        log.severity
      );
      return;
    }

    // Backend fallback
    let severity = 2;
    if (monitoredFile.includes('/etc/passwd') || monitoredFile.includes('/etc/shadow')) {
      severity = 4;
    } else if (message.includes('DELETED')) {
      severity = 4;
    } else if (message.includes('MODIFIED') || message.includes('UPDATED')) {
      severity = 3;
    }

    await createAlert(agentId, formatted.title, formatted.description,
      monitoredFile.includes('/etc/') ? 'integrity' : 'file_monitoring', severity);
  }

  // ========================
  // 4. PROCESS MONITORING
  // Agent severity is the primary source here — it has the full cmdline
  // and MITRE-tagged rules. Backend only creates alerts when the agent
  // has flagged something (severity >= 2), replacing the old keyword list.
  // ========================

  if (type === 'process') {
    if (agentAlreadyScored(log)) {
      // Agent detected something suspicious — create a rich alert
      const processMatch = message.match(/New Process: (.+?) \(PID/);
      const processName = processMatch ? processMatch[1] : 'unknown';

      await createAlert(
        agentId,
        `⚠️ Suspicious Process: ${processName} [${log.rule_id}]`,
        `${message}${formatMitreContext(log)}`,
        'process',
        log.severity
      );
    }
    // severity=1 (benign/unclassified) process events are streamed to the
    // frontend live log but don't generate alerts — reduces noise significantly.
  }
}

module.exports = { analyzeLog };