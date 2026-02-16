const { createAlert } = require('./supabase');
const { notifyCriticalAlert } = require('./email');
const { supabase } = require('./supabase');

// ========================
// PORT SCAN DETECTION
// ========================

// Track blocked IPs to detect port scanning patterns
const blockedIPs = new Map(); // IP -> { count, firstSeen, lastSeen, ports }

/**
 * Detect port scanning patterns from firewall blocks
 */
function analyzeFirewallBlock(message, agentId) {
  // Parse UFW block message
  // Example: "UFW BLOCK IN=eth0 SRC=192.168.1.100 DST=192.168.1.1 PROTO=TCP DPT=22"
  
  const srcMatch = message.match(/SRC=([0-9.]+)/);
  const dptMatch = message.match(/DPT=([0-9]+)/);
  const protoMatch = message.match(/PROTO=(\w+)/);
  
  if (!srcMatch || !dptMatch) return null;
  
  const sourceIP = srcMatch[1];
  const destPort = dptMatch[1];
  const protocol = protoMatch ? protoMatch[1] : 'TCP';
  
  const now = Date.now();
  
  // Get or create tracking entry for this IP
  if (!blockedIPs.has(sourceIP)) {
    blockedIPs.set(sourceIP, {
      count: 0,
      firstSeen: now,
      lastSeen: now,
      ports: new Set()
    });
  }
  
  const ipData = blockedIPs.get(sourceIP);
  ipData.count++;
  ipData.lastSeen = now;
  ipData.ports.add(destPort);
  
  // Clean up old entries (older than 1 hour)
  for (const [ip, data] of blockedIPs.entries()) {
    if (now - data.lastSeen > 3600000) {
      blockedIPs.delete(ip);
    }
  }
  
  // Detect port scan patterns
  const timeWindow = now - ipData.firstSeen;
  const uniquePorts = ipData.ports.size;
  
  // Pattern 1: Multiple ports in short time (Classic port scan)
  if (uniquePorts >= 5 && timeWindow < 60000) { // 5+ ports in 1 minute
    return {
      type: 'port_scan_detected',
      severity: 4,
      title: '🚨 Port Scan Detected',
      description: `IP ${sourceIP} attempted to access ${uniquePorts} different ports in ${Math.round(timeWindow/1000)} seconds. This is likely a port scanning attack.`,
      details: `Ports scanned: ${Array.from(ipData.ports).join(', ')}`
    };
  }
  
  // Pattern 2: Slow scan (many attempts over longer period)
  if (ipData.count >= 20 && timeWindow < 300000) { // 20+ attempts in 5 minutes
    return {
      type: 'slow_scan_detected',
      severity: 3,
      title: '⚠️ Slow Port Scan Detected',
      description: `IP ${sourceIP} made ${ipData.count} connection attempts to ${uniquePorts} ports over ${Math.round(timeWindow/60000)} minutes. This may be a stealth scan.`,
      details: `Ports targeted: ${Array.from(ipData.ports).join(', ')}`
    };
  }
  
  // Pattern 3: Repeated attacks on same port (brute force)
  if (ipData.count >= 10 && uniquePorts === 1) {
    return {
      type: 'brute_force_detected',
      severity: 4,
      title: '🔨 Brute Force Attack Detected',
      description: `IP ${sourceIP} made ${ipData.count} repeated connection attempts to port ${destPort}. This appears to be a brute force attack.`,
      details: `Target port: ${destPort} (${protocol})`
    };
  }
  
  // Pattern 4: High-value port targeting
  const sensitivePorts = ['22', '3389', '445', '135', '1433', '3306', '5432', '27017'];
  if (sensitivePorts.includes(destPort) && ipData.count >= 3) {
    return {
      type: 'sensitive_port_probe',
      severity: 3,
      title: '🎯 Sensitive Port Probe',
      description: `IP ${sourceIP} is probing sensitive port ${destPort}. This port is commonly targeted by attackers.`,
      details: `Port ${destPort} is used for: ${getPortDescription(destPort)}`
    };
  }
  
  return null;
}

/**
 * Get description of common ports
 */
function getPortDescription(port) {
  const portMap = {
    '22': 'SSH (Remote Access)',
    '3389': 'RDP (Windows Remote Desktop)',
    '445': 'SMB (Windows File Sharing)',
    '135': 'Windows RPC',
    '1433': 'MS SQL Server',
    '3306': 'MySQL Database',
    '5432': 'PostgreSQL Database',
    '27017': 'MongoDB Database',
    '80': 'HTTP Web Server',
    '443': 'HTTPS Web Server',
    '21': 'FTP File Transfer',
    '23': 'Telnet',
    '25': 'SMTP Email',
    '53': 'DNS',
    '110': 'POP3 Email',
    '143': 'IMAP Email'
  };
  return portMap[port] || 'Unknown Service';
}

// ========================
// FILE MONITORING HELPERS
// ========================

/**
 * Extracts the actual monitored file name from a log message
 * Handles temp files like .goutputstream-XXXXX
 */
function extractMonitoredFileName(message) {
  // Pattern 1: "Monitored file MODIFIED: /path/to/file"
  const modifiedMatch = message.match(/Monitored file (?:MODIFIED|UPDATED|DELETED|MOVED): (.+?)(?:\s|$)/);
  if (modifiedMatch) {
    return modifiedMatch[1];
  }
  
  // Pattern 2: Look for actual file paths (not temp files)
  const pathMatch = message.match(/\/[\w\/.-]+/g);
  if (pathMatch) {
    // Filter out obvious temp files
    const realFiles = pathMatch.filter(path => 
      !path.includes('.goutputstream') &&
      !path.endsWith('~') &&
      !path.includes('.swp') &&
      !path.includes('.tmp')
    );
    return realFiles[0] || pathMatch[0];
  }
  
  return null;
}

/**
 * Creates a human-readable alert title and message
 */
function formatFileAlert(message, monitoredFile) {
  const filename = monitoredFile.split('/').pop(); // Get just the filename
  
  if (message.includes('MODIFIED') || message.includes('modified')) {
    return {
      title: `File Modified: ${filename}`,
      description: `The monitored file "${monitoredFile}" was modified.`
    };
  }
  
  if (message.includes('UPDATED') || message.includes('saved by editor')) {
    return {
      title: `File Saved: ${filename}`,
      description: `The monitored file "${monitoredFile}" was saved by an editor.`
    };
  }
  
  if (message.includes('DELETED') || message.includes('deleted')) {
    return {
      title: `🚨 File Deleted: ${filename}`,
      description: `CRITICAL: The monitored file "${monitoredFile}" was deleted!`
    };
  }
  
  if (message.includes('MOVED') || message.includes('RENAMED')) {
    return {
      title: `File Moved: ${filename}`,
      description: `The monitored file "${monitoredFile}" was moved or renamed.`
    };
  }
  
  if (message.includes('created')) {
    return {
      title: `File Created: ${filename}`,
      description: `A new file was created in the monitored location: "${monitoredFile}"`
    };
  }
  
  // Fallback
  return {
    title: `File Event: ${filename}`,
    description: message
  };
}

/**
 * Check if this file event should generate an alert
 */
function shouldCreateFileAlert(message, monitoredFile) {
  // ALWAYS alert on critical actions
  if (message.includes('DELETED') || message.includes('deleted')) {
    return true; // File deletion is always critical
  }
  
  if (message.includes('MOVED') || message.includes('RENAMED')) {
    return true; // File moving could be suspicious
  }
  
  // ALWAYS alert for critical system files
  if (monitoredFile.includes('/etc/passwd') || 
      monitoredFile.includes('/etc/shadow') ||
      monitoredFile.includes('/etc/sudoers') ||
      monitoredFile.includes('/etc/ssh/sshd_config')) {
    return true; // Critical system files - alert on any change
  }
  
  // For regular files, only alert on ACTUAL modifications, not temp file noise
  if (message.includes('MODIFIED') || message.includes('UPDATED')) {
    return true; // Direct modification or editor save
  }
  
  // Skip alerts for:
  // - "File/Dir created" (too noisy)
  // - "Monitored file being edited" (intermediate state)
  // - Temp file events
  if (message.includes('being edited') || 
      message.includes('File/Dir created') ||
      monitoredFile.includes('.goutputstream') ||
      monitoredFile.includes('.swp')) {
    return false;
  }
  
  // Default: create alert for unknown file events (be cautious)
  return true;
}

// ========================
// LOGIN MONITORING HELPERS
// ========================

/**
 * Extract username from login messages
 */
function extractUsername(message) {
  // SSH login patterns
  let match = message.match(/for (\w+) from/);
  if (match) return match[1];
  
  // Sudo patterns
  match = message.match(/(\w+)\s*:/);
  if (match && match[1] !== 'pam_unix') return match[1];
  
  // Session patterns
  match = message.match(/session opened for user (\w+)/);
  if (match) return match[1];
  
  return 'unknown';
}

/**
 * Extract IP address from login messages
 */
function extractIP(message) {
  const match = message.match(/from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/);
  return match ? match[1] : 'unknown';
}

// ========================
// MAIN LOG ANALYZER
// ========================

/**
 * Analyzes logs and triggers alerts for suspicious activity.
 */
async function analyzeLog(agentId, log) {
  const { type, service, message } = log;

  // ========================
  // 1. FIREWALL & PORT SCAN DETECTION
  // ========================
  
  if (type === 'firewall') {
    if (message.includes('BLOCK') || message.includes('UFW BLOCK')) {
      const scanAlert = analyzeFirewallBlock(message, agentId);
      
      if (scanAlert) {
        // Port scan or attack pattern detected!
        const alert = await createAlert(
          agentId,
          scanAlert.title,
          `${scanAlert.description}\n\n${scanAlert.details}`,
          'network',
          scanAlert.severity
        );
        
        // Send email notification for critical port scans
        if (alert && scanAlert.severity >= 3) {
          try {
            // Get agent info and user email
            const { data: agentData } = await supabase
              .from('agents')
              .select('name, owner_id')
              .eq('id', agentId)
              .single();
            
            if (agentData) {
              const { data: userData } = await supabase
                .from('auth.users')
                .select('email')
                .eq('id', agentData.owner_id)
                .single();
              
              if (userData?.email) {
                await notifyCriticalAlert(alert, agentData, userData.email);
              }
            }
          } catch (emailError) {
            console.error('Failed to send email notification:', emailError);
          }
        }
      }
      // Note: We don't create alerts for every single block to avoid spam
      // Only when patterns indicate scanning/attacks
    }
  }

  // ========================
  // 2. COMPREHENSIVE LOGIN MONITORING
  // ========================
  
  if (type === 'login') {
    const username = extractUsername(message);
    const ip = extractIP(message);
    
    // A. Failed SSH Password Attempts - CRITICAL
    if (service === 'sshd' && (message.includes('Failed password') || message.includes('authentication failure'))) {
      await createAlert(
        agentId, 
        '🔐 Failed SSH Login Attempt', 
        `Failed SSH login attempt for user "${username}" from ${ip}. This could indicate a brute force attack.`, 
        'security', 
        4  // CRITICAL severity
      );
    }
    
    // B. Failed sudo attempts - CRITICAL
    if (service === 'sudo' && message.includes('authentication failure')) {
      await createAlert(
        agentId,
        '⚠️ Failed Sudo Authentication',
        `User "${username}" failed to authenticate with sudo. Possible privilege escalation attempt.`,
        'security',
        4  // CRITICAL severity
      );
    }
    
    // C. Successful sudo to root - HIGH ALERT
    if (service === 'sudo' && message.includes('session opened for user root')) {
      await createAlert(
        agentId, 
        '🔓 Root Access Granted', 
        `User "${username}" successfully gained root access via sudo.`, 
        'security', 
        3  // HIGH severity
      );
    }
    
    // D. Multiple failed login attempts for invalid users - CRITICAL
    if (message.includes('Failed password') && message.includes('invalid user')) {
      await createAlert(
        agentId,
        '🚨 Invalid User Login Attempt',
        `Login attempt for non-existent user "${username}" from ${ip}. This is suspicious activity.`,
        'security',
        4  // CRITICAL severity
      );
    }
    
    // E. Successful SSH login - MEDIUM (for audit trail)
    if (service === 'sshd' && message.includes('Accepted publickey')) {
      await createAlert(
        agentId,
        '✅ Successful SSH Login',
        `User "${username}" successfully logged in via SSH from ${ip}.`,
        'security',
        2  // MEDIUM severity - for monitoring
      );
    }
    
    // F. Account lockout - HIGH
    if (message.includes('account locked') || message.includes('maximum number of authentication failures')) {
      await createAlert(
        agentId,
        '🔒 Account Locked',
        `Account "${username}" has been locked due to too many failed login attempts.`,
        'security',
        3  // HIGH severity
      );
    }
  }

  // ========================
  // 3. FILE MONITORING - WITH SMART FILTERING
  // ========================
  
  if (type === 'file_monitoring') {
    const monitoredFile = extractMonitoredFileName(message);
    
    if (!monitoredFile) {
      return;  // Skip temp files and unrecognized patterns
    }

    // Check if this event warrants an alert
    if (!shouldCreateFileAlert(message, monitoredFile)) {
      return;  // Log the event but don't create alert
    }

    // Critical system files get highest severity
    if (monitoredFile.includes('/etc/passwd') || monitoredFile.includes('/etc/shadow')) {
      const formatted = formatFileAlert(message, monitoredFile);
      await createAlert(
        agentId,
        formatted.title,
        formatted.description,
        'integrity',
        4  // CRITICAL
      );
    } 
    // Regular monitored files
    else {
      const formatted = formatFileAlert(message, monitoredFile);
      
      // Different severity based on action
      let severity = 2; // Default: medium
      if (message.includes('DELETED')) {
        severity = 4; // High: file deleted
      } else if (message.includes('MODIFIED') || message.includes('UPDATED')) {
        severity = 3; // Medium-high: file changed
      }
      
      await createAlert(
        agentId,
        formatted.title,
        formatted.description,
        'file_monitoring',
        severity
      );
    }
  }

  // ========================
  // 4. PROCESS MONITORING - PRIVILEGE ESCALATION
  // ========================
  
  if (type === 'process') {
    // Detect suspicious sudo usage
    if (message.includes('sudo')) {
      const processMatch = message.match(/New Process: (.+?) \(PID/);
      const processName = processMatch ? processMatch[1] : 'unknown';
      
      await createAlert(
        agentId,
        '⚠️ Sudo Command Executed',
        `A process "${processName}" was executed with sudo privileges.`,
        'privilege_escalation',
        2  // MEDIUM severity
      );
    }
    
    // Detect suspicious commands
    const suspiciousCommands = ['nc', 'netcat', 'ncat', 'wget', 'curl'];
    for (const cmd of suspiciousCommands) {
      if (message.toLowerCase().includes(cmd)) {
        await createAlert(
          agentId,
          '🚨 Suspicious Command Detected',
          `Potentially suspicious command detected: ${cmd}`,
          'process',
          3  // HIGH severity
        );
        break;
      }
    }
  }
}

module.exports = { analyzeLog };