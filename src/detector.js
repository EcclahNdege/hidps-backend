const { createAlert } = require('./supabase');

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
 * Analyzes logs and triggers alerts for suspicious activity.
 */
async function analyzeLog(agentId, log) {
  const { type, service, message } = log;

  // 1. Detect Failed SSH Logins (Brute Force indicators)
  if (type === 'login' && service === 'sshd') {
    if (message.includes('Failed password') || message.includes('authentication failure')) {
      await createAlert(
        agentId, 
        'Failed SSH Login Attempt', 
        `Multiple failed login attempts detected: ${message}`, 
        'security', 
        3
      );
    }
  }

  // 2. Detect Critical File Modifications (IMPROVED)
  if (type === 'file_monitoring') {
    const monitoredFile = extractMonitoredFileName(message);
    
    if (!monitoredFile) {
      // Skip temp files and unrecognized patterns
      return;
    }

    // Critical system files get highest severity
    if (monitoredFile.includes('/etc/passwd') || monitoredFile.includes('/etc/shadow')) {
      const formatted = formatFileAlert(message, monitoredFile);
      await createAlert(
        agentId,
        formatted.title,
        formatted.description,
        'integrity',
        4
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

  // 3. Detect Firewall Blocks (Port Scanning indicators)
  if (type === 'firewall') {
    if (message.includes('BLOCK')) {
      // Logic to avoid spamming alerts for every packet could be added here
      // For now, we log it or create a low severity alert
      // await createAlert(agentId, 'Firewall Block', message, 'network', 1);
    }
  }

  // 4. Detect new processes involving sudo (Privilege Escalation indicators)
  if (type === 'process') {
    if (message.includes('sudo')) {
      await createAlert(
        agentId,
        'Sudo Command Executed',
        `A command was executed with sudo: ${message}`,
        'privilege_escalation',
        2
      );
    }
  }

  if (type === 'login' && service === 'sudo') {
    if (message.includes('session opened for user root')) {
      await createAlert(
        agentId, 
        'Root Session Opened', 
        `Root session opened: ${message}`, 
        'security', 
        3
      );
    }
  }
}

module.exports = { analyzeLog };