const WebSocket = require('ws');
const url = require('url');
const { supabase, setAgentOnline, updateAgentStats, createAlert } = require('./supabase');
const { analyzeLog } = require('./detector');
const { signCommand } = require('./commandSigner');

// Map to store active agent connections: agent_id -> WebSocket
const agents = new Map();
// Map to store active frontend connections: user_id -> WebSocket (for live logs)
const frontends = new Set();

function setupWebSocketServer(server) {
  const wss = new WebSocket.Server({ server });

  wss.on('connection', async (ws, req) => {
    const parameters = url.parse(req.url, true).query;
    const agentId = parameters.agent_id;
    const userId = parameters.user_id;

    // --- HANDLE AGENT CONNECTION ---
    if (agentId) {
      console.log(`Agent connected: ${agentId}`);
      agents.set(agentId, ws);
      await setAgentOnline(agentId, true);

      ws.on('message', async (message) => {
        try {
          const data = JSON.parse(message);

          // Case A: System Stats Report
          if (data.type === 'agent_report') {
            // Generate alert if CPU or RAM usage is critically high
            const cpuUsage = data.data.cpu_usage;
            const ramUsage = data.data.ram_usage;
            
            // if (cpuUsage >= 90) {
            //   await createAlert(
            //     agentId,
            //     'High CPU Usage',
            //     `CPU usage is critically high at ${cpuUsage}%`,
            //     'system',
            //     3
            //   );
            // }
            if (ramUsage >= 90) {
              await createAlert(
                agentId,
                'High RAM Usage',
                `RAM usage is critically high at ${ramUsage}%`,
                'system',
                3
              );
            }
            await updateAgentStats(agentId, data.data);
            await supabase
              .from('agents')
              .update({ firewall_enabled: data.data.firewall_enabled })
              .eq('id', agentId);

            // 2. Broadcast to frontend so UI shows current rules/status
            broadcastToFrontends({
                type: 'firewall_sync',
                agent_id: agentId,
                rules: data.data.firewall_rules,
                enabled: data.data.firewall_enabled
            });
          }
          else if (data.type === 'firewall_update') {
            broadcastToFrontends({
                type: 'firewall_rules_updated',
                agent_id: agentId,
                rules: data.rules
            });
          }
          else if (data.type === 'command_response' && data.status === 'rejected') {
            // Agent rejected one of our commands (bad signature, replay, validation
            // failure, or protected port). This is itself a security-relevant event.
            console.warn(`Agent ${agentId} REJECTED command (id=${data.id}): ${data.reason}`);
            await createAlert(
              agentId,
              'Command Rejected by Agent',
              `Agent rejected a command: ${data.reason}`,
              'security',
              2
            );
            broadcastToFrontends({
              type: 'command_rejected',
              agent_id: agentId,
              reason: data.reason,
            });
          }
          else {
            // 1. Run detection logic
            analyzeLog(agentId, data);
            
            // 2. Ignore process logs for sleep and cpuUsage to reduce noise
            if (data.type === 'process' && 
                (data.message.includes('sleep') || data.message.includes('cpuUsage') || data.message.includes('kworker'))) {
              return;
            }
            // 3. Stream to Frontend (Live Logs)
            broadcastToFrontends({
              type: 'log_stream',
              agent_id: agentId,
              log: data
            });
          }
        } catch (err) {
          console.error('Error processing message:', err);
        }
      });

      ws.on('close', async () => {
        console.log(`Agent disconnected: ${agentId}`);
        agents.delete(agentId);
        await setAgentOnline(agentId, false);
      });
    } 
    
    // --- HANDLE FRONTEND CONNECTION ---
    else if (userId) {
      console.log(`Frontend User connected: ${userId}`);
      frontends.add(ws);
      
      ws.on('message', (message) => {
        const data = JSON.parse(message);

        if (data.type === 'frontend_command') {
          // Forward UI requests to add/delete rules to the specific agent
          sendCommandToAgent(data.agent_id, data.command, data.payload);
        }      
      });

      ws.on('close', () => {
        frontends.delete(ws);
      });
    }
  });

  return { agents, frontends };
}

function broadcastToFrontends(data) {
  const payload = JSON.stringify(data);
  for (const client of frontends) {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  }
}

function sendCommandToAgent(agentId, command, payload = {}) {
  const ws = agents.get(agentId);
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    console.warn(`Cannot send command. Agent ${agentId} is offline.`);
    return false;
  }

  let signedCommand;
  try {
    signedCommand = signCommand(command, payload);
  } catch (err) {
    // Happens if AGENT_SHARED_SECRET is not configured on the backend.
    console.error(`Failed to sign command '${command}' for agent ${agentId}: ${err.message}`);
    return false;
  }

  ws.send(JSON.stringify(signedCommand));
  console.log(`Sent signed command '${command}' (id=${signedCommand.id}) to agent ${agentId}`);
  return true;
}

module.exports = { setupWebSocketServer, sendCommandToAgent };