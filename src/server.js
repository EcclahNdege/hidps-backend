const express = require('express');
const http = require('http'); // Essential for sharing the Render port
const { setupWebSocketServer, sendCommandToAgent } = require('./websocket');
const { supabase } = require('./supabase');
const { createEnrollmentToken, redeemEnrollmentToken } = require('./enrollment');

const app = express();
app.use(express.json());

const server = http.createServer(app); // Wraps express to allow WebSockets on same port

// --- INITIALIZE WEBSOCKET LAYER ---
// We pass the 'server' object so WebSockets "hitchhike" on port 10000
const { agents } = setupWebSocketServer(server);

// --- HEALTH CHECK ENDPOINT ---
// Render needs this to confirm your service is "Healthy"
app.get('/', (req, res) => {
  res.status(200).send('HIDPS Backend is running.');
});

// --- AGENT REGISTRATION ---
// Creates a new agent row (if needed) and issues a short-lived, single-use
// enrollment token. The token is what gets handed to whoever is installing
// the agent -- NOT the real shared secret.
app.post('/agents/register', async (req, res) => {
  const { agent_id, name, owner_id } = req.body;

  if (!agent_id) {
    return res.status(400).json({ error: 'agent_id is required.' });
  }

  try {
    // Ensure the agent row exists. Adjust the upsert fields to match your
    // actual agents table schema/requirements (owner_id is likely required
    // by your RLS policies if you have them).
    const { error: upsertError } = await supabase
      .from('agents')
      .upsert(
        { id: agent_id, name: name || agent_id, owner_id, is_online: false },
        { onConflict: 'id' }
      );

    if (upsertError) {
      console.error('Failed to upsert agent row:', upsertError.message);
      return res.status(500).json({ error: 'Failed to register agent.' });
    }

    const { token, expiresAt } = await createEnrollmentToken(agent_id);

    return res.status(201).json({
      agent_id,
      enrollment_token: token,
      expires_at: expiresAt.toISOString(),
      message: 'Provide this enrollment token to the agent installer. It is valid once, for 15 minutes.',
    });
  } catch (err) {
    console.error('Error during agent registration:', err.message);
    return res.status(500).json({ error: 'Internal error during registration.' });
  }
});

// --- AGENT ENROLLMENT ---
// Called once by the agent itself on first boot. Exchanges a single-use
// enrollment token for the real AGENT_SHARED_SECRET, over HTTPS.
app.post('/enroll', async (req, res) => {
  const { agent_id, enrollment_token } = req.body;

  if (!agent_id || !enrollment_token) {
    return res.status(400).json({ error: 'agent_id and enrollment_token are required.' });
  }

  const result = await redeemEnrollmentToken(agent_id, enrollment_token);

  if (!result.success) {
    console.warn(`Enrollment failed for agent ${agent_id}: ${result.reason}`);
    return res.status(403).json({ error: result.reason });
  }

  console.log(`Agent ${agent_id} successfully enrolled.`);
  return res.status(200).json({ secret: result.secret });
});

// --- SUPABASE REALTIME LISTENERS ---
// 1. Listen for Firewall Toggles
supabase
  .channel('public:agents')
  .on(
    'postgres_changes',
    { event: 'UPDATE', schema: 'public', table: 'agents' },
    (payload) => {
      const { id, firewall_enabled } = payload.new;
      const oldState = payload.old.firewall_enabled;
      if (oldState === undefined) return;
      console.log("Payload received for agent update:", payload);
      if (firewall_enabled !== oldState) {
        console.log(`State change detected for ${id}: Firewall -> ${firewall_enabled}`);
        sendCommandToAgent(id, 'toggle_firewall', { enabled: firewall_enabled });
      }
    }
  )
  .subscribe();

// 2. Listen for File Monitoring Changes
supabase
  .channel('public:monitored_files')
  .on(
    'postgres_changes',
    { event: 'INSERT', schema: 'public', table: 'monitored_files' },
    (payload) => {
      const { agent_id, file_path } = payload.new;
      console.log(`New file monitor requested for ${agent_id}: ${file_path}`);
      sendCommandToAgent(agent_id, 'monitor_file', { path: file_path });
    }
  )
  .on(
    'postgres_changes',
    { event: 'DELETE', schema: 'public', table: 'monitored_files' },
    (payload) => {
      const { agent_id, file_path } = payload.old;
      if (file_path) {
        console.log(`Stop monitor requested for ${agent_id}: ${file_path}`);
        sendCommandToAgent(agent_id, 'unmonitor_file', { path: file_path });
      } else {
        console.warn("Check Replica Identity on Supabase for DELETE events.");
      }
    }
  )
  .subscribe();

// --- START SERVER ---
// Render provides the PORT dynamically; 0.0.0.0 is required for external access
const PORT = process.env.PORT || 3000;
const HOST = '0.0.0.0';
server.listen(PORT, HOST, () => {
  console.log(`HIDPS Backend and WebSocket server listening on port ${PORT}`);
});