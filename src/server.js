const express = require('express');
const http = require('http');
const { setupWebSocketServer, sendCommandToAgent } = require('./websocket');
const { supabase } = require('./supabase');

const app = express();
const server = http.createServer(app);

// Initialize WebSocket Layer
const { agents } = setupWebSocketServer(server);

// --- HEALTH CHECK ENDPOINT ---
app.get('/', (req, res) => {
  res.status(200).send('HIDPS Backend is running.');
});

// --- SUPABASE REALTIME LISTENERS ---

// 1. Listen for Firewall Toggles
// When Frontend updates 'agents' -> Backend sees it -> Commands Agent
supabase
  .channel('public:agents')
  .on(
    'postgres_changes',
    { event: 'UPDATE', schema: 'public', table: 'agents' },
    (payload) => {
      const { id, firewall_enabled } = payload.new;
      const oldState = payload.old.firewall_enabled;

      if (oldState === undefined) return; // Initial NULL state on first insert
      // Only send command if state actually changed
      console.log("Payload received for agent update:", payload);
      if (firewall_enabled !== oldState) {
        console.log(`State change detected for ${id}: Firewall -> ${firewall_enabled}`);
        sendCommandToAgent(id, 'toggle_firewall', { enabled: firewall_enabled });
      }
    }
  )
  .subscribe();

// 2. Listen for File Monitoring Changes
// When Frontend adds a file to 'monitored_files' -> Backend commands Agent
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
      // Note: DELETE payload.old only contains the ID unless REPLICA IDENTITY is FULL
      // If your table doesn't have Full Replica Identity, you might need to query the ID or change DB settings.
      // Assuming we can get the data, or payload.old contains file_path:
      const { agent_id, file_path } = payload.old;
      if (file_path) {
          console.log(`Stop monitor requested for ${agent_id}: ${file_path}`);
          sendCommandToAgent(agent_id, 'unmonitor_file', { path: file_path });
      } else {
          console.warn("Could not determine file path from DELETE event. Ensure Replica Identity is set to FULL for monitored_files table.");
      }
    }
  )
  .subscribe();

// --- START SERVER ---

const PORT = process.env.PORT || 3000; // Render provides the PORT env var
const HOST = '0.0.0.0'; // Listen on all network interfaces for containerized environments

server.listen(PORT, HOST, () => {
  console.log(`HIDPS Backend and WebSocket server listening on port ${PORT}`);
});