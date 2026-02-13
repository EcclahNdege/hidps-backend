const express = require('express');
const http = require('http'); // Essential for sharing the Render port
const { setupWebSocketServer, sendCommandToAgent } = require('./websocket');
const { supabase } = require('./supabase');

const app = express();
const server = http.createServer(app); // Wraps express to allow WebSockets on same port

// --- INITIALIZE WEBSOCKET LAYER ---
// We pass the 'server' object so WebSockets "hitchhike" on port 10000
const { agents } = setupWebSocketServer(server);

// --- HEALTH CHECK ENDPOINT ---
// Render needs this to confirm your service is "Healthy"
app.get('/', (req, res) => {
  res.status(200).send('HIDPS Backend is running.');
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