/**
 * server.js — Lite Solutions
 * - Static files from root (index.html, panel.html, admin.html, etc.)
 * - Discord OAuth2 login for client panel (/panel.html)
 * - Admin auth (2 passwords in Variables) with session
 * - Admin API for tickets read/send via bot token
 *
 * Works on https://www.litesolutions.pl
 */

const path = require("path");
const express = require("express");
const session = require("express-session");
const crypto = require("crypto");

// Node 20 has global fetch. If you are on older node, install node-fetch.
const app = express();
app.set("trust proxy", 1); // important on Railway / reverse proxies

// -------------------- ENV --------------------
const {
  NODE_ENV,
  PORT,

  // Discord OAuth (client login)
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI, // e.g. https://www.litesolutions.pl/auth/discord/callback

  // Session cookie
  SESSION_SECRET,

  // Admin
  ADMIN_PASS_1,
  ADMIN_PASS_2,

  // Discord bot token for admin tickets API
  DISCORD_BOT_TOKEN,
  DISCORD_TICKETS_CATEGORY_ID, // e.g. 1266064860802973859
} = process.env;

const IS_PROD = NODE_ENV === "production";
const SERVER_PORT = PORT || 3000;

function must(name) {
  if (!process.env[name]) {
    console.error(`❌ Missing ENV: ${name}`);
    process.exit(1);
  }
}

// Required for OAuth + sessions
must("SESSION_SECRET");
must("DISCORD_CLIENT_ID");
must("DISCORD_CLIENT_SECRET");
must("DISCORD_REDIRECT_URI");

// Admin passwords are required only if you use admin login.
// If you want to run without admin, comment these two must() lines.
must("ADMIN_PASS_1");
must("ADMIN_PASS_2");

// Bot token is required only for tickets API.
// You can leave it empty if you don't use tickets endpoints.
const HAS_BOT_API = !!DISCORD_BOT_TOKEN;

// -------------------- MIDDLEWARE --------------------
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    name: "ls.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax", // OAuth redirect works fine with lax on same-site
      secure: IS_PROD, // MUST be true on https
      maxAge: 1000 * 60 * 60 * 24 * 14, // 14 days
    },
  })
);

// No-store for auth sensitive endpoints
function noStore(res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
}

// -------------------- STATIC FILES (ROOT) --------------------
// IMPORTANT: you said all files are in repo root, no /public
app.use(
  express.static(__dirname, {
    extensions: ["html"],
    setHeaders(res, filePath) {
      if (filePath.endsWith(".html")) {
        res.setHeader("Cache-Control", "no-store");
      }
    },
  })
);

// -------------------- HELPERS --------------------
function requireClientAuth(req, res, next) {
  if (req.session?.user) return next();
  return res.redirect("/auth/discord");
}

function requireAdminAuth(req, res, next) {
  if (req.session?.admin) return next();
  return res.status(401).json({ error: "Unauthorized" });
}

function b64url(buf) {
  return Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function sha256base64url(str) {
  return b64url(crypto.createHash("sha256").update(str).digest());
}

function buildDiscordAuthUrl(req) {
  const state = b64url(crypto.randomBytes(16));
  const codeVerifier = b64url(crypto.randomBytes(32));
  const codeChallenge = sha256base64url(codeVerifier);

  req.session.oauth = {
    state,
    codeVerifier,
    createdAt: Date.now(),
  };

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: "code",
    redirect_uri: DISCORD_REDIRECT_URI,
    scope: "identify",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    prompt: "none",
  });

  return `https://discord.com/oauth2/authorize?${params.toString()}`;
}

async function discordTokenExchange(code, codeVerifier) {
  const body = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    client_secret: DISCORD_CLIENT_SECRET,
    grant_type: "authorization_code",
    code,
    redirect_uri: DISCORD_REDIRECT_URI,
    code_verifier: codeVerifier,
  });

  const resp = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`Token exchange failed: ${resp.status} ${text}`);
  }
  return resp.json();
}

async function discordGetUser(accessToken) {
  const resp = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`Get user failed: ${resp.status} ${text}`);
  }
  return resp.json();
}

function discordAvatarUrl(user) {
  // If no avatar, use default
  if (!user.avatar) {
    const idx = Number(user.discriminator) % 5 || 0;
    return `https://cdn.discordapp.com/embed/avatars/${idx}.png`;
  }
  const ext = user.avatar.startsWith("a_") ? "gif" : "png";
  return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${ext}?size=128`;
}

// ---- Discord bot API helpers for tickets ----
async function discordBotFetch(endpoint, options = {}) {
  if (!HAS_BOT_API) throw new Error("DISCORD_BOT_TOKEN is not set");

  const resp = await fetch(`https://discord.com/api/v10${endpoint}`, {
    ...options,
    headers: {
      Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    throw new Error(`Discord API error ${resp.status}: ${text}`);
  }
  // some endpoints return empty body
  const txt = await resp.text();
  return txt ? JSON.parse(txt) : null;
}

async function listTicketsInCategory(guildId, categoryId) {
  // We need to list channels in guild and filter by parent_id
  // GET /guilds/{guild.id}/channels requires bot in guild with proper perms.
  const channels = await discordBotFetch(`/guilds/${guildId}/channels`, { method: "GET" });
  return (channels || [])
    .filter((c) => c.parent_id === categoryId && c.type === 0) // 0 = GUILD_TEXT
    .map((c) => ({ id: c.id, name: c.name }));
}

async function getLastMessages(channelId, limit = 50) {
  const msgs = await discordBotFetch(`/channels/${channelId}/messages?limit=${limit}`, { method: "GET" });
  // Discord returns newest first. We want oldest -> newest for chat view
  return (msgs || []).reverse();
}

async function sendMessageAsBot(channelId, content) {
  return discordBotFetch(`/channels/${channelId}/messages`, {
    method: "POST",
    body: JSON.stringify({ content }),
  });
}

// -------------------- ROUTES --------------------

// Home - always show index.html (NOT auto login)
app.get("/", (req, res) => {
  noStore(res);
  return res.sendFile(path.join(__dirname, "index.html"));
});

// Client panel - must be authenticated
app.get("/panel.html", requireClientAuth, (req, res) => {
  noStore(res);
  return res.sendFile(path.join(__dirname, "panel.html"));
});

// Admin page is just static file (login is inside the file)
app.get("/admin.html", (req, res) => {
  noStore(res);
  return res.sendFile(path.join(__dirname, "admin.html"));
});

// ---- Discord OAuth ----
app.get("/auth/discord", (req, res) => {
  noStore(res);
  const url = buildDiscordAuthUrl(req);
  return res.redirect(url);
});

app.get("/auth/discord/callback", async (req, res) => {
  noStore(res);

  try {
    const { code, state } = req.query;

    if (!code || !state) return res.status(400).send("Missing code/state.");
    if (!req.session.oauth) return res.status(400).send("No oauth session.");

    if (state !== req.session.oauth.state) {
      return res.status(400).send("Invalid state.");
    }

    const { codeVerifier } = req.session.oauth;
    // cleanup oauth temp
    req.session.oauth = null;

    const token = await discordTokenExchange(code, codeVerifier);
    const user = await discordGetUser(token.access_token);

    // store minimal user data in session
    req.session.user = {
      id: user.id,
      username: user.username,
      global_name: user.global_name || null,
      discriminator: user.discriminator,
      avatar: user.avatar || null,
      avatar_url: discordAvatarUrl(user),
    };

    // redirect to panel
    return res.redirect("/panel.html");
  } catch (e) {
    console.error("OAuth callback error:", e);
    return res.status(500).send("OAuth error. Check server logs.");
  }
});

app.post("/auth/logout", (req, res) => {
  noStore(res);
  req.session.destroy(() => {
    res.clearCookie("ls.sid");
    return res.json({ ok: true });
  });
});

// Current logged in user for panel
app.get("/api/me", (req, res) => {
  noStore(res);
  if (!req.session.user) return res.status(401).json({ error: "Unauthorized" });
  return res.json({ user: req.session.user });
});

// ---- Admin auth (2 passwords) ----
app.post("/admin/auth/login", (req, res) => {
  noStore(res);
  const { pass1, pass2 } = req.body || {};

  if (typeof pass1 !== "string" || typeof pass2 !== "string") {
    return res.status(400).json({ error: "Bad request" });
  }

  if (pass1 === ADMIN_PASS_1 && pass2 === ADMIN_PASS_2) {
    req.session.admin = { ok: true, at: Date.now() };
    return res.json({ ok: true });
  }

  return res.status(401).json({ error: "Unauthorized" });
});

app.post("/admin/auth/logout", (req, res) => {
  noStore(res);
  if (req.session) {
    req.session.admin = null;
  }
  return res.json({ ok: true });
});

app.get("/api/admin/me", (req, res) => {
  noStore(res);
  if (!req.session?.admin) return res.status(401).json({ ok: false });
  return res.json({ ok: true });
});

// ---- Admin Tickets API (Discord bot token) ----
// IMPORTANT: these endpoints require:
// - DISCORD_BOT_TOKEN
// - DISCORD_TICKETS_CATEGORY_ID
// - and your guildId param in request
//
// How to call:
// GET /api/admin/tickets?guildId=YOUR_GUILD_ID
// GET /api/admin/tickets/:channelId
// POST /api/admin/tickets/:channelId/send
//
// Your admin.html can store guildId in JS later.

app.get("/api/admin/tickets", requireAdminAuth, async (req, res) => {
  noStore(res);

  try {
    if (!HAS_BOT_API) return res.status(400).json({ error: "DISCORD_BOT_TOKEN not set" });
    const guildId = String(req.query.guildId || "");
    const categoryId = String(DISCORD_TICKETS_CATEGORY_ID || "");

    if (!guildId) return res.status(400).json({ error: "Missing guildId query" });
    if (!categoryId) return res.status(400).json({ error: "Missing DISCORD_TICKETS_CATEGORY_ID" });

    const tickets = await listTicketsInCategory(guildId, categoryId);
    return res.json({ tickets });
  } catch (e) {
    console.error("Tickets list error:", e);
    return res.status(500).json({ error: "Tickets list failed" });
  }
});

app.get("/api/admin/tickets/:channelId", requireAdminAuth, async (req, res) => {
  noStore(res);

  try {
    if (!HAS_BOT_API) return res.status(400).json({ error: "DISCORD_BOT_TOKEN not set" });

    const channelId = req.params.channelId;
    const msgs = await getLastMessages(channelId, 50);

    const messages = (msgs || []).map((m) => ({
      id: m.id,
      author: m.author?.username || "Unknown",
      authorType: m.author?.bot ? "bot" : "user",
      content: m.content || "",
      timestamp: m.timestamp || m.edited_timestamp || new Date().toISOString(),
    }));

    return res.json({ messages });
  } catch (e) {
    console.error("Ticket read error:", e);
    return res.status(500).json({ error: "Ticket read failed" });
  }
});

app.post("/api/admin/tickets/:channelId/send", requireAdminAuth, async (req, res) => {
  noStore(res);

  try {
    if (!HAS_BOT_API) return res.status(400).json({ error: "DISCORD_BOT_TOKEN not set" });

    const channelId = req.params.channelId;
    const { content } = req.body || {};
    if (!content || typeof content !== "string" || !content.trim()) {
      return res.status(400).json({ error: "Missing content" });
    }

    await sendMessageAsBot(channelId, content.trim().slice(0, 1900));
    return res.json({ ok: true });
  } catch (e) {
    console.error("Ticket send error:", e);
    return res.status(500).json({ error: "Ticket send failed" });
  }
});

// Fallback: if someone hits unknown route, serve index for convenience
app.use((req, res) => {
  // If file exists, express.static would have served it. Here we just show 404.
  return res.status(404).send("Not Found");
});

// -------------------- START --------------------
app.listen(SERVER_PORT, () => {
  console.log(`✅ server.js running on port ${SERVER_PORT} (${IS_PROD ? "prod" : "dev"})`);
  console.log(`- Home: / -> index.html`);
  console.log(`- Panel: /panel.html (requires Discord login)`);
  console.log(`- Admin: /admin.html (login inside file)`);
});
