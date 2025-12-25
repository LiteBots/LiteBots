/**
 * server.js — Lite Solutions
 * - Static files from root (index.html, panel.html, admin.html, etc.)
 * - Discord OAuth2 login for client panel (/panel.html)
 * - Admin auth (ONE input, accepts 2 passwords in Variables) with session
 * - Admin API for tickets read/send via bot token
 */

const path = require("path");
const express = require("express");
const session = require("express-session");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", 1);

const {
  NODE_ENV,
  PORT,

  // Discord OAuth (client login)
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI, // e.g. https://www.litesolutions.pl/auth/discord/callback

  // Session cookie
  SESSION_SECRET,

  // Admin (two allowed passwords)
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

must("SESSION_SECRET");
must("DISCORD_CLIENT_ID");
must("DISCORD_CLIENT_SECRET");
must("DISCORD_REDIRECT_URI");

// Admin passwords required (since you want admin login)
must("ADMIN_PASS_1");
must("ADMIN_PASS_2");

const HAS_BOT_API = !!DISCORD_BOT_TOKEN;

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
      sameSite: "lax",
      secure: IS_PROD,
      maxAge: 1000 * 60 * 60 * 24 * 14, // 14 days
    },
  })
);

function noStore(res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
}

// -------------------- STATIC (ROOT) --------------------
app.use(
  express.static(__dirname, {
    extensions: ["html"],
    setHeaders(res, filePath) {
      if (filePath.endsWith(".html")) res.setHeader("Cache-Control", "no-store");
    },
  })
);

// -------------------- AUTH GUARDS --------------------
function requireClientAuth(req, res, next) {
  if (req.session?.user) return next();
  return res.redirect("/auth/discord");
}

function requireAdminAuth(req, res, next) {
  if (req.session?.admin) return next();
  return res.status(401).json({ error: "Unauthorized" });
}

// -------------------- OAUTH HELPERS --------------------
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
  if (!user.avatar) {
    const idx = Number(user.discriminator) % 5 || 0;
    return `https://cdn.discordapp.com/embed/avatars/${idx}.png`;
  }
  const ext = user.avatar.startsWith("a_") ? "gif" : "png";
  return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${ext}?size=128`;
}

// -------------------- DISCORD BOT API (TICKETS) --------------------
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

  const txt = await resp.text();
  return txt ? JSON.parse(txt) : null;
}

async function listTicketsInCategory(guildId, categoryId) {
  const channels = await discordBotFetch(`/guilds/${guildId}/channels`, { method: "GET" });
  return (channels || [])
    .filter((c) => c.parent_id === categoryId && c.type === 0) // 0 = text
    .map((c) => ({ id: c.id, name: c.name }));
}

async function getLastMessages(channelId, limit = 50) {
  const msgs = await discordBotFetch(`/channels/${channelId}/messages?limit=${limit}`, { method: "GET" });
  return (msgs || []).reverse();
}

async function sendMessageAsBot(channelId, content) {
  return discordBotFetch(`/channels/${channelId}/messages`, {
    method: "POST",
    body: JSON.stringify({ content }),
  });
}

// -------------------- ROUTES --------------------

// Home always index.html
app.get("/", (req, res) => {
  noStore(res);
  return res.sendFile(path.join(__dirname, "index.html"));
});

// Panel requires Discord login
app.get("/panel.html", requireClientAuth, (req, res) => {
  noStore(res);
  return res.sendFile(path.join(__dirname, "panel.html"));
});

// Admin page is static (login inside admin.html)
app.get("/admin.html", (req, res) => {
  noStore(res);
  return res.sendFile(path.join(__dirname, "admin.html"));
});

// ---- Discord OAuth ----
app.get("/auth/discord", (req, res) => {
  noStore(res);
  return res.redirect(buildDiscordAuthUrl(req));
});

app.get("/auth/discord/callback", async (req, res) => {
  noStore(res);

  try {
    const { code, state } = req.query;

    if (!code || !state) return res.status(400).send("Missing code/state.");
    if (!req.session.oauth) return res.status(400).send("No oauth session.");
    if (state !== req.session.oauth.state) return res.status(400).send("Invalid state.");

    const { codeVerifier } = req.session.oauth;
    req.session.oauth = null;

    const token = await discordTokenExchange(code, codeVerifier);
    const user = await discordGetUser(token.access_token);

    req.session.user = {
      id: user.id,
      username: user.username,
      global_name: user.global_name || null,
      discriminator: user.discriminator,
      avatar: user.avatar || null,
      avatar_url: discordAvatarUrl(user),
    };

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

// Panel user
app.get("/api/me", (req, res) => {
  noStore(res);
  if (!req.session.user) return res.status(401).json({ error: "Unauthorized" });
  return res.json({ user: req.session.user });
});

// ---- Admin auth (ONE INPUT, accepts 2 passwords) ----
app.post("/admin/auth/login", (req, res) => {
  noStore(res);

  const { password } = req.body || {};
  if (typeof password !== "string") return res.status(400).json({ error: "Bad request" });

  const ok = password === ADMIN_PASS_1 || password === ADMIN_PASS_2;

  if (ok) {
    req.session.admin = { ok: true, at: Date.now() };
    return res.json({ ok: true });
  }
  return res.status(401).json({ error: "Unauthorized" });
});

app.post("/admin/auth/logout", (req, res) => {
  noStore(res);
  if (req.session) req.session.admin = null;
  return res.json({ ok: true });
});

app.get("/api/admin/me", (req, res) => {
  noStore(res);
  if (!req.session?.admin) return res.status(401).json({ ok: false });
  return res.json({ ok: true });
});

// ---- Admin tickets API ----
// Call examples:
// GET /api/admin/tickets?guildId=YOUR_GUILD_ID
// GET /api/admin/tickets/:channelId
// POST /api/admin/tickets/:channelId/send {content}
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

// 404
app.use((req, res) => res.status(404).send("Not Found"));

app.listen(SERVER_PORT, () => {
  console.log(`✅ server.js running on port ${SERVER_PORT} (${IS_PROD ? "prod" : "dev"})`);
});
