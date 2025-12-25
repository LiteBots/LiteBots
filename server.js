const express = require("express");
const session = require("express-session");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");

const app = express();

const {
  PORT = 3000,
  NODE_ENV = "development",

  // Sessions
  SESSION_SECRET,

  // Client panel Discord OAuth
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI, // https://www.litesolutions.pl/auth/discord/callback
  POST_LOGIN_REDIRECT = "/panel.html",

  // Admin login (two passwords)
  ADMIN_PASS_1,
  ADMIN_PASS_2,

  // Discord bot for tickets (admin)
  DISCORD_BOT_TOKEN,
  DISCORD_TICKETS_CATEGORY_ID, // ID kategorii, w której są kanały ticketów
} = process.env;

function requireEnv(name) {
  if (!process.env[name]) {
    console.error(`[ENV] Missing ${name}`);
    process.exit(1);
  }
}

// Required for base app
requireEnv("SESSION_SECRET");

// Required for client OAuth (panel)
requireEnv("DISCORD_CLIENT_ID");
requireEnv("DISCORD_CLIENT_SECRET");
requireEnv("DISCORD_REDIRECT_URI");

// Admin passwords required for admin panel login
requireEnv("ADMIN_PASS_1");
requireEnv("ADMIN_PASS_2");

app.set("trust proxy", 1);
app.use(express.json());

// ---- Sessions ----
app.use(
  session({
    name: "ls_sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  })
);

// ---- Helpers ----
function discordAvatarUrl(user) {
  if (!user?.id) return null;
  if (!user.avatar) return "https://cdn.discordapp.com/embed/avatars/0.png";
  const isGif = user.avatar.startsWith("a_");
  const ext = isGif ? "gif" : "png";
  return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${ext}?size=128`;
}

function requireUser(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: "unauthorized" });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session?.admin) return res.status(401).json({ error: "admin_unauthorized" });
  next();
}

// ============================================================================
// CLIENT AUTH: Discord OAuth2 (Panel Klienta)
// ============================================================================

app.get("/auth/discord", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify",
    state,
    prompt: "none",
  });

  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

app.get("/auth/discord/callback", async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.status(400).send("Missing code");
    if (!state || state !== req.session.oauthState) return res.status(400).send("Invalid state");

    const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code: String(code),
        redirect_uri: DISCORD_REDIRECT_URI,
      }),
    });

    if (!tokenRes.ok) {
      const txt = await tokenRes.text();
      console.error("[Discord token exchange failed]", tokenRes.status, txt);
      return res.status(500).send("Discord token exchange failed");
    }

    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token;

    const meRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!meRes.ok) {
      const txt = await meRes.text();
      console.error("[Discord profile fetch failed]", meRes.status, txt);
      return res.status(500).send("Discord profile fetch failed");
    }

    const user = await meRes.json();

    req.session.user = {
      discordId: user.id,
      username: user.global_name || user.username,
      avatarUrl: discordAvatarUrl(user),
    };

    delete req.session.oauthState;
    return res.redirect(POST_LOGIN_REDIRECT);
  } catch (err) {
    console.error("[/auth/discord/callback] Error:", err);
    return res.status(500).send("Login error");
  }
});

app.post("/auth/logout", (req, res) => {
  // Wylogowanie klienta (nie admina)
  delete req.session.user;
  res.json({ ok: true });
});

// Client API
app.get("/api/me", requireUser, (req, res) => {
  res.json({ user: req.session.user });
});

// ============================================================================
// ADMIN AUTH: login with 2 passwords (Variables)
// ============================================================================

app.post("/admin/auth/login", (req, res) => {
  const { pass1, pass2 } = req.body || {};
  const ok = typeof pass1 === "string" && typeof pass2 === "string" &&
    pass1 === ADMIN_PASS_1 && pass2 === ADMIN_PASS_2;

  if (!ok) return res.status(401).json({ error: "invalid_admin_passwords" });

  req.session.admin = true;
  res.json({ ok: true });
});

app.post("/admin/auth/logout", (req, res) => {
  delete req.session.admin;
  res.json({ ok: true });
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({ admin: true });
});

// Protect admin.html + ticket routes
app.get("/admin.html", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (!req.session?.admin) return res.redirect("/admin/login.html");
  return res.sendFile(path.join(__dirname, "admin.html"));
});

// ============================================================================
// DISCORD BOT: tickets list + read messages + send message
// Tickets assumed: channels in a specific category (DISCORD_TICKETS_CATEGORY_ID)
// ============================================================================

async function discordBotFetch(url, options = {}) {
  if (!DISCORD_BOT_TOKEN) {
    throw new Error("Missing DISCORD_BOT_TOKEN (Railway Variables)");
  }
  const headers = {
    Authorization: `Bot ${DISCORD_BOT_TOKEN}`,
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };
  const res = await fetch(url, { ...options, headers });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Discord API error ${res.status}: ${text}`);
  }
  return res;
}

// List ticket channels in category
app.get("/api/admin/tickets", requireAdmin, async (req, res) => {
  try {
    if (!DISCORD_TICKETS_CATEGORY_ID) {
      return res.json({ tickets: [] });
    }

    // Discord API: list channels in a guild requires guild_id, but category-only list is not directly available.
    // Minimal approach: require you to provide a list of ticket channel IDs in DB later.
    //
    // Practical approach (works): set DISCORD_GUILD_ID and fetch all channels, filter by parent_id (category).
    const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;
    if (!DISCORD_GUILD_ID) {
      return res.status(400).json({ error: "Missing DISCORD_GUILD_ID for tickets listing" });
    }

    const r = await discordBotFetch(`https://discord.com/api/v10/guilds/${DISCORD_GUILD_ID}/channels`);
    const channels = await r.json();

    const tickets = (channels || [])
      .filter(ch => ch && ch.parent_id === DISCORD_TICKETS_CATEGORY_ID && ch.type === 0) // type 0 = text channel
      .map(ch => ({ id: ch.id, name: ch.name }));

    res.json({ tickets });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "tickets_fetch_failed" });
  }
});

// Read last messages from a ticket channel
app.get("/api/admin/tickets/:channelId", requireAdmin, async (req, res) => {
  try {
    const channelId = String(req.params.channelId || "").trim();
    if (!channelId) return res.status(400).json({ error: "missing_channel_id" });

    const r = await discordBotFetch(`https://discord.com/api/v10/channels/${channelId}/messages?limit=50`);
    const msgs = await r.json();

    const messages = (msgs || [])
      .reverse()
      .map(m => ({
        id: m.id,
        author: (m.author?.global_name || m.author?.username || "User"),
        authorType: m.author?.bot ? "bot" : "user",
        content: m.content || "",
        timestamp: m.timestamp,
      }));

    res.json({ messages });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "ticket_messages_failed" });
  }
});

// Send message as bot to ticket channel
app.post("/api/admin/tickets/:channelId/send", requireAdmin, async (req, res) => {
  try {
    const channelId = String(req.params.channelId || "").trim();
    const content = String(req.body?.content || "").trim();
    if (!channelId) return res.status(400).json({ error: "missing_channel_id" });
    if (!content) return res.status(400).json({ error: "missing_content" });

    await discordBotFetch(`https://discord.com/api/v10/channels/${channelId}/messages`, {
      method: "POST",
      body: JSON.stringify({ content }),
    });

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "ticket_send_failed" });
  }
});

// ============================================================================
// STATIC FILES (ROOT)
// ============================================================================

app.use(express.static(__dirname));

// Landing: always index.html
app.get("/", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  return res.sendFile(path.join(__dirname, "index.html"));
});

// Client panel protected
app.get("/panel.html", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (!req.session?.user) return res.redirect("/auth/discord");
  return res.sendFile(path.join(__dirname, "panel.html"));
});

// Admin login page is public
app.get("/admin/login.html", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  return res.sendFile(path.join(__dirname, "admin/login.html"));
});

// If you keep login file in root instead, change path above to:
// return res.sendFile(path.join(__dirname, "admin.login.html"));

app.use((req, res) => {
  res.status(404).send("Not Found");
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
