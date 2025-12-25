/**
 * server.js — Lite Solutions (landing + panel) w ROOT (bez folderu /public)
 *
 * ✅ /              -> index.html (landing)
 * ✅ /auth/discord  -> start Discord OAuth
 * ✅ /auth/discord/callback -> callback, zapis sesji
 * ✅ /panel.html    -> chroniony (bez sesji przekieruje na /auth/discord)
 * ✅ /api/me        -> dane usera (avatarUrl, username, discordId)
 *
 * Wymagane Railway Variables:
 * - SESSION_SECRET
 * - DISCORD_CLIENT_ID
 * - DISCORD_CLIENT_SECRET
 * - DISCORD_REDIRECT_URI   (np. https://www.litesolutions.pl/auth/discord/callback)
 * - NODE_ENV=production
 * Opcjonalne:
 * - POST_LOGIN_REDIRECT=/panel.html
 *
 * Install:
 *   npm i express express-session node-fetch@2
 *
 * Run:
 *   node server.js
 */

const express = require("express");
const session = require("express-session");
const path = require("path");
const crypto = require("crypto");
const fetch = require("node-fetch");

const app = express();

const {
  PORT = 3000,
  NODE_ENV = "development",
  SESSION_SECRET,
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  POST_LOGIN_REDIRECT = "/panel.html",
} = process.env;

// ---- Fail fast on missing envs ----
function requireEnv(name) {
  if (!process.env[name]) {
    console.error(`[ENV] Missing ${name}`);
    process.exit(1);
  }
}
requireEnv("SESSION_SECRET");
requireEnv("DISCORD_CLIENT_ID");
requireEnv("DISCORD_CLIENT_SECRET");
requireEnv("DISCORD_REDIRECT_URI");

// Railway/proxy friendly
app.set("trust proxy", 1);

app.use(express.json());

// ---- Sessions ----
app.use(
  session({
    name: "ls_panel_sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: NODE_ENV === "production", // https required
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
  })
);

// ---- Helper: Discord avatar URL ----
function discordAvatarUrl(user) {
  if (!user?.id) return null;
  if (!user.avatar) return "https://cdn.discordapp.com/embed/avatars/0.png";
  const isGif = user.avatar.startsWith("a_");
  const ext = isGif ? "gif" : "png";
  return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${ext}?size=128`;
}

// ---- Auth guard ----
function requireAuth(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: "unauthorized" });
  next();
}

// ============================================================================
// AUTH: Discord OAuth2
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
    prompt: "none", // change to "consent" if you want always prompt
  });

  // NOTE: use discord.com/api/oauth2/authorize
  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

app.get("/auth/discord/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code) return res.status(400).send("Missing code");
    if (!state || state !== req.session.oauthState) return res.status(400).send("Invalid state");

    // Exchange code -> token
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

    // Fetch user profile
    const meRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!meRes.ok) {
      const txt = await meRes.text();
      console.error("[Discord profile fetch failed]", meRes.status, txt);
      return res.status(500).send("Discord profile fetch failed");
    }

    const user = await meRes.json();

    // Store minimal user in session
    req.session.user = {
      discordId: user.id,
      username: user.global_name || user.username,
      avatarUrl: discordAvatarUrl(user),
    };

    // cleanup state
    delete req.session.oauthState;

    // redirect to panel
    return res.redirect(POST_LOGIN_REDIRECT);
  } catch (err) {
    console.error("[/auth/discord/callback] Error:", err);
    return res.status(500).send("Login error");
  }
});

app.post("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("ls_panel_sid");
    res.json({ ok: true });
  });
});

// ============================================================================
// API
// ============================================================================

app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

// (przykład endpointu chronionego)
app.get("/api/ping", requireAuth, (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// ============================================================================
// STATIC + PAGES (ROOT FILES)
// ============================================================================

// Serwuj wszystkie pliki statyczne z katalogu ROOT (tam gdzie index.html, panel.html, assets itp.)
app.use(
  express.static(__dirname, {
    // na dev możesz wyłączyć cache, w prod zostaw default
    etag: true,
  })
);

// Landing zawsze ma się otwierać na /
app.get("/", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  return res.sendFile(path.join(__dirname, "index.html"));
});

// Panel jest chroniony — bez sesji przekieruje na login
app.get("/panel.html", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (!req.session?.user) return res.redirect("/auth/discord");
  return res.sendFile(path.join(__dirname, "panel.html"));
});

// Fallback: jeśli ktoś wejdzie w coś nieistniejącego, daj 404 (żeby nie mylić z SPA rewritem)
app.use((req, res) => {
  res.status(404).send("Not Found");
});

// ============================================================================
// START
// ============================================================================

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
