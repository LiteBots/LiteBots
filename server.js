/**
 * server.js — Lite Solutions Panel (Railway)
 *
 * ✅ Discord OAuth2 login
 * ✅ Session cookie (HTTP-only)
 * ✅ /api/me endpoint for the panel (avatar, username, discordId)
 * ✅ Static serving for panel.html (+ assets)
 *
 * Railway ENV (Variables):
 * - PORT                          (Railway sets automatically)
 * - BASE_URL                      e.g. https://twoja-apka.up.railway.app
 * - SESSION_SECRET                random long string
 * - DISCORD_CLIENT_ID
 * - DISCORD_CLIENT_SECRET
 * - DISCORD_REDIRECT_URI          e.g. https://twoja-apka.up.railway.app/auth/discord/callback
 * - POST_LOGIN_REDIRECT           e.g. /panel.html  (optional)
 *
 * Optional:
 * - NODE_ENV=production
 * - ALLOWED_ORIGIN                e.g. https://twoja-domena.pl (optional CORS)
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
  BASE_URL,
  SESSION_SECRET,
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  POST_LOGIN_REDIRECT = "/panel.html",
  ALLOWED_ORIGIN,
} = process.env;

// --- Basic env validation (fail fast) ---
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
requireEnv("BASE_URL");

// --- Trust proxy for Railway (important for secure cookies behind proxy) ---
app.set("trust proxy", 1);

app.use(express.json());

// --- Optional simple CORS (only if you split frontend domain) ---
if (ALLOWED_ORIGIN) {
  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
  });
}

// --- Sessions ---
app.use(
  session({
    name: "ls_panel_sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: NODE_ENV === "production", // requires https (Railway provides)
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
  })
);

// --- Helper: build Discord avatar URL ---
function discordAvatarUrl(user) {
  // user: { id, avatar }
  if (!user?.id) return null;
  if (!user.avatar) {
    // default avatar index based on discriminator is deprecated in newer discord; fallback to embed avatar by user id hash-ish
    // simplest fallback:
    return "https://cdn.discordapp.com/embed/avatars/0.png";
  }
  const isGif = user.avatar.startsWith("a_");
  const ext = isGif ? "gif" : "png";
  return `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.${ext}?size=128`;
}

// --- OAuth2: start login ---
app.get("/auth/discord", (req, res) => {
  const state = crypto.randomBytes(16).toString("hex");
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: "code",
    scope: "identify", // add "email" if you want email
    state,
    prompt: "none", // change to "consent" if you want always prompt
  });

  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

// --- OAuth2 callback ---
app.get("/auth/discord/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code) return res.status(400).send("Missing code");
    if (!state || state !== req.session.oauthState) {
      return res.status(400).send("Invalid state");
    }

    // Exchange code -> access token
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
      console.error("[Discord token] Failed:", tokenRes.status, txt);
      return res.status(500).send("Discord token exchange failed");
    }

    const tokenData = await tokenRes.json();
    // tokenData: { access_token, token_type, expires_in, refresh_token, scope }
    const accessToken = tokenData.access_token;

    // Fetch user profile
    const meRes = await fetch("https://discord.com/api/users/@me", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!meRes.ok) {
      const txt = await meRes.text();
      console.error("[Discord /users/@me] Failed:", meRes.status, txt);
      return res.status(500).send("Discord profile fetch failed");
    }

    const user = await meRes.json(); // { id, username, global_name, avatar, ... }

    // Store minimal user in session (DON'T store secrets client-side)
    req.session.user = {
      discordId: user.id,
      username: user.global_name || user.username,
      avatarUrl: discordAvatarUrl(user),
    };

    // If you NEED token later (e.g. guilds), you can store access token in session.
    // For panel profile only, it's not necessary.
    // req.session.discordAccessToken = accessToken;

    // cleanup
    delete req.session.oauthState;

    res.redirect(POST_LOGIN_REDIRECT);
  } catch (err) {
    console.error("[/auth/discord/callback] Error:", err);
    res.status(500).send("Login error");
  }
});

// --- Logout ---
app.post("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("ls_panel_sid");
    res.json({ ok: true });
  });
});

// --- Auth middleware ---
function requireAuth(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: "unauthorized" });
  next();
}

// --- API: current user for top-right chip ---
app.get("/api/me", requireAuth, (req, res) => {
  res.json({
    user: req.session.user,
  });
});

// --- Example protected endpoint (future: services/licenses/tickets) ---
app.get("/api/ping", requireAuth, (req, res) => {
  res.json({ ok: true, ts: Date.now() });
});

// --- Static files ---
// Put your panel.html in ./public/panel.html (and other files like index.html, workspace.html, etc.)
app.use(express.static(path.join(__dirname, "public")));

// --- Simple guard: if someone opens panel without login, redirect to /auth/discord ---
// If you prefer to allow viewing without login, remove this.
app.get("/panel.html", (req, res, next) => {
  if (!req.session?.user) return res.redirect("/auth/discord");
  next();
});

// --- Home ---
app.get("/", (req, res) => {
  // Option: show tiny landing or redirect to panel
  res.redirect("/panel.html");
});

// --- Start ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`BASE_URL: ${BASE_URL}`);
});
