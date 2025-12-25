// bot.js
// Discord.js v14
// Ticket panel: "Ticket test" + button -> creates ticket channel in category 1266064860802973859

const {
  Client,
  GatewayIntentBits,
  Partials,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  PermissionsBitField,
  ChannelType,
  Events,
} = require("discord.js");

const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const TICKETS_CATEGORY_ID = process.env.DISCORD_TICKETS_CATEGORY_ID || "1266064860802973859";

// (opcjonalnie) jeżeli chcesz wysyłać panel tylko w konkretny kanał (np. na starcie)
// ustaw DISCORD_TICKETS_PANEL_CHANNEL_ID w Railway Variables
const PANEL_CHANNEL_ID = process.env.DISCORD_TICKETS_PANEL_CHANNEL_ID || "";

if (!DISCORD_BOT_TOKEN) {
  console.error("❌ Brakuje DISCORD_BOT_TOKEN w Variables (Railway).");
  process.exit(1);
}

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent, // jeśli chcesz !ticketpanel jako komendę tekstową
  ],
  partials: [Partials.Channel],
});

// ---- helpers ----
function buildTicketPanelMessage() {
  const row = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId("ticket:create")
      .setLabel("Utwórz ticket")
      .setStyle(ButtonStyle.Primary)
  );

  return { content: "🎫 **Ticket test**", components: [row] };
}

async function createTicketChannel({ guild, user }) {
  // Sprawdź kategorię
  const category = guild.channels.cache.get(TICKETS_CATEGORY_ID);
  if (!category) {
    throw new Error(
      `Nie znaleziono kategorii o ID ${TICKETS_CATEGORY_ID}. Sprawdź ID i czy bot jest na serwerze.`
    );
  }

  // (opcjonalnie) zabezpieczenie: jeden ticket na usera
  const existing = guild.channels.cache.find(
    (ch) =>
      ch.type === ChannelType.GuildText &&
      ch.parentId === TICKETS_CATEGORY_ID &&
      ch.topic === `ticket:${user.id}`
  );
  if (existing) return existing;

  // Nazwa kanału: ticket-zxq0-1234 (skrót id)
  const safeName =
    `ticket-${user.username}`.toLowerCase().replace(/[^a-z0-9\-]/g, "-").slice(0, 20) +
    `-${user.id.slice(-4)}`;

  const channel = await guild.channels.create({
    name: safeName,
    type: ChannelType.GuildText,
    parent: TICKETS_CATEGORY_ID,
    topic: `ticket:${user.id}`,
    permissionOverwrites: [
      // zablokuj wszystkim
      {
        id: guild.roles.everyone.id,
        deny: [PermissionsBitField.Flags.ViewChannel],
      },
      // pozwól autorowi
      {
        id: user.id,
        allow: [
          PermissionsBitField.Flags.ViewChannel,
          PermissionsBitField.Flags.SendMessages,
          PermissionsBitField.Flags.ReadMessageHistory,
          PermissionsBitField.Flags.AttachFiles,
          PermissionsBitField.Flags.EmbedLinks,
        ],
      },
      // pozwól botowi
      {
        id: guild.members.me.id,
        allow: [
          PermissionsBitField.Flags.ViewChannel,
          PermissionsBitField.Flags.SendMessages,
          PermissionsBitField.Flags.ReadMessageHistory,
          PermissionsBitField.Flags.ManageChannels,
          PermissionsBitField.Flags.ManageMessages,
        ],
      },
    ],
  });

  return channel;
}

// ---- events ----
client.once(Events.ClientReady, async () => {
  console.log(`✅ Bot zalogowany jako ${client.user.tag}`);

  // Auto-wysłanie panelu na starcie (opcjonalne)
  if (PANEL_CHANNEL_ID) {
    try {
      const ch = await client.channels.fetch(PANEL_CHANNEL_ID);
      if (ch && ch.isTextBased()) {
        await ch.send(buildTicketPanelMessage());
        console.log("✅ Wysłano panel ticketów do kanału:", PANEL_CHANNEL_ID);
      } else {
        console.log("⚠️ PANEL_CHANNEL_ID nie wskazuje na kanał tekstowy.");
      }
    } catch (e) {
      console.log("⚠️ Nie udało się wysłać panelu na start:", e.message);
    }
  }

  console.log("ℹ️ Komenda tekstowa: !ticketpanel (w kanale, gdzie chcesz panel).");
});

client.on(Events.MessageCreate, async (message) => {
  if (message.author.bot) return;
  if (!message.guild) return;

  // Prosta komenda do wysłania panelu
  if (message.content.trim() === "!ticketpanel") {
    try {
      await message.channel.send(buildTicketPanelMessage());
      await message.reply("✅ Panel ticketów wysłany.");
    } catch (e) {
      await message.reply("❌ Nie udało się wysłać panelu.");
    }
  }
});

client.on(Events.InteractionCreate, async (interaction) => {
  try {
    if (!interaction.isButton()) return;
    if (interaction.customId !== "ticket:create") return;

    // Szybka odpowiedź ephemeral
    await interaction.deferReply({ ephemeral: true });

    const guild = interaction.guild;
    const user = interaction.user;

    if (!guild) {
      return interaction.editReply("❌ To działa tylko na serwerze.");
    }

    const channel = await createTicketChannel({ guild, user });

    // wiadomość startowa w tickecie
    await channel.send(
      `👋 Witaj <@${user.id}>!\nOpisz problem, a wsparcie odpowie tutaj.\n\n🔒 Ten kanał widzisz tylko Ty i bot.`
    );

    return interaction.editReply(
      `✅ Ticket utworzony: <#${channel.id}>`
    );
  } catch (e) {
    console.error("Ticket error:", e);
    if (interaction.deferred || interaction.replied) {
      return interaction.editReply(`❌ Błąd: ${e.message}`);
    }
  }
});

client.login(DISCORD_BOT_TOKEN);
