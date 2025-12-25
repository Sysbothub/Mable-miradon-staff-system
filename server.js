require('dotenv').config();
const { Client, GatewayIntentBits, Partials, EmbedBuilder, ChannelType, AttachmentBuilder } = require('discord.js');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// --- DB CONNECTION ---
mongoose.connect(process.env.MONGODB_URI);

const Staff = mongoose.model('Staff', new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    discordId: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    ticketsClosed: { type: Number, default: 0 },
    repliesSent: { type: Number, default: 0 }
}));

const Thread = mongoose.model('Thread', new mongoose.Schema({
    userId: String,
    userTag: String,
    botId: String,
    botName: String,
    messages: [{
        authorTag: String,
        content: String,
        attachments: [String],
        timestamp: { type: Date, default: Date.now },
        fromBot: { type: Boolean, default: false }
    }],
    lastMessageAt: { type: Date, default: Date.now }
}));

// --- MIDDLEWARE ---
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET || 'terminal-secret-2025',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 } 
}));

const isAuth = (req, res, next) => req.session.staffId ? next() : res.status(401).send("Unauthorized");
const isAdmin = (req, res, next) => (req.session.staffId && req.session.isAdmin) ? next() : res.status(403).send("Admin only");

// --- BOT CLUSTERING ---
const botConfigs = [
    { name: "Bot One", token: process.env.BOT_ONE_TOKEN },
    { name: "Bot Two", token: process.env.BOT_TWO_TOKEN }
];
const clients = [];

async function sendLog(title, description, color = '#3b82f6', files = []) {
    if (!process.env.LOG_CHANNEL_ID || !clients[0]) return;
    try {
        const channel = await clients[0].channels.fetch(process.env.LOG_CHANNEL_ID);
        const logEmbed = new EmbedBuilder().setTitle(title).setDescription(description).setColor(color).setTimestamp();
        await channel.send({ embeds: [logEmbed], files: files });
    } catch (e) { console.error("Logging error:", e); }
}

botConfigs.forEach(config => {
    if (!config.token) return;
    const client = new Client({
        intents: [
            GatewayIntentBits.Guilds, 
            GatewayIntentBits.DirectMessages, 
            GatewayIntentBits.MessageContent, 
            GatewayIntentBits.GuildMembers, 
            GatewayIntentBits.GuildInvites
        ],
        partials: [Partials.Channel, Partials.Message]
    });

    client.on('messageCreate', async (message) => {
        // STRICT DM FILTER
        if (message.author.bot || message.guild) return;

        let thread = await Thread.findOne({ userId: message.author.id, botId: client.user.id });
        if (!thread) {
            thread = new Thread({ userId: message.author.id, userTag: message.author.tag, botId: client.user.id, botName: client.user.username, messages: [] });
            sendLog("🆕 New Ticket", `**User:** ${message.author.tag}\n**Bot:** ${client.user.username}`, '#facc15');
        }
        
        const msgData = { authorTag: message.author.tag, content: message.content || "[Attachment]", attachments: message.attachments.map(a => a.url), fromBot: false };
        thread.messages.push(msgData);
        thread.lastMessageAt = new Date();
        await thread.save();

        io.emit('new_message', { threadId: thread._id, ...msgData });
    });

    client.login(config.token).catch(console.error);
    clients.push(client);
});

// --- API ROUTES ---

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await Staff.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.staffId = user._id; req.session.isAdmin = user.isAdmin; req.session.username = user.username;
        res.json({ success: true, isAdmin: user.isAdmin, username: user.username });
    } else res.status(401).send("Invalid Credentials");
});

app.get('/api/threads', isAuth, async (req, res) => {
    const threads = await Thread.find().sort({ lastMessageAt: -1 });
    res.json(threads);
});

app.post('/api/reply', isAuth, async (req, res) => {
    const { threadId, content } = req.body;
    const thread = await Thread.findById(threadId);
    if (!thread) return res.status(404).send("Thread not found");
    
    const client = clients.find(c => c.user.id === thread.botId);
    try {
        const user = await client.users.fetch(thread.userId);
        const embed = new EmbedBuilder()
            .setColor('#3b82f6')
            .setAuthor({ name: `Support Team: ${req.session.username}`, iconURL: client.user.displayAvatarURL() })
            .setDescription(content)
            .setTimestamp();

        await user.send({ embeds: [embed] });

        const reply = { authorTag: `Staff (${req.session.username})`, content, fromBot: true, attachments: [] };
        thread.messages.push(reply);
        thread.lastMessageAt = new Date();
        await thread.save();

        // Increment Staff Stat
        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { repliesSent: 1 } });

        io.emit('new_message', { threadId: thread._id, ...reply });
        res.json({ success: true });
    } catch (err) { res.status(500).send("Discord DM failed"); }
});

app.post('/api/close-thread', isAuth, async (req, res) => {
    const { threadId } = req.body;
    const thread = await Thread.findById(threadId);
    if (!thread) return res.status(404).send("Thread not found");

    // 1. Generate Transcript
    let transcriptText = `SUPPORT TRANSCRIPT\nUser: ${thread.userTag} (${thread.userId})\nBot: ${thread.botName}\nClosed By: ${req.session.username}\n--------------------------------------\n\n`;
    thread.messages.forEach(m => {
        transcriptText += `[${new Date(m.timestamp).toLocaleString()}] ${m.authorTag}: ${m.content}\n`;
    });

    const fileName = `transcript-${thread.userId}.txt`;
    const filePath = path.join(__dirname, fileName);

    try {
        fs.writeFileSync(filePath, transcriptText);
        const attachment = new AttachmentBuilder(filePath);

        // 2. Log to Discord
        await sendLog("🔒 Ticket Closed & Purged", `**Staff:** ${req.session.username}\n**User:** ${thread.userTag}`, '#ef4444', [attachment]);

        // 3. Increment Staff Stat & Delete DB Entry
        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { ticketsClosed: 1 } });
        await Thread.findByIdAndDelete(threadId);
        
        fs.unlinkSync(filePath);
        res.json({ success: true });
    } catch (e) { res.status(500).send("Transcript failed"); }
});

// --- ADMIN API ---

app.get('/api/admin/stats', isAdmin, async (req, res) => {
    const staff = await Staff.find({}, 'username ticketsClosed repliesSent isAdmin').sort({ ticketsClosed: -1 });
    res.json(staff);
});

app.post('/api/admin/broadcast', isAdmin, async (req, res) => {
    const { message } = req.body;
    const threads = await Thread.find();
    let count = 0;
    for (const thread of threads) {
        const client = clients.find(c => c.user.id === thread.botId);
        if(!client) continue;
        try {
            const user = await client.users.fetch(thread.userId);
            const embed = new EmbedBuilder().setTitle("📢 Announcement").setColor('#f59e0b').setDescription(message).setTimestamp();
            await user.send({ embeds: [embed] });
            count++;
        } catch(e) {}
    }
    sendLog("📢 Broadcast Sent", `By: ${req.session.username}\nReached: ${count} users`);
    res.json({ success: true, count });
});

app.get('/api/admin/servers', isAdmin, async (req, res) => {
    let list = [];
    clients.forEach(c => {
        if (!c.isReady()) return;
        c.guilds.cache.forEach(g => {
            list.push({ id: g.id, name: g.name, members: g.memberCount, botName: c.user.username, botId: c.user.id });
        });
    });
    res.json({ servers: list });
});

app.post('/api/admin/create-invite', isAdmin, async (req, res) => {
    const { serverId, botId } = req.body;
    const client = clients.find(c => c.user.id === botId);
    try {
        const guild = await client.guilds.fetch(serverId);
        const channel = guild.channels.cache.find(c => c.type === ChannelType.GuildText && c.permissionsFor(client.user).has('CreateInstantInvite'));
        const invite = await channel.createInvite({ maxAge: 3600, maxUses: 1 });
        res.json({ success: true, url: invite.url });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/admin/staff/add', isAdmin, async (req, res) => {
    const { username, discordId, adminStatus } = req.body;
    const tempPass = Math.random().toString(36).slice(-10);
    const hashedPassword = await bcrypt.hash(tempPass, 10);
    await new Staff({ username, discordId, password: hashedPassword, isAdmin: adminStatus }).save();
    try {
        const user = await clients[0].users.fetch(discordId);
        await user.send({ content: `**Access Granted**\nUser: ${username}\nPass: ${tempPass}` });
    } catch(e) {}
    res.json({ success: true });
});

server.listen(process.env.PORT || 10000, () => console.log("Terminal Active"));
