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

// --- DATABASE MODELS ---
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

// --- AUTOMATIC ADMIN SETUP ---
async function setupDefaultAdmin() {
    const adminExists = await Staff.findOne({ username: 'admin' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash('map4491', 10);
        await new Staff({
            username: 'admin',
            password: hashedPassword,
            discordId: '000000000000000000',
            isAdmin: true
        }).save();
        console.log("✅ Default Admin Created: User 'admin' | Pass 'map4491'");
    }
}
setupDefaultAdmin();

// --- MIDDLEWARE ---
app.set('trust proxy', 1); // Fix for Render proxy
app.use(express.json());
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: true, 
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24,
        secure: true, // Required for Render HTTPS
        sameSite: 'none' // Required for cross-domain cookies
    } 
}));

const isAuth = (req, res, next) => req.session.staffId ? next() : res.status(401).send("Unauthorized");
const isAdmin = (req, res, next) => (req.session.staffId && req.session.isAdmin) ? next() : res.status(403).send("Admin only");

// --- DYNAMIC BOT CLUSTERING ---
const botTokens = [process.env.BOT_ONE_TOKEN, process.env.BOT_TWO_TOKEN];
const clients = [];

async function sendLog(title, description, color = '#3b82f6', files = []) {
    if (!process.env.LOG_CHANNEL_ID || !clients[0]) return;
    try {
        const channel = await clients[0].channels.fetch(process.env.LOG_CHANNEL_ID);
        const logEmbed = new EmbedBuilder().setTitle(title).setDescription(description).setColor(color).setTimestamp();
        await channel.send({ embeds: [logEmbed], files: files });
    } catch (e) { console.error("Log Error:", e); }
}

botTokens.forEach(token => {
    if (!token) return;
    const client = new Client({
        intents: [GatewayIntentBits.Guilds, GatewayIntentBits.DirectMessages, GatewayIntentBits.MessageContent, GatewayIntentBits.GuildMembers, GatewayIntentBits.GuildInvites],
        partials: [Partials.Channel, Partials.Message]
    });

    client.on('messageCreate', async (message) => {
        if (message.author.bot || message.guild) return; 

        let thread = await Thread.findOne({ userId: message.author.id, botId: client.user.id });
        if (!thread) {
            thread = new Thread({ userId: message.author.id, userTag: message.author.tag, botId: client.user.id, botName: client.user.username, messages: [] });
            sendLog("🆕 Ticket Created", `**User:** ${message.author.tag}\n**Bot:** ${client.user.username}`, '#facc15');
        }
        
        const msgData = { authorTag: message.author.tag, content: message.content || "[Media]", attachments: message.attachments.map(a => a.url), fromBot: false };
        thread.messages.push(msgData);
        thread.lastMessageAt = new Date();
        await thread.save();

        io.emit('new_message', { threadId: thread._id, ...msgData });
    });

    client.login(token).catch(e => console.error("Bot Login Failed:", e.message));
    clients.push(client);
});

// --- API ENDPOINTS ---
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await Staff.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.staffId = user._id; 
        req.session.isAdmin = user.isAdmin; 
        req.session.username = user.username;
        req.session.save((err) => {
            if (err) return res.status(500).send("Session Error");
            res.json({ success: true, isAdmin: user.isAdmin, username: user.username });
        });
    } else res.status(401).send("Invalid Credentials");
});

app.get('/api/threads', isAuth, async (req, res) => {
    const threads = await Thread.find().sort({ lastMessageAt: -1 });
    res.json(threads);
});

app.post('/api/reply', isAuth, async (req, res) => {
    const { threadId, content } = req.body;
    const thread = await Thread.findById(threadId);
    if (!thread) return res.status(404).send("Not Found");
    
    const client = clients.find(c => c.user.id === thread.botId);
    try {
        const user = await client.users.fetch(thread.userId);
        const embed = new EmbedBuilder()
            .setColor('#3b82f6')
            .setAuthor({ name: `Support: ${req.session.username}`, iconURL: client.user.displayAvatarURL() })
            .setDescription(content)
            .setTimestamp();

        await user.send({ embeds: [embed] });
        const reply = { authorTag: `Staff (${req.session.username})`, content, fromBot: true, attachments: [] };
        thread.messages.push(reply);
        thread.lastMessageAt = new Date();
        await thread.save();

        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { repliesSent: 1 } });
        io.emit('new_message', { threadId: thread._id, ...reply });
        res.json({ success: true });
    } catch (err) { res.status(500).send("DM Failed"); }
});

app.post('/api/close-thread', isAuth, async (req, res) => {
    const { threadId } = req.body;
    const thread = await Thread.findById(threadId);
    if (!thread) return res.status(404).send("Not Found");

    let transcript = `OFFICIAL TRANSCRIPT: ${thread.userTag}\nBot: ${thread.botName}\nHandled By: ${req.session.username}\n\n`;
    thread.messages.forEach(m => {
        transcript += `[${m.timestamp.toISOString()}] ${m.authorTag}: ${m.content}\n`;
    });

    const fName = `transcript-${thread.userId}.txt`;
    const fPath = path.join(__dirname, fName);

    try {
        fs.writeFileSync(fPath, transcript);
        const attachment = new AttachmentBuilder(fPath);
        await sendLog("🔒 Archive Logged", `User: ${thread.userTag}\nStaff: ${req.session.username}`, '#ef4444', [attachment]);
        
        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { ticketsClosed: 1 } });
        await Thread.findByIdAndDelete(threadId);
        fs.unlinkSync(fPath);
        res.json({ success: true });
    } catch (e) { res.status(500).send("Archive Error"); }
});

app.get('/api/admin/stats', isAdmin, async (req, res) => {
    const stats = await Staff.find().sort({ ticketsClosed: -1 });
    res.json(stats);
});

app.get('/api/admin/servers', isAdmin, async (req, res) => {
    let servers = [];
    clients.forEach(c => {
        if (!c.isReady()) return;
        c.guilds.cache.forEach(g => servers.push({ id: g.id, name: g.name, members: g.memberCount, botName: c.user.username, botId: c.user.id }));
    });
    res.json(servers);
});

app.post('/api/admin/create-invite', isAdmin, async (req, res) => {
    const { serverId, botId } = req.body;
    const client = clients.find(c => c.user.id === botId);
    try {
        const guild = await client.guilds.fetch(serverId);
        const chan = guild.channels.cache.find(c => c.type === ChannelType.GuildText && c.permissionsFor(client.user).has('CreateInstantInvite'));
        const inv = await chan.createInvite({ maxAge: 3600, maxUses: 1 });
        res.json({ success: true, url: inv.url });
    } catch (e) { res.status(500).json({ error: "No Permission" }); }
});

app.post('/api/admin/staff/add', isAdmin, async (req, res) => {
    const { username, discordId, adminStatus } = req.body;
    const tempPass = Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(tempPass, 10);
    await new Staff({ username, discordId, password: hashedPassword, isAdmin: adminStatus }).save();
    try {
        const user = await clients[0].users.fetch(discordId);
        await user.send(`**Terminal Access**\nUser: ${username}\nPass: ${tempPass}`);
    } catch(e) {}
    res.json({ success: true });
});

server.listen(process.env.PORT || 10000, () => console.log("HQ Terminal Ready"));
