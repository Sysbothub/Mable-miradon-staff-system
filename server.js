require('dotenv').config();
const axios = require('axios'); // Required for SellApp API
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

const License = mongoose.model('License', new mongoose.Schema({
    key: String,
    instanceId: String,
    discordId: String,
    serverId: String,
    serverName: String,
    channelId: String,
    type: String,
    duration: String,
    activatedAt: { type: Date, default: Date.now },
    expiresAt: Date,
    reminderSent: { type: Boolean, default: false }
}));

const Config = mongoose.model('Config', new mongoose.Schema({
    id: { type: String, default: 'global' },
    supportOnline: { type: Boolean, default: true },
    offlineNote: { type: String, default: '' }
}));

// --- AUTOMATIC ADMIN & CONFIG SETUP ---
async function setupDefaults() {
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

    const configExists = await Config.findOne({ id: 'global' });
    if (!configExists) {
        await new Config({ id: 'global', supportOnline: true }).save();
        console.log("✅ Default Config Created");
    }
}
setupDefaults();

// --- MIDDLEWARE ---
app.set('trust proxy', 1); 
app.use(express.json({ limit: '10mb' })); 
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET || 'hq-secret-key',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, 
        secure: true, 
        sameSite: 'none' 
    } 
}));

const isAuth = (req, res, next) => req.session.staffId ? next() : res.status(401).send("Unauthorized");
const isAdmin = (req, res, next) => (req.session.staffId && req.session.isAdmin) ? next() : res.status(403).send("Admin only");

const getPanelUrl = () => process.env.APP_URL || "Panel URL Not Configured";

// --- DYNAMIC BOT CLUSTERING ---
const botTokens = [process.env.BOT_ONE_TOKEN, process.env.BOT_TWO_TOKEN].filter(t => t);
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
    const client = new Client({
        intents: [GatewayIntentBits.Guilds, GatewayIntentBits.DirectMessages, GatewayIntentBits.MessageContent, GatewayIntentBits.GuildMembers, GatewayIntentBits.GuildInvites],
        partials: [Partials.Channel, Partials.Message]
    });

    client.on('messageCreate', async (message) => {
        if (message.author.bot || message.guild) return; 
        let thread = await Thread.findOne({ userId: message.author.id, botId: client.user.id });
        if (!thread) {
            thread = new Thread({ userId: message.author.id, userTag: message.author.tag, botId: client.user.id, botName: client.user.username, messages: [] });
            
            // --- AUTO DM LOGIC ---
            const config = await Config.findOne({ id: 'global' });
            const isManualOnline = config ? config.supportOnline : true;
            const offlineNote = config ? config.offlineNote : '';

            // Calculate Time in AST (Atlantic Standard Time)
            const now = new Date();
            const options = { timeZone: 'America/Halifax', hour12: false, hour: 'numeric', minute: 'numeric' };
            const formatter = new Intl.DateTimeFormat('en-US', options);
            const parts = formatter.formatToParts(now);
            const hour = parseInt(parts.find(p => p.type === 'hour').value);
            const minute = parseInt(parts.find(p => p.type === 'minute').value);
            const currentTotalMinutes = (hour * 60) + minute;

            const startTotal = 8 * 60; // 08:00 AM
            const endTotal = 23 * 60 + 59; // 11:59 PM
            
            const isWorkHours = currentTotalMinutes >= startTotal && currentTotalMinutes <= endTotal;

            let autoReply;

            // Priority: Manual Offline > Schedule > Online
            if (!isManualOnline) {
                const noteText = offlineNote ? `**Reason:** ${offlineNote}\n\n` : '';
                autoReply = new EmbedBuilder()
                    .setColor('#ef4444')
                    .setTitle('Support Currently Offline')
                    .setDescription(`Support has been toggled offline by staff.\n\n${noteText}We have received your message and will respond as soon as we are available.\n\n**Support Hours:** 8:00 AM - 11:59 PM AST`)
                    .setTimestamp();

            } else if (!isWorkHours) {
                autoReply = new EmbedBuilder()
                    .setColor('#f59e0b')
                    .setTitle('Support Closed')
                    .setDescription('You have reached us outside of support hours. A staff member will check your ticket when we open.\n\n**Support Hours:** 8:00 AM - 11:59 PM AST\n**Current Status:** Closed')
                    .setTimestamp();

            } else {
                autoReply = new EmbedBuilder()
                    .setColor('#3b82f6')
                    .setTitle('Support Ticket Opened')
                    .setDescription('Thank you for reaching out to Miraidon Trade Services. A staff member will respond to your inquiry within **12-24 hours**.\n\n**Support Hours:** 8:00 AM AST - 11:59 PM AST\n**Note:** Support may be unavailable during holidays.\n\n*Our average response time is currently 2 hours.*')
                    .setTimestamp();
            }
            
            try {
                const imageDir = path.join(__dirname, 'public', 'image');
                if (fs.existsSync(imageDir)) {
                    const files = fs.readdirSync(imageDir).filter(f => !f.startsWith('.'));
                    if (files.length > 0) {
                        const attachment = new AttachmentBuilder(path.join(imageDir, files[0]));
                        await message.author.send({ embeds: [autoReply], files: [attachment] }).catch(() => {});
                    } else {
                        await message.author.send({ embeds: [autoReply] }).catch(() => {});
                    }
                } else {
                    await message.author.send({ embeds: [autoReply] }).catch(() => {});
                }
            } catch (err) {
                await message.author.send({ embeds: [autoReply] }).catch(() => {});
            }

            sendLog("🆕 Ticket Created", `**User:** ${message.author.tag}\n**Bot:** ${client.user.username}`, '#facc15');
        }
        
        const attachments = message.attachments.map(a => a.url);
        const msgData = { 
            authorTag: message.author.tag, 
            content: message.content || (attachments.length > 0 ? "[Sent Attachment]" : "[Media]"), 
            attachments: attachments, 
            fromBot: false,
            timestamp: new Date()
        };

        thread.messages.push(msgData);
        thread.lastMessageAt = new Date();
        await thread.save();
        io.emit('new_message', { threadId: thread._id, notif_sound: true, ...msgData });
    });

    client.login(token).catch(e => console.error("Bot Login Failed:", e.message));
    clients.push(client);
});

// --- API ENDPOINTS ---

app.post('/api/public/request-reset', async (req, res) => {
    const { discordId } = req.body;
    if (!discordId) return res.status(400).json({ error: "Discord ID required" });
    const staff = await Staff.findOne({ discordId });
    if (!staff) return res.status(404).json({ error: "No staff found" });
    const newPass = Math.random().toString(36).slice(-8);
    staff.password = await bcrypt.hash(newPass, 10);
    await staff.save();
    try {
        const user = await clients[0].users.fetch(discordId);
        await user.send(`**Terminal Recovery**\n**New Key:** ${newPass}\n**URL:** ${getPanelUrl()}`);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "DM Failed" }); }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await Staff.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.staffId = user._id; 
        req.session.isAdmin = user.isAdmin; 
        req.session.username = user.username;
        req.session.save(() => res.json({ success: true, isAdmin: user.isAdmin, username: user.username }));
    } else res.status(401).send("Invalid Credentials");
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.json({ success: true });
    });
});

app.get('/api/threads', isAuth, async (req, res) => {
    const threads = await Thread.find().sort({ lastMessageAt: -1 });
    res.json(threads);
});

app.post('/api/reply', isAuth, async (req, res) => {
    const { threadId, content, fileBase64, fileName } = req.body;
    const thread = await Thread.findById(threadId);
    if (!thread) return res.status(404).send("Not Found");
    const client = clients.find(c => c.user.id === thread.botId);
    try {
        const user = await client.users.fetch(thread.userId);
        let messageOptions = {
            embeds: [new EmbedBuilder().setColor('#3b82f6').setAuthor({ name: `Support: ${req.session.username}`, iconURL: client.user.displayAvatarURL() }).setDescription(content || "Sent an attachment").setTimestamp()]
        };

        if (fileBase64) {
            const buffer = Buffer.from(fileBase64.split(',')[1], 'base64');
            messageOptions.files = [new AttachmentBuilder(buffer, { name: fileName || 'upload.png' })];
        }

        const sentMsg = await user.send(messageOptions);
        const attachmentUrls = sentMsg.attachments.map(a => a.url);

        const reply = { 
            authorTag: `Staff (${req.session.username})`, 
            content: content || "[File Attachment]", 
            fromBot: true, 
            attachments: attachmentUrls,
            timestamp: new Date()
        };

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
    let transcript = `OFFICIAL TRANSCRIPT: ${thread.userTag}\nBot: ${thread.botName}\n\n`;
    thread.messages.forEach(m => { transcript += `[${m.timestamp.toISOString()}] ${m.authorTag}: ${m.content}\n`; });
    const fPath = path.join(__dirname, `transcript-${thread.userId}.txt`);
    try {
        fs.writeFileSync(fPath, transcript);
        await sendLog("🔒 Archive Logged", `User: ${thread.userTag}`, '#ef4444', [new AttachmentBuilder(fPath)]);
        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { ticketsClosed: 1 } });
        await Thread.findByIdAndDelete(threadId);
        fs.unlinkSync(fPath);
        res.json({ success: true });
    } catch (e) { res.status(500).send("Archive Error"); }
});

// --- STAFF SELF-SERVE RESET (STRICT VALIDATION) ---
app.post('/api/staff/self-reset', isAuth, async (req, res) => {
    const { newPassword } = req.body;

    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(newPassword);
    const hasNumber = /\d/.test(newPassword);
    const hasSymbol = /[!@#$%^&*(),.?":{}|<>]/.test(newPassword);

    if (!newPassword || newPassword.length < minLength || !hasUpperCase || !hasNumber || !hasSymbol) {
        return res.status(400).json({ 
            error: "Password must be 8+ chars, with at least 1 Uppercase, 1 Number, and 1 Symbol." 
        });
    }

    const staff = await Staff.findById(req.session.staffId);
    if (!staff) return res.status(404).send("Not Found");
    
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    staff.password = hashedPassword;
    await staff.save();
    
    try {
        const user = await clients[0].users.fetch(staff.discordId);
        await user.send(`**Terminal Security Alert**\n\nYour Security Key has been **manually updated** by you.\n**Access URL:** ${getPanelUrl()}`);
        res.json({ success: true });
    } catch (e) {
        // Return success even if DM fails (password WAS changed)
        res.json({ success: true });
    }
});

// --- ADMIN API ---
app.get('/api/admin/stats', isAdmin, async (req, res) => {
    const stats = await Staff.find().sort({ ticketsClosed: -1 });
    res.json(stats);
});

app.post('/api/admin/staff/reset-password', isAdmin, async (req, res) => {
    const { staffId } = req.body;
    const staff = await Staff.findById(staffId);
    if (!staff) return res.status(404).send("Staff not found");

    const newPass = Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(newPass, 10);
    
    staff.password = hashedPassword;
    await staff.save();
    
    try {
        const user = await clients[0].users.fetch(staff.discordId);
        await user.send(`**Terminal Security Alert**\n\nYour security key has been reset by an Administrator.\n**New Key:** ${newPass}\n**Access URL:** ${getPanelUrl()}`);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: "Password updated in DB but DM failed." });
    }
});

// --- LICENSE ACTIVATION (STRICT VALIDATION) ---
app.post('/api/admin/license/activate', isAdmin, async (req, res) => {
    const { 
        license_key, instance_name, activation_type, duration,
        server_name, server_id, channel_id, discord_id 
    } = req.body;
    
    // Strict Validation
    if (!server_name || !server_id || !channel_id || !discord_id || !license_key) {
        return res.status(400).json({ error: "All fields (Server Name/ID, Channel ID, Discord ID) are required." });
    }

    const SELLAPP_TOKEN = process.env.SELLAPP_TOKEN;

    if (!SELLAPP_TOKEN) return res.status(500).json({ error: "System Error: Missing API Token" });

    try {
        const response = await axios.post('https://sell.app/api/v2/licenses/activate', {
            license_key: license_key,
            instance_name: instance_name
        }, {
            headers: {
                'Authorization': `Bearer ${SELLAPP_TOKEN}`,
                'Content-Type': 'application/json',
                'accept': 'application/json'
            }
        });

        let expiresAt = null;
        if (duration && duration !== 'Lifetime') {
            const days = parseInt(duration.split(' ')[0]);
            if (!isNaN(days)) {
                expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
            }
        }

        await new License({
            key: license_key,
            instanceId: response.data.id,
            discordId: discord_id,
            serverId: server_id,
            serverName: server_name,
            channelId: channel_id,
            type: activation_type,
            duration: duration,
            expiresAt: expiresAt
        }).save();

        const logDescription = [
            `**Staff:** ${req.session.username}`,
            `**Type:** ${activation_type || 'N/A'}`,
            `**Duration:** ${duration || 'N/A'}`,
            `**User:** <@${discord_id}> (${discord_id})`,
            `**Server:** ${server_name} (${server_id})`,
            `**Channel:** <#${channel_id}> (${channel_id})`,
            `**Instance:** ${instance_name}`,
            `**Key ID:** ${response.data.id}`
        ].join('\n');

        await sendLog("🔑 License Activated", logDescription, '#10b981');
        
        res.json({ success: true, data: response.data });

    } catch (err) {
        console.error(err);
        const msg = err.response?.data?.message || "Activation Failed";
        res.status(400).json({ error: msg });
    }
});

app.post('/api/admin/manual-dm', isAdmin, async (req, res) => {
    const { discordId, content } = req.body;
    if (!discordId || !content) return res.status(400).json({ error: "Missing ID or Message" });

    try {
        let thread = await Thread.findOne({ userId: discordId });
        let client;

        if (thread) {
            client = clients.find(c => c.user.id === thread.botId);
        } else {
            client = clients[0];
        }

        if (!client || !client.isReady()) return res.status(500).json({ error: "Bot Cluster Offline" });

        const user = await client.users.fetch(discordId);
        const embed = new EmbedBuilder()
            .setColor('#3b82f6')
            .setAuthor({ name: `Staff Message (${req.session.username})`, iconURL: client.user.displayAvatarURL() })
            .setDescription(content)
            .setTimestamp();

        const sentMsg = await user.send({ embeds: [embed] });
        const attachmentUrls = sentMsg.attachments.map(a => a.url);

        if (!thread) {
            thread = new Thread({
                userId: discordId,
                userTag: user.tag,
                botId: client.user.id,
                botName: client.user.username,
                messages: []
            });
            await sendLog("🆕 Manual Ticket Created", `**Staff:** ${req.session.username}\n**User:** ${user.tag} (${discordId})`, '#facc15');
        }

        const msgData = {
            authorTag: `Staff (${req.session.username})`,
            content: content,
            attachments: attachmentUrls,
            fromBot: true,
            timestamp: new Date()
        };

        thread.messages.push(msgData);
        thread.lastMessageAt = new Date();
        await thread.save();

        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { repliesSent: 1 } });
        io.emit('new_message', { threadId: thread._id, ...msgData });

        res.json({ success: true, threadId: thread._id });

    } catch (e) {
        console.error(e);
        res.status(500).json({ error: "DM Failed: Invalid ID or Privacy Settings." });
    }
});

app.get('/api/admin/config', isAdmin, async (req, res) => {
    const config = await Config.findOne({ id: 'global' });
    res.json(config);
});

app.post('/api/admin/config/toggle', isAdmin, async (req, res) => {
    const { note } = req.body;
    const config = await Config.findOne({ id: 'global' });
    
    config.supportOnline = !config.supportOnline;
    
    if (config.supportOnline) {
        config.offlineNote = ''; 
    } else {
        config.offlineNote = note || '';
    }
    
    await config.save();
    res.json({ success: true, supportOnline: config.supportOnline });
});

app.get('/api/admin/servers', isAdmin, async (req, res) => {
    let servers = [];
    clients.forEach(c => {
        if (!c.isReady()) return;
        c.guilds.cache.forEach(g => servers.push({ id: g.id, name: g.name, members: g.memberCount, botName: c.user.username, botId: c.user.id }));
    });
    res.json(servers);
});

app.post('/api/admin/leave-server', isAdmin, async (req, res) => {
    const { serverId, botId } = req.body;
    const client = clients.find(c => c.user.id === botId);
    try {
        const guild = await client.guilds.fetch(serverId);
        await guild.leave();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "Failed to leave" }); }
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

app.post('/api/admin/dm-owner', isAdmin, async (req, res) => {
    const { serverId, botId, message } = req.body;
    const client = clients.find(c => c.user.id === botId);
    try {
        const guild = await client.guilds.fetch(serverId);
        const owner = await client.users.fetch(guild.ownerId);
        await owner.send(`**Notification regarding ${guild.name}:**\n${message}`);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "DM Failed" }); }
});

app.post('/api/admin/bulk-message', isAdmin, async (req, res) => {
    const { message } = req.body;
    let sentCount = 0;
    for (const client of clients) {
        if (!client.isReady()) continue;
        for (const [id, guild] of client.guilds.cache) {
            try {
                const owner = await client.users.fetch(guild.ownerId);
                await owner.send(`**Broadcast:**\n${message}`);
                sentCount++;
            } catch (e) { console.error("Bulk Fail on " + guild.name); }
        }
    }
    res.json({ success: true, sentTo: sentCount });
});

app.post('/api/admin/staff/add', isAdmin, async (req, res) => {
    const { username, discordId, adminStatus } = req.body;
    const tempPass = Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(tempPass, 10);
    
    await new Staff({ username, discordId, password: hashedPassword, isAdmin: adminStatus }).save();
    try {
        const user = await clients[0].users.fetch(discordId);
        await user.send(`**Terminal Access Established**\n\n**Identifier:** ${username}\n**Security Key:** ${tempPass}\n**Access URL:** ${getPanelUrl()}`);
    } catch(e) { console.error("Could not DM staff member credentials."); }
    res.json({ success: true });
});

app.post('/api/admin/staff/delete', isAdmin, async (req, res) => {
    const { staffId } = req.body;
    if (staffId === req.session.staffId.toString()) return res.status(400).json({ error: "Cannot delete yourself" });
    try {
        await Staff.findByIdAndDelete(staffId);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "Delete failed" }); }
});

setInterval(async () => {
    const client = clients[0];
    if (!client || !client.isReady()) return;

    const threeDaysFromNow = new Date(Date.now() + 259200000); 
    
    const expiringLicenses = await License.find({
        expiresAt: { $lt: threeDaysFromNow, $gt: new Date() },
        reminderSent: false
    });

    for (const lic of expiringLicenses) {
        try {
            const user = await client.users.fetch(lic.discordId);
            const embed = new EmbedBuilder()
                .setTitle("⚠️ License Expiration Warning")
                .setDescription(`Your **${lic.type}** license is expiring soon!\n\n**Server:** ${lic.serverName}\n**Expires:** <t:${Math.floor(lic.expiresAt.getTime() / 1000)}:R>\n\nPlease purchase a new license to maintain access.`)
                .setColor('#f59e0b');
            
            await user.send({ embeds: [embed] });
            
            lic.reminderSent = true;
            await lic.save();
            console.log(`Sent expiry reminder to ${lic.discordId}`);
        } catch (e) {
            console.error(`Failed to DM expiry to ${lic.discordId}:`, e.message);
        }
    }
}, 1000 * 60 * 60 * 12);

server.listen(process.env.PORT || 10000, () => console.log("HQ Terminal Ready"));
