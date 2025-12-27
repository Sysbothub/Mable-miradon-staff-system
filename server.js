/**
 * =========================================================================================
 * MIRAIDON TRADE SERVICES - MASTER SERVER (v8.1)
 * =========================================================================================
 * * STATUS: FULLY EXPANDED & VERBOSE
 * * FIX: Restored full 1-5 Star Rating Buttons
 * * FEATURES: All previous features included.
 * =========================================================================================
 */

// 1. Load Environment Configuration
require('dotenv').config();

// 2. Import Required Modules
const axios = require('axios');
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const { 
    Client, 
    GatewayIntentBits, 
    Partials, 
    EmbedBuilder, 
    ChannelType, 
    AttachmentBuilder,
    ActionRowBuilder, 
    ButtonBuilder, 
    ButtonStyle 
} = require('discord.js');

// 3. Initialize Server Instance
const app = express();
const server = http.createServer(app);
const io = new Server(server);


// =========================================================================================
//  SECTION: FILE SYSTEM STORAGE
// =========================================================================================

// Determine correct storage path based on environment (Render vs Local)
let DATA_DIR;
if (process.env.RENDER === 'true') {
    DATA_DIR = '/var/data';
} else {
    DATA_DIR = path.join(__dirname, 'local_storage');
}

// Ensure Data Directory Exists
if (!fs.existsSync(DATA_DIR)) {
    console.log(`[SYSTEM] Initializing Data Directory at: ${DATA_DIR}`);
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Ensure Archive Directory Exists
const ARCHIVE_DIR = path.join(DATA_DIR, 'archives');
if (!fs.existsSync(ARCHIVE_DIR)) {
    console.log(`[SYSTEM] Initializing Archive Directory at: ${ARCHIVE_DIR}`);
    fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
}

console.log(`[SYSTEM] 📂 Storage Mounted Successfully at: ${DATA_DIR}`);


// =========================================================================================
//  SECTION: DATABASE CONNECTION & SCHEMAS
// =========================================================================================

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log("[SYSTEM] ✅ MongoDB Connection Successful");
        initializeSystemDefaults();
        repairDatabaseIntegrity();
    })
    .catch((error) => {
        console.error("[SYSTEM] ❌ CRITICAL DB ERROR:", error);
    });

/**
 * SCHEMA: Staff
 * Managing login credentials and performance metrics.
 */
const StaffSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    discordId: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    // Metrics
    ticketsClosed: { type: Number, default: 0 },
    repliesSent: { type: Number, default: 0 },
    ratingSum: { type: Number, default: 0 },
    ratingCount: { type: Number, default: 0 }
});
const Staff = mongoose.model('Staff', StaffSchema);

/**
 * SCHEMA: Thread
 * Represents an active support ticket.
 */
const ThreadSchema = new mongoose.Schema({
    userId: String,
    userTag: String,
    botId: String,
    botName: String,
    claimedBy: { type: String, default: null }, // Legacy compatibility
    messages: [{
        authorTag: String,
        content: String,
        attachments: [String],
        timestamp: { type: Date, default: Date.now },
        fromBot: { type: Boolean, default: false }
    }],
    lastMessageAt: { type: Date, default: Date.now }
});
const Thread = mongoose.model('Thread', ThreadSchema);

/**
 * SCHEMA: License
 * Manages keys generated via Sell.App API.
 */
const LicenseSchema = new mongoose.Schema({
    key: String,
    instanceId: String,
    discordId: String,
    serverId: String,      // For tracking removal later
    serverName: String,    // For tracking removal later
    channelId: String,
    type: String,
    duration: String,
    activatedAt: { type: Date, default: Date.now },
    expiresAt: Date, // Null = Lifetime
    reminderSent: { type: Boolean, default: false } // Tracks if 3-day warning was sent
});
const License = mongoose.model('License', LicenseSchema);

/**
 * SCHEMA: Config
 * Global settings (Online/Offline Toggle).
 */
const ConfigSchema = new mongoose.Schema({
    id: { type: String, default: 'global' },
    supportOnline: { type: Boolean, default: true },
    offlineNote: { type: String, default: '' }
});
const Config = mongoose.model('Config', ConfigSchema);

/**
 * SCHEMA: UserNote
 * CRM Sticky Notes for users.
 */
const UserNoteSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    note: { type: String, default: "" },
    updatedBy: String,
    updatedAt: { type: Date, default: Date.now }
});
const UserNote = mongoose.model('UserNote', UserNoteSchema);

/**
 * SCHEMA: Macro
 * Canned responses for staff.
 */
const MacroSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true }
});
const Macro = mongoose.model('Macro', MacroSchema);

/**
 * SCHEMA: FAQ
 * Dynamic Questions/Answers for the public page.
 */
const FAQSchema = new mongoose.Schema({
    question: { type: String, required: true },
    answer: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const FAQ = mongoose.model('FAQ', FAQSchema);


// =========================================================================================
//  SECTION: STARTUP ROUTINES
// =========================================================================================

async function initializeSystemDefaults() {
    // Create default Admin if missing
    const adminExists = await Staff.findOne({ username: 'admin' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash('map4491', 10);
        await new Staff({ 
            username: 'admin', 
            password: hashedPassword, 
            discordId: '000000000000000000', 
            isAdmin: true 
        }).save();
        console.log("[SYSTEM] ✅ Default Admin Account Created");
    }

    // Create default Config if missing
    const configExists = await Config.findOne({ id: 'global' });
    if (!configExists) {
        await new Config({ id: 'global', supportOnline: true }).save();
        console.log("[SYSTEM] ✅ Default Configuration Created");
    }
}

async function repairDatabaseIntegrity() {
    // Ensures legacy tickets have the 'claimedBy' field to prevent UI crashes
    try {
        await Thread.updateMany(
            { claimedBy: { $exists: false } },
            { $set: { claimedBy: null } }
        );
        console.log("[SYSTEM] ✅ Database Integrity Verified");
    } catch (e) {
        console.error("[SYSTEM] Repair Failed:", e);
    }
}


// =========================================================================================
//  SECTION: EXPRESS MIDDLEWARE & AUTHENTICATION
// =========================================================================================

// Proxy trust for Render/Nginx
app.set('trust proxy', 1);

// JSON Parsing (Large limit for file uploads like zips)
app.use(express.json({ limit: '50mb' }));

// Session Management
app.use(session({
    secret: process.env.SESSION_SECRET || 'hq-secret-key-default',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, // 24 Hours
        secure: true, 
        sameSite: 'none' 
    } 
}));

// Middleware: Authentication Guard
const isAuth = (req, res, next) => {
    if (req.session.staffId) {
        return next();
    }
    // If API request, return JSON error
    if (req.path.startsWith('/api')) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    // If Page request, redirect to login
    return res.redirect('/login.html');
};

// Middleware: Admin Guard
const isAdmin = (req, res, next) => {
    if (req.session.staffId && req.session.isAdmin) {
        return next();
    }
    console.log(`[AUTH] 🛑 Non-Admin attempted to access ${req.path}`);
    return res.status(403).json({ error: "Admin Access Required" });
};

const getPanelUrl = () => {
    return process.env.APP_URL || "Panel URL Not Configured";
};

// --- STATIC FILE SERVING ---

// 1. Serve Public Files
app.use(express.static(path.join(__dirname, 'public')));

// 2. Serve Protected Staff Files
app.use('/staff', isAuth, express.static(path.join(__dirname, 'public/staff')));


// =========================================================================================
//  SECTION: DISCORD BOT LOGIC
// =========================================================================================

const botTokens = [
    process.env.BOT_ONE_TOKEN, 
    process.env.BOT_TWO_TOKEN
].filter(token => token !== undefined && token !== "");

const clients = [];

async function sendLog(title, description, color = '#3b82f6', files = []) {
    if (!process.env.LOG_CHANNEL_ID || !clients[0]) {
        return;
    }
    
    try {
        const channel = await clients[0].channels.fetch(process.env.LOG_CHANNEL_ID);
        const logEmbed = new EmbedBuilder()
            .setTitle(title)
            .setDescription(description)
            .setColor(color)
            .setTimestamp();
            
        await channel.send({ embeds: [logEmbed], files: files });
        console.log(`[LOG] 📝 Sent Log Embed: ${title}`);
    } catch (e) { 
        console.error("[LOG] ❌ Error sending log:", e.message); 
    }
}

botTokens.forEach((token, index) => {
    const client = new Client({
        intents: [
            GatewayIntentBits.Guilds, 
            GatewayIntentBits.DirectMessages, 
            GatewayIntentBits.MessageContent, 
            GatewayIntentBits.GuildMembers, 
            GatewayIntentBits.GuildInvites,
            GatewayIntentBits.GuildMessageTyping, 
            GatewayIntentBits.DirectMessageTyping
        ],
        partials: [Partials.Channel, Partials.Message]
    });

    client.once('ready', () => {
        console.log(`[BOT_${index + 1}] 🤖 Active: ${client.user.tag}`);
    });

    // TYPING INDICATOR
    client.on('typingStart', async (typing) => {
        if (typing.user.bot) return;
        io.emit('user_typing', { userId: typing.user.id });
    });

    // INTERACTION (BUTTONS)
    client.on('interactionCreate', async (interaction) => {
        if (!interaction.isButton()) return;

        const parts = interaction.customId.split('_');
        const action = parts[0];
        
        if (action === 'rate') {
            const scoreStr = parts[1];
            const staffId = parts[2];
            const score = parseInt(scoreStr);
            
            console.log(`[RATING] ⭐ User rated staff ${staffId}: ${score} stars`);

            await Staff.findByIdAndUpdate(staffId, { 
                $inc: { ratingSum: score, ratingCount: 1 } 
            });

            const disabledRow = new ActionRowBuilder().addComponents(
                new ButtonBuilder().setCustomId('done').setLabel(`Rated ${score} Stars`).setStyle(ButtonStyle.Success).setDisabled(true)
            );

            await interaction.update({ 
                content: `**Thank you!** You rated your support experience **${score}/5** stars.`, 
                components: [disabledRow] 
            });
        }
    });

    // MESSAGE HANDLER (CORE LOGIC)
    client.on('messageCreate', async (message) => {
        if (message.author.bot || message.guild) {
            return;
        }
        
        let thread = await Thread.findOne({ 
            userId: message.author.id, 
            botId: client.user.id 
        });
        
        // NEW THREAD CREATION
        if (!thread) {
            console.log(`[TICKET] 📩 New Thread Created: ${message.author.tag}`);
            
            thread = new Thread({ 
                userId: message.author.id, 
                userTag: message.author.tag, 
                botId: client.user.id, 
                botName: client.user.username, 
                messages: [] 
            });
            
            const config = await Config.findOne({ id: 'global' });
            const isManualOnline = config ? config.supportOnline : true;
            const offlineNote = config ? config.offlineNote : '';

            // Timezone Logic (AST)
            const now = new Date();
            const options = { timeZone: 'America/Halifax', hour12: false, hour: 'numeric', minute: 'numeric' };
            const formatter = new Intl.DateTimeFormat('en-US', options);
            const parts = formatter.formatToParts(now);
            const hour = parseInt(parts.find(p => p.type === 'hour').value);
            const minute = parseInt(parts.find(p => p.type === 'minute').value);
            const currentTotalMinutes = (hour * 60) + minute;
            const startTotal = 8 * 60; // 8:00 AM
            const endTotal = 23 * 60 + 59; // 11:59 PM
            const isWorkHours = currentTotalMinutes >= startTotal && currentTotalMinutes <= endTotal;

            let autoReply;

            if (!isManualOnline) {
                console.log(`[TICKET] ⚠️ Auto-Reply: Offline Mode`);
                const noteText = offlineNote ? `**Reason:** ${offlineNote}\n\n` : '';
                autoReply = new EmbedBuilder().setColor('#ef4444').setTitle('Support Currently Offline').setDescription(`Support has been toggled offline by staff.\n\n${noteText}We will respond when available.`).setTimestamp();
            } else if (!isWorkHours) {
                console.log(`[TICKET] ⚠️ Auto-Reply: Outside Hours`);
                autoReply = new EmbedBuilder().setColor('#f59e0b').setTitle('Support Closed').setDescription('Hours: 8:00 AM - 11:59 PM AST.').setTimestamp();
            } else {
                console.log(`[TICKET] ✅ Auto-Reply: Online`);
                autoReply = new EmbedBuilder().setColor('#3b82f6').setTitle('Support Ticket Opened').setDescription('A staff member will respond to your inquiry within **12-24 hours**.').setTimestamp();
            }
            
            try { 
                await message.author.send({ embeds: [autoReply] }).catch(() => {}); 
            } catch (err) {}

            sendLog("🆕 Ticket Created", `**User:** ${message.author.tag}\n**Bot:** ${client.user.username}`, '#facc15');
        }
        
        console.log(`[MSG] 📥 ${message.author.tag}: ${message.content.substring(0, 30)}...`);

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
        
        io.emit('new_message', { 
            threadId: thread._id, 
            notif_sound: true, 
            ...msgData 
        });
    });

    client.login(token).catch(e => console.error(`[BOT] ❌ Login Failed Bot ${index + 1}`));
    clients.push(client);
});


// =========================================================================================
//  SECTION: SOCKET.IO (REAL-TIME COMMUNICATION)
// =========================================================================================

const activeViewers = {}; 

io.on('connection', (socket) => {
    
    socket.on('join_ticket_room', ({ threadId, username }) => {
        socket.join(threadId);
        
        if (!activeViewers[threadId]) {
            activeViewers[threadId] = new Set();
        }
        activeViewers[threadId].add(username);
        
        console.log(`[SOCKET] 👤 ${username} joined ticket room: ${threadId}`);
        io.to(threadId).emit('viewers_updated', Array.from(activeViewers[threadId]));
        
        socket.currentThreadId = threadId;
        socket.currentUser = username;
    });

    socket.on('leave_ticket_room', () => {
        if (socket.currentThreadId && socket.currentUser) {
            const tId = socket.currentThreadId;
            socket.leave(tId);
            
            if (activeViewers[tId]) {
                activeViewers[tId].delete(socket.currentUser);
                io.to(tId).emit('viewers_updated', Array.from(activeViewers[tId]));
            }
            
            socket.currentThreadId = null;
        }
    });

    socket.on('disconnect', () => {
        if (socket.currentThreadId && socket.currentUser) {
            const tId = socket.currentThreadId;
            if (activeViewers[tId]) {
                activeViewers[tId].delete(socket.currentUser);
                io.to(tId).emit('viewers_updated', Array.from(activeViewers[tId]));
            }
        }
    });

    socket.on('staff_typing', async (data) => {
        const { threadId } = data;
        const thread = await Thread.findById(threadId);
        if (!thread) return;
        
        const client = clients.find(c => c.user.id === thread.botId);
        if (client) {
            try {
                const user = await client.users.fetch(thread.userId);
                const dmChannel = user.dmChannel || await user.createDM();
                await dmChannel.sendTyping();
            } catch(e) {}
        }
    });
});


// =========================================================================================
//  SECTION: API ROUTES - AUTH & TICKET OPS
// =========================================================================================

/**
 * AUTH: Check Status
 */
app.get('/api/auth/user', isAuth, (req, res) => {
    res.json({ username: req.session.username, isAdmin: req.session.isAdmin });
});

/**
 * AUTH: Login
 */
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    console.log(`[AUTH] 🔐 Login attempt for: ${username}`);
    
    const user = await Staff.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.staffId = user._id; 
        req.session.isAdmin = user.isAdmin; 
        req.session.username = user.username;
        req.session.save(() => {
            console.log(`[AUTH] ✅ Login Successful: ${username}`);
            res.json({ success: true, isAdmin: user.isAdmin, username: user.username });
        });
    } else {
        console.log(`[AUTH] ❌ Login Failed: ${username}`);
        res.status(401).json({ error: "Invalid Credentials" });
    }
});

/**
 * AUTH: Logout
 */
app.post('/api/logout', (req, res) => { 
    console.log(`[AUTH] 🚪 Logout request`);
    req.session.destroy(() => { 
        res.clearCookie('connect.sid'); 
        res.json({ success: true }); 
    }); 
});

/**
 * AUTH: Request Reset
 */
app.post('/api/public/request-reset', async (req, res) => {
    const { discordId } = req.body;
    console.log(`[AUTH] 🔄 Password reset requested for ID: ${discordId}`);
    
    const staff = await Staff.findOne({ discordId });
    if (!staff) {
        return res.status(404).json({ error: "No staff found" });
    }
    
    const newPass = Math.random().toString(36).slice(-8);
    staff.password = await bcrypt.hash(newPass, 10);
    await staff.save();
    
    try {
        const user = await clients[0].users.fetch(discordId);
        await user.send(`**Terminal Recovery**\n**New Key:** ${newPass}\n**URL:** ${getPanelUrl()}`);
        console.log(`[AUTH] ✅ Reset DM sent to ${staff.username}`);
        res.json({ success: true });
    } catch (e) { 
        console.error(`[AUTH] ❌ Failed to DM reset key: ${e.message}`);
        res.status(500).json({ error: "DM Failed" }); 
    }
});

/**
 * TICKETS: Get List
 */
app.get('/api/threads', isAuth, async (req, res) => { 
    const threads = await Thread.find().sort({ lastMessageAt: -1 }); 
    res.json(threads); 
});

/**
 * TICKETS: Reply
 */
app.post('/api/reply', isAuth, async (req, res) => {
    const { threadId, content, fileBase64, fileName } = req.body;
    
    const thread = await Thread.findById(threadId);
    if (!thread) {
        return res.status(404).json({ error: "Not Found" });
    }
    
    const client = clients.find(c => c.user.id === thread.botId);
    try {
        const user = await client.users.fetch(thread.userId);
        
        let messageOptions = { 
            embeds: [new EmbedBuilder()
                .setColor('#3b82f6')
                .setAuthor({ name: `Support: ${req.session.username}`, iconURL: client.user.displayAvatarURL() })
                .setDescription(content || "Sent an attachment")
                .setTimestamp()
            ] 
        };
        
        if (fileBase64) {
            console.log(`[REPLY] 📎 Sending file: ${fileName}`);
            messageOptions.files = [new AttachmentBuilder(Buffer.from(fileBase64.split(',')[1], 'base64'), { name: fileName || 'upload.png' })];
        }
        
        await user.send(messageOptions);
        
        const reply = { 
            authorTag: `Staff (${req.session.username})`, 
            content: content || "[File Attachment]", 
            fromBot: true, 
            timestamp: new Date() 
        };
        
        thread.messages.push(reply);
        thread.lastMessageAt = new Date();
        await thread.save();
        
        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { repliesSent: 1 } });
        io.emit('new_message', { threadId: thread._id, ...reply });
        
        console.log(`[REPLY] 📤 Sent to ${thread.userTag}: ${content ? content.substring(0, 20) : "File"}`);
        res.json({ success: true });
    } catch (err) { 
        console.error(`[REPLY] ❌ Failed: ${err.message}`);
        res.status(500).json({ error: "DM Failed" }); 
    }
});

/**
 * TICKETS: Close & Archive
 */
app.post('/api/close-thread', isAuth, async (req, res) => {
    const { threadId } = req.body;
    console.log(`[ARCHIVE] 🔒 Archiving thread ${threadId}`);

    const thread = await Thread.findById(threadId);
    if (!thread) {
        return res.status(404).json({ error: "Not Found" });
    }

    let transcriptText = `OFFICIAL TRANSCRIPT: ${thread.userTag}\nBot: ${thread.botName}\n\n`;
    thread.messages.forEach(m => { 
        transcriptText += `[${m.timestamp.toISOString()}] ${m.authorTag}: ${m.content}\n`; 
    });
    
    const tempPath = path.join(__dirname, `temp-${thread.userId}.txt`);

    try {
        fs.writeFileSync(tempPath, transcriptText);
        
        await sendLog("🔒 Archive Logged", `User: ${thread.userTag}\n**Closed By:** ${req.session.username}`, '#ef4444', [new AttachmentBuilder(tempPath)]);
        
        const userDir = path.join(ARCHIVE_DIR, thread.userId);
        if (!fs.existsSync(userDir)) {
            fs.mkdirSync(userDir, { recursive: true });
        }
        
        const filePath = path.join(userDir, `${Date.now()}-${threadId}.json`);

        const archiveData = {
            meta: { 
                closedBy: req.session.username, 
                closedAt: new Date(), 
                userTag: thread.userTag 
            },
            messages: thread.messages
        };

        fs.writeFileSync(filePath, JSON.stringify(archiveData, null, 2));
        
        // FIXED: Full 5-Star Rating System restored
        const staffId = req.session.staffId;
        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId(`rate_1_${staffId}`).setLabel('1⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_2_${staffId}`).setLabel('2⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_3_${staffId}`).setLabel('3⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_4_${staffId}`).setLabel('4⭐').setStyle(ButtonStyle.Primary),
            new ButtonBuilder().setCustomId(`rate_5_${staffId}`).setLabel('5⭐').setStyle(ButtonStyle.Success)
        );
        
        const embed = new EmbedBuilder().setTitle("How was your support?").setDescription(`You were helped by **${req.session.username}**. Please rate your experience.`).setColor('#3b82f6');

        const client = clients.find(c => c.user.id === thread.botId);
        if (client) { 
            try { 
                const user = await client.users.fetch(thread.userId); 
                await user.send({ embeds: [embed], components: [row] }); 
                console.log(`[ARCHIVE] 📤 Rating request sent to ${thread.userTag}`);
            } catch(e) {
                console.error(`[ARCHIVE] ❌ Could not send rating request: ${e.message}`);
            } 
        }

        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { ticketsClosed: 1 } });
        await Thread.findByIdAndDelete(threadId);
        fs.unlinkSync(tempPath);

        res.json({ success: true });
    } catch (e) { 
        console.error(`[ARCHIVE] ❌ Critical Error:`, e);
        res.status(500).json({ error: "Archive Failed" }); 
    }
});


// =========================================================================================
//  SECTION: API ROUTES - CRM & NOTES
// =========================================================================================

app.get('/api/crm/user/:discordId', isAuth, async (req, res) => {
    const { discordId } = req.params;
    
    const noteDoc = await UserNote.findOne({ userId: discordId });
    
    const userDir = path.join(ARCHIVE_DIR, discordId);
    let historyFiles = [];

    if (fs.existsSync(userDir)) {
        const files = fs.readdirSync(userDir).filter(f => f.endsWith('.json'));
        historyFiles = files.map(file => {
            try {
                const content = JSON.parse(fs.readFileSync(path.join(userDir, file), 'utf8'));
                return { 
                    filename: file, 
                    closedAt: content.meta.closedAt, 
                    closedBy: content.meta.closedBy 
                };
            } catch (err) { return null; }
        }).filter(x => x).sort((a, b) => new Date(b.closedAt) - new Date(a.closedAt));
    }

    res.json({ 
        note: noteDoc ? noteDoc.note : "", 
        history: historyFiles 
    });
});

app.get('/api/crm/transcript/:discordId/:filename', isAuth, (req, res) => {
    const { discordId, filename } = req.params;
    
    if (filename.includes('..') || discordId.includes('..')) {
        return res.status(403).json({ error: "Invalid path" });
    }
    
    const filePath = path.join(ARCHIVE_DIR, discordId, filename);
    if (fs.existsSync(filePath)) {
        res.json(JSON.parse(fs.readFileSync(filePath, 'utf8')));
    } else {
        res.status(404).json({ error: "Transcript not found" });
    }
});

app.post('/api/crm/note', isAuth, async (req, res) => {
    await UserNote.findOneAndUpdate(
        { userId: req.body.userId }, 
        { 
            note: req.body.note, 
            updatedBy: req.session.username, 
            updatedAt: new Date() 
        }, 
        { upsert: true, new: true }
    );
    console.log(`[CRM] 📝 Note updated for ${req.body.userId} by ${req.session.username}`);
    res.json({ success: true });
});


// =========================================================================================
//  SECTION: API ROUTES - ADMIN MANAGEMENT
// =========================================================================================

app.get('/api/admin/stats', isAdmin, async (req, res) => { 
    const stats = await Staff.find().sort({ ticketsClosed: -1 }); 
    res.json(stats); 
});

app.get('/api/admin/config', isAdmin, async (req, res) => { 
    const config = await Config.findOne({ id: 'global' }); 
    res.json(config); 
});

app.post('/api/admin/config/toggle', isAdmin, async (req, res) => { 
    const { note } = req.body;
    
    const config = await Config.findOne({ id: 'global' }); 
    config.supportOnline = !config.supportOnline; 
    config.offlineNote = config.supportOnline ? '' : (note || ''); 
    await config.save(); 
    
    console.log(`[CONFIG] ⚙️ Support Status Toggled: ${config.supportOnline}`);
    res.json({ success: true, supportOnline: config.supportOnline }); 
});

app.get('/api/admin/servers', isAdmin, async (req, res) => {
    let servers = [];
    clients.forEach(c => {
        if (!c.isReady()) return;
        c.guilds.cache.forEach(g => {
            servers.push({
                id: g.id,
                name: g.name,
                members: g.memberCount,
                botName: c.user.username,
                botId: c.user.id
            });
        });
    });
    res.json(servers);
});

// Admin Fleet Actions
app.post('/api/admin/leave-server', isAdmin, async (req, res) => {
    const client = clients.find(c => c.user.id === req.body.botId);
    try {
        const guild = await client.guilds.fetch(req.body.serverId);
        await guild.leave();
        console.log(`[ADMIN] 👋 Left server: ${guild.name}`);
        res.json({ success: true });
    } catch (e) { 
        res.status(500).json({ error: "Failed to leave" }); 
    }
});

app.post('/api/admin/create-invite', isAdmin, async (req, res) => {
    const client = clients.find(c => c.user.id === req.body.botId);
    try {
        const guild = await client.guilds.fetch(req.body.serverId);
        const chan = guild.channels.cache.find(c => 
            c.type === ChannelType.GuildText && 
            c.permissionsFor(client.user).has('CreateInstantInvite')
        );
        const inv = await chan.createInvite({ maxAge: 3600, maxUses: 1 });
        console.log(`[ADMIN] 🔗 Invite created for ${guild.name}`);
        res.json({ success: true, url: inv.url });
    } catch (e) { 
        res.status(500).json({ error: "No Permission" }); 
    }
});

app.post('/api/admin/dm-owner', isAdmin, async (req, res) => {
    const client = clients.find(c => c.user.id === req.body.botId);
    try {
        const guild = await client.guilds.fetch(req.body.serverId);
        const owner = await client.users.fetch(guild.ownerId);
        await owner.send(`**Notification regarding ${guild.name}:**\n${req.body.message}`);
        console.log(`[ADMIN] 📤 DM sent to owner of ${guild.name}`);
        res.json({ success: true });
    } catch (e) { 
        res.status(500).json({ error: "DM Failed" }); 
    }
});

app.post('/api/admin/bulk-message', isAdmin, async (req, res) => {
    console.log(`[ADMIN] ⚠️ STARTING GLOBAL BROADCAST`);
    let sentCount = 0;
    
    for (const client of clients) {
        if (!client.isReady()) continue;
        for (const [id, guild] of client.guilds.cache) {
            try {
                const owner = await client.users.fetch(guild.ownerId);
                await owner.send(`**Broadcast:**\n${req.body.message}`);
                sentCount++;
            } catch (e) {}
        }
    }
    console.log(`[ADMIN] ✅ Broadcast complete. Sent to ${sentCount} owners.`);
    res.json({ success: true, sentTo: sentCount });
});

// Admin Staff Management
app.post('/api/admin/staff/add', isAdmin, async (req, res) => { 
    const tempPass = Math.random().toString(36).slice(-8); 
    const hashedPassword = await bcrypt.hash(tempPass, 10); 
    
    await new Staff({ 
        username: req.body.username, 
        discordId: req.body.discordId, 
        password: hashedPassword, 
        isAdmin: req.body.adminStatus 
    }).save(); 
    
    try { 
        const user = await clients[0].users.fetch(req.body.discordId); 
        await user.send(`**Staff Access Granted**\nUser: ${req.body.username}\nPass: ${tempPass}\nURL: ${getPanelUrl()}`); 
    } catch(e) {} 
    
    console.log(`[ADMIN] 👤 Staff added: ${req.body.username}`);
    res.json({ success: true }); 
});

app.post('/api/admin/staff/delete', isAdmin, async (req, res) => { 
    if (req.body.staffId === req.session.staffId.toString()) {
        return res.status(400).json({ error: "Cannot delete yourself" }); 
    }
    await Staff.findByIdAndDelete(req.body.staffId); 
    console.log(`[ADMIN] 🗑️ Staff deleted: ${req.body.staffId}`);
    res.json({ success: true }); 
});

app.post('/api/admin/manual-dm', isAdmin, async (req, res) => {
    try {
        let thread = await Thread.findOne({ userId: req.body.discordId });
        let client = clients[0]; 
        const user = await client.users.fetch(req.body.discordId);
        
        await user.send({ 
            embeds: [new EmbedBuilder().setColor('#3b82f6').setAuthor({ name: `Staff Message (${req.session.username})`, iconURL: client.user.displayAvatarURL() }).setDescription(req.body.content).setTimestamp()] 
        });
        
        if (!thread) { 
            thread = new Thread({ 
                userId: req.body.discordId, 
                userTag: user.tag, 
                botId: client.user.id, 
                botName: client.user.username, 
                messages: [] 
            }); 
            await sendLog("🆕 Manual Ticket", `Staff: ${req.session.username}`, '#facc15'); 
        }
        
        const msgData = { 
            authorTag: `Staff (${req.session.username})`, 
            content: req.body.content, 
            fromBot: true, 
            timestamp: new Date() 
        };
        
        thread.messages.push(msgData); 
        thread.lastMessageAt = new Date(); 
        await thread.save(); 
        
        io.emit('new_message', { threadId: thread._id, ...msgData });
        console.log(`[ADMIN] 📤 Manual DM sent to ${user.tag}`);
        res.json({ success: true });
    } catch (e) { 
        console.error(`[ADMIN] ❌ Manual DM Failed:`, e);
        res.status(500).json({ error: "DM Failed" }); 
    }
});

// Admin Macros
app.get('/api/macros', isAuth, async (req, res) => { 
    const macros = await Macro.find().sort({ title: 1 }); 
    res.json(macros); 
});

app.post('/api/admin/macros/add', isAdmin, async (req, res) => {
    const { title, content } = req.body;
    if (!title || !content) return res.status(400).json({ error: "Missing fields" });
    
    await new Macro({ title, content }).save();
    console.log(`[ADMIN] ➕ Macro added: ${title}`);
    res.json({ success: true });
});

app.post('/api/admin/macros/delete', isAdmin, async (req, res) => {
    await Macro.findByIdAndDelete(req.body.id);
    console.log(`[ADMIN] ➖ Macro deleted`);
    res.json({ success: true });
});

// Admin FAQ
app.get('/api/faq', async (req, res) => {
    const faqs = await FAQ.find().sort({ createdAt: 1 });
    res.json(faqs);
});

app.post('/api/admin/faq/add', isAdmin, async (req, res) => {
    const { question, answer } = req.body;
    if (!question || !answer) return res.status(400).json({ error: "Missing Q or A" });
    
    await new FAQ({ question, answer }).save();
    console.log(`[ADMIN] ❓ FAQ added`);
    res.json({ success: true });
});

app.post('/api/admin/faq/delete', isAdmin, async (req, res) => {
    await FAQ.findByIdAndDelete(req.body.id);
    console.log(`[ADMIN] ❌ FAQ deleted`);
    res.json({ success: true });
});


// =========================================================================================
//  SECTION: LICENSE MANAGEMENT (SELL.APP)
// =========================================================================================

app.post('/api/admin/license/activate', isAdmin, async (req, res) => {
    try {
        console.log(`[LICENSE] 🚀 Attempting activation for Key: ${req.body.license_key}`);

        // 1. Activate via Sell.App API
        const response = await axios.post('https://sell.app/api/v2/licenses/activate', { 
            license_key: req.body.license_key, 
            instance_name: req.body.instance_name 
        }, { 
            headers: { 
                'Authorization': `Bearer ${process.env.SELLAPP_TOKEN}`, 
                'Content-Type': 'application/json' 
            } 
        });
        
        // 2. Calculate Expiration Date
        let expiresAt = null; 
        if (req.body.duration && req.body.duration !== 'Lifetime') { 
            const days = parseInt(req.body.duration.split(' ')[0]); 
            if (!isNaN(days)) expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000); 
        }
        
        // 3. Save to Local DB (With new Server Fields)
        await new License({ 
            key: req.body.license_key, 
            instanceId: response.data.id, 
            discordId: req.body.discord_id, 
            serverId: req.body.server_id,       // Added v7.8
            serverName: req.body.server_name,   // Added v7.8
            channelId: req.body.channel_id, 
            type: req.body.type, 
            duration: req.body.duration, 
            expiresAt: expiresAt 
        }).save();
        
        await sendLog("🔑 License Activated", `**Staff:** ${req.session.username}\n**Key:** ${req.body.license_key}\n**User:** ${req.body.discord_id}\n**Server:** ${req.body.server_name} (${req.body.server_id})`, '#10b981');
        
        // 4. Auto-DM User
        try {
            const discordUser = await clients[0].users.fetch(req.body.discord_id);
            if(discordUser) {
                const embed = new EmbedBuilder()
                    .setTitle("License Activated ✅")
                    .setColor('#10b981')
                    .setDescription(`Your **${req.body.type}** license has been successfully activated for server: **${req.body.server_name}**.`)
                    .addFields(
                        { name: 'License Key', value: req.body.license_key, inline: true },
                        { name: 'Duration', value: req.body.duration, inline: true },
                        { name: 'Instance ID', value: req.body.instance_name, inline: false }
                    )
                    .setFooter({ text: "Thank you for supporting Miraidon Trade Services!" })
                    .setTimestamp();
                await discordUser.send({ embeds: [embed] });
                console.log(`[LICENSE] 📤 Auto-DM sent to ${req.body.discord_id}`);
            }
        } catch(e) {
            console.error(`[LICENSE] ❌ Failed to DM user: ${e.message}`);
        }

        res.json({ success: true, data: response.data });
    } catch (err) { 
        console.error(`[LICENSE] ❌ Activation Failed:`, err.response?.data || err.message);
        res.status(400).json({ error: err.response?.data?.message || "Activation Failed" }); 
    }
});

// =========================================================================================
//  SECTION: AUTOMATED TASKS
// =========================================================================================

async function checkExpirations() {
    console.log("[SYSTEM] 🕒 Checking for expiring licenses...");
    const now = new Date();
    const threeDaysFromNow = new Date();
    threeDaysFromNow.setDate(now.getDate() + 3);

    try {
        // Find licenses expiring between Now and 3 Days from now, that haven't been reminded
        const expiringLicenses = await License.find({
            expiresAt: { $gt: now, $lt: threeDaysFromNow },
            reminderSent: false
        });

        for (const lic of expiringLicenses) {
            try {
                const user = await clients[0].users.fetch(lic.discordId);
                const embed = new EmbedBuilder()
                    .setTitle("⚠️ License Expiring Soon")
                    .setColor('#f59e0b')
                    .setDescription(`Your **${lic.type}** license for **${lic.serverName || 'Unknown Server'}** is set to expire in less than 3 days.`)
                    .addFields({ name: 'License Key', value: lic.key })
                    .setFooter({ text: "Please renew to avoid service interruption." })
                    .setTimestamp();
                
                await user.send({ embeds: [embed] });
                
                // Mark as sent
                lic.reminderSent = true;
                await lic.save();
                console.log(`[EXPIRY] 📤 Sent reminder to user ${lic.discordId}`);
            } catch (err) {
                console.error(`[EXPIRY] ❌ Failed to DM user ${lic.discordId}:`, err.message);
            }
        }
    } catch (e) {
        console.error("[EXPIRY] ❌ Check failed:", e);
    }
}

// Run expiration check every hour (3600000 ms)
setInterval(checkExpirations, 3600000);


// =========================================================================================
//  SECTION: BOOTSTRAP
// =========================================================================================

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
    console.log(`[SYSTEM] 🚀 MIRAIDON TRADE SERVICES Ready on Port ${PORT}`);
    console.log(`[SYSTEM] 🔗 Local URL: http://localhost:${PORT}`);
});
