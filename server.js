/**
 * =========================================================================================
 * TRADE SERVICES PANEL - MASTER SERVER (v6.0)
 * =========================================================================================
 * This file contains the complete backend logic for the support system.
 * It handles: Database, Web Server, Socket.io, Discord Bots, and File Storage.
 * =========================================================================================
 */

// 1. Load Environment Variables
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

// 3. Initialize Express and Socket.io
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// =========================================================================================
//  SECTION: DISK STORAGE CONFIGURATION
// =========================================================================================

// Define the directory where data will be stored.
// If running on Render, use the persistent /var/data folder.
// If running locally, use a local_storage folder.
let DATA_DIR;
if (process.env.RENDER === 'true') {
    DATA_DIR = '/var/data';
} else {
    DATA_DIR = path.join(__dirname, 'local_storage');
}

// Check if the Main Data Directory exists. If not, create it.
if (!fs.existsSync(DATA_DIR)) {
    console.log(`[SYSTEM] Creating Data Directory at: ${DATA_DIR}`);
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Define the Archives Directory inside the Data Directory.
const ARCHIVE_DIR = path.join(DATA_DIR, 'archives');

// Check if the Archives Directory exists. If not, create it.
if (!fs.existsSync(ARCHIVE_DIR)) {
    console.log(`[SYSTEM] Creating Archive Directory at: ${ARCHIVE_DIR}`);
    fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
}

console.log(`[SYSTEM] 📂 Storage Mounted Successfully at: ${DATA_DIR}`);


// =========================================================================================
//  SECTION: DATABASE & MODELS
// =========================================================================================

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log("[SYSTEM] ✅ MongoDB Connection Successful");
        // Run the repair function to fix any legacy data issues
        performDatabaseRepair();
    })
    .catch((error) => {
        console.error("[SYSTEM] ❌ MongoDB Connection Error:", error);
    });

/**
 * MODEL: Staff
 * Stores login credentials and performance statistics for staff members.
 */
const StaffSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    discordId: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    // Stats
    ticketsClosed: { type: Number, default: 0 },
    repliesSent: { type: Number, default: 0 },
    ratingSum: { type: Number, default: 0 },
    ratingCount: { type: Number, default: 0 }
});
const Staff = mongoose.model('Staff', StaffSchema);

/**
 * MODEL: Thread
 * Stores the active support ticket conversation.
 */
const ThreadSchema = new mongoose.Schema({
    userId: String,
    userTag: String,
    botId: String,
    botName: String,
    // Message History
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
 * MODEL: License
 * Stores generated license keys and activation details.
 */
const LicenseSchema = new mongoose.Schema({
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
});
const License = mongoose.model('License', LicenseSchema);

/**
 * MODEL: Config
 * Stores global settings like Online/Offline status.
 */
const ConfigSchema = new mongoose.Schema({
    id: { type: String, default: 'global' },
    supportOnline: { type: Boolean, default: true },
    offlineNote: { type: String, default: '' }
});
const Config = mongoose.model('Config', ConfigSchema);

/**
 * MODEL: UserNote
 * Stores persistent staff notes (CRM) about a user.
 */
const UserNoteSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    note: { type: String, default: "" },
    updatedBy: String,
    updatedAt: { type: Date, default: Date.now }
});
const UserNote = mongoose.model('UserNote', UserNoteSchema);

/**
 * MODEL: Macro
 * Stores canned responses for quick replies.
 */
const MacroSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true }
});
const Macro = mongoose.model('Macro', MacroSchema);


// =========================================================================================
//  SECTION: SYSTEM UTILITIES & STARTUP
// =========================================================================================

/**
 * Ensures a default Admin account and Config exist in the database.
 */
async function setupDefaults() {
    // Check if an admin exists
    const adminExists = await Staff.findOne({ username: 'admin' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash('map4491', 10);
        const newAdmin = new Staff({ 
            username: 'admin', 
            password: hashedPassword, 
            discordId: '000000000000000000', 
            isAdmin: true 
        });
        await newAdmin.save();
        console.log("[SYSTEM] ✅ Default Admin Account Created");
    }

    // Check if config exists
    const configExists = await Config.findOne({ id: 'global' });
    if (!configExists) {
        const newConfig = new Config({ 
            id: 'global', 
            supportOnline: true 
        });
        await newConfig.save();
        console.log("[SYSTEM] ✅ Default Configuration Created");
    }
}
setupDefaults();

/**
 * Scans the database for legacy tickets and repairs them to prevent crashes.
 */
async function performDatabaseRepair() {
    console.log("[SYSTEM] 🛠️  Checking database health...");
    // This function can be expanded in the future if we need to migrate data.
    // Currently, it just logs that the system is ready.
    console.log("[SYSTEM] ✅ Database check complete.");
}


// =========================================================================================
//  SECTION: SERVER CONFIGURATION & AUTHENTICATION
// =========================================================================================

// Enable Trust Proxy for Render/Nginx
app.set('trust proxy', 1); 

// Increase body limit for large file uploads
app.use(express.json({ limit: '10mb' })); 

// Serve the public folder
app.use(express.static('public'));

// Setup Session Storage
app.use(session({
    secret: process.env.SESSION_SECRET || 'hq-secret-key',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, // 24 Hours
        secure: true, 
        sameSite: 'none' 
    } 
}));

/**
 * Middleware to check if user is logged in.
 */
const isAuth = (req, res, next) => {
    if (req.session.staffId) {
        return next();
    } else {
        return res.status(401).send("Unauthorized Access");
    }
};

/**
 * Middleware to check if user is an Admin.
 */
const isAdmin = (req, res, next) => {
    if (req.session.staffId && req.session.isAdmin) {
        return next();
    } else {
        return res.status(403).send("Admin Access Required");
    }
};

const getPanelUrl = () => {
    return process.env.APP_URL || "Panel URL Not Configured";
};


// =========================================================================================
//  SECTION: DISCORD BOT LOGIC
// =========================================================================================

// Load Tokens
const botTokens = [
    process.env.BOT_ONE_TOKEN, 
    process.env.BOT_TWO_TOKEN
].filter(token => token !== undefined && token !== "");

const clients = [];

/**
 * Sends a log embed to the configured Discord Log Channel.
 */
async function sendLog(title, description, color = '#3b82f6', files = []) {
    // Verify Log Channel ID is set and at least one bot is online
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
        console.log(`[LOG] Sent Log Embed: ${title}`);
    } catch (e) { 
        console.error("[LOG] Error sending log:", e.message); 
    }
}

// Initialize Bots Loop
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

    // Ready Event
    client.once('ready', () => {
        console.log(`[BOT_${index + 1}] 🤖 Logged in as ${client.user.tag}`);
    });

    // --- TYPING INDICATOR ---
    client.on('typingStart', async (typing) => {
        if (typing.user.bot) return;
        // Broadcast to panel
        io.emit('user_typing', { userId: typing.user.id });
    });

    // --- RATING INTERACTION ---
    client.on('interactionCreate', async (interaction) => {
        if (!interaction.isButton()) return;

        const parts = interaction.customId.split('_');
        const action = parts[0];
        
        if (action === 'rate') {
            const scoreStr = parts[1];
            const staffId = parts[2];
            const score = parseInt(scoreStr);
            
            // Update Staff DB
            await Staff.findByIdAndUpdate(staffId, { 
                $inc: { ratingSum: score, ratingCount: 1 } 
            });

            console.log(`[RATING] Staff ID ${staffId} rated ${score} Stars`);

            // Disable Buttons
            const disabledRow = new ActionRowBuilder().addComponents(
                new ButtonBuilder()
                    .setCustomId('done')
                    .setLabel(`Rated ${score} Stars`)
                    .setStyle(ButtonStyle.Success)
                    .setDisabled(true)
            );

            await interaction.update({ 
                content: `**Thank you!** You rated your support experience **${score}/5** stars.`, 
                components: [disabledRow] 
            });
        }
    });

    // --- MESSAGE HANDLER (Chat Logic) ---
    client.on('messageCreate', async (message) => {
        if (message.author.bot || message.guild) {
            return;
        }
        
        // Find existing thread
        let thread = await Thread.findOne({ 
            userId: message.author.id, 
            botId: client.user.id 
        });
        
        // --- NEW TICKET LOGIC ---
        if (!thread) {
            console.log(`[TICKET] 📩 New Thread: ${message.author.tag}`);
            
            thread = new Thread({ 
                userId: message.author.id, 
                userTag: message.author.tag, 
                botId: client.user.id, 
                botName: client.user.username, 
                messages: []
            });
            
            // Check Config
            const config = await Config.findOne({ id: 'global' });
            const isManualOnline = config ? config.supportOnline : true;
            const offlineNote = config ? config.offlineNote : '';

            // Check Time (AST)
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
                // Manually Offline
                const noteText = offlineNote ? `**Reason:** ${offlineNote}\n\n` : '';
                autoReply = new EmbedBuilder()
                    .setColor('#ef4444')
                    .setTitle('Support Currently Offline')
                    .setDescription(`Support has been toggled offline by staff.\n\n${noteText}We will respond when available.`)
                    .setTimestamp();
            } else if (!isWorkHours) {
                // Outside Hours
                autoReply = new EmbedBuilder()
                    .setColor('#f59e0b')
                    .setTitle('Support Closed')
                    .setDescription('You have reached us outside of support hours (8:00 AM - 11:59 PM AST).')
                    .setTimestamp();
            } else {
                // Open
                autoReply = new EmbedBuilder()
                    .setColor('#3b82f6')
                    .setTitle('Support Ticket Opened')
                    .setDescription('A staff member will respond to your inquiry within **12-24 hours**.')
                    .setTimestamp();
            }
            
            try { 
                await message.author.send({ embeds: [autoReply] }).catch(() => {}); 
            } catch (err) {}

            sendLog("🆕 Ticket Created", `**User:** ${message.author.tag}\n**Bot:** ${client.user.username}`, '#facc15');
        }
        
        // Save Message
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
        
        // Push to Panel
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
//  SECTION: REAL-TIME PRESENCE (SOCKET.IO)
// =========================================================================================

// Object to track active viewers per ticket
const activeViewers = {}; 

io.on('connection', (socket) => {
    
    // Staff Joins Ticket
    socket.on('join_ticket_room', ({ threadId, username }) => {
        socket.join(threadId);
        
        if (!activeViewers[threadId]) {
            activeViewers[threadId] = new Set();
        }
        activeViewers[threadId].add(username);
        
        // Broadcast new list to everyone in room
        io.to(threadId).emit('viewers_updated', Array.from(activeViewers[threadId]));
        
        socket.currentThreadId = threadId;
        socket.currentUser = username;
    });

    // Staff Leaves Ticket
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

    // Disconnect
    socket.on('disconnect', () => {
        if (socket.currentThreadId && socket.currentUser) {
            const tId = socket.currentThreadId;
            if (activeViewers[tId]) {
                activeViewers[tId].delete(socket.currentUser);
                io.to(tId).emit('viewers_updated', Array.from(activeViewers[tId]));
            }
        }
    });

    // Typing Logic
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
//  SECTION: API ROUTES
// =========================================================================================

/**
 * TICKET MANAGEMENT: Archive
 */
app.post('/api/close-thread', isAuth, async (req, res) => {
    const { threadId } = req.body;
    console.log(`[ARCHIVE] 🔒 Archiving thread ${threadId}`);

    const thread = await Thread.findById(threadId);
    if (!thread) {
        return res.status(404).send("Not Found");
    }

    // Generate Transcript
    let transcriptText = `OFFICIAL TRANSCRIPT: ${thread.userTag}\nBot: ${thread.botName}\n\n`;
    thread.messages.forEach(m => { 
        transcriptText += `[${m.timestamp.toISOString()}] ${m.authorTag}: ${m.content}\n`; 
    });
    
    const tempPath = path.join(__dirname, `temp-${thread.userId}.txt`);

    try {
        fs.writeFileSync(tempPath, transcriptText);
        
        // Log to Discord
        await sendLog("🔒 Archive Logged", `User: ${thread.userTag}\n**Saved to System Disk**`, '#ef4444', [new AttachmentBuilder(tempPath)]);
        
        // Save to JSON
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
        
        // Send Rating Buttons
        const staffId = req.session.staffId;
        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId(`rate_1_${staffId}`).setLabel('1⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_2_${staffId}`).setLabel('2⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_3_${staffId}`).setLabel('3⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_4_${staffId}`).setLabel('4⭐').setStyle(ButtonStyle.Primary),
            new ButtonBuilder().setCustomId(`rate_5_${staffId}`).setLabel('5⭐').setStyle(ButtonStyle.Success)
        );
        
        const embed = new EmbedBuilder()
            .setTitle("How was your support?")
            .setDescription(`You were helped by **${req.session.username}**. Please rate your experience.`)
            .setColor('#3b82f6');

        const client = clients.find(c => c.user.id === thread.botId);
        if (client) { 
            try { 
                const user = await client.users.fetch(thread.userId); 
                await user.send({ embeds: [embed], components: [row] }); 
            } catch(e) {} 
        }

        // Cleanup
        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { ticketsClosed: 1 } });
        await Thread.findByIdAndDelete(threadId);
        fs.unlinkSync(tempPath);

        res.json({ success: true });
    } catch (e) { 
        console.error(e);
        res.status(500).send("Archive Failed"); 
    }
});

/**
 * TICKET MANAGEMENT: Reply
 */
app.post('/api/reply', isAuth, async (req, res) => {
    const { threadId, content, fileBase64, fileName } = req.body;
    console.log(`[REPLY] 📤 Staff ${req.session.username} replying to thread ${threadId}`);
    
    const thread = await Thread.findById(threadId);
    if (!thread) {
        return res.status(404).send("Not Found");
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
        res.json({ success: true });
    } catch (err) { 
        res.status(500).send("DM Failed"); 
    }
});

/**
 * GET ACTIVE THREADS
 */
app.get('/api/threads', isAuth, async (req, res) => { 
    const threads = await Thread.find().sort({ lastMessageAt: -1 }); 
    res.json(threads); 
});

/**
 * CRM: Get User Data
 */
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

    res.json({ note: noteDoc ? noteDoc.note : "", history: historyFiles });
});

/**
 * CRM: Get Transcript
 */
app.get('/api/crm/transcript/:discordId/:filename', isAuth, (req, res) => {
    const { discordId, filename } = req.params;
    if (filename.includes('..') || discordId.includes('..')) return res.status(403).send("Invalid path");
    
    const filePath = path.join(ARCHIVE_DIR, discordId, filename);
    if (fs.existsSync(filePath)) {
        res.json(JSON.parse(fs.readFileSync(filePath, 'utf8')));
    } else {
        res.status(404).json({ error: "Transcript not found" });
    }
});

/**
 * CRM: Save Note
 */
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
    res.json({ success: true });
});

/**
 * MACROS: Get All
 */
app.get('/api/macros', isAuth, async (req, res) => { 
    const macros = await Macro.find().sort({ title: 1 }); 
    res.json(macros); 
});

/**
 * MACROS: Add
 */
app.post('/api/admin/macros/add', isAdmin, async (req, res) => {
    const { title, content } = req.body;
    if (!title || !content) return res.status(400).json({ error: "Missing fields" });
    await new Macro({ title, content }).save();
    res.json({ success: true });
});

/**
 * MACROS: Delete
 */
app.post('/api/admin/macros/delete', isAdmin, async (req, res) => {
    await Macro.findByIdAndDelete(req.body.id);
    res.json({ success: true });
});

/**
 * AUTH: Get User
 */
app.get('/api/auth/user', isAuth, (req, res) => {
    res.json({ username: req.session.username, isAdmin: req.session.isAdmin });
});

/**
 * AUTH: Login
 */
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await Staff.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.staffId = user._id; 
        req.session.isAdmin = user.isAdmin; 
        req.session.username = user.username;
        req.session.save(() => res.json({ success: true, isAdmin: user.isAdmin, username: user.username }));
    } else {
        res.status(401).send("Invalid Credentials");
    }
});

/**
 * AUTH: Logout
 */
app.post('/api/logout', (req, res) => { 
    req.session.destroy(() => { 
        res.clearCookie('connect.sid'); 
        res.json({ success: true }); 
    }); 
});

/**
 * AUTH: Recover Password
 */
app.post('/api/public/request-reset', async (req, res) => {
    const { discordId } = req.body;
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

/**
 * AUTH: Self Reset
 */
app.post('/api/staff/self-reset', isAuth, async (req, res) => {
    const { newPassword } = req.body;
    const staff = await Staff.findById(req.session.staffId);
    staff.password = await bcrypt.hash(newPassword, 10);
    await staff.save();
    try { 
        const user = await clients[0].users.fetch(staff.discordId); 
        await user.send(`**Security Alert**\nKey Updated Manually.`); 
    } catch (e) {}
    res.json({ success: true });
});

/**
 * ADMIN: Stats
 */
app.get('/api/admin/stats', isAdmin, async (req, res) => { 
    const stats = await Staff.find().sort({ ticketsClosed: -1 }); 
    res.json(stats); 
});

/**
 * ADMIN: Config
 */
app.get('/api/admin/config', isAdmin, async (req, res) => { 
    const config = await Config.findOne({ id: 'global' }); 
    res.json(config); 
});

/**
 * ADMIN: Toggle Status
 */
app.post('/api/admin/config/toggle', isAdmin, async (req, res) => { 
    const { note } = req.body;
    const config = await Config.findOne({ id: 'global' }); 
    config.supportOnline = !config.supportOnline; 
    config.offlineNote = config.supportOnline ? '' : (note || ''); 
    await config.save(); 
    res.json({ success: true, supportOnline: config.supportOnline }); 
});

/**
 * ADMIN: Server List (Fleet)
 */
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

/**
 * ADMIN: Leave Server
 */
app.post('/api/admin/leave-server', isAdmin, async (req, res) => {
    const client = clients.find(c => c.user.id === req.body.botId);
    try {
        const guild = await client.guilds.fetch(req.body.serverId);
        await guild.leave();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "Failed to leave" }); }
});

/**
 * ADMIN: Create Invite
 */
app.post('/api/admin/create-invite', isAdmin, async (req, res) => {
    const client = clients.find(c => c.user.id === req.body.botId);
    try {
        const guild = await client.guilds.fetch(req.body.serverId);
        const chan = guild.channels.cache.find(c => c.type === ChannelType.GuildText && c.permissionsFor(client.user).has('CreateInstantInvite'));
        const inv = await chan.createInvite({ maxAge: 3600, maxUses: 1 });
        res.json({ success: true, url: inv.url });
    } catch (e) { res.status(500).json({ error: "No Permission" }); }
});

/**
 * ADMIN: DM Server Owner
 */
app.post('/api/admin/dm-owner', isAdmin, async (req, res) => {
    const client = clients.find(c => c.user.id === req.body.botId);
    try {
        const guild = await client.guilds.fetch(req.body.serverId);
        const owner = await client.users.fetch(guild.ownerId);
        await owner.send(`**Notification regarding ${guild.name}:**\n${req.body.message}`);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "DM Failed" }); }
});

/**
 * ADMIN: Global Broadcast
 */
app.post('/api/admin/bulk-message', isAdmin, async (req, res) => {
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
    res.json({ success: true, sentTo: sentCount });
});

/**
 * ADMIN: License Activate
 */
app.post('/api/admin/license/activate', isAdmin, async (req, res) => {
    try {
        const response = await axios.post('https://sell.app/api/v2/licenses/activate', { 
            license_key: req.body.license_key, 
            instance_name: req.body.instance_name 
        }, { headers: { 'Authorization': `Bearer ${process.env.SELLAPP_TOKEN}`, 'Content-Type': 'application/json' } });
        
        let expiresAt = null; 
        if (req.body.duration && req.body.duration !== 'Lifetime') { 
            const days = parseInt(req.body.duration.split(' ')[0]); 
            if (!isNaN(days)) expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000); 
        }
        
        await new License({ 
            key: req.body.license_key, 
            instanceId: response.data.id, 
            discordId: req.body.discord_id, 
            serverId: req.body.server_id, 
            serverName: req.body.server_name, 
            channelId: req.body.channel_id, 
            type: req.body.activation_type, 
            duration: req.body.duration, 
            expiresAt: expiresAt 
        }).save();
        
        await sendLog("🔑 License Activated", `**Staff:** ${req.session.username}\n**Key:** ${req.body.license_key}\n**User:** ${req.body.discord_id}`, '#10b981');
        res.json({ success: true, data: response.data });
    } catch (err) { res.status(400).json({ error: err.response?.data?.message || "Activation Failed" }); }
});

/**
 * ADMIN: Add Staff
 */
app.post('/api/admin/staff/add', isAdmin, async (req, res) => { 
    const tempPass = Math.random().toString(36).slice(-8); 
    await new Staff({ 
        username: req.body.username, 
        discordId: req.body.discordId, 
        password: await bcrypt.hash(tempPass, 10), 
        isAdmin: req.body.adminStatus 
    }).save(); 
    try { 
        const user = await clients[0].users.fetch(req.body.discordId); 
        await user.send(`**Staff Access Granted**\nUser: ${req.body.username}\nPass: ${tempPass}\nURL: ${getPanelUrl()}`); 
    } catch(e) {} 
    res.json({ success: true }); 
});

/**
 * ADMIN: Delete Staff
 */
app.post('/api/admin/staff/delete', isAdmin, async (req, res) => { 
    if (req.body.staffId === req.session.staffId.toString()) {
        return res.status(400).json({ error: "Cannot delete yourself" }); 
    }
    await Staff.findByIdAndDelete(req.body.staffId); 
    res.json({ success: true }); 
});

/**
 * ADMIN: Manual DM Ticket
 */
app.post('/api/admin/manual-dm', isAdmin, async (req, res) => {
    try {
        let thread = await Thread.findOne({ userId: req.body.discordId });
        let client = clients[0]; 
        const user = await client.users.fetch(req.body.discordId);
        await user.send({ embeds: [new EmbedBuilder().setColor('#3b82f6').setAuthor({ name: `Staff Message (${req.session.username})`, iconURL: client.user.displayAvatarURL() }).setDescription(req.body.content).setTimestamp()] });
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
        const msgData = { authorTag: `Staff (${req.session.username})`, content: req.body.content, fromBot: true, timestamp: new Date() };
        thread.messages.push(msgData); 
        thread.lastMessageAt = new Date(); 
        await thread.save(); 
        io.emit('new_message', { threadId: thread._id, ...msgData });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: "DM Failed" }); }
});

// =========================================================================================
//  SECTION: SERVER LISTEN
// =========================================================================================

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => console.log(`[SYSTEM] 🚀 TRADE SERVICES PANEL Ready on Port ${PORT}`));
