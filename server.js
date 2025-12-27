require('dotenv').config();

// ==========================================
// 1. IMPORTS & SETUP
// ==========================================
const axios = require('axios');
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

// ==========================================
// 2. DISK STORAGE CONFIGURATION
// ==========================================

// Determine correct storage path (Render vs Local)
const DATA_DIR = process.env.RENDER === 'true' ? '/var/data' : path.join(__dirname, 'local_storage');

// Create Data Directory if it does not exist
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    console.log(`[SYSTEM] Created Data Directory: ${DATA_DIR}`);
}

// Create Archive Directory if it does not exist
const ARCHIVE_DIR = path.join(DATA_DIR, 'archives');
if (!fs.existsSync(ARCHIVE_DIR)) {
    fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
    console.log(`[SYSTEM] Created Archive Directory: ${ARCHIVE_DIR}`);
}

console.log(`[SYSTEM] 📂 Storage Mounted at: ${DATA_DIR}`);

// ==========================================
// 3. DATABASE CONNECTION & MODELS
// ==========================================

mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log("[SYSTEM] ✅ MongoDB Connected");
        // Run the repair function immediately on startup
        performDatabaseRepair(); 
    })
    .catch(e => {
        console.error("[SYSTEM] ❌ DB Error:", e);
    });

// --- STAFF MODEL ---
const Staff = mongoose.model('Staff', new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    discordId: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    // Statistics
    ticketsClosed: { type: Number, default: 0 },
    repliesSent: { type: Number, default: 0 },
    ratingSum: { type: Number, default: 0 },
    ratingCount: { type: Number, default: 0 }
}));

// --- THREAD MODEL (TICKETS) ---
const Thread = mongoose.model('Thread', new mongoose.Schema({
    userId: String,
    userTag: String,
    botId: String,
    botName: String,
    // Claiming / Locking
    claimedBy: { type: String, default: null },
    claimedAt: { type: Date, default: null },
    // Messages Array
    messages: [{
        authorTag: String,
        content: String,
        attachments: [String],
        timestamp: { type: Date, default: Date.now },
        fromBot: { type: Boolean, default: false }
    }],
    lastMessageAt: { type: Date, default: Date.now }
}));

// --- LICENSE MODEL ---
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

// --- CONFIG MODEL ---
const Config = mongoose.model('Config', new mongoose.Schema({
    id: { type: String, default: 'global' },
    supportOnline: { type: Boolean, default: true },
    offlineNote: { type: String, default: '' }
}));

// --- USER NOTES (CRM) MODEL ---
const UserNote = mongoose.model('UserNote', new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    note: { type: String, default: "" },
    updatedBy: String,
    updatedAt: { type: Date, default: Date.now }
}));

// --- MACRO MODEL ---
const Macro = mongoose.model('Macro', new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true }
}));

// ==========================================
// 4. SYSTEM UTILITIES & REPAIR
// ==========================================

async function setupDefaults() {
    // 1. Create Default Admin if missing
    const adminExists = await Staff.findOne({ username: 'admin' });
    if (!adminExists) {
        const hashedPassword = await bcrypt.hash('map4491', 10);
        await new Staff({ 
            username: 'admin', 
            password: hashedPassword, 
            discordId: '000000000000000000', 
            isAdmin: true 
        }).save();
        console.log("[SYSTEM] ✅ Default Admin Created");
    }

    // 2. Create Default Config if missing
    const configExists = await Config.findOne({ id: 'global' });
    if (!configExists) {
        await new Config({ id: 'global', supportOnline: true }).save();
        console.log("[SYSTEM] ✅ Default Config Created");
    }
}
setupDefaults();

// Auto-Repair to fix legacy tickets missing the claimedBy field
async function performDatabaseRepair() {
    console.log("[SYSTEM] 🛠️  Running database integrity check...");
    try {
        const result = await Thread.updateMany(
            { claimedBy: { $exists: false } },
            { $set: { claimedBy: null, claimedAt: null } }
        );
        
        if (result.modifiedCount > 0) {
            console.log(`[SYSTEM] ✅ Repaired ${result.modifiedCount} legacy tickets.`);
        } else {
            console.log("[SYSTEM] ✅ Database is healthy (No legacy tickets found).");
        }
    } catch (e) {
        console.error("[SYSTEM] ❌ Database Repair Failed:", e);
    }
}

// ==========================================
// 5. MIDDLEWARE
// ==========================================

app.set('trust proxy', 1); 
app.use(express.json({ limit: '10mb' })); 
app.use(express.static('public'));

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

// Guard: Is User Logged In?
const isAuth = (req, res, next) => {
    if (req.session.staffId) {
        return next();
    } else {
        return res.status(401).send("Unauthorized");
    }
};

// Guard: Is User Admin?
const isAdmin = (req, res, next) => {
    if (req.session.staffId && req.session.isAdmin) {
        return next();
    } else {
        return res.status(403).send("Admin only");
    }
};

const getPanelUrl = () => {
    return process.env.APP_URL || "Panel URL Not Configured";
};

// ==========================================
// 6. DISCORD BOT HANDLERS
// ==========================================

const botTokens = [
    process.env.BOT_ONE_TOKEN, 
    process.env.BOT_TWO_TOKEN
].filter(t => t);

const clients = [];

// Helper function to send logs to the Discord Log Channel
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
        console.log(`[LOG] Log sent: ${title}`);
    } catch (e) { 
        console.error("[LOG] Error sending log:", e.message); 
    }
}

// Loop through tokens and start bots
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
        console.log(`[BOT_${index + 1}] 🤖 Logged in as ${client.user.tag}`);
    });

    // --- A. USER TYPING EVENT ---
    client.on('typingStart', async (typing) => {
        if (typing.user.bot) return;
        // Broadcast to web panel
        io.emit('user_typing', { userId: typing.user.id });
    });

    // --- B. INTERACTION EVENT (RATINGS) ---
    client.on('interactionCreate', async (interaction) => {
        if (!interaction.isButton()) return;

        // ID Format: action_score_staffId
        const parts = interaction.customId.split('_');
        const action = parts[0];
        const scoreStr = parts[1];
        const staffId = parts[2];

        if (action === 'rate') {
            const score = parseInt(scoreStr);
            
            // Increment Staff Stats in DB
            await Staff.findByIdAndUpdate(staffId, { 
                $inc: { ratingSum: score, ratingCount: 1 } 
            });

            console.log(`[RATING] User rated Staff ${staffId}: ${score} Stars`);

            // Create disabled buttons to prevent voting twice
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

    // --- C. MESSAGE EVENT (NEW TICKET & REPLIES) ---
    client.on('messageCreate', async (message) => {
        if (message.author.bot || message.guild) {
            return;
        }
        
        // Find existing thread
        let thread = await Thread.findOne({ 
            userId: message.author.id, 
            botId: client.user.id 
        });
        
        // IF NEW TICKET
        if (!thread) {
            console.log(`[TICKET] 📩 New Thread Started: ${message.author.tag}`);
            
            // Create Database Entry
            thread = new Thread({ 
                userId: message.author.id, 
                userTag: message.author.tag, 
                botId: client.user.id, 
                botName: client.user.username, 
                messages: [],
                claimedBy: null, // Default to null (Important for UI)
                claimedAt: null
            });
            
            // Load Config
            const config = await Config.findOne({ id: 'global' });
            const isManualOnline = config ? config.supportOnline : true;
            const offlineNote = config ? config.offlineNote : '';

            // Calculate AST Time
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

            // Determine Auto-Reply Content
            if (!isManualOnline) {
                const noteText = offlineNote ? `**Reason:** ${offlineNote}\n\n` : '';
                autoReply = new EmbedBuilder()
                    .setColor('#ef4444')
                    .setTitle('Support Currently Offline')
                    .setDescription(`Support has been toggled offline by staff.\n\n${noteText}We will respond when available.`)
                    .setTimestamp();
            } else if (!isWorkHours) {
                autoReply = new EmbedBuilder()
                    .setColor('#f59e0b')
                    .setTitle('Support Closed')
                    .setDescription('You have reached us outside of support hours (8:00 AM - 11:59 PM AST).')
                    .setTimestamp();
            } else {
                autoReply = new EmbedBuilder()
                    .setColor('#3b82f6')
                    .setTitle('Support Ticket Opened')
                    .setDescription('A staff member will respond to your inquiry within **12-24 hours**.')
                    .setTimestamp();
            }
            
            // Send Auto-Reply
            try { 
                await message.author.send({ embeds: [autoReply] }).catch(() => {}); 
            } catch (err) {
                // Ignore DM errors (user might have DMs off)
            }

            // Log Creation
            await sendLog("🆕 Ticket Created", `**User:** ${message.author.tag}\n**Bot:** ${client.user.username}`, '#facc15');
        }
        
        console.log(`[MSG] 📥 From ${message.author.tag}: ${message.content.substring(0, 30)}...`);

        const attachments = message.attachments.map(a => a.url);
        
        const msgData = { 
            authorTag: message.author.tag, 
            content: message.content || (attachments.length > 0 ? "[Sent Attachment]" : "[Media]"), 
            attachments: attachments, 
            fromBot: false, 
            timestamp: new Date() 
        };

        // Update DB
        thread.messages.push(msgData);
        thread.lastMessageAt = new Date();
        await thread.save();
        
        // Push to Web Panel via Socket.io
        io.emit('new_message', { 
            threadId: thread._id, 
            notif_sound: true, 
            ...msgData 
        });
    });

    client.login(token).catch(e => console.error(`[BOT] ❌ Login Failed Bot ${index + 1}`));
    clients.push(client);
});

// ==========================================
// 7. SOCKET.IO (REAL-TIME EVENTS)
// ==========================================

io.on('connection', (socket) => {
    // Event: Staff is typing in the panel
    socket.on('staff_typing', async (data) => {
        const { threadId } = data;
        const thread = await Thread.findById(threadId);
        if (!thread) return;
        
        const client = clients.find(c => c.user.id === thread.botId);
        if (client) {
            try {
                const user = await client.users.fetch(thread.userId);
                // Trigger Discord's "Bot is typing..." indicator
                const dmChannel = user.dmChannel || await user.createDM();
                await dmChannel.sendTyping();
            } catch(e) {
                // Ignore errors if user blocked bot
            }
        }
    });
});

// ==========================================
// 8. API ROUTES: TICKET MANAGEMENT
// ==========================================

// Route: Archive (Close) Ticket
app.post('/api/close-thread', isAuth, async (req, res) => {
    const { threadId } = req.body;
    console.log(`[ARCHIVE] 🔒 Archiving thread ${threadId} by ${req.session.username}`);

    const thread = await Thread.findById(threadId);
    if (!thread) {
        return res.status(404).send("Not Found");
    }

    // 1. Generate Transcript Text
    let transcriptText = `OFFICIAL TRANSCRIPT: ${thread.userTag}\nBot: ${thread.botName}\n\n`;
    thread.messages.forEach(m => { 
        transcriptText += `[${m.timestamp.toISOString()}] ${m.authorTag}: ${m.content}\n`; 
    });
    
    const tempPath = path.join(__dirname, `temp-${thread.userId}.txt`);

    try {
        fs.writeFileSync(tempPath, transcriptText);
        
        // 2. Send Transcript to Discord Log Channel
        await sendLog("🔒 Archive Logged", `User: ${thread.userTag}\n**Saved to System Disk**`, '#ef4444', [new AttachmentBuilder(tempPath)]);
        
        // 3. Save Full JSON to Persistent Disk (For CRM)
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
        console.log(`[ARCHIVE] ✅ Saved to disk: ${filePath}`);
        
        // 4. Send 5-Star Rating Buttons to User
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
            } catch(e) {
                console.error("Failed to send rating request to user");
            } 
        }

        // 5. Cleanup Database
        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { ticketsClosed: 1 } });
        await Thread.findByIdAndDelete(threadId);
        fs.unlinkSync(tempPath); // Remove temp file

        res.json({ success: true });
    } catch (e) { 
        console.error(e);
        res.status(500).send("Archive Failed"); 
    }
});

// Route: Claim Ticket
app.post('/api/claim', isAuth, async (req, res) => {
    const { threadId } = req.body;
    console.log(`[CLAIM] Attempt by ${req.session.username} on ${threadId}`);
    
    const thread = await Thread.findById(threadId);
    if (!thread) {
        return res.status(404).send("Not Found");
    }

    // Check if already locked by someone else
    if (thread.claimedBy && thread.claimedBy !== req.session.username && !req.session.isAdmin) {
        return res.status(403).json({ error: `Locked by ${thread.claimedBy}` });
    }

    thread.claimedBy = req.session.username;
    thread.claimedAt = new Date();
    await thread.save();
    
    // Broadcast update
    io.emit('thread_update', { threadId, claimedBy: thread.claimedBy });
    res.json({ success: true, claimedBy: thread.claimedBy });
});

// Route: Unclaim Ticket
app.post('/api/unclaim', isAuth, async (req, res) => {
    const { threadId } = req.body;
    const thread = await Thread.findById(threadId);
    
    if (!thread) return res.status(404).send("Not Found");

    // Only allow unclaim if user owns it or is admin
    if (thread.claimedBy && thread.claimedBy !== req.session.username && !req.session.isAdmin) {
        return res.status(403).json({ error: "Permission Denied" });
    }

    thread.claimedBy = null;
    thread.claimedAt = null;
    await thread.save();

    io.emit('thread_update', { threadId, claimedBy: null });
    res.json({ success: true });
});

// Route: Reply to User
app.post('/api/reply', isAuth, async (req, res) => {
    const { threadId, content, fileBase64, fileName } = req.body;
    console.log(`[REPLY] 📤 Staff ${req.session.username} replying to thread ${threadId}`);
    
    const thread = await Thread.findById(threadId);
    if (!thread) return res.status(404).send("Not Found");
    
    const client = clients.find(c => c.user.id === thread.botId);
    try {
        const user = await client.users.fetch(thread.userId);
        
        let messageOptions = { 
            embeds: [new EmbedBuilder().setColor('#3b82f6').setAuthor({ name: `Support: ${req.session.username}`, iconURL: client.user.displayAvatarURL() }).setDescription(content || "Sent an attachment").setTimestamp()] 
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
        console.error("[REPLY] Failed:", err);
        res.status(500).send("DM Failed"); 
    }
});

// Route: Fetch All Active Threads
app.get('/api/threads', isAuth, async (req, res) => { 
    const threads = await Thread.find().sort({ lastMessageAt: -1 }); 
    res.json(threads); 
});

// ==========================================
// 9. API ROUTES: CRM & HISTORY
// ==========================================

// Get User History (Reads from Disk)
app.get('/api/crm/user/:discordId', isAuth, async (req, res) => {
    const { discordId } = req.params;
    console.log(`[CRM] 🔍 Fetching history for ${discordId}`);
    
    // 1. Get Sticky Note from DB
    const noteDoc = await UserNote.findOne({ userId: discordId });
    
    // 2. Get JSON Files from Disk
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

// Read Specific Transcript (Reads from Disk)
app.get('/api/crm/transcript/:discordId/:filename', isAuth, (req, res) => {
    const { discordId, filename } = req.params;
    
    // Security Check
    if (filename.includes('..') || discordId.includes('..')) {
        return res.status(403).send("Invalid path");
    }
    
    const filePath = path.join(ARCHIVE_DIR, discordId, filename);
    if (fs.existsSync(filePath)) {
        res.json(JSON.parse(fs.readFileSync(filePath, 'utf8')));
    } else {
        res.status(404).json({ error: "Transcript not found" });
    }
});

// Save Sticky Note (Writes to DB)
app.post('/api/crm/note', isAuth, async (req, res) => {
    console.log(`[CRM] 📝 Note updated for ${req.body.userId} by ${req.session.username}`);
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

// ==========================================
// 10. API ROUTES: MACROS
// ==========================================

app.get('/api/macros', isAuth, async (req, res) => { 
    const macros = await Macro.find().sort({ title: 1 }); 
    res.json(macros); 
});

app.post('/api/admin/macros/add', isAdmin, async (req, res) => {
    const { title, content } = req.body;
    if (!title || !content) return res.status(400).json({ error: "Missing fields" });
    
    await new Macro({ title, content }).save();
    res.json({ success: true });
});

app.post('/api/admin/macros/delete', isAdmin, async (req, res) => {
    await Macro.findByIdAndDelete(req.body.id);
    res.json({ success: true });
});

// ==========================================
// 11. API ROUTES: AUTHENTICATION
// ==========================================

// Get Current User
app.get('/api/auth/user', isAuth, (req, res) => {
    res.json({ 
        username: req.session.username, 
        isAdmin: req.session.isAdmin 
    });
});

// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    console.log(`[AUTH] 🔐 Login attempt: ${username}`);
    
    const user = await Staff.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.staffId = user._id; 
        req.session.isAdmin = user.isAdmin; 
        req.session.username = user.username;
        req.session.save(() => {
            res.json({ success: true, isAdmin: user.isAdmin, username: user.username });
        });
    } else {
        res.status(401).send("Invalid Credentials");
    }
});

// Logout
app.post('/api/logout', (req, res) => { 
    console.log(`[AUTH] 🔓 Logout: ${req.session.username}`);
    req.session.destroy(() => { 
        res.clearCookie('connect.sid'); 
        res.json({ success: true }); 
    }); 
});

// Request Password Reset (Sends Discord DM)
app.post('/api/public/request-reset', async (req, res) => {
    const { discordId } = req.body;
    console.log(`[AUTH] 🆘 Recovery requested: ${discordId}`);
    
    const staff = await Staff.findOne({ discordId });
    if (!staff) {
        return res.status(404).json({ error: "No staff found with this ID" });
    }
    
    const newPass = Math.random().toString(36).slice(-8);
    staff.password = await bcrypt.hash(newPass, 10);
    await staff.save();
    
    try {
        const user = await clients[0].users.fetch(discordId);
        await user.send(`**Terminal Recovery**\n**New Key:** ${newPass}\n**URL:** ${getPanelUrl()}`);
        res.json({ success: true });
    } catch (e) { 
        res.status(500).json({ error: "DM Failed - Check Bot Permissions" }); 
    }
});

// Self Reset Password
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

// ==========================================
// 12. API ROUTES: ADMIN & MANAGEMENT
// ==========================================

// Get Stats
app.get('/api/admin/stats', isAdmin, async (req, res) => { 
    const stats = await Staff.find().sort({ ticketsClosed: -1 }); 
    res.json(stats); 
});

// Get Config
app.get('/api/admin/config', isAdmin, async (req, res) => { 
    const config = await Config.findOne({ id: 'global' }); 
    res.json(config); 
});

// Toggle Support Status
app.post('/api/admin/config/toggle', isAdmin, async (req, res) => { 
    const { note } = req.body;
    console.log(`[ADMIN] ⚙️ Toggle support. Note: ${note}`);
    
    const config = await Config.findOne({ id: 'global' }); 
    config.supportOnline = !config.supportOnline; 
    config.offlineNote = config.supportOnline ? '' : (note || ''); 
    
    await config.save(); 
    res.json({ success: true, supportOnline: config.supportOnline }); 
});

// Bot Fleet: Get Servers
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

// Bot Fleet: Leave Server
app.post('/api/admin/leave-server', isAdmin, async (req, res) => {
    const client = clients.find(c => c.user.id === req.body.botId);
    try {
        const guild = await client.guilds.fetch(req.body.serverId);
        await guild.leave();
        console.log(`[ADMIN] Bot left server: ${guild.name}`);
        res.json({ success: true });
    } catch (e) { 
        res.status(500).json({ error: "Failed to leave" }); 
    }
});

// Bot Fleet: Create Invite
app.post('/api/admin/create-invite', isAdmin, async (req, res) => {
    const client = clients.find(c => c.user.id === req.body.botId);
    try {
        const guild = await client.guilds.fetch(req.body.serverId);
        const chan = guild.channels.cache.find(c => 
            c.type === ChannelType.GuildText && 
            c.permissionsFor(client.user).has('CreateInstantInvite')
        );
        const inv = await chan.createInvite({ maxAge: 3600, maxUses: 1 });
        res.json({ success: true, url: inv.url });
    } catch (e) { 
        res.status(500).json({ error: "No Permission to Invite" }); 
    }
});

// Bot Fleet: DM Owner
app.post('/api/admin/dm-owner', isAdmin, async (req, res) => {
    const client = clients.find(c => c.user.id === req.body.botId);
    try {
        const guild = await client.guilds.fetch(req.body.serverId);
        const owner = await client.users.fetch(guild.ownerId);
        await owner.send(`**Notification regarding ${guild.name}:**\n${req.body.message}`);
        console.log(`[ADMIN] Sent DM to owner of ${guild.name}`);
        res.json({ success: true });
    } catch (e) { 
        res.status(500).json({ error: "DM Failed" }); 
    }
});

// Bot Fleet: Global Broadcast
app.post('/api/admin/bulk-message', isAdmin, async (req, res) => {
    console.log(`[ADMIN] Starting global broadcast...`);
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
    
    console.log(`[ADMIN] Broadcast sent to ${sentCount} owners.`);
    res.json({ success: true, sentTo: sentCount });
});

// License Activation
app.post('/api/admin/license/activate', isAdmin, async (req, res) => {
    console.log(`[LICENSE] 🔑 Activation attempt for ${req.body.discord_id}`);
    try {
        const response = await axios.post('https://sell.app/api/v2/licenses/activate', { 
            license_key: req.body.license_key, 
            instance_name: req.body.instance_name 
        }, { 
            headers: { 
                'Authorization': `Bearer ${process.env.SELLAPP_TOKEN}`, 
                'Content-Type': 'application/json' 
            } 
        });
        
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
        
        console.log(`[LICENSE] ✅ Success: ${req.body.license_key}`);
        res.json({ success: true, data: response.data });
    } catch (err) { 
        console.error(err);
        res.status(400).json({ error: err.response?.data?.message || "Activation Failed" }); 
    }
});

// Staff Management: Add
app.post('/api/admin/staff/add', isAdmin, async (req, res) => { 
    console.log(`[ADMIN] 👤 Adding staff: ${req.body.username}`);
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
    
    res.json({ success: true }); 
});

// Staff Management: Delete
app.post('/api/admin/staff/delete', isAdmin, async (req, res) => { 
    console.log(`[ADMIN] 🗑️ Deleting staff ID: ${req.body.staffId}`);
    
    if (req.body.staffId === req.session.staffId.toString()) {
        return res.status(400).json({ error: "Cannot delete yourself" }); 
    }
    
    await Staff.findByIdAndDelete(req.body.staffId); 
    res.json({ success: true }); 
});

// Manual DM (Open Ticket)
app.post('/api/admin/manual-dm', isAdmin, async (req, res) => {
    console.log(`[ADMIN] 📨 Manual DM to ${req.body.discordId}`);
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
        
        res.json({ success: true });
    } catch (e) { 
        res.status(500).json({ error: "DM Failed" }); 
    }
});

// ==========================================
// 13. START SERVER
// ==========================================

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => console.log(`[SYSTEM] 🚀 HQ Terminal Ready on Port ${PORT}`));
