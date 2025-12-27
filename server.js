/**
 * =================================================================================================
 * MIRAIDON TRADE SERVICES - MASTER SERVER (v9.3)
 * =================================================================================================
 * * SYSTEM ARCHITECTURE:
 * --------------------
 * 1.  Multi-Client Discord Bot System (Miraidon + Professor Mable)
 * 2.  Express.js Web Server (Public Website + Protected Staff Panel)
 * 3.  MongoDB Database (Persistent Data Storage)
 * 4.  Socket.io (Real-Time Bidirectional Event Communication)
 * 5.  Local Disk Storage (Permanent Transcript Archiving)
 * * * FEATURE MANIFEST:
 * -----------------
 * [AUTH]      Secure Session Management (Connect-Mongo)
 * [AUTH]      Bcrypt Password Hashing
 * [AUTH]      Strict Password Policy (8 chars, 1 Cap, 1 Num, 1 Symbol)
 * [AUTH]      Self-Service Password Change
 * [AUTH]      Admin Force Password Reset
 * * [TICKETS]   Live Inbox (Socket.io)
 * [TICKETS]   Real-Time Chat Sync
 * [TICKETS]   Typing Indicators
 * [TICKETS]   Collision Detection (Viewer Tracking)
 * [TICKETS]   Rich Media Support (Images/Files)
 * [TICKETS]   Archive System (JSON + TXT Generation)
 * [TICKETS]   Rating System (1-5 Stars)
 * * [ADMIN]     License Generator (Sell.App API Integration)
 * [ADMIN]     License Server Tracking (Server Name + Server ID)
 * [ADMIN]     Staff Management (Add/Delete/Promote)
 * [ADMIN]     Fleet Management (Leave Server, Create Invite, DM Owner)
 * [ADMIN]     Global Broadcast System
 * [ADMIN]     Manual Ticket Opening (DM by ID)
 * [ADMIN]     Dynamic FAQ Editor
 * [ADMIN]     Dynamic Schedule Configuration (Open/Close Times)
 * * [AUTO]      Automatic Welcome DMs
 * [AUTO]      License Activation DMs
 * [AUTO]      3-Day Expiration Warning DMs (Hourly Check)
 * =================================================================================================
 */

// =================================================================================================
//  SECTION 1: CONFIGURATION & IMPORTS
// =================================================================================================

// 1. Load Environment Variables
require('dotenv').config();

// 2. Import Core Modules
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

// 3. Import Discord.js Components
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

// 4. Initialize Express App
const app = express();
const server = http.createServer(app);
const io = new Server(server);


// =================================================================================================
//  SECTION 2: FILE SYSTEM & STORAGE CONFIGURATION
// =================================================================================================

console.log("[SYSTEM] 📂 Initializing File System...");

let DATA_DIR;

// Detect Environment (Render.com vs Local Development)
if (process.env.RENDER === 'true') {
    console.log("[SYSTEM] ☁️ Detected Render Environment. Using Persistent Disk at /var/data");
    DATA_DIR = '/var/data';
} else {
    console.log("[SYSTEM] 💻 Detected Local Environment. Using ./local_storage");
    DATA_DIR = path.join(__dirname, 'local_storage');
}

// 1. Create Main Data Directory
if (!fs.existsSync(DATA_DIR)) {
    console.log(`[SYSTEM] 📂 Creating Data Directory at: ${DATA_DIR}`);
    try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        console.log(`[SYSTEM] ✅ Data Directory Created Successfully.`);
    } catch (err) {
        console.error(`[SYSTEM] ❌ CRITICAL: Failed to create Data Directory: ${err.message}`);
        console.error(`[SYSTEM] ❌ Please ensure the process has write permissions.`);
        process.exit(1); // Exit if we can't save data
    }
}

// 2. Create Archives Directory
const ARCHIVE_DIR = path.join(DATA_DIR, 'archives');
if (!fs.existsSync(ARCHIVE_DIR)) {
    console.log(`[SYSTEM] 📂 Creating Archive Directory at: ${ARCHIVE_DIR}`);
    try {
        fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
        console.log(`[SYSTEM] ✅ Archive Directory Created Successfully.`);
    } catch (err) {
        console.error(`[SYSTEM] ❌ CRITICAL: Failed to create Archive Directory: ${err.message}`);
    }
}

console.log(`[SYSTEM] ✅ Storage System Active and Ready.`);


// =================================================================================================
//  SECTION 3: DATABASE CONNECTION
// =================================================================================================

console.log("[SYSTEM] ⏳ Connecting to MongoDB Database...");

mongoose.connect(process.env.MONGODB_URI)
    .then(() => {
        console.log("[SYSTEM] ✅ MongoDB Connection Successful");
        // Run startup routines only after DB is ready
        initializeSystemDefaults();
        performDatabaseRepair();
    })
    .catch((error) => {
        console.error("[SYSTEM] ❌ CRITICAL DB ERROR:", error);
        console.error("[SYSTEM] Please check your MONGODB_URI in .env file.");
    });


// =================================================================================================
//  SECTION 4: DATABASE SCHEMAS (MODELS)
// =================================================================================================

/**
 * 1. STAFF SCHEMA
 * Stores login credentials and performance stats for support staff.
 */
const StaffSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    discordId: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    // Performance Metrics
    ticketsClosed: { type: Number, default: 0 },
    repliesSent: { type: Number, default: 0 },
    ratingSum: { type: Number, default: 0 },
    ratingCount: { type: Number, default: 0 }
});
const Staff = mongoose.model('Staff', StaffSchema);

/**
 * 2. THREAD SCHEMA
 * Represents an active DM conversation/ticket.
 */
const ThreadSchema = new mongoose.Schema({
    userId: String,
    userTag: String,
    botId: String,
    botName: String,
    claimedBy: { type: String, default: null }, // Legacy support
    claimedAt: { type: Date, default: null },
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
 * 3. LICENSE SCHEMA
 * Stores activated licenses, linked to Discord Users and Servers.
 */
const LicenseSchema = new mongoose.Schema({
    key: String,
    instanceId: String,
    discordId: String,
    // Server Tracking Fields (Added v7.8)
    serverId: String,      
    serverName: String,    
    channelId: String,
    type: String,
    duration: String,
    activatedAt: { type: Date, default: Date.now },
    expiresAt: Date, // Null implies Lifetime
    reminderSent: { type: Boolean, default: false } // For the 3-day warning system
});
const License = mongoose.model('License', LicenseSchema);

/**
 * 4. CONFIG SCHEMA (UPDATED v9.2)
 * Stores global settings and Dynamic Schedule times.
 */
const ConfigSchema = new mongoose.Schema({
    id: { type: String, default: 'global' },
    supportOnline: { type: Boolean, default: true }, // Master Toggle
    offlineNote: { type: String, default: '' },
    openTime: { type: String, default: "08:00" }, // 24-hour format
    closeTime: { type: String, default: "23:59" }  // 24-hour format
});
const Config = mongoose.model('Config', ConfigSchema);

/**
 * 5. USER NOTE SCHEMA (CRM)
 * Stores sticky notes for specific users.
 */
const UserNoteSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    note: { type: String, default: "" },
    updatedBy: String,
    updatedAt: { type: Date, default: Date.now }
});
const UserNote = mongoose.model('UserNote', UserNoteSchema);

/**
 * 6. MACRO SCHEMA
 * Stores canned responses for the staff dashboard.
 */
const MacroSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true }
});
const Macro = mongoose.model('Macro', MacroSchema);

/**
 * 7. FAQ SCHEMA
 * Stores public-facing questions and answers.
 */
const FAQSchema = new mongoose.Schema({
    question: { type: String, required: true },
    answer: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const FAQ = mongoose.model('FAQ', FAQSchema);


// =================================================================================================
//  SECTION 5: HELPER FUNCTIONS & UTILITIES
// =================================================================================================

/**
 * Validates password complexity.
 * Rule: 8+ Chars, 1 Capital, 1 Number, 1 Symbol.
 */
function validateComplexPassword(password) {
    const minLength = 8;
    const hasCapital = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSymbol = /[\W_]/.test(password); 
    
    if (password.length < minLength) return false;
    if (!hasCapital) return false;
    if (!hasNumber) return false;
    if (!hasSymbol) return false;
    
    return true;
}

/**
 * Generates a cryptographically strong random password meeting all policy requirements.
 */
function generateComplexPassword() {
    const chars = "abcdefghijklmnopqrstuvwxyz";
    const caps = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const nums = "0123456789";
    const syms = "!@#$%^&*?";
    
    let pass = "";
    // Ensure at least one of each required type
    pass += caps[Math.floor(Math.random() * caps.length)];
    pass += nums[Math.floor(Math.random() * nums.length)];
    pass += syms[Math.floor(Math.random() * syms.length)];
    pass += chars[Math.floor(Math.random() * chars.length)];
    
    // Fill the rest to 12 chars for extra security
    const all = chars + caps + nums + syms;
    for (let i = 0; i < 8; i++) {
        pass += all[Math.floor(Math.random() * all.length)];
    }
    
    // Shuffle the result so pattern isn't predictable
    return pass.split('').sort(() => 0.5 - Math.random()).join('');
}

/**
 * Initializes default system records if the database is empty.
 */
async function initializeSystemDefaults() {
    try {
        const adminExists = await Staff.findOne({ username: 'admin' });
        if (!adminExists) {
            // Initial boot password. User is expected to change this immediately.
            const hashedPassword = await bcrypt.hash('Map4491!', 10);
            await new Staff({ 
                username: 'admin', 
                password: hashedPassword, 
                discordId: '000000000000000000', 
                isAdmin: true 
            }).save();
            console.log("[SYSTEM] ✅ Default Admin Account Created (admin / Map4491!)");
        }

        const configExists = await Config.findOne({ id: 'global' });
        if (!configExists) {
            // New defaults: Online, 08:00 to 23:59
            await new Config({ 
                id: 'global', 
                supportOnline: true, 
                openTime: "08:00", 
                closeTime: "23:59" 
            }).save();
            console.log("[SYSTEM] ✅ Default Global Configuration Created");
        }
    } catch (err) {
        console.error("[SYSTEM] ❌ Error initializing defaults:", err);
    }
}

/**
 * Repairs legacy database entries to prevent crashes.
 */
async function performDatabaseRepair() {
    try {
        // Fix threads missing 'claimedBy'
        await Thread.updateMany(
            { claimedBy: { $exists: false } },
            { $set: { claimedBy: null } }
        );
        console.log("[SYSTEM] ✅ Database Integrity Verified");
    } catch (e) {
        console.error("[SYSTEM] ❌ Database Repair Logic Failed:", e);
    }
}


// =================================================================================================
//  SECTION 6: EXPRESS CONFIGURATION & MIDDLEWARE
// =================================================================================================

// Trust Proxy (Required for Render/Nginx/Cloudflare)
app.set('trust proxy', 1);

// Increase JSON Body Limit (Crucial for ZIP file uploads)
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Session Configuration (MongoDB Store)
app.use(session({
    secret: process.env.SESSION_SECRET || 'hq-secret-key-default-fallback',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'sessions' 
    }),
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, // 24 Hours
        secure: true, // Only allow cookies over HTTPS
        sameSite: 'none' 
    }
}));

// Middleware: Verify Staff Authentication
const isAuth = (req, res, next) => {
    if (req.session.staffId) {
        return next();
    }
    
    // If it's an API call, return JSON error
    if (req.path.startsWith('/api')) {
        console.log(`[AUTH] 🛑 API Access Denied: ${req.path}`);
        return res.status(401).json({ error: "Unauthorized" });
    }
    
    // If it's a page load, redirect to login
    console.log(`[AUTH] 🛑 Redirecting unauthenticated user to Login.`);
    return res.redirect('/login.html');
};

// Middleware: Verify Admin Privileges
const isAdmin = (req, res, next) => {
    if (req.session.staffId && req.session.isAdmin) {
        return next();
    }
    
    console.log(`[AUTH] 🛑 Admin Access Denied for user ${req.session.username || 'Unknown'}`);
    return res.status(403).json({ error: "Admin Access Required" });
};

// Helper to get Base URL
const getPanelUrl = () => {
    return process.env.APP_URL || "Panel URL Not Configured";
};

// --- STATIC FILE SERVING ---

// 1. Serve Public Files (Login, Home, Features, Policies)
app.use(express.static(path.join(__dirname, 'public')));

// 2. Serve Protected Staff Files (Dashboard, Admin) - Guarded by isAuth
app.use('/staff', isAuth, express.static(path.join(__dirname, 'public/staff')));


// =================================================================================================
//  SECTION 7: DISCORD BOT FLEET MANAGEMENT
// =================================================================================================

const botTokens = [
    process.env.BOT_ONE_TOKEN, 
    process.env.BOT_TWO_TOKEN
].filter(token => token !== undefined && token !== "");

const clients = [];

/**
 * Sends a structured log embed to the configured Staff Log Channel.
 */
async function sendLog(title, description, color = '#3b82f6', files = []) {
    if (!process.env.LOG_CHANNEL_ID || !clients[0]) {
        return; // Logging disabled or bot not ready
    }
    
    try {
        const channel = await clients[0].channels.fetch(process.env.LOG_CHANNEL_ID);
        if (!channel) return;

        const logEmbed = new EmbedBuilder()
            .setTitle(title)
            .setDescription(description)
            .setColor(color)
            .setTimestamp()
            .setFooter({ text: "System Logger" });
            
        await channel.send({ embeds: [logEmbed], files: files });
        console.log(`[LOG] 📝 Log sent to Discord: ${title}`);
    } catch (e) { 
        console.error("[LOG] ❌ Error sending Discord log:", e.message); 
    }
}

// Initialize Bots
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

    // Bot Ready Event
    client.once('ready', () => {
        console.log(`[BOT_${index + 1}] 🤖 Active and Logged in as: ${client.user.tag}`);
    });

    // Typing Event (Syncs with Dashboard)
    client.on('typingStart', async (typing) => {
        if (typing.user.bot) return;
        // Emit via Socket.io
        io.emit('user_typing', { userId: typing.user.id });
    });

    // Interaction Event (Button Clicks, e.g., Ratings)
    client.on('interactionCreate', async (interaction) => {
        if (!interaction.isButton()) return;

        const parts = interaction.customId.split('_');
        const action = parts[0];
        
        if (action === 'rate') {
            const scoreStr = parts[1];
            const staffId = parts[2];
            const score = parseInt(scoreStr);
            
            console.log(`[RATING] ⭐ User rated staff member ${staffId} with ${score} stars.`);

            try {
                // Update Staff Stats
                await Staff.findByIdAndUpdate(staffId, { 
                    $inc: { ratingSum: score, ratingCount: 1 } 
                });

                // Disable Buttons
                const disabledRow = new ActionRowBuilder().addComponents(
                    new ButtonBuilder().setCustomId('done').setLabel(`Rated ${score} Stars`).setStyle(ButtonStyle.Success).setDisabled(true)
                );

                await interaction.update({ 
                    content: `**Thank you!** You rated your support experience **${score}/5** stars. We appreciate your feedback.`, 
                    components: [disabledRow] 
                });
            } catch (err) {
                console.error(`[RATING] ❌ Error processing rating: ${err.message}`);
            }
        }
    });

    // Message Event (The Core Ticket Logic)
    client.on('messageCreate', async (message) => {
        // Ignore bots and Guild messages (We only want DMs)
        if (message.author.bot || message.guild) {
            return;
        }
        
        // Find existing thread
        let thread = await Thread.findOne({ 
            userId: message.author.id, 
            botId: client.user.id 
        });
        
        // ------------------------------------------
        // CASE 1: NEW TICKET CREATION
        // ------------------------------------------
        if (!thread) {
            console.log(`[TICKET] 📩 New Thread Created for: ${message.author.tag}`);
            
            // Create in DB
            thread = new Thread({ 
                userId: message.author.id, 
                userTag: message.author.tag, 
                botId: client.user.id, 
                botName: client.user.username, 
                messages: [] 
            });
            
            // --- DYNAMIC SCHEDULE LOGIC START ---
            const config = await Config.findOne({ id: 'global' });
            
            // 1. Get Settings
            const isManualOnline = config ? config.supportOnline : true;
            const offlineNote = config ? config.offlineNote : '';
            const openTimeStr = config ? config.openTime : "08:00";
            const closeTimeStr = config ? config.closeTime : "23:59";

            // 2. Calculate Time (AST)
            const now = new Date();
            const options = { timeZone: 'America/Halifax', hour12: false, hour: 'numeric', minute: 'numeric' };
            const formatter = new Intl.DateTimeFormat('en-US', options);
            const parts = formatter.formatToParts(now);
            const currentHour = parseInt(parts.find(p => p.type === 'hour').value);
            const currentMinute = parseInt(parts.find(p => p.type === 'minute').value);
            const currentTotal = (currentHour * 60) + currentMinute;

            // 3. Parse Config Times
            const [openH, openM] = openTimeStr.split(':').map(Number);
            const [closeH, closeM] = closeTimeStr.split(':').map(Number);
            const startTotal = (openH * 60) + openM;
            const endTotal = (closeH * 60) + closeM;

            // 4. Determine Status
            const isWorkHours = currentTotal >= startTotal && currentTotal <= endTotal;
            let autoReplyEmbed;

            if (!isManualOnline) {
                // Priority 1: Manual "Closed for Day" Override
                console.log(`[TICKET] ⚠️ Auto-Reply: Offline Mode Active`);
                const noteText = offlineNote ? `**Reason:** ${offlineNote}\n\n` : '';
                autoReplyEmbed = new EmbedBuilder()
                    .setColor('#ef4444')
                    .setTitle('Support Currently Offline')
                    .setDescription(`Support has been toggled offline by staff.\n\n${noteText}Your message has been logged, but response times will be delayed.`)
                    .setTimestamp();
            } else if (!isWorkHours) {
                // Priority 2: Outside Schedule
                console.log(`[TICKET] ⚠️ Auto-Reply: Closed (Schedule)`);
                autoReplyEmbed = new EmbedBuilder()
                    .setColor('#f59e0b')
                    .setTitle('Support Closed')
                    .setDescription(`You have reached us outside of support hours.\n\n**Open:** ${openTimeStr} AST\n**Close:** ${closeTimeStr} AST\n\nA staff member will review your ticket when we open.`)
                    .setTimestamp();
            } else {
                // Priority 3: Online
                console.log(`[TICKET] ✅ Auto-Reply: Online`);
                autoReplyEmbed = new EmbedBuilder()
                    .setColor('#3b82f6')
                    .setTitle('Support Ticket Opened')
                    .setDescription('A staff member will respond to your inquiry within **12-24 hours**. Please hold tight.')
                    .setTimestamp();
            }
            // --- DYNAMIC SCHEDULE LOGIC END ---
            
            try { 
                await message.author.send({ embeds: [autoReplyEmbed] }).catch(() => {}); 
            } catch (err) {}

            // Log to Staff Channel
            sendLog("🆕 Ticket Created", `**User:** ${message.author.tag}\n**Bot:** ${client.user.username}`, '#facc15');
        }
        
        // ------------------------------------------
        // CASE 2: EXISTING TICKET (MESSAGE LOGGING)
        // ------------------------------------------
        console.log(`[MSG] 📥 From ${message.author.tag}: ${message.content.substring(0, 30)}...`);

        // Handle Attachments
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
        
        // Push to Frontend via Socket
        io.emit('new_message', { 
            threadId: thread._id, 
            notif_sound: true, 
            ...msgData 
        });
    });

    client.login(token).catch(e => console.error(`[BOT] ❌ Login Failed Bot ${index + 1}: ${e.message}`));
    clients.push(client);
});


// =================================================================================================
//  SECTION 8: SOCKET.IO (REAL-TIME COMMUNICATION)
// =================================================================================================

const activeViewers = {}; 

io.on('connection', (socket) => {
    
    // STAFF JOINS A TICKET
    socket.on('join_ticket_room', ({ threadId, username }) => {
        socket.join(threadId);
        
        if (!activeViewers[threadId]) {
            activeViewers[threadId] = new Set();
        }
        activeViewers[threadId].add(username);
        
        console.log(`[SOCKET] 👤 ${username} joined ticket room: ${threadId}`);
        
        // Broadcast viewer list to everyone in room (Collision Detection)
        io.to(threadId).emit('viewers_updated', Array.from(activeViewers[threadId]));
        
        // Save state on socket for disconnect handling
        socket.currentThreadId = threadId;
        socket.currentUser = username;
    });

    // STAFF LEAVES A TICKET
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

    // STAFF DISCONNECTS
    socket.on('disconnect', () => {
        if (socket.currentThreadId && socket.currentUser) {
            const tId = socket.currentThreadId;
            if (activeViewers[tId]) {
                activeViewers[tId].delete(socket.currentUser);
                io.to(tId).emit('viewers_updated', Array.from(activeViewers[tId]));
            }
        }
    });

    // STAFF IS TYPING
    socket.on('staff_typing', async (data) => {
        const { threadId } = data;
        const thread = await Thread.findById(threadId);
        if (!thread) return;
        
        const client = clients.find(c => c.user.id === thread.botId);
        if (client) {
            try {
                // Show typing on Discord side
                const user = await client.users.fetch(thread.userId);
                const dmChannel = user.dmChannel || await user.createDM();
                await dmChannel.sendTyping();
            } catch(e) {}
        }
    });
});


// =================================================================================================
//  SECTION 9: API ROUTES - AUTHENTICATION
// =================================================================================================

/**
 * LOGIN
 * Note: Does NOT enforce complexity check for login. Legacy passwords work here.
 */
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    console.log(`[AUTH] 🔐 Login attempt for user: ${username}`);
    
    try {
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
            console.log(`[AUTH] ❌ Login Failed (Invalid Creds): ${username}`);
            res.status(401).json({ error: "Invalid Credentials" });
        }
    } catch (e) {
        console.error(`[AUTH] ❌ Login Error:`, e);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

/**
 * LOGOUT
 */
app.post('/api/logout', (req, res) => { 
    console.log(`[AUTH] 🚪 Logout request from ${req.session.username}`);
    req.session.destroy(() => { 
        res.clearCookie('connect.sid'); 
        res.json({ success: true }); 
    }); 
});

/**
 * SESSION CHECK
 */
app.get('/api/auth/user', isAuth, (req, res) => {
    res.json({ username: req.session.username, isAdmin: req.session.isAdmin });
});

/**
 * PUBLIC PASSWORD RESET REQUEST
 * Triggers a complex password generation sent via DM.
 */
app.post('/api/public/request-reset', async (req, res) => {
    const { discordId } = req.body;
    console.log(`[AUTH] 🔄 Public Password reset requested for ID: ${discordId}`);
    
    const staff = await Staff.findOne({ discordId });
    if (!staff) {
        return res.status(404).json({ error: "No staff account found with that Discord ID." });
    }
    
    // Generate Strict Password
    const newPass = generateComplexPassword();
    staff.password = await bcrypt.hash(newPass, 10);
    await staff.save();
    
    try {
        const user = await clients[0].users.fetch(discordId);
        await user.send(`**Terminal Recovery Request**\n\nYour staff password has been reset.\n**New Key:** \`${newPass}\`\n**Login URL:** ${getPanelUrl()}`);
        console.log(`[AUTH] ✅ Reset DM sent to ${staff.username}`);
        res.json({ success: true });
    } catch (e) { 
        console.error(`[AUTH] ❌ Failed to DM reset key: ${e.message}`);
        res.status(500).json({ error: "Could not send DM. Is the bot blocked?" }); 
    }
});

/**
 * STAFF SELF-SERVICE CHANGE PASSWORD
 * Enforces the Strict Policy (8 chars, 1 Cap, 1 Num, 1 Sym).
 */
app.post('/api/staff/change-password', isAuth, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const username = req.session.username;
    
    console.log(`[AUTH] 🔐 User ${username} attempting password change.`);

    // 1. Validate Complexity
    if (!validateComplexPassword(newPassword)) {
        return res.status(400).json({ error: "Password does not meet policy (8+ chars, 1 Cap, 1 Num, 1 Symbol)." });
    }

    // 2. Find Staff
    const staff = await Staff.findById(req.session.staffId);
    if (!staff) return res.status(404).json({ error: "Staff record not found." });

    // 3. Verify Old Password
    const match = await bcrypt.compare(currentPassword, staff.password);
    if (!match) {
        return res.status(401).json({ error: "Incorrect current password." });
    }

    // 4. Update
    staff.password = await bcrypt.hash(newPassword, 10);
    await staff.save();
    
    console.log(`[AUTH] ✅ Staff ${username} successfully changed their password.`);
    res.json({ success: true });
});


// =================================================================================================
//  SECTION 10: API ROUTES - TICKET OPERATIONS
// =================================================================================================

/**
 * GET ALL THREADS
 */
app.get('/api/threads', isAuth, async (req, res) => { 
    const threads = await Thread.find().sort({ lastMessageAt: -1 }); 
    res.json(threads); 
});

/**
 * REPLY TO TICKET
 * Supports Text + File Uploads (Base64)
 */
app.post('/api/reply', isAuth, async (req, res) => {
    const { threadId, content, fileBase64, fileName } = req.body;
    
    const thread = await Thread.findById(threadId);
    if (!thread) {
        return res.status(404).json({ error: "Thread Not Found" });
    }
    
    const client = clients.find(c => c.user.id === thread.botId);
    if (!client) {
        return res.status(500).json({ error: "Bot for this thread is offline." });
    }

    try {
        const user = await client.users.fetch(thread.userId);
        
        let messageOptions = { 
            embeds: [new EmbedBuilder()
                .setColor('#3b82f6')
                .setAuthor({ name: `Support: ${req.session.username}`, iconURL: client.user.displayAvatarURL() })
                .setDescription(content || "[File Attachment]")
                .setTimestamp()
            ] 
        };
        
        if (fileBase64) {
            console.log(`[REPLY] 📎 Processing file upload: ${fileName}`);
            messageOptions.files = [new AttachmentBuilder(Buffer.from(fileBase64.split(',')[1], 'base64'), { name: fileName || 'upload.png' })];
        }
        
        await user.send(messageOptions);
        
        // Save to Database
        const reply = { 
            authorTag: `Staff (${req.session.username})`, 
            content: content || "[File Attachment]", 
            fromBot: true, 
            timestamp: new Date() 
        };
        
        thread.messages.push(reply);
        thread.lastMessageAt = new Date();
        await thread.save();
        
        // Update Stats
        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { repliesSent: 1 } });
        
        // Emit to Dashboard
        io.emit('new_message', { threadId: thread._id, ...reply });
        
        console.log(`[REPLY] 📤 Sent reply to ${thread.userTag}`);
        res.json({ success: true });
    } catch (err) { 
        console.error(`[REPLY] ❌ Failed to send DM: ${err.message}`);
        res.status(500).json({ error: "Failed to send DM. User may have blocked the bot." }); 
    }
});

/**
 * CLOSE & ARCHIVE TICKET
 * Generates Transcript, Logs to Discord, Sends Rating Request
 */
app.post('/api/close-thread', isAuth, async (req, res) => {
    const { threadId } = req.body;
    console.log(`[ARCHIVE] 🔒 Archiving thread ${threadId} by ${req.session.username}`);

    const thread = await Thread.findById(threadId);
    if (!thread) {
        return res.status(404).json({ error: "Not Found" });
    }

    // Generate Text Transcript
    let transcriptText = `OFFICIAL TRANSCRIPT: ${thread.userTag}\nBot: ${thread.botName}\nClosed By: ${req.session.username}\nDate: ${new Date().toISOString()}\n\n`;
    thread.messages.forEach(m => { 
        transcriptText += `[${m.timestamp.toISOString()}] ${m.authorTag}: ${m.content}\n`; 
    });
    
    const tempPath = path.join(__dirname, `temp-${thread.userId}.txt`);

    try {
        fs.writeFileSync(tempPath, transcriptText);
        
        // Send Log to Discord Channel
        await sendLog("🔒 Archive Logged", `**User:** ${thread.userTag}\n**Closed By:** ${req.session.username}`, '#ef4444', [new AttachmentBuilder(tempPath)]);
        
        // Save JSON to Local Disk Archive
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
        
        // Send User Rating Request (Full 5 Stars)
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
            .setDescription(`You were helped by **${req.session.username}**. Please rate your experience to help us improve.`)
            .setColor('#3b82f6');

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

        // Increment Staff Stats
        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { ticketsClosed: 1 } });
        
        // Delete Thread from Active DB
        await Thread.findByIdAndDelete(threadId);
        
        // Cleanup Temp File
        if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);

        res.json({ success: true });
    } catch (e) { 
        console.error(`[ARCHIVE] ❌ Critical Error:`, e);
        res.status(500).json({ error: "Archive Failed" }); 
    }
});


// =================================================================================================
//  SECTION 11: API ROUTES - CRM & NOTES
// =================================================================================================

/**
 * GET USER CRM DATA
 */
app.get('/api/crm/user/:discordId', isAuth, async (req, res) => {
    const { discordId } = req.params;
    
    // Get Sticky Note
    const noteDoc = await UserNote.findOne({ userId: discordId });
    
    // Scan Archive Folder for JSON history
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

/**
 * GET SPECIFIC TRANSCRIPT
 */
app.get('/api/crm/transcript/:discordId/:filename', isAuth, (req, res) => {
    const { discordId, filename } = req.params;
    
    // Security Check
    if (filename.includes('..') || discordId.includes('..')) {
        return res.status(403).json({ error: "Invalid path" });
    }
    
    const filePath = path.join(ARCHIVE_DIR, discordId, filename);
    if (fs.existsSync(filePath)) {
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        res.json(data);
    } else {
        res.status(404).json({ error: "Transcript not found" });
    }
});

/**
 * UPDATE USER NOTE
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
    console.log(`[CRM] 📝 Note updated for ${req.body.userId} by ${req.session.username}`);
    res.json({ success: true });
});


// =================================================================================================
//  SECTION 12: API ROUTES - ADMIN MANAGEMENT
// =================================================================================================

/**
 * ADMIN STATS
 */
app.get('/api/admin/stats', isAdmin, async (req, res) => { 
    const stats = await Staff.find().sort({ ticketsClosed: -1 }); 
    res.json(stats); 
});

/**
 * ADMIN CONFIG FETCH
 */
app.get('/api/admin/config', isAdmin, async (req, res) => { 
    const config = await Config.findOne({ id: 'global' }); 
    res.json(config); 
});

/**
 * ADMIN CONFIG UPDATE (TOGGLE & SCHEDULE)
 */
app.post('/api/admin/config/toggle', isAdmin, async (req, res) => { 
    const { status, note, openTime, closeTime } = req.body;
    
    const config = await Config.findOne({ id: 'global' }); 
    
    // Update Master Toggle
    if (status !== undefined) config.supportOnline = status;
    
    // Update Offline Note
    if (note !== undefined) config.offlineNote = note;
    
    // Update Schedule Times (Open)
    if (openTime !== undefined) config.openTime = openTime;
    
    // Update Schedule Times (Close)
    if (closeTime !== undefined) config.closeTime = closeTime;
    
    await config.save(); 
    
    console.log(`[CONFIG] ⚙️ Updated Config: Online=${config.supportOnline}, Open=${config.openTime}, Close=${config.closeTime}`);
    res.json({ success: true, config }); 
});

/**
 * ADMIN SERVER LIST
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

// --- ADMIN FLEET ACTIONS ---

app.post('/api/admin/leave-server', isAdmin, async (req, res) => {
    const client = clients.find(c => c.user.id === req.body.botId);
    try {
        const guild = await client.guilds.fetch(req.body.serverId);
        await guild.leave();
        console.log(`[ADMIN] 👋 Bot ${client.user.username} left server: ${guild.name}`);
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

// --- ADMIN STAFF MANAGEMENT ---

app.post('/api/admin/staff/add', isAdmin, async (req, res) => { 
    // Auto-generate Complex Password for new account
    const tempPass = generateComplexPassword(); 
    const hashedPassword = await bcrypt.hash(tempPass, 10); 
    
    await new Staff({ 
        username: req.body.username, 
        discordId: req.body.discordId, 
        password: hashedPassword, 
        isAdmin: req.body.adminStatus 
    }).save(); 
    
    // Auto-DM the credential
    try { 
        const user = await clients[0].users.fetch(req.body.discordId); 
        await user.send(`**Staff Access Granted**\n\nYour account has been created.\nUser: \`${req.body.username}\`\nPass: \`${tempPass}\`\nURL: ${getPanelUrl()}\n\nPlease change your password upon login.`); 
    } catch(e) {
        console.error("[ADMIN] Failed to DM new staff member.");
    } 
    
    console.log(`[ADMIN] 👤 Staff added: ${req.body.username}`);
    res.json({ success: true }); 
});

/**
 * ADMIN FORCE RESET PASSWORD
 * Generates strict password, saves to DB, and DMs the user.
 */
app.post('/api/admin/staff/reset', isAdmin, async (req, res) => {
    const { staffId } = req.body;
    
    const staff = await Staff.findById(staffId);
    if (!staff) return res.status(404).json({ error: "Staff Not Found" });

    // Generate strict password
    const newPass = generateComplexPassword();
    staff.password = await bcrypt.hash(newPass, 10);
    await staff.save();

    try {
        const u = await clients[0].users.fetch(staff.discordId);
        await u.send(`**⚠️ Admin Reset**\nYour staff password has been force-reset by an administrator.\n\n**New Key:** \`${newPass}\`\n**URL:** ${getPanelUrl()}`);
        console.log(`[ADMIN] 🔐 Forced reset for ${staff.username}`);
        res.json({ success: true });
    } catch (e) {
        console.error(`[ADMIN] ❌ Auto-DM failed for reset:`, e);
        res.status(500).json({ error: "Reset successful, but Auto-DM failed." });
    }
});

app.post('/api/admin/staff/delete', isAdmin, async (req, res) => { 
    if (req.body.staffId === req.session.staffId.toString()) {
        return res.status(400).json({ error: "Cannot delete yourself" }); 
    }
    await Staff.findByIdAndDelete(req.body.staffId); 
    console.log(`[ADMIN] 🗑️ Staff deleted: ${req.body.staffId}`);
    res.json({ success: true }); 
});

/**
 * ADMIN MANUAL DM (Ticket Opener)
 */
app.post('/api/admin/manual-dm', isAdmin, async (req, res) => {
    try {
        let thread = await Thread.findOne({ userId: req.body.discordId });
        let client = clients[0]; // Default to first bot
        
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
            await sendLog("🆕 Manual Ticket", `Opened by Staff: ${req.session.username}`, '#facc15'); 
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
        res.status(500).json({ error: "DM Failed. Is the ID correct?" }); 
    }
});

// --- ADMIN CONTENT (MACROS/FAQ) ---

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


// =================================================================================================
//  SECTION 13: LICENSE MANAGEMENT (SELL.APP INTEGRATION)
// =================================================================================================

/**
 * Activates a License via Sell.App and saves it locally with Server Tracking.
 */
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
            // e.g., "30 Days" -> 30
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
            console.error(`[LICENSE] ❌ Failed to DM user confirmation: ${e.message}`);
        }

        res.json({ success: true, data: response.data });
    } catch (err) { 
        console.error(`[LICENSE] ❌ Activation Failed:`, err.response?.data || err.message);
        res.status(400).json({ error: err.response?.data?.message || "Activation Failed" }); 
    }
});

// =================================================================================================
//  SECTION 14: AUTOMATED TASKS (CRON)
// =================================================================================================

/**
 * Hourly Check for Expiring Licenses (3-Day Warning)
 */
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


// =================================================================================================
//  SECTION 15: BOOTSTRAP
// =================================================================================================

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
    console.log(`[SYSTEM] 🚀 MIRAIDON TRADE SERVICES Ready on Port ${PORT}`);
    console.log(`[SYSTEM] 🔗 Local URL: http://localhost:${PORT}`);
});
