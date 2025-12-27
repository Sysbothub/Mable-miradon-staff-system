/**
 * =================================================================================================
 * MIRAIDON TRADE SERVICES - MASTER SERVER (v10.6 - THE ABSOLUTE UNABRIDGED BUILD)
 * =================================================================================================
 * * STATUS: 100% UNCOMPRESSED, MAXIMAL VERBOSITY, NO DELETIONS
 * * LINE COUNT TARGET: 1850+
 * -------------------------------------------------------------------------------------------------
 * * CORE ARCHITECTURE MANIFEST:
 * 1.  DISCORD SDK INTEGRATION: 
 * - Independent client management for Miraidon (SV) and Professor Mable (ZA).
 * - Real-time event emitters for typing and message synchronization.
 * 2.  RESTful API LAYER:
 * - Secure administrative endpoints guarded by session-based authentication.
 * - CRM logic for persistent user notes and historic transcript retrieval.
 * 3.  PERSISTENCE ENGINE:
 * - MongoDB for dynamic configuration, staff performance, and active threads.
 * - Local File System for immutable JSON and TXT archival of closed support inquiries.
 * 4.  REAL-TIME SYNC:
 * - Socket.io implementation for staff collision detection and instant inbox refreshing.
 * 5.  AUTOMATION:
 * - Scheduled cron logic for Trustpilot review requests and license expiration warnings.
 * =================================================================================================
 */

// =================================================================================================
//  SECTION 1: MODULE LOADING AND GLOBAL CONFIGURATION
// =================================================================================================

// 1.1. Environment Variable Loading
// This ensures that sensitive keys like MONGODB_URI and BOT_TOKENS are accessible.
require('dotenv').config();

// 1.2. Core Node.js Networking and File System Modules
const fs = require('fs');
const path = require('path');
const http = require('http');

// 1.3. Web Framework and Session Management Dependencies
const express = require('express');
const session = require('express-session');

// 1.4. Database and Real-time Communication Libraries
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo');
const { Server } = require('socket.io');

// 1.5. Cryptography and External API Integration
const bcrypt = require('bcrypt');
const axios = require('axios');

// 1.6. Discord SDK Components for Gateway Interaction
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

// 1.7. Application Instance Initialization
const app = express();
const server = http.createServer(app);
const io = new Server(server);


// =================================================================================================
//  SECTION 2: PERSISTENT DISK STORAGE ARCHITECTURE
// =================================================================================================

console.log("[STORAGE] 📂 Checking persistent disk mount points...");

let DATA_DIR;

/**
 * PATH RESOLUTION LOGIC:
 * Handles the distinction between local development and cloud production (Render).
 */
if (process.env.RENDER === 'true') {
    console.log("[STORAGE] ☁️ Production environment detected (Render.com).");
    console.log("[STORAGE] 📍 Mapping persistence to /var/data mount point.");
    DATA_DIR = '/var/data';
} else {
    console.log("[STORAGE] 💻 Development environment detected.");
    console.log("[STORAGE] 📍 Mapping persistence to local_storage directory.");
    DATA_DIR = path.join(__dirname, 'local_storage');
}

/**
 * ROOT DIRECTORY VERIFICATION:
 * Ensures the system has a root directory to store all user-generated data.
 */
const rootExists = fs.existsSync(DATA_DIR);
if (rootExists === false) {
    console.log(`[STORAGE] 📂 Root directory missing. Creating: ${DATA_DIR}`);
    try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        console.log(`[STORAGE] ✅ Root Data Directory established.`);
    } catch (mkdirError) {
        console.error(`[STORAGE] ❌ CRITICAL: Permission denied writing to disk: ${mkdirError.message}`);
        console.error(`[STORAGE] ❌ Ensure the user running the process has recursive write access.`);
        process.exit(1); 
    }
} else {
    console.log(`[STORAGE] ✅ Root directory confirmed: ${DATA_DIR}`);
}

/**
 * ARCHIVE SUB-DIRECTORY VERIFICATION:
 * Segregates support transcripts into a dedicated folder to prevent clutter.
 */
const ARCHIVE_DIR = path.join(DATA_DIR, 'archives');
const archiveExists = fs.existsSync(ARCHIVE_DIR);
if (archiveExists === false) {
    console.log(`[STORAGE] 📂 Archive sub-directory missing. Creating: ${ARCHIVE_DIR}`);
    try {
        fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
        console.log(`[STORAGE] ✅ Archive directory established.`);
    } catch (archiveMkdirError) {
        console.error(`[STORAGE] ❌ WARNING: Failed to create archive folder: ${archiveMkdirError.message}`);
    }
} else {
    console.log(`[STORAGE] ✅ Archive directory confirmed: ${ARCHIVE_DIR}`);
}


// =================================================================================================
//  SECTION 3: MONGODB DATABASE PERSISTENCE LAYER
// =================================================================================================

console.log("[DATABASE] ⏳ Attempting handshake with MongoDB cluster...");

/**
 * ESTABLISH CONNECTION:
 * Connects to the URI provided in the .env file.
 */
mongoose.connect(process.env.MONGODB_URI)
    .then(function() {
        console.log("================================================================================");
        console.log("[DATABASE] ✅ Handshake Successful: MONGODB CLUSTER ACTIVE");
        console.log(`[DATABASE] 🕒 Connected at: ${new Date().toLocaleString()}`);
        console.log("================================================================================");
        
        // Execute startup maintenance routines
        initializeSystemDefaults();
        performDatabaseRepair();
    })
    .catch(function(dbError) {
        console.error("================================================================================");
        console.error("[DATABASE] ❌ CRITICAL HANDSHAKE FAILURE");
        console.error(`[DATABASE] 🛑 REASON: ${dbError.message}`);
        console.error("[DATABASE] 🛑 ACTION: System halt imminent. Verify MONGODB_URI.");
        console.error("================================================================================");
    });


// =================================================================================================
//  SECTION 4: DATA SCHEMAS AND OBJECT MODELS
// =================================================================================================

/**
 * 4.1. STAFF SCHEMA
 * Manages administrative credentials, discord links, and performance metrics.
 */
const StaffSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: true, 
        unique: true 
    },
    password: { 
        type: String, 
        required: true 
    },
    discordId: { 
        type: String, 
        required: true 
    },
    isAdmin: { 
        type: Boolean, 
        default: false 
    },
    avatar: { 
        type: String, 
        default: 'https://cdn.discordapp.com/embed/avatars/0.png' 
    },
    ticketsClosed: { 
        type: Number, 
        default: 0 
    },
    repliesSent: { 
        type: Number, 
        default: 0 
    },
    ratingSum: { 
        type: Number, 
        default: 0 
    },
    ratingCount: { 
        type: Number, 
        default: 0 
    }
});
const Staff = mongoose.model('Staff', StaffSchema);

/**
 * 4.2. THREAD SCHEMA
 * Represents an active support inquiry between a user and the staff panel.
 */
const ThreadSchema = new mongoose.Schema({
    userId: { 
        type: String, 
        required: true 
    },
    userTag: { 
        type: String, 
        required: true 
    },
    userAvatar: { 
        type: String, 
        default: 'https://cdn.discordapp.com/embed/avatars/0.png' 
    },
    botId: { 
        type: String, 
        required: true 
    },
    botName: { 
        type: String, 
        required: true 
    },
    claimedBy: { 
        type: String, 
        default: null 
    },
    claimedAt: { 
        type: Date, 
        default: null 
    },
    messages: [{
        authorTag: { 
            type: String 
        },
        authorAvatar: { 
            type: String, 
            default: 'https://cdn.discordapp.com/embed/avatars/0.png' 
        },
        content: { 
            type: String 
        },
        attachments: [String],
        timestamp: { 
            type: Date, 
            default: Date.now 
        },
        fromBot: { 
            type: Boolean, 
            default: false 
        }
    }],
    lastMessageAt: { 
        type: Date, 
        default: Date.now 
    }
});
const Thread = mongoose.model('Thread', ThreadSchema);

/**
 * 4.3. LICENSE SCHEMA
 * Tracks activated keys, duration, and server identifiers for premium services.
 */
const LicenseSchema = new mongoose.Schema({
    key: { 
        type: String, 
        required: true 
    },
    instanceId: { 
        type: String 
    },
    discordId: { 
        type: String, 
        required: true 
    },
    serverId: { 
        type: String 
    },
    serverName: { 
        type: String 
    },
    channelId: { 
        type: String 
    },
    type: { 
        type: String 
    },
    duration: { 
        type: String 
    },
    activatedAt: { 
        type: Date, 
        default: Date.now 
    },
    expiresAt: { 
        type: Date 
    },
    reminderSent: { 
        type: Boolean, 
        default: false 
    },
    reviewRequestSent: { 
        type: Boolean, 
        default: false 
    }
});
const License = mongoose.model('License', LicenseSchema);

/**
 * 4.4. CONFIG SCHEMA
 * Stores global settings, support hours, and bot fleet status.
 */
const ConfigSchema = new mongoose.Schema({
    id: { 
        type: String, 
        default: 'global' 
    },
    supportOnline: { 
        type: Boolean, 
        default: true 
    },
    offlineNote: { 
        type: String, 
        default: '' 
    },
    openTime: { 
        type: String, 
        default: "08:00" 
    },
    closeTime: { 
        type: String, 
        default: "23:59" 
    },
    botFleetStatus: [{
        botId: String,
        botName: String,
        tradingActive: { 
            type: Boolean, 
            default: true 
        }
    }]
});
const Config = mongoose.model('Config', ConfigSchema);

/**
 * 4.5. CRM AND CONTENT MODELS
 * User notes, staff macros, and FAQ database.
 */
const UserNoteSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    note: { type: String, default: "" },
    updatedBy: { type: String },
    updatedAt: { type: Date, default: Date.now }
});
const UserNote = mongoose.model('UserNote', UserNoteSchema);

const MacroSchema = new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true }
});
const Macro = mongoose.model('Macro', MacroSchema);

const FAQSchema = new mongoose.Schema({
    question: { type: String, required: true },
    answer: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const FAQ = mongoose.model('FAQ', FAQSchema);


// =================================================================================================
//  SECTION 5: SYSTEM HELPERS AND UTILITIES
// =================================================================================================

/**
 * Helper: validateComplexPassword
 * Enforces security policy: 8 chars, 1 Capital, 1 Number, 1 Symbol.
 */
function validateComplexPassword(passwordValue) {
    const minLen = 8;
    const regexCapital = /[A-Z]/;
    const regexNumber = /[0-9]/;
    const regexSymbol = /[\W_]/; 
    
    if (passwordValue.length < minLen) {
        return false;
    }
    
    const hasCap = regexCapital.test(passwordValue);
    if (hasCap === false) {
        return false;
    }
    
    const hasNum = regexNumber.test(passwordValue);
    if (hasNum === false) {
        return false;
    }
    
    const hasSym = regexSymbol.test(passwordValue);
    if (hasSym === false) {
        return false;
    }
    
    return true;
}

/**
 * Helper: generateComplexPassword
 * Generates a compliant secure key for automated resets.
 */
function generateComplexPassword() {
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const nums = "0123456789";
    const syms = "!@#$%^&*?";
    
    let result = "";
    result += upper[Math.floor(Math.random() * upper.length)];
    result += nums[Math.floor(Math.random() * nums.length)];
    result += syms[Math.floor(Math.random() * syms.length)];
    result += lower[Math.floor(Math.random() * lower.length)];
    
    const combined = lower + upper + nums + syms;
    for (let i = 0; i < 10; i++) {
        result += combined[Math.floor(Math.random() * combined.length)];
    }
    
    return result.split('').sort(function(){ return 0.5 - Math.random(); }).join('');
}

/**
 * Initializer: initializeSystemDefaults
 * Ensures the database is not empty upon first boot.
 */
async function initializeSystemDefaults() {
    try {
        const checkAdmin = await Staff.findOne({ username: 'admin' });
        if (checkAdmin === null) {
            console.log("[INIT] 👤 Creating master administrative account...");
            const hash = await bcrypt.hash('Map4491!', 10);
            const masterAdmin = new Staff({ 
                username: 'admin', 
                password: hash, 
                discordId: '000000000000000000', 
                isAdmin: true 
            });
            await masterAdmin.save();
            console.log("[INIT] ✅ Master admin created.");
        }

        const checkConfig = await Config.findOne({ id: 'global' });
        if (checkConfig === null) {
            console.log("[INIT] ⚙️ Creating global configuration profile...");
            const masterConfig = new Config({ 
                id: 'global', 
                supportOnline: true, 
                openTime: "08:00", 
                closeTime: "23:59" 
            });
            await masterConfig.save();
            console.log("[INIT] ✅ Master configuration created.");
        }
    } catch (bootstrapError) {
        console.error("[INIT] ❌ Initialization routine failed:");
        console.error(bootstrapError);
    }
}

/**
 * Repair: performDatabaseRepair
 * Ensures legacy records are compatible with new features (Avatars/Reviews).
 */
async function performDatabaseRepair() {
    try {
        // Fix thread metadata
        await Thread.updateMany(
            { claimedBy: { $exists: false } },
            { $set: { claimedBy: null } }
        );
        
        await Thread.updateMany(
            { userAvatar: { $exists: false } },
            { $set: { userAvatar: 'https://cdn.discordapp.com/embed/avatars/0.png' } }
        );

        // Fix license flags
        await License.updateMany(
            { reviewRequestSent: { $exists: false } },
            { $set: { reviewRequestSent: false } }
        );

        console.log("[REPAIR] ✅ Database schema verification complete.");
    } catch (repairError) {
        console.error("[REPAIR] ❌ Repair routine failed:");
        console.error(repairError);
    }
}


// =================================================================================================
//  SECTION 6: EXPRESS WEB SERVER MIDDLEWARE AND SECURITY
// =================================================================================================

// 6.1. Networking Configuration
app.set('trust proxy', 1);

// 6.2. Body Parsers (Maximum payload size for media)
app.use(express.json({ limit: '60mb' }));
app.use(express.urlencoded({ extended: true, limit: '60mb' }));

// 6.3. Session Architecture (MongoDB Store)
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-security-key-miraidon-ca',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'staff_sessions' 
    }),
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, // 24-hour persistent login
        secure: true, // Only serve over HTTPS
        sameSite: 'none' 
    }
}));

// 6.4. Authentication Middleware
const isAuth = function(request, response, next) {
    if (request.session.staffId) {
        return next();
    }
    
    if (request.path.startsWith('/api')) {
        console.log(`[AUTH] 🛑 Unauthorized API Access: ${request.path}`);
        return response.status(401).json({ error: "Access Denied: Authentication Required" });
    }
    
    console.log(`[AUTH] 🛑 Redirecting guest to login for protected path: ${request.path}`);
    return response.redirect('/login.html');
};

// 6.5. Administrative Authorization Middleware
const isAdmin = function(request, response, next) {
    if (request.session.staffId && request.session.isAdmin === true) {
        return next();
    }
    
    console.log(`[AUTH] 🛑 Forbidden: Admin account required for path ${request.path}`);
    return response.status(403).json({ error: "Access Denied: Administrative Clearance Required" });
};

// 6.6. Static Path Mapping
// Public pages: Home, Status, Login
app.use(express.static(path.join(__dirname, 'public')));

// Protected pages: Admin, Dashboard
app.use('/staff', isAuth, express.static(path.join(__dirname, 'public/staff')));


// =================================================================================================
//  SECTION 7: DISCORD CLIENT SERVICE LAYER (MIRAIDON FLEET)
// =================================================================================================

/**
 * DISCORD INITIALIZATION:
 * Loads tokens for both Miraidon and Professor Mable.
 */
const botTokens = [
    process.env.BOT_ONE_TOKEN, 
    process.env.BOT_TWO_TOKEN
].filter(function(t) {
    return (t !== undefined && t !== "");
});

const clients = [];

/**
 * Service: sendLog
 * Dispatches embeds to the developer log channel.
 */
async function sendLog(title, description, colorCode = '#3b82f6', files = []) {
    if (!process.env.LOG_CHANNEL_ID || !clients[0]) {
        return;
    }
    
    try {
        const targetChannel = await clients[0].channels.fetch(process.env.LOG_CHANNEL_ID);
        if (targetChannel) {
            const embed = new EmbedBuilder()
                .setTitle(title)
                .setDescription(description)
                .setColor(colorCode)
                .setTimestamp()
                .setFooter({ text: "TSP Master Control" });
                
            await targetChannel.send({ embeds: [embed], files: files });
        }
    } catch (logErr) { 
        console.error(`[LOG] ❌ Embed dispatch failure: ${logErr.message}`); 
    }
}

// 7.1. Gateway Connection Loop
botTokens.forEach(function(tokenValue, tokenIndex) {
    const discordClient = new Client({
        intents: [
            GatewayIntentBits.Guilds, 
            GatewayIntentBits.DirectMessages, 
            GatewayIntentBits.MessageContent, 
            GatewayIntentBits.GuildMembers
        ],
        partials: [Partials.Channel, Partials.Message]
    });

    // Handle Gateway Connectivity
    discordClient.once('ready', function() {
        console.log(`[FLEET] 🤖 Client ${tokenIndex + 1} Active: ${discordClient.user.tag}`);
    });

    // Handle Typing synchronization
    discordClient.on('typingStart', function(event) {
        if (event.user.bot === true) return;
        io.emit('user_typing', { userId: event.user.id });
    });

    // Handle Interaction (Support Ratings)
    discordClient.on('interactionCreate', async function(interaction) {
        if (interaction.isButton() === false) return;

        const parts = interaction.customId.split('_');
        const type = parts[0];
        
        if (type === 'rate') {
            const stars = parseInt(parts[1]);
            const staffId = parts[2];
            
            console.log(`[RATING] ⭐ Staff ${staffId} received rating: ${stars}`);

            try {
                // Increment score and count
                await Staff.findByIdAndUpdate(staffId, { 
                    $inc: { ratingSum: stars, ratingCount: 1 } 
                });

                const confirmationRow = new ActionRowBuilder().addComponents(
                    new ButtonBuilder().setCustomId('done').setLabel(`Feedback Logged`).setStyle(ButtonStyle.Success).setDisabled(true)
                );

                await interaction.update({ 
                    content: `**Thank you!** You successfully rated your session **${stars}/5 stars**.`, 
                    components: [confirmationRow] 
                });
            } catch (err) {
                console.error(`[RATING] ❌ Database update failure: ${err.message}`);
            }
        }
    });

    // MAIN MESSAGE DISPATCHER (Ticket Logic)
    discordClient.on('messageCreate', async function(message) {
        // Discard logic: Bots, Guild messages, Empty content
        if (message.author.bot === true || message.guild !== null) {
            return;
        }
        
        const discordUserId = message.author.id;
        const currentAvatar = message.author.displayAvatarURL({ extension: 'png', size: 128 });

        // Query active support threads
        let activeThread = await Thread.findOne({ 
            userId: discordUserId, 
            botId: discordClient.user.id 
        });
        
        // --- CASE: NEW INQUIRY ---
        if (activeThread === null) {
            console.log(`[TICKET] 📩 Initial Message from: ${message.author.tag}`);
            
            activeThread = new Thread({ 
                userId: discordUserId, 
                userTag: message.author.tag, 
                userAvatar: currentAvatar, 
                botId: discordClient.user.id, 
                botName: discordClient.user.username, 
                messages: [] 
            });
            
            // Query System Config for Schedule check
            const systemConfig = await Config.findOne({ id: 'global' });
            const isToggledOn = systemConfig ? systemConfig.supportOnline : true;
            const openTime = systemConfig ? systemConfig.openTime : "08:00";
            const closeTime = systemConfig ? systemConfig.closeTime : "23:59";

            // Calculate current minute total in AST
            const dateObj = new Date();
            const timeStr = new Intl.DateTimeFormat('en-US', { timeZone: 'America/Halifax', hour12: false, hour: 'numeric', minute: 'numeric' }).format(dateObj);
            const [nowH, nowM] = timeStr.split(':').map(Number);
            const currentMinuteTotal = (nowH * 60) + nowM;

            const [configOpenH, configOpenM] = openTime.split(':').map(Number);
            const [configCloseH, configCloseM] = closeTime.split(':').map(Number);
            const startLimit = (configOpenH * 60) + configOpenM;
            const endLimit = (configCloseH * 60) + configCloseM;

            const isOperatingHours = (currentMinuteTotal >= startLimit && currentMinuteTotal <= endLimit);

            let greetingEmbed;

            if (isToggledOn === false) {
                greetingEmbed = new EmbedBuilder()
                    .setColor('#ef4444')
                    .setTitle('Inquiries Paused')
                    .setDescription(`Support is currently offline for a scheduled break.\n\n**Reason:** ${systemConfig.offlineNote || 'No reason provided.'}`)
                    .setTimestamp();
            } else if (isOperatingHours === false) {
                greetingEmbed = new EmbedBuilder()
                    .setColor('#f59e0b')
                    .setTitle('Support Desk Closed')
                    .setDescription(`You have contacted us outside of normal Support hours.\n\n**Schedule:** ${openTime} - ${closeTime} AST.\nWe Have Received your message and will respond as soon as available.`)
                    .setTimestamp();
            } else {
                greetingEmbed = new EmbedBuilder()
                    .setColor('#3b82f6')
                    .setTitle('Ticket Dispatched')
                    .setDescription('Your inquiry has reached our staff console.\n**Estimated response time** is 2-3 Hours.')
                    .setTimestamp();
            }
            
            try { 
                await message.author.send({ embeds: [greetingEmbed] }); 
            } catch (err) {
                console.warn(`[TICKET] ⚠️ Failed to greet user ${message.author.tag}`);
            }

            sendLog("🆕 Ticket Initialized", `**User:** ${message.author.tag}\n**Entry Gateway:** ${discordClient.user.username}`, '#facc15');
        } else {
            // Update User Avatar cache
            if (activeThread.userAvatar !== currentAvatar) {
                activeThread.userAvatar = currentAvatar;
            }
        }
        
        // --- CASE: CONTINUING CORRESPONDENCE ---
        console.log(`[TICKET] 📥 Inbound Message from ${message.author.tag}`);

        const attachmentUrls = message.attachments.map(function(a) {
            return a.url;
        });
        
        const threadMessageObject = { 
            authorTag: message.author.tag, 
            authorAvatar: currentAvatar, 
            content: message.content || "[Media/System Attachment]", 
            attachments: attachmentUrls, 
            fromBot: false, 
            timestamp: new Date() 
        };

        activeThread.messages.push(threadMessageObject);
        activeThread.lastMessageAt = new Date();
        await activeThread.save();
        
        // Push notification to staff dashboard
        io.emit('new_message', { 
            threadId: activeThread._id, 
            notif_sound: true, 
            ...threadMessageObject 
        });
    });

    // Execute Client Login
    discordClient.login(tokenValue).catch(function(err) {
        console.error(`[FLEET] ❌ Client ${tokenIndex + 1} authentication error: ${err.message}`);
    });
    
    clients.push(discordClient);
});


// =================================================================================================
//  SECTION 8: REAL-TIME COMMUNICATION GATEWAY (SOCKET.IO)
// =================================================================================================

const threadVewingMembers = {}; 

io.on('connection', function(socketInstance) {
    
    /**
     * EVENT: join_ticket_room
     * Handles collision detection for staff members.
     */
    socketInstance.on('join_ticket_room', function(payload) {
        const id = payload.threadId;
        const name = payload.username;

        socketInstance.join(id);
        
        if (threadVewingMembers[id] === undefined) {
            threadVewingMembers[id] = new Set();
        }
        threadVewingMembers[id].add(name);
        
        console.log(`[SOCKET] 👤 User ${name} monitoring room ${id}`);
        
        // Broadcast to specific room only
        io.to(id).emit('viewers_updated', Array.from(threadVewingMembers[id]));
        
        // Cache data on socket object
        socketInstance.currentThreadId = id; 
        socketInstance.currentUser = name;
    });

    /**
     * EVENT: leave_ticket_room
     * Cleans up collision detection cache.
     */
    socketInstance.on('leave_ticket_room', function() {
        if (socketInstance.currentThreadId && socketInstance.currentUser) {
            const id = socketInstance.currentThreadId;
            socketInstance.leave(id);
            
            if (threadVewingMembers[id]) {
                threadVewingMembers[id].delete(socketInstance.currentUser);
                io.to(id).emit('viewers_updated', Array.from(threadVewingMembers[id]));
            }
            
            socketInstance.currentThreadId = null;
        }
    });

    /**
     * EVENT: disconnect
     * Automatic cleanup on browser close.
     */
    socketInstance.on('disconnect', function() {
        if (socketInstance.currentThreadId && socketInstance.currentUser) {
            const id = socketInstance.currentThreadId;
            if (threadVewingMembers[id]) {
                threadVewingMembers[id].delete(socketInstance.currentUser);
                io.to(id).emit('viewers_updated', Array.from(threadVewingMembers[id]));
            }
        }
    });

    /**
     * EVENT: staff_typing
     * Proxies typing state to Discord user.
     */
    socketInstance.on('staff_typing', async function(payload) {
        const threadId = payload.threadId;
        const threadDoc = await Thread.findById(threadId);
        
        if (threadDoc) {
            const bot = clients.find(function(c) {
                return (c.user.id === threadDoc.botId);
            });
            
            if (bot) {
                try {
                    const discordUser = await bot.users.fetch(threadDoc.userId);
                    const channel = discordUser.dmChannel || await discordUser.createDM();
                    await channel.sendTyping();
                } catch(e) { /* Discord DM restricted */ }
            }
        }
    });
});


// =================================================================================================
//  SECTION 9: STAFF AUTHENTICATION SYSTEM API
// =================================================================================================

/**
 * ROUTE: Staff Authentication Login
 * POST /api/login
 */
app.post('/api/login', async function(request, response) {
    const user = request.body.username;
    const pass = request.body.password;
    
    console.log(`[AUTH] 🔑 Login attempt for user: ${user}`);
    
    try {
        const staffMember = await Staff.findOne({ username: user });
        
        if (staffMember === null) {
            return response.status(401).json({ error: "Access Denied: Invalid Credentials" });
        }

        const isMatch = await bcrypt.compare(pass, staffMember.password);
        if (isMatch === true) {
            
            // Execute Profile Photo Synchronization
            try {
                if (clients[0]) {
                    const discordProfile = await clients[0].users.fetch(staffMember.discordId);
                    if (discordProfile) {
                        staffMember.avatar = discordProfile.displayAvatarURL({ extension: 'png', size: 128 });
                        await staffMember.save();
                        console.log(`[AUTH] 🖼️ Avatar synchronized for ${user}`);
                    }
                }
            } catch (pfpError) { 
                console.error(`[AUTH] ⚠️ Avatar sync failed: ${pfpError.message}`); 
            }

            request.session.staffId = staffMember._id; 
            request.session.isAdmin = staffMember.isAdmin; 
            request.session.username = staffMember.username;
            
            request.session.save(function() {
                console.log(`[AUTH] ✅ Session established for ${user}`);
                return response.json({ 
                    success: true, 
                    isAdmin: staffMember.isAdmin, 
                    username: staffMember.username 
                });
            });
        } else {
            console.log(`[AUTH] ❌ Login failure: ${user}`);
            return response.status(401).json({ error: "Access Denied: Invalid Credentials" });
        }
    } catch (criticalAuthError) {
        console.error("[AUTH] ❌ Critical login logic error:");
        console.error(criticalAuthError);
        return response.status(500).json({ error: "Internal Authentication Error" });
    }
});

/**
 * ROUTE: Staff Logout
 * POST /api/logout
 */
app.post('/api/logout', function(request, response) { 
    const actor = request.session.username || 'unknown';
    console.log(`[AUTH] 🚪 Closing session for user: ${actor}`);
    
    request.session.destroy(function(err) { 
        if (err) {
            console.error("[AUTH] ❌ Session destruction error:");
            console.error(err);
            return response.status(500).json({ error: "Internal server error during logout." });
        }
        response.clearCookie('connect.sid'); 
        return response.json({ success: true }); 
    }); 
});

/**
 * ROUTE: Session Identity Retrieval
 * GET /api/auth/user
 */
app.get('/api/auth/user', isAuth, function(request, response) {
    return response.json({ 
        username: request.session.username, 
        isAdmin: request.session.isAdmin 
    });
});

/**
 * ROUTE: Staff Account Recovery (Public)
 * POST /api/public/request-reset
 */
app.post('/api/public/request-reset', async function(request, response) {
    const id = request.body.discordId;
    console.log(`[AUTH] 🔄 Recovery request for ID: ${id}`);
    
    try {
        const staff = await Staff.findOne({ discordId: id });
        if (staff === null) {
            return response.status(404).json({ error: "Target ID not registered." });
        }
        
        // Force key generation
        const secureKey = generateComplexPassword();
        staff.password = await bcrypt.hash(secureKey, 10);
        await staff.save();
        
        // Dispatch to target
        const handle = await clients[0].users.fetch(id);
        const embed = new EmbedBuilder()
            .setTitle("🔑 Terminal Recovery Triggered")
            .setDescription(`A secure key reset was authorized.\n\n**New Key:** \`${secureKey}\`\n**Portal:** ${getPanelUrl()}\n\nUpdate this key via the dashboard immediately.`)
            .setColor('#facc15');
            
        await handle.send({ embeds: [embed] });
        
        console.log(`[AUTH] ✅ Recovery key dispatched to ${staff.username}`);
        return response.json({ success: true });
    } catch (resetErr) { 
        console.error(`[AUTH] ❌ Recovery failure: ${resetErr.message}`);
        return response.status(500).json({ error: "Dispatch failed. Verify DM availability." }); 
    }
});

/**
 * ROUTE: Self-Service Password Rotation
 * POST /api/staff/change-password
 */
app.post('/api/staff/change-password', isAuth, async function(request, response) {
    const current = request.body.currentPassword;
    const proposed = request.body.newPassword;
    const actor = request.session.username;
    
    console.log(`[AUTH] 🔐 User ${actor} rotating secure key...`);

    try {
        // Enforce complexity
        const isValid = validateComplexPassword(proposed);
        if (isValid === false) {
            return response.status(400).json({ error: "Proposed key violates complexity policy (8 chars, 1 Capital, 1 Num, 1 Sym)." });
        }

        const doc = await Staff.findById(request.session.staffId);
        if (doc === null) {
            return response.status(404).json({ error: "Staff record missing." });
        }

        const isAuthorized = await bcrypt.compare(current, doc.password);
        if (isAuthorized === false) {
            return response.status(401).json({ error: "Current key verification failed." });
        }

        doc.password = await bcrypt.hash(proposed, 10);
        await doc.save();
        
        console.log(`[AUTH] ✅ Rotation successful for ${actor}`);
        return response.json({ success: true });
    } catch (rotateErr) {
        console.error("[AUTH] ❌ Rotation logic failure:");
        console.error(rotateErr);
        return response.status(500).json({ error: "Persistence error." });
    }
});


// =================================================================================================
//  SECTION 10: SUPPORT TICKET OPERATIONS API
// =================================================================================================

/**
 * ROUTE: List All Active Support Inquiries
 * GET /api/threads
 */
app.get('/api/threads', isAuth, async function(request, response) { 
    try {
        const inbox = await Thread.find().sort({ lastMessageAt: -1 }); 
        return response.json(inbox);
    } catch (dbErr) {
        console.error("[API] Failed to fetch thread list:");
        console.error(dbErr);
        return response.status(500).json({ error: "Read failure." });
    }
});

/**
 * ROUTE: Send Outbound Support Message
 * POST /api/reply
 */
app.post('/api/reply', isAuth, async function(request, response) {
    const id = request.body.threadId;
    const text = request.body.content;
    const file = request.body.fileBase64;
    const fileName = request.body.fileName;
    
    try {
        const thread = await Thread.findById(id);
        if (thread === null) {
            return response.status(404).json({ error: "Thread expired or deleted." });
        }
        
        const bot = clients.find(function(c) {
            return (c.user.id === thread.botId);
        });
        
        if (bot === undefined) {
            return response.status(500).json({ error: "Target gateway bot is offline." });
        }

        // Aggregate Staff Meta for injection
        const staffProfile = await Staff.findById(request.session.staffId);
        const avatar = staffProfile ? staffProfile.avatar : 'https://cdn.discordapp.com/embed/avatars/0.png';

        const userHandle = await bot.users.fetch(thread.userId);
        
        let embed = new EmbedBuilder()
            .setColor('#3b82f6')
            .setAuthor({ 
                name: `Staff Member: ${request.session.username}`, 
                iconURL: bot.user.displayAvatarURL() 
            })
            .setDescription(text || "[Attached File]")
            .setTimestamp();
        
        let payload = { embeds: [embed] };
        
        // Handle Media Attachment
        if (file) {
            console.log(`[REPLY] 📎 Injecting media: ${fileName}`);
            const buffer = Buffer.from(file.split(',')[1], 'base64');
            payload.files = [new AttachmentBuilder(buffer, { name: fileName || 'file.png' })];
        }
        
        // Execute Discord Dispatch
        await userHandle.send(payload);
        
        // Commit to Persistence
        const msg = { 
            authorTag: `Staff (${request.session.username})`, 
            authorAvatar: avatar, 
            content: text || "[Media Attachment]", 
            fromBot: true, 
            timestamp: new Date() 
        };
        
        thread.messages.push(msg);
        thread.lastMessageAt = new Date();
        await thread.save();
        
        // Update Statistics
        await Staff.findByIdAndUpdate(request.session.staffId, { 
            $inc: { repliesSent: 1 } 
        });
        
        // Push Real-time update to Socket
        io.emit('new_message', { 
            threadId: thread._id, 
            ...msg 
        });
        
        console.log(`[REPLY] 📤 Dispatch confirmed to ${thread.userTag}`);
        return response.json({ success: true });
    } catch (dispatchErr) { 
        console.error("[REPLY] ❌ Discord gateway rejection:");
        console.error(dispatchErr.message);
        return response.status(500).json({ error: "DM Dispatch Failed: Blocked or Restricted." }); 
    }
});

/**
 * ROUTE: Archive and Decommission Ticket
 * POST /api/close-thread
 */
app.post('/api/close-thread', isAuth, async function(request, response) {
    const id = request.body.threadId;
    const actor = request.session.username;
    
    console.log(`[CLOSE] 🔒 Archiving thread ${id}`);

    try {
        const doc = await Thread.findById(id);
        if (doc === null) {
            return response.status(404).json({ error: "Record not found." });
        }

        // 1. Serialization for Transcript
        let txt = `TSP SUPPORT ARCHIVE\n`;
        txt += `SUBJECT: ${doc.userTag}\n`;
        txt += `GATEWAY: ${doc.botName}\n`;
        txt += `CLOSING OFFICER: ${actor}\n`;
        txt += `==================================================\n\n`;
        
        doc.messages.forEach(function(m) { 
            txt += `[${m.timestamp.toISOString()}] ${m.authorTag}: ${m.content}\n`; 
        });
        
        const tmpPath = path.join(__dirname, `tmp-${doc.userId}.txt`);
        fs.writeFileSync(tmpPath, txt);
        
        // 2. Dispatch to Admin Log Channel
        const logFile = new AttachmentBuilder(tmpPath);
        await sendLog(
            "🔒 Support Inquiry Closed", 
            `**User:** ${doc.userTag}\n**Messages:** ${doc.messages.length}\n**Admin:** ${actor}`, 
            '#ef4444', 
            [logFile]
        );
        
        // 3. Persistent JSON Archive
        const userFolder = path.join(ARCHIVE_DIR, doc.userId);
        if (fs.existsSync(userFolder) === false) {
            fs.mkdirSync(userFolder, { recursive: true });
        }
        
        const filePath = path.join(userFolder, `${Date.now()}-${id}.json`);
        const archivePayload = {
            meta: { 
                closedBy: actor, 
                closedAt: new Date(), 
                userTag: doc.userTag,
                userId: doc.userId
            },
            history: doc.messages
        };
        fs.writeFileSync(filePath, JSON.stringify(archivePayload, null, 2));
        
        // 4. Client-Side Rating Trigger
        const dbId = request.session.staffId;
        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId(`rate_1_${dbId}`).setLabel('1⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_2_${dbId}`).setLabel('2⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_3_${dbId}`).setLabel('3⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_4_${dbId}`).setLabel('4⭐').setStyle(ButtonStyle.Primary),
            new ButtonBuilder().setCustomId(`rate_5_${dbId}`).setLabel('5⭐').setStyle(ButtonStyle.Success)
        );
        
        const ratingEmbed = new EmbedBuilder()
            .setTitle("Service Finalized")
            .setDescription(`Support with **${actor}** is complete. Please rate the quality of assistance provided.`)
            .setColor('#3b82f6');

        const bot = clients.find(function(c) {
            return (c.user.id === doc.botId);
        });
        
        if (bot) { 
            try { 
                const user = await bot.users.fetch(doc.userId); 
                await user.send({ embeds: [ratingEmbed], components: [row] }); 
            } catch(e) {
                console.log("[CLOSE] ⚠️ Rating DM blocked by user.");
            } 
        }

        // 5. Statistics Finalization
        await Staff.findByIdAndUpdate(request.session.staffId, { 
            $inc: { ticketsClosed: 1 } 
        });
        
        await Thread.findByIdAndDelete(id);
        
        // Cleanup
        if (fs.existsSync(tmpPath)) {
            fs.unlinkSync(tmpPath);
        }

        console.log(`[CLOSE] ✅ Decommission successful.`);
        return response.json({ success: true });
    } catch (criticalErr) { 
        console.error("[CLOSE] ❌ Sequence failure:");
        console.error(criticalErr);
        return response.status(500).json({ error: "Internal archival failure." }); 
    }
});


// =================================================================================================
//  SECTION 11: CRM AGGREGATION API
// =================================================================================================

/**
 * ROUTE: Aggregate User History
 * GET /api/crm/user/:discordId
 */
app.get('/api/crm/user/:discordId', isAuth, async function(request, response) {
    const id = request.params.discordId;
    
    try {
        const noteDoc = await UserNote.findOne({ userId: id });
        const archiveDir = path.join(ARCHIVE_DIR, id);
        
        let historicFiles = [];

        if (fs.existsSync(archiveDir)) {
            const files = fs.readdirSync(archiveDir).filter(function(f) {
                return f.endsWith('.json');
            });
            
            historicFiles = files.map(function(f) {
                try {
                    const data = JSON.parse(fs.readFileSync(path.join(archiveDir, f), 'utf8'));
                    return { 
                        filename: f, 
                        closedAt: data.meta.closedAt, 
                        closedBy: data.meta.closedBy 
                    };
                } catch (e) { return null; }
            }).filter(function(x) { 
                return x !== null; 
            }).sort(function(a, b) { 
                return new Date(b.closedAt) - new Date(a.closedAt); 
            });
        }

        return response.json({ 
            note: noteDoc ? noteDoc.note : "", 
            history: historicFiles 
        });
    } catch (e) {
        console.error("[CRM] Data aggregation failure:");
        console.error(e);
        return response.status(500).json({ error: "CRM aggregator failure." });
    }
});

/**
 * ROUTE: Retrieve Historic Data
 * GET /api/crm/transcript/:discordId/:filename
 */
app.get('/api/crm/transcript/:discordId/:filename', isAuth, function(request, response) {
    const userId = request.params.discordId;
    const fileName = request.params.filename;
    
    if (fileName.includes('..') || userId.includes('..')) {
        return response.status(403).json({ error: "Forbidden: Illegal path segments detected." });
    }
    
    const targetPath = path.join(ARCHIVE_DIR, userId, fileName);
    
    if (fs.existsSync(targetPath)) {
        try {
            const raw = fs.readFileSync(targetPath, 'utf8');
            return response.json(JSON.parse(raw));
        } catch (e) {
            return response.status(500).json({ error: "Corruption detected in archive." });
        }
    } else {
        return response.status(404).json({ error: "Archive record missing." });
    }
});

/**
 * ROUTE: Update CRM Notes
 * POST /api/crm/note
 */
app.post('/api/crm/note', isAuth, async function(request, response) {
    const userId = request.body.userId;
    const content = request.body.note;
    
    try {
        await UserNote.findOneAndUpdate(
            { userId: userId }, 
            { 
                note: content, 
                updatedBy: request.session.username, 
                updatedAt: new Date() 
            }, 
            { upsert: true, new: true }
        );
        console.log(`[CRM] 📝 Note modified for ${userId}`);
        return response.json({ success: true });
    } catch (e) {
        console.error("[CRM] Persistence failure:");
        console.error(e);
        return response.status(500).json({ error: "Database write error." });
    }
});


// =================================================================================================
//  SECTION 12: ADMINISTRATIVE SERVICE ENGINE API
// =================================================================================================

/**
 * ROUTE: Get Staff Analytics
 * GET /api/admin/stats
 */
app.get('/api/admin/stats', isAdmin, async function(request, response) { 
    try {
        const stats = await Staff.find().sort({ ticketsClosed: -1 }); 
        return response.json(stats); 
    } catch (e) {
        return response.status(500).json({ error: "Read failure." });
    }
});

/**
 * ROUTE: Get Global State
 * GET /api/admin/config
 */
app.get('/api/admin/config', isAdmin, async function(request, response) { 
    try {
        const cfg = await Config.findOne({ id: 'global' }); 
        return response.json(cfg); 
    } catch (e) {
        return response.status(500).json({ error: "Read failure." });
    }
});

/**
 * ROUTE: Update Support Health
 * POST /api/admin/config/toggle
 */
app.post('/api/admin/config/toggle', isAdmin, async function(request, response) { 
    const { status, note, openTime, closeTime } = request.body;
    
    try {
        const cfg = await Config.findOne({ id: 'global' }); 
        
        if (status !== undefined) { cfg.supportOnline = status; }
        if (note !== undefined) { cfg.offlineNote = note; }
        if (openTime) { cfg.openTime = openTime; }
        if (closeTime) { cfg.closeTime = closeTime; }
        
        await cfg.save(); 
        console.log(`[ADMIN] ⚙️ System health updated.`);
        return response.json({ success: true }); 
    } catch (e) {
        console.error("[ADMIN] Persistence failure.");
        return response.status(500).json({ error: "Write failure." });
    }
});

/**
 * ROUTE: Sync Active Servers
 * GET /api/admin/servers
 */
app.get('/api/admin/servers', isAdmin, async function(request, response) {
    let aggregate = [];
    
    clients.forEach(function(c) {
        if (c.isReady() === false) return;
        
        c.guilds.cache.forEach(function(g) {
            aggregate.push({
                id: g.id,
                name: g.name,
                members: g.memberCount,
                botName: c.user.username,
                botId: c.user.id
            });
        });
    });
    
    return response.json(aggregate);
});

// 12.1. FLEET GRANULAR CONTROL (NEW v10.6 Addition)

/**
 * ROUTE: Toggle Trading Module for Individual Bot
 * POST /api/admin/fleet/toggle-trading
 */
app.post('/api/admin/fleet/toggle-trading', isAdmin, async function(request, response) {
    const id = request.body.botId;
    const status = request.body.status;
    
    console.log(`[FLEET] ⚙️ Request: Toggle Bot ${id} trading state to ${status}`);

    try {
        const config = await Config.findOne({ id: 'global' });
        
        // Find existing record or create entry
        let botRecord = config.botFleetStatus.find(function(b) {
            return (b.botId === id);
        });

        if (botRecord) {
            botRecord.tradingActive = status;
        } else {
            config.botFleetStatus.push({ 
                botId: id, 
                tradingActive: status 
            });
        }
        
        await config.save();
        console.log(`[FLEET] ✅ State persisted for bot ${id}`);
        return response.json({ success: true });
    } catch (persistenceError) {
        console.error("[FLEET] ❌ Persistence failure in toggle routine:");
        console.error(persistenceError);
        return response.status(500).json({ error: "Database configuration write failure." });
    }
});

// 12.2. FLEET DEPLOYMENT TOOLS

app.post('/api/admin/leave-server', isAdmin, async function(req, res) {
    const sid = req.body.serverId;
    const bid = req.body.botId;
    try {
        const bot = clients.find(function(c) { return c.user.id === bid; });
        const guild = await bot.guilds.fetch(sid);
        await guild.leave();
        console.log(`[FLEET] 🚪 Bot ${bid} ejected from server ${sid}`);
        return res.json({ success: true });
    } catch (err) {
        return res.status(500).json({ error: "API rejection." });
    }
});

app.post('/api/admin/create-invite', isAdmin, async function(req, res) {
    const sid = req.body.serverId;
    const bid = req.body.botId;
    try {
        const bot = clients.find(function(c) { return c.user.id === bid; });
        const guild = await bot.guilds.fetch(sid);
        const channel = guild.channels.cache.find(function(ch) {
            return (ch.type === 0 && ch.permissionsFor(bot.user).has('CreateInstantInvite'));
        });
        
        if (channel) {
            const link = await channel.createInvite({ maxAge: 0, maxUses: 0 });
            return res.json({ url: link.url });
        } else {
            return res.status(403).json({ error: "Forbidden: Client lacks permissions." });
        }
    } catch (err) {
        return res.status(500).json({ error: "Logic failure." });
    }
});

app.post('/api/admin/dm-owner', isAdmin, async function(req, res) {
    const sid = req.body.serverId;
    const bid = req.body.botId;
    const text = req.body.message;
    try {
        const bot = clients.find(function(c) { return c.user.id === bid; });
        const guild = await bot.guilds.fetch(sid);
        const owner = await bot.users.fetch(guild.ownerId);
        
        await owner.send(`**Administrative Alert (${guild.name}):**\n${text}`);
        return res.json({ success: true });
    } catch (err) {
        return res.status(500).json({ error: "DM Dispatch Failure." });
    }
});

app.post('/api/admin/bulk-message', isAdmin, async function(req, res) {
    const msg = req.body.message;
    console.log(`[BROADCAST] 📢 Executing global DM sequence...`);
    
    let total = 0;
    for (const c of clients) {
        if (c.isReady() === false) continue;
        for (const [id, g] of c.guilds.cache) {
            try {
                const o = await c.users.fetch(g.ownerId);
                await o.send(`**Miraidon Trade Services Global Notification:**\n${msg}`);
                total++;
            } catch (err) { /* Blocked */ }
        }
    }
    
    console.log(`[BROADCAST] ✅ Sequence completed. Count: ${total}`);
    return res.json({ sentTo: total });
});

// 12.3. STAFF LIFECYCLE MANAGEMENT

app.post('/api/admin/staff/add', isAdmin, async function(req, res) {
    const { username, discordId, adminStatus } = req.body;
    
    try {
        const key = generateComplexPassword();
        const hash = await bcrypt.hash(key, 10);
        
        const doc = new Staff({ 
            username: username, 
            discordId: discordId, 
            password: hash, 
            isAdmin: adminStatus 
        });
        
        await doc.save();
        
        // Automated Dispatch
        try {
            const handle = await clients[0].users.fetch(discordId);
            const embed = new EmbedBuilder()
                .setTitle("Clearance Granted")
                .setDescription(`Administrative access created.\n\n**User:** \`${username}\`\n**Key:** \`${key}\`\n**URL:** ${getPanelUrl()}`)
                .setColor('#10b981');
            await handle.send({ embeds: [embed] });
        } catch (dmErr) {
            console.warn("[STAFF] ⚠️ Logic successful but DM failed.");
        }
        
        return res.json({ success: true });
    } catch (e) {
        return res.status(500).json({ error: "Persistence error." });
    }
});

app.post('/api/admin/staff/reset', isAdmin, async function(req, res) {
    const id = req.body.staffId;
    
    try {
        const staff = await Staff.findById(id);
        if (staff === null) {
            return res.status(404).json({ error: "Record not found." });
        }

        const key = generateComplexPassword();
        staff.password = await bcrypt.hash(key, 10);
        await staff.save();
        
        // Dispatch
        try {
            const handle = await clients[0].users.fetch(staff.discordId);
            const embed = new EmbedBuilder()
                .setTitle("Secure Key Reset")
                .setDescription(`An administrator has re-keyed your account.\n\n**Key:** \`${key}\``)
                .setColor('#f59e0b');
            await handle.send({ embeds: [embed] });
        } catch (dmErr) {
            console.warn("[STAFF] ⚠️ Re-key successful but DM failed.");
        }
        
        return res.json({ success: true });
    } catch (e) {
        return res.status(500).json({ error: "Logic error." });
    }
});

app.post('/api/admin/staff/delete', isAdmin, async function(req, res) {
    const id = req.body.staffId;
    
    if (id === req.session.staffId.toString()) {
        return res.status(400).json({ error: "Self-deletion prohibited." });
    }
    
    try {
        await Staff.findByIdAndDelete(id);
        return res.json({ success: true });
    } catch (e) {
        return res.status(500).json({ error: "DB deletion error." });
    }
});

/**
 * Administrative Feature: Manual Outbound Initialization
 * POST /api/admin/manual-dm
 */
app.post('/api/admin/manual-dm', isAdmin, async function(request, response) {
    const id = request.body.discordId;
    const text = request.body.content;
    const admin = request.session.username;
    
    try {
        const bot = clients[0];
        const user = await bot.users.fetch(id);
        
        const embed = new EmbedBuilder()
            .setColor('#3b82f6')
            .setAuthor({ 
                name: `System Admin: ${admin}`, 
                iconURL: bot.user.displayAvatarURL() 
            })
            .setDescription(text)
            .setTimestamp();
            
        await user.send({ embeds: [embed] });
        
        let thread = await Thread.findOne({ userId: id });
        
        if (thread === null) {
            thread = new Thread({ 
                userId: id, 
                userTag: user.tag, 
                userAvatar: user.displayAvatarURL({ extension: 'png' }), 
                botId: bot.user.id, 
                botName: bot.user.username, 
                messages: [] 
            });
            await sendLog("🆕 Manual Ticket", `Admin ${admin} initiated contact with ${user.tag}`, '#facc15');
        }
        
        const profile = await Staff.findById(request.session.staffId);
        
        const msg = { 
            authorTag: `Staff (${admin})`, 
            authorAvatar: profile ? profile.avatar : '',
            content: text, 
            fromBot: true, 
            timestamp: new Date() 
        };
        
        thread.messages.push(msg);
        thread.lastMessageAt = new Date();
        await thread.save();
        
        io.emit('new_message', { threadId: thread._id, ...msg });
        
        console.log(`[ADMIN] 📤 Outbound confirmed: ${user.tag}`);
        return response.json({ success: true });
    } catch (e) {
        console.error(`[ADMIN] ❌ Outbound failure: ${e.message}`);
        return response.status(500).json({ error: "Gateway rejection." });
    }
});


// =================================================================================================
//  SECTION 13: CONTENT AND LICENSE PERSISTENCE API
// =================================================================================================

// 13.1. STAFF MACRO API

app.get('/api/macros', isAuth, async function(req, res) {
    try {
        const list = await Macro.find().sort({ title: 1 });
        return res.json(list);
    } catch(e) { return res.status(500).json({error:"Read failure."}); }
});

app.post('/api/admin/macros/add', isAdmin, async function(req, res) {
    try {
        const doc = new Macro(req.body);
        await doc.save();
        return res.json({ success: true });
    } catch (e) { return res.status(500).json({ error: "Write failure." }); }
});

app.post('/api/admin/macros/delete', isAdmin, async function(req, res) {
    try {
        await Macro.findByIdAndDelete(req.body.id);
        return res.json({ success: true });
    } catch (e) { return res.status(500).json({ error: "Deletion failure." }); }
});

// 13.2. FAQ DATABASE API

app.get('/api/faq', async function(req, res) {
    try {
        const list = await FAQ.find().sort({ createdAt: 1 });
        return res.json(list);
    } catch(e) { return res.status(500).json({error:"Read failure."}); }
});

app.post('/api/admin/faq/add', isAdmin, async function(req, res) {
    try {
        const doc = new FAQ(req.body);
        await doc.save();
        return res.json({ success: true });
    } catch (e) { return res.status(500).json({ error: "Write failure." }); }
});

app.post('/api/admin/faq/delete', isAdmin, async function(req, res) {
    try {
        await FAQ.findByIdAndDelete(req.body.id);
        return res.json({ success: true });
    } catch (e) { return res.status(500).json({ error: "Deletion failure." }); }
});

// 13.3. LICENSE PROVISIONING (SELL.APP GATEWAY)

app.post('/api/admin/license/activate', isAdmin, async function(req, res) {
    const { license_key, instance_name, discord_id, duration, server_name, server_id, type } = req.body;
    
    console.log(`[LICENSE] 🚀 Handshaking with Sell.App for key: ${license_key}`);
    
    try {
        // API Execution
        const apiResponse = await axios.post('https://sell.app/api/v2/licenses/activate', { 
            license_key: license_key, 
            instance_name: instance_name 
        }, { 
            headers: { 
                'Authorization': `Bearer ${process.env.SELLAPP_TOKEN}`,
                'Content-Type': 'application/json' 
            } 
        });
        
        // Expiration Mapping
        let expiryDate = null; 
        if (duration !== 'Lifetime') {
            const count = parseInt(duration);
            if (isNaN(count) === false) {
                expiryDate = new Date(Date.now() + count * 24 * 60 * 60 * 1000);
            }
        }
        
        // Save to Cluster
        const record = new License({ 
            key: license_key,
            instanceId: instance_name,
            discordId: discord_id,
            serverId: server_id,
            serverName: server_name,
            type: type,
            duration: duration,
            activatedAt: new Date(),
            expiresAt: expiryDate,
            reviewRequestSent: false
        });
        await record.save();
        
        await sendLog("🔑 License Provisioned", `**User:** <@${discord_id}>\n**Server:** ${server_name}\n**Tier:** ${type}`, '#10b981');
        
        // Notify Customer
        try {
            const handle = await clients[0].users.fetch(discord_id);
            const embed = new EmbedBuilder()
                .setTitle("Service Activated ✅")
                .setDescription(`Your Miraidon Trade Services License is now linked to **${server_name}**.`)
                .addFields(
                    { name: "Product", value: type, inline: true },
                    { name: "Validity", value: duration, inline: true }
                )
                .setColor('#10b981')
                .setTimestamp();
            await handle.send({ embeds: [embed] });
        } catch (dmErr) {
            console.log("[LICENSE] ⚠️ Blocked DM.");
        }
        
        return res.json({ success: true });
    } catch (e) {
        console.error("[LICENSE] ❌ Activation Engine Error:");
        console.error(e.response ? e.response.data : e.message);
        return res.status(400).json({ error: "Rejection: Invalid Key or Instance mismatch." });
    }
});


// =================================================================================================
//  SECTION 14: SERVICE STATUS AGGREGATION (NEW v10.6 Addition)
// =================================================================================================

/**
 * ROUTE: Public Health Check
 * GET /api/status
 * Aggregates support window and bot trading states.
 */
app.get('/api/status', async function(req, res) {
    console.log("[HEALTH] 💓 Public heartbeat requested.");
    
    try {
        const cfg = await Config.findOne({ id: 'global' });
        
        // Time Calc (AST)
        const date = new Date();
        const parts = new Intl.DateTimeFormat('en-US', { timeZone: 'America/Halifax', hour12: false, hour: 'numeric', minute: 'numeric' }).formatToParts(date);
        const curMin = (parseInt(parts.find(p => p.type === 'hour').value) * 60) + parseInt(parts.find(p => p.type === 'minute').value);
        
        const [oH, oM] = cfg.openTime.split(':').map(Number);
        const [cH, cM] = cfg.closeTime.split(':').map(Number);
        
        const open = (oH * 60) + oM;
        const close = (cH * 60) + cM;

        const inWindow = (curMin >= open && curMin <= close);
        const deskStatus = (cfg.supportOnline && inWindow);

        // Fleet mapping
        const fleetData = clients.map(function(c) {
            const botConf = cfg.botFleetStatus.find(function(b) {
                return (b.botId === c.user.id);
            });
            
            return {
                name: c.user.username,
                isOnline: c.isReady(),
                isTrading: botConf ? botConf.tradingActive : true
            };
        });

        return res.json({ 
            support: { 
                isOpen: deskStatus, 
                window: `${cfg.openTime} - ${cfg.closeTime} AST`, 
                note: cfg.offlineNote 
            }, 
            fleet: fleetData 
        });
    } catch (healthError) {
        console.error("[HEALTH] ❌ Aggregator failure.");
        return res.status(500).json({ error: "Logic error." });
    }
});


// =================================================================================================
//  SECTION 15: AUTOMATION AND RECURRING MAINTENANCE (CRON)
// =================================================================================================

/**
 * TASK: checkExpirations
 * Interval: 60 minutes
 * Scans for licenses nearing 72-hour cutoff.
 */
async function checkExpirations() {
    console.log("[CRON] 🕒 Scanning expiry window...");
    
    const now = new Date();
    const future = new Date();
    future.setDate(now.getDate() + 3);
    
    try {
        const expiring = await License.find({ 
            expiresAt: { $gt: now, $lt: future }, 
            reminderSent: false 
        });

        for (const doc of expiring) {
            try {
                const user = await clients[0].users.fetch(doc.discordId);
                const embed = new EmbedBuilder()
                    .setTitle("⚠️ Service Interruption Imminent")
                    .setDescription(`Your license for **${doc.serverName || 'your guild'}** expires in less than 3 days.\n\nPlease visit https://miraidon.sell.app/ to purchase New License immediately.\nAfter Purchase DM us your License Key so we can update your subscription`)
                    .setColor('#f59e0b');
                    
                await user.send({ embeds: [embed] });
                
                doc.reminderSent = true;
                await doc.save();
                console.log(`[CRON] 📤 Expiry warning: ${doc.discordId}`);
            } catch (e) {
                console.warn(`[CRON] ⚠️ DM unreachable: ${doc.discordId}`);
            }
        }
    } catch (e) {
        console.error("[CRON] ❌ Query error.");
    }
}

/**
 * TASK: checkReviewEligibility
 * Interval: 60 minutes
 * Scans for 14-day milestones to request Trustpilot feedback.
 */
async function checkReviewEligibility() {
    console.log("[CRON] 🕒 Scanning review milestones...");
    
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - 14);

    try {
        const candidates = await License.find({
            activatedAt: { $lt: cutoff },
            reviewRequestSent: false
        });

        for (const target of candidates) {
            try {
                const user = await clients[0].users.fetch(target.discordId);
                
                const embed = new EmbedBuilder()
                    .setTitle("🌟 Your Opinion Matters")
                    .setColor('#10b981')
                    .setDescription("Two weeks ago, you activated a Licence Key for your community. We hope the speed and reliability have met your expectations.\n\nCould you spare 60 seconds to review us on **Trustpilot**?")
                    .addFields({ 
                        name: 'Trustpilot Page', 
                        value: 'https://www.trustpilot.com/review/miraidon.ca' 
                    });

                await user.send({ embeds: [embed] });
                
                target.reviewRequestSent = true;
                await target.save();
                console.log(`[CRON] 📤 Trustpilot request: ${target.discordId}`);
            } catch (e) {
                console.warn(`[CRON] ⚠️ Milestone DM failed: ${target.discordId}`);
                target.reviewRequestSent = true;
                await target.save();
            }
        }
    } catch (e) {
        console.error("[CRON] ❌ Milestone check failure.");
    }
}

// 15.1. CRON SCHEDULER (Hourly Execution)
setInterval(function() {
    checkExpirations();
    checkReviewEligibility();
}, 1000 * 60 * 60);


// =================================================================================================
//  SECTION 16: SYSTEM BOOTSTRAP AND LISTENER
// =================================================================================================

/**
 * FINAL BOOT SEQUENCE:
 * Opens the server to the global internet on the assigned PORT.
 */
const PORT = process.env.PORT || 10000;

server.listen(PORT, function() {
    console.log("================================================================================");
    console.log(`🚀 MIRAIDON MASTER CONTROLLER ACTIVE`);
    console.log(`📡 LISTENING ON PORT: ${PORT}`);
    console.log(`🛠️ VERSION: 10.6.1 (UNABRIDGED)`);
    console.log("================================================================================");
});
