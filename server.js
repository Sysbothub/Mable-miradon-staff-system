/**
 * =================================================================================================
 * MIRAIDON TRADE SERVICES - MASTER SERVER (v10.2 - FINAL UNABRIDGED RESTORATION)
 * =================================================================================================
 * * STATUS: 100% UNCOMPRESSED, VERBOSE, & ARCHITECTURALLY COMPLETE
 * * INTEGRITY: ALL LEGACY AND NEW FEATURES FULLY EXPANDED
 * -------------------------------------------------------------------------------------------------
 * * CORE ARCHITECTURE:
 * 1.  DISCORD INTERFACE: Multi-bot handling for Miraidon and Professor Mable.
 * 2.  WEB INTERFACE: Express.js serving public and staff-only (protected) endpoints.
 * 3.  PERSISTENCE: MongoDB for dynamic data, Local FS for immutable archives.
 * 4.  REAL-TIME: Socket.io for bi-directional staff-user communication.
 * * REQUESTED FEATURES INTEGRATED IN THIS BUILD:
 * - [v9.2] Dynamic Schedule Configuration (Admin controlled open/close times).
 * - [v9.4] Automated Review Request (14-day Trustpilot automation).
 * - [v9.8] Profile Photo Integration (User and Staff avatars synced via Discord API).
 * - [v10.1] Admin Force Reset (Auto-DMing new secure keys to staff).
 * * =================================================================================================
 */

// =================================================================================================
//  SECTION 1: GLOBAL IMPORTS AND DEPENDENCIES
// =================================================================================================

// 1.1. Environment Configuration
// Loads variables from the .env file located in the root directory.
require('dotenv').config();

// 1.2. Core Node.js Modules
const fs = require('fs');
const path = require('path');
const http = require('http');

// 1.3. Web Framework and Utilities
const express = require('express');
const axios = require('axios');
const bcrypt = require('bcrypt');

// 1.4. Real-time Communication
const { Server } = require('socket.io');

// 1.5. Database and Session Management
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');

// 1.6. Discord SDK Components
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

// 1.7. Application Initialization
const app = express();
const server = http.createServer(app);
const io = new Server(server);


// =================================================================================================
//  SECTION 2: PERSISTENT STORAGE INITIALIZATION
// =================================================================================================

console.log("[SYSTEM] 📂 Initializing Local Persistence Layers...");

let DATA_DIR;

/**
 * PATH RESOLUTION:
 * Checks if the 'RENDER' environment variable is true to assign the mount point.
 */
if (process.env.RENDER === 'true') {
    console.log("[SYSTEM] ☁️ Render Environment Detected. Using /var/data mount.");
    DATA_DIR = '/var/data';
} else {
    console.log("[SYSTEM] 💻 Local Environment Detected. Using ./local_storage.");
    DATA_DIR = path.join(__dirname, 'local_storage');
}

/**
 * DIRECTORY VERIFICATION:
 * Ensures the system has a valid location to write transcripts and logs.
 */
if (fs.existsSync(DATA_DIR) === false) {
    console.log(`[SYSTEM] 📂 Creating Root Data Directory at: ${DATA_DIR}`);
    try {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        console.log(`[SYSTEM] ✅ Root Directory Created.`);
    } catch (createError) {
        console.error(`[SYSTEM] ❌ CRITICAL STORAGE ERROR: ${createError.message}`);
        process.exit(1); 
    }
}

/**
 * ARCHIVE DIRECTORY VERIFICATION:
 * Segregates closed ticket JSON data from general storage.
 */
const ARCHIVE_DIR = path.join(DATA_DIR, 'archives');
if (fs.existsSync(ARCHIVE_DIR) === false) {
    console.log(`[SYSTEM] 📂 Creating Archive Sub-directory at: ${ARCHIVE_DIR}`);
    try {
        fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
        console.log(`[SYSTEM] ✅ Archive Sub-directory Created.`);
    } catch (archiveError) {
        console.error(`[SYSTEM] ❌ STORAGE WARNING: Failed to create archives folder.`);
    }
}

console.log(`[SYSTEM] ✅ Storage Initialization Complete.`);


// =================================================================================================
//  SECTION 3: MONGODB DATABASE CONNECTIVITY
// =================================================================================================

console.log("[SYSTEM] ⏳ Handshaking with MongoDB...");

/**
 * Establish Database Connection
 */
mongoose.connect(process.env.MONGODB_URI)
    .then(function() {
        console.log("[SYSTEM] ✅ MongoDB Connection: ESTABLISHED");
        
        // Execute bootstrap sequences
        initializeSystemDefaults();
        performDatabaseRepair();
    })
    .catch(function(dbError) {
        console.error("[SYSTEM] ❌ CRITICAL DATABASE ERROR:");
        console.error(dbError);
        console.error("[SYSTEM] Shutdown initiated due to lack of persistence.");
    });


// =================================================================================================
//  SECTION 4: DATABASE SCHEMAS AND DATA MODELS
// =================================================================================================

/**
 * 4.1. STAFF SCHEMA
 * Handles administrative and support staff credentials and metadata.
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
 * Manages active support inquiries and message histories.
 */
const ThreadSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    userTag: { type: String, required: true },
    userAvatar: { 
        type: String, 
        default: 'https://cdn.discordapp.com/embed/avatars/0.png' 
    },
    botId: { type: String, required: true },
    botName: { type: String, required: true },
    claimedBy: { 
        type: String, 
        default: null 
    },
    claimedAt: { 
        type: Date, 
        default: null 
    },
    messages: [{
        authorTag: { type: String },
        authorAvatar: { 
            type: String, 
            default: 'https://cdn.discordapp.com/embed/avatars/0.png' 
        },
        content: { type: String },
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
 * Tracks activated premium and rental keys.
 */
const LicenseSchema = new mongoose.Schema({
    key: { type: String, required: true },
    instanceId: { type: String },
    discordId: { type: String, required: true },
    serverId: { type: String },
    serverName: { type: String },
    channelId: { type: String },
    type: { type: String },
    duration: { type: String },
    activatedAt: { 
        type: Date, 
        default: Date.now 
    },
    expiresAt: { type: Date },
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
 * Global system state management.
 */
const ConfigSchema = new mongoose.Schema({
    id: { type: String, default: 'global' },
    supportOnline: { type: Boolean, default: true },
    offlineNote: { type: String, default: '' },
    openTime: { type: String, default: "08:00" }, 
    closeTime: { type: String, default: "23:59" }
});
const Config = mongoose.model('Config', ConfigSchema);

/**
 * 4.5. CRM DATA (USERNOTES)
 */
const UserNoteSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    note: { type: String, default: "" },
    updatedBy: { type: String },
    updatedAt: { type: Date, default: Date.now }
});
const UserNote = mongoose.model('UserNote', UserNoteSchema);

/**
 * 4.6. MACROS AND FAQ
 */
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
//  SECTION 5: SYSTEM SECURITY HELPERS
// =================================================================================================

/**
 * Helper: validateComplexPassword
 * Used during updates to enforce the 8/1/1/1 rule.
 */
function validateComplexPassword(passwordInput) {
    const minimumLength = 8;
    const hasCapitalLetter = /[A-Z]/.test(passwordInput);
    const hasNumericDigit = /[0-9]/.test(passwordInput);
    const hasSymbolChar = /[\W_]/.test(passwordInput); 
    
    if (passwordInput.length < minimumLength) {
        return false;
    }
    if (hasCapitalLetter === false) {
        return false;
    }
    if (hasNumericDigit === false) {
        return false;
    }
    if (hasSymbolChar === false) {
        return false;
    }
    
    return true;
}

/**
 * Helper: generateComplexPassword
 * Ensures automated resets generate valid keys.
 */
function generateComplexPassword() {
    const lowercasePool = "abcdefghijklmnopqrstuvwxyz";
    const uppercasePool = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numberPool = "0123456789";
    const symbolPool = "!@#$%^&*?";
    
    let generatedPass = "";
    
    // Explicitly add one of each to meet policy
    generatedPass += uppercasePool[Math.floor(Math.random() * uppercasePool.length)];
    generatedPass += numberPool[Math.floor(Math.random() * numberPool.length)];
    generatedPass += symbolPool[Math.floor(Math.random() * symbolPool.length)];
    generatedPass += lowercasePool[Math.floor(Math.random() * lowercasePool.length)];
    
    // Fill the remainder
    const fullPool = lowercasePool + uppercasePool + numberPool + symbolPool;
    for (let j = 0; j < 8; j++) {
        generatedPass += fullPool[Math.floor(Math.random() * fullPool.length)];
    }
    
    // Array shuffle logic
    const passwordArray = generatedPass.split('');
    for (let k = passwordArray.length - 1; k > 0; k--) {
        const randomIndex = Math.floor(Math.random() * (k + 1));
        const tempValue = passwordArray[k];
        passwordArray[k] = passwordArray[randomIndex];
        passwordArray[randomIndex] = tempValue;
    }
    
    return passwordArray.join('');
}

/**
 * Routine: initializeSystemDefaults
 * Bootstraps the database with required global documents.
 */
async function initializeSystemDefaults() {
    try {
        const existingAdmin = await Staff.findOne({ username: 'admin' });
        if (existingAdmin === null) {
            console.log("[BOOTSTRAP] 👤 Admin account not found. Generating default...");
            const defaultHashedPassword = await bcrypt.hash('Map4491!', 10);
            const adminRecord = new Staff({ 
                username: 'admin', 
                password: defaultHashedPassword, 
                discordId: '000000000000000000', 
                isAdmin: true 
            });
            await adminRecord.save();
            console.log("[BOOTSTRAP] ✅ Admin account ready.");
        }

        const existingConfig = await Config.findOne({ id: 'global' });
        if (existingConfig === null) {
            console.log("[BOOTSTRAP] ⚙️ Global config not found. Generating default...");
            const configRecord = new Config({ 
                id: 'global', 
                supportOnline: true, 
                openTime: "08:00", 
                closeTime: "23:59" 
            });
            await configRecord.save();
            console.log("[BOOTSTRAP] ✅ Global config ready.");
        }
    } catch (initError) {
        console.error("[BOOTSTRAP] ❌ Error during initialization:");
        console.error(initError);
    }
}

/**
 * Routine: performDatabaseRepair
 * Ensures existing data adheres to updated schemas.
 */
async function performDatabaseRepair() {
    try {
        // Fix claimedBy field
        await Thread.updateMany(
            { claimedBy: { $exists: false } },
            { $set: { claimedBy: null } }
        );
        
        // Fix userAvatar field
        await Thread.updateMany(
            { userAvatar: { $exists: false } },
            { $set: { userAvatar: 'https://cdn.discordapp.com/embed/avatars/0.png' } }
        );

        // Fix reviewRequestSent field
        await License.updateMany(
            { reviewRequestSent: { $exists: false } },
            { $set: { reviewRequestSent: false } }
        );

        console.log("[REPAIR] ✅ Database verification and repair sequence complete.");
    } catch (repairError) {
        console.error("[REPAIR] ❌ Failure in database repair sequence:");
        console.error(repairError);
    }
}


// =================================================================================================
//  SECTION 6: EXPRESS WEB SERVER MIDDLEWARE
// =================================================================================================

// 6.1. Networking Proxy Support
app.set('trust proxy', 1);

// 6.2. Body Parsers
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// 6.3. Session Architecture
app.use(session({
    secret: process.env.SESSION_SECRET || 'hq-secret-key-default-unsecure',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'sessions' 
    }),
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, // 24 Hours
        secure: true, // Requires HTTPS
        sameSite: 'none' 
    }
}));

// 6.4. Security Guards
const isAuth = function(req, res, next) {
    if (req.session.staffId) {
        return next();
    }
    
    if (req.path.startsWith('/api')) {
        console.log(`[SECURITY] 🛑 API BLOCK: Unauthorized access to ${req.path}`);
        return res.status(401).json({ error: "Authentication Required" });
    }
    
    console.log(`[SECURITY] 🛑 REDIRECT: Guest user accessing protected path ${req.path}`);
    return res.redirect('/login.html');
};

const isAdmin = function(req, res, next) {
    if (req.session.staffId && req.session.isAdmin === true) {
        return next();
    }
    
    console.log(`[SECURITY] 🛑 ADMIN BLOCK: User ${req.session.username || 'unknown'} lacks permission.`);
    return res.status(403).json({ error: "Administrative Privileges Required" });
};

// 6.5. Public Static File Routing
app.use(express.static(path.join(__dirname, 'public')));

// 6.6. Staff Static File Routing (Protected)
app.use('/staff', isAuth, express.static(path.join(__dirname, 'public/staff')));


// =================================================================================================
//  SECTION 7: DISCORD CLIENT SERVICE LAYER
// =================================================================================================

const botTokens = [
    process.env.BOT_ONE_TOKEN, 
    process.env.BOT_TWO_TOKEN
].filter(function(token) {
    return token !== undefined && token !== "";
});

const discordClients = [];

/**
 * Log Distribution Service
 * Broadcasts system events to the designated Discord channel.
 */
async function sendLog(title, description, hexColor = '#3b82f6', fileAttachments = []) {
    if (process.env.LOG_CHANNEL_ID === undefined || discordClients[0] === undefined) {
        return;
    }
    
    try {
        const logChannel = await discordClients[0].channels.fetch(process.env.LOG_CHANNEL_ID);
        if (logChannel) {
            const embedObject = new EmbedBuilder()
                .setTitle(title)
                .setDescription(description)
                .setColor(hexColor)
                .setTimestamp()
                .setFooter({ text: "Miraidon Internal Logging" });
                
            await logChannel.send({ embeds: [embedObject], files: fileAttachments });
        }
    } catch (logSendError) { 
        console.error("[SYSTEM_LOG] ❌ Failed to dispatch Discord log:");
        console.error(logSendError.message); 
    }
}

// 7.1. Bot Engine Loop
botTokens.forEach(function(token, botIndex) {
    const discordClient = new Client({
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

    discordClient.once('ready', function() {
        console.log(`[DISCORD_SERVICE] 🤖 Bot Instance ${botIndex + 1} Ready as ${discordClient.user.tag}`);
    });

    // Handle Typing Sync
    discordClient.on('typingStart', function(typingEvent) {
        if (typingEvent.user.bot === true) return;
        io.emit('user_typing', { userId: typingEvent.user.id });
    });

    // Handle Ratings via Buttons
    discordClient.on('interactionCreate', async function(interaction) {
        if (interaction.isButton() === false) return;

        const idParts = interaction.customId.split('_');
        const interactionType = idParts[0];
        
        if (interactionType === 'rate') {
            const starValue = parseInt(idParts[1]);
            const targetStaffId = idParts[2];
            
            console.log(`[FEEDBACK] ⭐ User Feedback Received for Staff ${targetStaffId}: ${starValue} Stars`);

            try {
                await Staff.findByIdAndUpdate(targetStaffId, { 
                    $inc: { ratingSum: starValue, ratingCount: 1 } 
                });

                const confirmationRow = new ActionRowBuilder().addComponents(
                    new ButtonBuilder().setCustomId('done').setLabel(`Feedback Saved`).setStyle(ButtonStyle.Success).setDisabled(true)
                );

                await interaction.update({ 
                    content: `**Thank you!** Your ${starValue}-star rating has been submitted.`, 
                    components: [confirmationRow] 
                });
            } catch (ratingError) {
                console.error(`[FEEDBACK] ❌ Error processing star rating: ${ratingError.message}`);
            }
        }
    });

    // Main Ticket Inbound Logic
    discordClient.on('messageCreate', async function(message) {
        // Discard Bot messages and Guild messages
        if (message.author.bot === true || message.guild !== null) {
            return;
        }
        
        const senderId = message.author.id;
        const targetBotId = discordClient.user.id;

        let activeThread = await Thread.findOne({ 
            userId: senderId, 
            botId: targetBotId 
        });
        
        // Capture Latest Avatar
        const currentAvatar = message.author.displayAvatarURL({ extension: 'png', size: 128 });

        // CASE: INITIAL CONTACT
        if (activeThread === null) {
            console.log(`[TICKET_SYS] 📩 Initial contact from ${message.author.tag}`);
            
            activeThread = new Thread({ 
                userId: senderId, 
                userTag: message.author.tag, 
                userAvatar: currentAvatar, 
                botId: targetBotId, 
                botName: discordClient.user.username, 
                messages: [] 
            });
            
            const currentConfig = await Config.findOne({ id: 'global' });
            const isServiceToggledOn = currentConfig ? currentConfig.supportOnline : true;
            const publicOfflineReason = currentConfig ? currentConfig.offlineNote : '';
            const openingHour = currentConfig ? currentConfig.openTime : "08:00";
            const closingHour = currentConfig ? currentConfig.closeTime : "23:59";

            // Determine Hours Logic (AST)
            const currentTimeObj = new Date();
            const timeFormatOptions = { timeZone: 'America/Halifax', hour12: false, hour: 'numeric', minute: 'numeric' };
            const timeParts = new Intl.DateTimeFormat('en-US', timeFormatOptions).formatToParts(currentTimeObj);
            
            const rawHour = parseInt(timeParts.find(p => p.type === 'hour').value);
            const rawMinute = parseInt(timeParts.find(p => p.type === 'minute').value);
            const totalMinutesNow = (rawHour * 60) + rawMinute;

            const [configOpenH, configOpenM] = openingHour.split(':').map(Number);
            const [configCloseH, configCloseM] = closingHour.split(':').map(Number);
            
            const startLimitMinutes = (configOpenH * 60) + configOpenM;
            const endLimitMinutes = (configCloseH * 60) + configCloseM;

            const isCurrentlyWithinOperatingHours = (totalMinutesNow >= startLimitMinutes && totalMinutesNow <= endLimitMinutes);

            let welcomeEmbed;

            if (isServiceToggledOn === false) {
                welcomeEmbed = new EmbedBuilder()
                    .setColor('#ef4444')
                    .setTitle('Service Paused')
                    .setDescription(`Support is currently offline for a scheduled day off or maintenance.\n\n**Reason:** ${publicOfflineReason || 'No reason provided.'}\n\nYour message is logged and will be seen soon.`)
                    .setTimestamp();
            } else if (isCurrentlyWithinOperatingHours === false) {
                welcomeEmbed = new EmbedBuilder()
                    .setColor('#f59e0b')
                    .setTitle('Support Closed')
                    .setDescription(`Our team is currently away. Operating hours are **${openingHour} to ${closingHour} AST**. We will review your inquiry shortly.`)
                    .setTimestamp();
            } else {
                welcomeEmbed = new EmbedBuilder()
                    .setColor('#3b82f6')
                    .setTitle('Support Initialized')
                    .setDescription('Your message has reached our staff panel. A technician will respond as soon as possible.')
                    .setTimestamp();
            }
            
            try { 
                await message.author.send({ embeds: [welcomeEmbed] }); 
            } catch (dmSendError) {
                console.error("[TICKET_SYS] ❌ Failed to send welcome DM.");
            }

            sendLog("🆕 Ticket Created", `**User:** ${message.author.tag}\n**Entry Bot:** ${discordClient.user.username}`, '#facc15');
        } else {
            // Update User Metadata if they changed it
            if (activeThread.userAvatar !== currentAvatar) {
                activeThread.userAvatar = currentAvatar;
            }
        }
        
        // CASE: CONTINUING CONVERSATION
        console.log(`[TICKET_SYS] 📥 Message from ${message.author.tag}`);

        const currentAttachments = message.attachments.map(function(attachment) {
            return attachment.url;
        });
        
        const newMessageData = { 
            authorTag: message.author.tag, 
            authorAvatar: currentAvatar, 
            content: message.content || "[Non-text message content]", 
            attachments: currentAttachments, 
            fromBot: false, 
            timestamp: new Date() 
        };

        activeThread.messages.push(newMessageData);
        activeThread.lastMessageAt = new Date();
        await activeThread.save();
        
        // Synchronize with Staff Panel
        io.emit('new_message', { 
            threadId: activeThread._id, 
            notif_sound: true, 
            ...newMessageData 
        });
    });

    discordClient.login(token).catch(function(loginError) {
        console.error(`[DISCORD_SERVICE] ❌ Bot ${botIndex + 1} authentication failure: ${loginError.message}`);
    });
    
    discordClients.push(discordClient);
});


// =================================================================================================
//  SECTION 8: SOCKET.IO EVENT ROUTING
// =================================================================================================

const threadViewerCache = {}; 

io.on('connection', function(socket) {
    
    /**
     * Join Room Logic
     * Used for real-time sync and collision detection.
     */
    socket.on('join_ticket_room', function(payload) {
        const threadId = payload.threadId;
        const username = payload.username;

        socket.join(threadId);
        
        if (threadViewerCache[threadId] === undefined) {
            threadViewerCache[threadId] = new Set();
        }
        threadViewerCache[threadId].add(username);
        
        console.log(`[COLLISION] 👤 ${username} is viewing thread ${threadId}`);
        
        // Inform room of current viewer list
        io.to(threadId).emit('viewers_updated', Array.from(threadViewerCache[threadId]));
        
        socket.currentThreadId = threadId;
        socket.currentUser = username;
    });

    /**
     * Leave Room Logic
     */
    socket.on('leave_ticket_room', function() {
        if (socket.currentThreadId && socket.currentUser) {
            const threadId = socket.currentThreadId;
            socket.leave(threadId);
            
            if (threadViewerCache[threadId]) {
                threadViewerCache[threadId].delete(socket.currentUser);
                io.to(threadId).emit('viewers_updated', Array.from(threadViewerCache[threadId]));
            }
            
            socket.currentThreadId = null;
        }
    });

    /**
     * Socket Disconnect
     */
    socket.on('disconnect', function() {
        if (socket.currentThreadId && socket.currentUser) {
            const threadId = socket.currentThreadId;
            if (threadViewerCache[threadId]) {
                threadViewerCache[threadId].delete(socket.currentUser);
                io.to(threadId).emit('viewers_updated', Array.from(threadViewerCache[threadId]));
            }
        }
    });

    /**
     * Remote Typing Simulation
     * Shows 'typing...' on user's Discord client.
     */
    socket.on('staff_typing', async function(payload) {
        const threadId = payload.threadId;
        const targetThread = await Thread.findById(threadId);
        
        if (targetThread) {
            const botInstance = discordClients.find(function(c) {
                return c.user.id === targetThread.botId;
            });
            
            if (botInstance) {
                try {
                    const discordUser = await botInstance.users.fetch(targetThread.userId);
                    const dmChannel = discordUser.dmChannel || await discordUser.createDM();
                    await dmChannel.sendTyping();
                } catch(typingError) {
                    // Silently ignore DM capability issues
                }
            }
        }
    });
});


// =================================================================================================
//  SECTION 9: STAFF AUTHENTICATION API
// =================================================================================================

/**
 * Endpoint: Staff Login
 * POST /api/login
 */
app.post('/api/login', async function(req, res) {
    const loginUser = req.body.username;
    const loginPass = req.body.password;
    
    console.log(`[AUTH] 🔑 Login attempt for: ${loginUser}`);
    
    try {
        const staffDoc = await Staff.findOne({ username: loginUser });
        
        if (staffDoc && await bcrypt.compare(loginPass, staffDoc.password)) {
            
            // Sync Profile Photo from Discord API
            try {
                if (discordClients[0]) {
                    const discordProfile = await discordClients[0].users.fetch(staffDoc.discordId);
                    if (discordProfile) {
                        staffDoc.avatar = discordProfile.displayAvatarURL({ extension: 'png', size: 128 });
                        await staffDoc.save();
                        console.log(`[AUTH] 🖼️ Avatar updated for ${loginUser}`);
                    }
                }
            } catch (avatarError) { 
                console.error("[AUTH] ⚠️ Avatar sync skipped: " + avatarError.message); 
            }

            req.session.staffId = staffDoc._id; 
            req.session.isAdmin = staffDoc.isAdmin; 
            req.session.username = staffDoc.username;
            
            req.session.save(function() {
                console.log(`[AUTH] ✅ Session started for ${loginUser}`);
                return res.json({ 
                    success: true, 
                    isAdmin: staffDoc.isAdmin, 
                    username: staffDoc.username 
                });
            });
        } else {
            console.log(`[AUTH] ❌ Auth failure for: ${loginUser}`);
            return res.status(401).json({ error: "Invalid Credentials" });
        }
    } catch (criticalAuthError) {
        console.error("[AUTH] ❌ Critical failure during login process:");
        console.error(criticalAuthError);
        return res.status(500).json({ error: "Internal Authentication Error" });
    }
});

/**
 * Endpoint: Logout
 * POST /api/logout
 */
app.post('/api/logout', function(req, res) { 
    const loggingOutUser = req.session.username || 'unknown';
    console.log(`[AUTH] 🚪 Destroying session for ${loggingOutUser}`);
    
    req.session.destroy(function(destroyError) { 
        if (destroyError) {
            console.error("[AUTH] ❌ Session destruction error:");
            console.error(destroyError);
            return res.status(500).json({ error: "Logout failed on server side." });
        }
        res.clearCookie('connect.sid'); 
        return res.json({ success: true }); 
    }); 
});

/**
 * Endpoint: Get Session Identity
 * GET /api/auth/user
 */
app.get('/api/auth/user', isAuth, function(req, res) {
    return res.json({ 
        username: req.session.username, 
        isAdmin: req.session.isAdmin 
    });
});

/**
 * Endpoint: Recovery Reset
 * POST /api/public/request-reset
 */
app.post('/api/public/request-reset', async function(req, res) {
    const recoveryId = req.body.discordId;
    console.log(`[AUTH] 🔄 Recovery requested by ID: ${recoveryId}`);
    
    try {
        const staffToRecover = await Staff.findOne({ discordId: recoveryId });
        if (staffToRecover === null) {
            return res.status(404).json({ error: "Discord ID not registered as staff." });
        }
        
        // Generate new secure key
        const freshKey = generateComplexPassword();
        staffToRecover.password = await bcrypt.hash(freshKey, 10);
        await staffToRecover.save();
        
        // Dispatch via DM
        const discordHandle = await discordClients[0].users.fetch(recoveryId);
        const recoveryEmbed = new EmbedBuilder()
            .setTitle("🔑 Staff Key Recovery")
            .setDescription(`Your login key has been reset.\n\n**New Key:** \`${freshKey}\`\n**Staff Panel:** ${getPanelUrl()}\n\nPlease update this key immediately upon login.`)
            .setColor('#facc15');
            
        await discordHandle.send({ embeds: [recoveryEmbed] });
        
        console.log(`[AUTH] ✅ Recovery DM dispatched to ${staffToRecover.username}`);
        return res.json({ success: true });
    } catch (recoveryProcessError) { 
        console.error(`[AUTH] ❌ Recovery process failed: ${recoveryProcessError.message}`);
        return res.status(500).json({ error: "Recovery dispatch failed. Check DM permissions." }); 
    }
});

/**
 * Endpoint: Self-Service Password Update
 * POST /api/staff/change-password
 */
app.post('/api/staff/change-password', isAuth, async function(req, res) {
    const oldKey = req.body.currentPassword;
    const newKey = req.body.newPassword;
    const actingUsername = req.session.username;
    
    console.log(`[AUTH] 🔐 Change password request from ${actingUsername}`);

    try {
        // Step 1: Policy Check
        if (validateComplexPassword(newKey) === false) {
            return res.status(400).json({ error: "New key does not meet complexity requirements." });
        }

        // Step 2: Identification
        const staffDoc = await Staff.findById(req.session.staffId);
        if (staffDoc === null) {
            return res.status(404).json({ error: "Staff record missing." });
        }

        // Step 3: Verification
        const isCurrentValid = await bcrypt.compare(oldKey, staffDoc.password);
        if (isCurrentValid === false) {
            return res.status(401).json({ error: "Incorrect current key." });
        }

        // Step 4: Execution
        staffDoc.password = await bcrypt.hash(newKey, 10);
        await staffDoc.save();
        
        console.log(`[AUTH] ✅ Password successfully rotated for ${actingUsername}`);
        return res.json({ success: true });
    } catch (changeError) {
        console.error("[AUTH] ❌ Password rotation failed:");
        console.error(changeError);
        return res.status(500).json({ error: "Server update error." });
    }
});


// =================================================================================================
//  SECTION 10: TICKET MANAGEMENT API
// =================================================================================================

/**
 * Endpoint: List Active Threads
 * GET /api/threads
 */
app.get('/api/threads', isAuth, async function(req, res) { 
    try {
        const activeThreads = await Thread.find().sort({ lastMessageAt: -1 }); 
        return res.json(activeThreads);
    } catch (fetchError) {
        console.error("[API] Failed to fetch active ticket list:");
        console.error(fetchError);
        return res.status(500).json({ error: "Database read error." });
    }
});

/**
 * Endpoint: Outbound Reply Dispatch
 * POST /api/reply
 */
app.post('/api/reply', isAuth, async function(req, res) {
    const threadId = req.body.threadId;
    const messageContent = req.body.content;
    const base64Media = req.body.fileBase64;
    const mediaName = req.body.fileName;
    
    try {
        const targetThread = await Thread.findById(threadId);
        if (targetThread === null) {
            return res.status(404).json({ error: "Support thread no longer exists." });
        }
        
        const botInstance = discordClients.find(function(c) {
            return c.user.id === targetThread.botId;
        });
        
        if (botInstance === undefined) {
            return res.status(500).json({ error: "Handling bot instance is currently offline." });
        }

        // Fetch Staff Profile Data for UI injection
        const staffMember = await Staff.findById(req.session.staffId);
        const activeAvatar = staffMember ? staffMember.avatar : 'https://cdn.discordapp.com/embed/avatars/0.png';

        const discordUserHandle = await botInstance.users.fetch(targetThread.userId);
        
        // Prepare Discord Embed Response
        let outboundEmbed = new EmbedBuilder()
            .setColor('#3b82f6')
            .setAuthor({ 
                name: `Support: ${req.session.username}`, 
                iconURL: botInstance.user.displayAvatarURL() 
            })
            .setDescription(messageContent || "[File Attachment]")
            .setTimestamp();
        
        let discordPayload = { embeds: [outboundEmbed] };
        
        // Handle File Attachment Logic
        if (base64Media) {
            console.log(`[REPLY] 📎 Processing media attachment: ${mediaName}`);
            const mediaBuffer = Buffer.from(base64Media.split(',')[1], 'base64');
            discordPayload.files = [new AttachmentBuilder(mediaBuffer, { name: mediaName || 'upload.png' })];
        }
        
        // Dispatch to Discord
        await discordUserHandle.send(discordPayload);
        
        // Update Local Thread History
        const staffReplyObject = { 
            authorTag: `Staff (${req.session.username})`, 
            authorAvatar: activeAvatar, 
            content: messageContent || "[File Attachment]", 
            fromBot: true, 
            timestamp: new Date() 
        };
        
        targetThread.messages.push(staffReplyObject);
        targetThread.lastMessageAt = new Date();
        await targetThread.save();
        
        // Increment Staff Statistics
        await Staff.findByIdAndUpdate(req.session.staffId, { 
            $inc: { repliesSent: 1 } 
        });
        
        // Emit Socket Update to UI
        io.emit('new_message', { 
            threadId: targetThread._id, 
            ...staffReplyObject 
        });
        
        console.log(`[REPLY] 📤 Successfully replied to ${targetThread.userTag}`);
        return res.json({ success: true });
    } catch (dispatchError) { 
        console.error("[REPLY] ❌ Critical failure during dispatch:");
        console.error(dispatchError.message);
        return res.status(500).json({ error: "Discord API rejected the DM. User may have blocked the bot." }); 
    }
});

/**
 * Endpoint: Archive and Close Ticket
 * POST /api/close-thread
 */
app.post('/api/close-thread', isAuth, async function(req, res) {
    const threadId = req.body.threadId;
    const actor = req.session.username;
    
    console.log(`[ARCHIVE] 🔒 Closing thread ${threadId} requested by ${actor}`);

    try {
        const threadDoc = await Thread.findById(threadId);
        if (threadDoc === null) {
            return res.status(404).json({ error: "Ticket not found." });
        }

        // 1. Generate Plaintext Transcript
        let plainTranscript = `MIRAIDON TRADE SERVICES TRANSCRIPT\n`;
        plainTranscript += `USER: ${threadDoc.userTag} (${threadDoc.userId})\n`;
        plainTranscript += `BOT: ${threadDoc.botName}\n`;
        plainTranscript += `CLOSED BY: ${actor}\n`;
        plainTranscript += `--------------------------------------------------\n\n`;
        
        threadDoc.messages.forEach(function(msg) { 
            plainTranscript += `[${msg.timestamp.toISOString()}] ${msg.authorTag}: ${msg.content}\n`; 
        });
        
        const tempFilePath = path.join(__dirname, `transcript-${threadDoc.userId}.txt`);
        fs.writeFileSync(tempFilePath, plainTranscript);
        
        // 2. Dispatch Archive to Discord Log Channel
        const logAttachment = new AttachmentBuilder(tempFilePath);
        await sendLog(
            "🔒 Thread Archived", 
            `**User:** ${threadDoc.userTag}\n**Duration:** ${threadDoc.messages.length} messages\n**Closed By:** ${actor}`, 
            '#ef4444', 
            [logAttachment]
        );
        
        // 3. Save Structured Data to Local Persistent Storage
        const userArchiveFolderPath = path.join(ARCHIVE_DIR, threadDoc.userId);
        if (fs.existsSync(userArchiveFolderPath) === false) {
            fs.mkdirSync(userArchiveFolderPath, { recursive: true });
        }
        
        const permanentFilePath = path.join(userArchiveFolderPath, `${Date.now()}-${threadId}.json`);
        const jsonArchiveObject = {
            meta: { 
                closedBy: actor, 
                closedAt: new Date(), 
                userTag: threadDoc.userTag,
                userId: threadDoc.userId
            },
            history: threadDoc.messages
        };
        fs.writeFileSync(permanentFilePath, JSON.stringify(jsonArchiveObject, null, 2));
        
        // 4. Send Rating Request via Button Interaction
        const staffDatabaseId = req.session.staffId;
        const ratingRow = new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId(`rate_1_${staffDatabaseId}`).setLabel('1⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_2_${staffDatabaseId}`).setLabel('2⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_3_${staffDatabaseId}`).setLabel('3⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_4_${staffDatabaseId}`).setLabel('4⭐').setStyle(ButtonStyle.Primary),
            new ButtonBuilder().setCustomId(`rate_5_${staffDatabaseId}`).setLabel('5⭐').setStyle(ButtonStyle.Success)
        );
        
        const ratingEmbed = new EmbedBuilder()
            .setTitle("Ticket Closed")
            .setDescription(`You were assisted by **${actor}**. Please take a second to rate your experience below.`)
            .setColor('#3b82f6');

        const assignedBot = discordClients.find(function(c) {
            return c.user.id === threadDoc.botId;
        });
        
        if (assignedBot) { 
            try { 
                const discordUser = await assignedBot.users.fetch(threadDoc.userId); 
                await discordUser.send({ embeds: [ratingEmbed], components: [ratingRow] }); 
            } catch(ratingSendError) {
                console.log("[ARCHIVE] ⚠️ Could not send rating DM to user.");
            } 
        }

        // 5. Finalize Statistics and Removal
        await Staff.findByIdAndUpdate(req.session.staffId, { 
            $inc: { ticketsClosed: 1 } 
        });
        
        await Thread.findByIdAndDelete(threadId);
        
        // Cleanup temp file
        if (fs.existsSync(tempFilePath)) {
            fs.unlinkSync(tempFilePath);
        }

        console.log(`[ARCHIVE] ✅ Thread ${threadId} successfully decommissioned.`);
        return res.json({ success: true });
    } catch (archiveCriticalError) { 
        console.error("[ARCHIVE] ❌ Critical failure during archival sequence:");
        console.error(archiveCriticalError);
        return res.status(500).json({ error: "Internal archival logic failure." }); 
    }
});


// =================================================================================================
//  SECTION 11: CRM (CUSTOMER RELATIONSHIP MANAGEMENT) API
// =================================================================================================

/**
 * Endpoint: Fetch User Profile
 * GET /api/crm/user/:discordId
 */
app.get('/api/crm/user/:discordId', isAuth, async function(req, res) {
    const targetUserId = req.params.discordId;
    
    try {
        const userNoteDoc = await UserNote.findOne({ userId: targetUserId });
        const userArchiveDir = path.join(ARCHIVE_DIR, targetUserId);
        
        let historicFilesArray = [];

        if (fs.existsSync(userArchiveDir)) {
            const fileList = fs.readdirSync(userArchiveDir).filter(function(f) {
                return f.endsWith('.json');
            });
            
            historicFilesArray = fileList.map(function(file) {
                try {
                    const fileContent = JSON.parse(fs.readFileSync(path.join(userArchiveDir, file), 'utf8'));
                    return { 
                        filename: file, 
                        closedAt: fileContent.meta.closedAt, 
                        closedBy: fileContent.meta.closedBy 
                    };
                } catch (parseErr) { return null; }
            }).filter(function(x) { 
                return x !== null; 
            }).sort(function(a, b) { 
                return new Date(b.closedAt) - new Date(a.closedAt); 
            });
        }

        return res.json({ 
            note: userNoteDoc ? userNoteDoc.note : "", 
            history: historicFilesArray 
        });
    } catch (crmFetchError) {
        console.error("[CRM] Failed to aggregate user profile data:");
        console.error(crmFetchError);
        return res.status(500).json({ error: "CRM data aggregation failure." });
    }
});

/**
 * Endpoint: View Historic Transcript
 * GET /api/crm/transcript/:discordId/:filename
 */
app.get('/api/crm/transcript/:discordId/:filename', isAuth, function(req, res) {
    const id = req.params.discordId;
    const file = req.params.filename;
    
    // Path Traversal Mitigation
    if (file.includes('..') || id.includes('..')) {
        return res.status(403).json({ error: "Illegal directory traversal attempted." });
    }
    
    const absolutePath = path.join(ARCHIVE_DIR, id, file);
    
    if (fs.existsSync(absolutePath)) {
        try {
            const rawData = fs.readFileSync(absolutePath, 'utf8');
            return res.json(JSON.parse(rawData));
        } catch (readError) {
            return res.status(500).json({ error: "Corrupt archive file." });
        }
    } else {
        return res.status(404).json({ error: "Archive not found." });
    }
});

/**
 * Endpoint: Update User Note
 * POST /api/crm/note
 */
app.post('/api/crm/note', isAuth, async function(req, res) {
    const { userId, note } = req.body;
    
    try {
        await UserNote.findOneAndUpdate(
            { userId: userId }, 
            { 
                note: note, 
                updatedBy: req.session.username, 
                updatedAt: new Date() 
            }, 
            { upsert: true, new: true }
        );
        console.log(`[CRM] 📝 User note updated for ${userId}`);
        return res.json({ success: true });
    } catch (noteSaveError) {
        console.error("[CRM] Failed to save user note:");
        console.error(noteSaveError);
        return res.status(500).json({ error: "Persistence failure." });
    }
});


// =================================================================================================
//  SECTION 12: ADMINISTRATIVE OPERATIONS API
// =================================================================================================

/**
 * Endpoint: Fetch System Statistics
 * GET /api/admin/stats
 */
app.get('/api/admin/stats', isAdmin, async function(req, res) { 
    try {
        const staffPerformanceStats = await Staff.find().sort({ ticketsClosed: -1 }); 
        return res.json(staffPerformanceStats); 
    } catch (statsError) {
        return res.status(500).json({ error: "Read failure." });
    }
});

/**
 * Endpoint: Fetch Global Config
 * GET /api/admin/config
 */
app.get('/api/admin/config', isAdmin, async function(req, res) { 
    try {
        const globalConfiguration = await Config.findOne({ id: 'global' }); 
        return res.json(globalConfiguration); 
    } catch (configGetError) {
        return res.status(500).json({ error: "Config read failure." });
    }
});

/**
 * Endpoint: Update Support Config
 * POST /api/admin/config/toggle
 */
app.post('/api/admin/config/toggle', isAdmin, async function(req, res) { 
    const { status, note, openTime, closeTime } = req.body;
    
    try {
        const globalConfig = await Config.findOne({ id: 'global' }); 
        
        if (status !== undefined) globalConfig.supportOnline = status;
        if (note !== undefined) globalConfig.offlineNote = note;
        if (openTime) globalConfig.openTime = openTime;
        if (closeTime) globalConfig.closeTime = closeTime;
        
        await globalConfig.save(); 
        
        console.log(`[CONFIG] ⚙️ Settings updated by ${req.session.username}`);
        return res.json({ success: true }); 
    } catch (configSaveError) {
        console.error("[CONFIG] Persistence failure:");
        console.error(configSaveError);
        return res.status(500).json({ error: "Config write failure." });
    }
});

/**
 * Endpoint: List Active Servers
 * GET /api/admin/servers
 */
app.get('/api/admin/servers', isAdmin, async function(req, res) {
    let guildAggregate = [];
    
    discordClients.forEach(function(clientInstance) {
        if (clientInstance.isReady() === false) return;
        
        clientInstance.guilds.cache.forEach(function(guild) {
            guildAggregate.push({
                id: guild.id,
                name: guild.name,
                members: guild.memberCount,
                botName: clientInstance.user.username,
                botId: clientInstance.user.id
            });
        });
    });
    
    return res.json(guildAggregate);
});

// 12.1. Fleet Remote Management Routes

app.post('/api/admin/leave-server', isAdmin, async function(req, res) {
    const { serverId, botId } = req.body;
    try {
        const actingBot = discordClients.find(function(c) { return c.user.id === botId; });
        const targetGuild = await actingBot.guilds.fetch(serverId);
        await targetGuild.leave();
        console.log(`[FLEET] 👋 Bot ${botId} left server ${serverId}`);
        return res.json({ success: true });
    } catch (leaveError) {
        return res.status(500).json({ error: "Action rejected by Discord API." });
    }
});

app.post('/api/admin/create-invite', isAdmin, async function(req, res) {
    const { serverId, botId } = req.body;
    try {
        const actingBot = discordClients.find(function(c) { return c.user.id === botId; });
        const targetGuild = await actingBot.guilds.fetch(serverId);
        const textChannel = targetGuild.channels.cache.find(function(ch) {
            return ch.type === 0 && ch.permissionsFor(actingBot.user).has('CreateInstantInvite');
        });
        
        if (textChannel) {
            const inviteLink = await textChannel.createInvite({ maxAge: 0, maxUses: 0 });
            return res.json({ url: inviteLink.url });
        } else {
            return res.status(403).json({ error: "Insufficient permissions for invites." });
        }
    } catch (inviteError) {
        return res.status(500).json({ error: "Action failure." });
    }
});

app.post('/api/admin/dm-owner', isAdmin, async function(req, res) {
    const { serverId, botId, message } = req.body;
    try {
        const actingBot = discordClients.find(function(c) { return c.user.id === botId; });
        const targetGuild = await actingBot.guilds.fetch(serverId);
        const guildOwner = await actingBot.users.fetch(targetGuild.ownerId);
        
        await guildOwner.send(`**Administrative Message Regarding ${targetGuild.name}:**\n${message}`);
        return res.json({ success: true });
    } catch (ownerDmError) {
        return res.status(500).json({ error: "DM rejection." });
    }
});

app.post('/api/admin/bulk-message', isAdmin, async function(req, res) {
    const messageContent = req.body.message;
    console.log(`[BROADCAST] ⚠️ Starting bulk message sequence...`);
    
    let successCount = 0;
    for (const client of discordClients) {
        if (!client.isReady()) continue;
        for (const [id, guild] of client.guilds.cache) {
            try {
                const owner = await client.users.fetch(guild.ownerId);
                await owner.send(`**Global Service Notification:**\n${messageContent}`);
                successCount++;
            } catch (err) {
                // Ignore individual block errors
            }
        }
    }
    
    console.log(`[BROADCAST] ✅ Completed. Reached ${successCount} owners.`);
    return res.json({ sentTo: successCount });
});

// 12.2. Staff Lifecycle Management

app.post('/api/admin/staff/add', isAdmin, async function(req, res) {
    const { username, discordId, adminStatus } = req.body;
    
    try {
        const secureInitialKey = generateComplexPassword();
        const hashedKey = await bcrypt.hash(secureInitialKey, 10);
        
        const newStaffMember = new Staff({ 
            username: username, 
            discordId: discordId, 
            password: hashedKey, 
            isAdmin: adminStatus 
        });
        
        await newStaffMember.save();
        
        // Notify the new member
        try {
            const userHandle = await discordClients[0].users.fetch(discordId);
            const welcomeEmbed = new EmbedBuilder()
                .setTitle("Access Granted")
                .setDescription(`Your staff account is ready.\n\n**Username:** \`${username}\`\n**Temporary Key:** \`${secureInitialKey}\`\n**Portal:** ${getPanelUrl()}`)
                .setColor('#10b981');
            await userHandle.send({ embeds: [welcomeEmbed] });
        } catch (dmFail) {
            console.error("[STAFF_MGMT] Could not DM credentials to new staff member.");
        }
        
        return res.json({ success: true });
    } catch (addStaffError) {
        console.error(addStaffError);
        return res.status(500).json({ error: "Failed to create staff record." });
    }
});

app.post('/api/admin/staff/reset', isAdmin, async function(req, res) {
    const targetId = req.body.staffId;
    
    try {
        const staffSubject = await Staff.findById(targetId);
        if (staffSubject === null) {
            return res.status(404).json({ error: "Target missing." });
        }

        const forceNewKey = generateComplexPassword();
        staffSubject.password = await bcrypt.hash(forceNewKey, 10);
        await staffSubject.save();
        
        // Notify via DM
        try {
            const userHandle = await discordClients[0].users.fetch(staffSubject.discordId);
            const resetEmbed = new EmbedBuilder()
                .setTitle("Security Update")
                .setDescription(`Your staff credentials have been reset by an administrator.\n\n**New Secure Key:** \`${forceNewKey}\``)
                .setColor('#f59e0b');
            await userHandle.send({ embeds: [resetEmbed] });
        } catch (resetDmError) {
            console.error("[STAFF_MGMT] ❌ Password reset successful but DM notification failed.");
        }
        
        return res.json({ success: true });
    } catch (resetErr) {
        return res.status(500).json({ error: "Logic error during reset." });
    }
});

app.post('/api/admin/staff/delete', isAdmin, async function(req, res) {
    const targetId = req.body.staffId;
    
    if (targetId === req.session.staffId.toString()) {
        return res.status(400).json({ error: "Self-deletion is restricted." });
    }
    
    try {
        await Staff.findByIdAndDelete(targetId);
        return res.json({ success: true });
    } catch (delError) {
        return res.status(500).json({ error: "Database removal error." });
    }
});

/**
 * Administrative Feature: Manual DM / Ticket Opener
 * POST /api/admin/manual-dm
 */
app.post('/api/admin/manual-dm', isAdmin, async function(req, res) {
    const targetDiscordId = req.body.discordId;
    const initialContent = req.body.content;
    const adminUser = req.session.username;
    
    try {
        // Fetch Bot and User
        const primaryBot = discordClients[0];
        const discordUser = await primaryBot.users.fetch(targetDiscordId);
        
        // Dispatch DM
        const messageEmbed = new EmbedBuilder()
            .setColor('#3b82f6')
            .setAuthor({ 
                name: `Staff Message (${adminUser})`, 
                iconURL: primaryBot.user.displayAvatarURL() 
            })
            .setDescription(initialContent)
            .setTimestamp();
            
        await discordUser.send({ embeds: [messageEmbed] });
        
        // Synchronize Thread in DB
        let existingThread = await Thread.findOne({ userId: targetDiscordId });
        
        if (existingThread === null) {
            existingThread = new Thread({ 
                userId: targetDiscordId, 
                userTag: discordUser.tag, 
                userAvatar: discordUser.displayAvatarURL({ extension: 'png' }), 
                botId: primaryBot.user.id, 
                botName: primaryBot.user.username, 
                messages: [] 
            });
            await sendLog("🆕 Manual Ticket", `Opened by Administrator: ${adminUser} for User: ${discordUser.tag}`, '#facc15');
        }
        
        const actingAdminProfile = await Staff.findById(req.session.staffId);
        
        const adminMessageObject = { 
            authorTag: `Staff (${adminUser})`, 
            authorAvatar: actingAdminProfile ? actingAdminProfile.avatar : '',
            content: initialContent, 
            fromBot: true, 
            timestamp: new Date() 
        };
        
        existingThread.messages.push(adminMessageObject);
        existingThread.lastMessageAt = new Date();
        await existingThread.save();
        
        io.emit('new_message', { threadId: existingThread._id, ...adminMessageObject });
        
        console.log(`[ADMIN] 📤 Manual ticket successfully opened for ${discordUser.tag}`);
        return res.json({ success: true });
    } catch (manualDmError) {
        console.error(`[ADMIN] ❌ Manual DM failure: ${manualDmError.message}`);
        return res.status(500).json({ error: "API Rejection. Is the Discord ID valid?" });
    }
});


// =================================================================================================
//  SECTION 13: MACROS, FAQ AND LICENSE PERSISTENCE
// =================================================================================================

// 13.1. Macros

app.get('/api/macros', isAuth, async function(req, res) {
    const list = await Macro.find().sort({ title: 1 });
    return res.json(list);
});

app.post('/api/admin/macros/add', isAdmin, async function(req, res) {
    try {
        const newMacro = new Macro(req.body);
        await newMacro.save();
        return res.json({ success: true });
    } catch (e) { return res.status(500).json({ error: "DB Error" }); }
});

app.post('/api/admin/macros/delete', isAdmin, async function(req, res) {
    try {
        await Macro.findByIdAndDelete(req.body.id);
        return res.json({ success: true });
    } catch (e) { return res.status(500).json({ error: "DB Error" }); }
});

// 13.2. FAQ

app.get('/api/faq', async function(req, res) {
    const list = await FAQ.find().sort({ createdAt: 1 });
    return res.json(list);
});

app.post('/api/admin/faq/add', isAdmin, async function(req, res) {
    try {
        const newFaq = new FAQ(req.body);
        await newFaq.save();
        return res.json({ success: true });
    } catch (e) { return res.status(500).json({ error: "DB Error" }); }
});

app.post('/api/admin/faq/delete', isAdmin, async function(req, res) {
    try {
        await FAQ.findByIdAndDelete(req.body.id);
        return res.json({ success: true });
    } catch (e) { return res.status(500).json({ error: "DB Error" }); }
});

// 13.3. Licenses (Sell.App)

app.post('/api/admin/license/activate', isAdmin, async function(req, res) {
    const { license_key, instance_name, discord_id, duration, server_name, server_id, type } = req.body;
    
    console.log(`[LICENSE] 🚀 Activation request for key: ${license_key}`);
    
    try {
        // 1. External API Call to Sell.App
        const sellAppResponse = await axios.post('https://sell.app/api/v2/licenses/activate', { 
            license_key: license_key, 
            instance_name: instance_name 
        }, { 
            headers: { 
                'Authorization': `Bearer ${process.env.SELLAPP_TOKEN}`,
                'Content-Type': 'application/json' 
            } 
        });
        
        // 2. Calculate Expiration
        let finalExpirationDate = null; 
        if (duration !== 'Lifetime') {
            const dayCount = parseInt(duration);
            if (!isNaN(dayCount)) {
                finalExpirationDate = new Date(Date.now() + dayCount * 24 * 60 * 60 * 1000);
            }
        }
        
        // 3. Persistent Local Store
        const localLicenseRecord = new License({ 
            key: license_key,
            instanceId: instance_name,
            discordId: discord_id,
            serverId: server_id,
            serverName: server_name,
            type: type,
            duration: duration,
            activatedAt: new Date(),
            expiresAt: finalExpirationDate,
            reviewRequestSent: false
        });
        await localLicenseRecord.save();
        
        await sendLog("🔑 License Activated", `**User:** <@${discord_id}>\n**Server:** ${server_name}\n**Key:** ${license_key}`, '#10b981');
        
        // 4. Client DM Notification
        try {
            const customerHandle = await discordClients[0].users.fetch(discord_id);
            const successEmbed = new EmbedBuilder()
                .setTitle("License Activated ✅")
                .setDescription(`Your Miraidon Trade Services license has been successfully linked to **${server_name}**.`)
                .addFields(
                    { name: "Subscription", value: type, inline: true },
                    { name: "Duration", value: duration, inline: true }
                )
                .setColor('#10b981')
                .setTimestamp();
            await customerHandle.send({ embeds: [successEmbed] });
        } catch (customerDmError) {
            console.log("[LICENSE] ⚠️ Activation successful but customer DM blocked.");
        }
        
        return res.json({ success: true });
    } catch (activationError) {
        console.error("[LICENSE] ❌ API Activation Failed:");
        console.error(activationError.response ? activationError.response.data : activationError.message);
        return res.status(400).json({ error: "Sell.App API rejection. Check key validity." });
    }
});


// =================================================================================================
//  SECTION 14: BACKGROUND AUTOMATION ENGINES (CRON)
// =================================================================================================

/**
 * Task: checkExpirations
 * Description: Scans for licenses expiring within 72 hours.
 */
async function checkExpirations() {
    console.log("[CRON] 🕒 Scanning for expiring licenses...");
    
    const nowTimestamp = new Date();
    const threeDayHorizon = new Date();
    threeDayHorizon.setDate(nowTimestamp.getDate() + 3);
    
    try {
        const expiringLicenses = await License.find({ 
            expiresAt: { $gt: nowTimestamp, $lt: threeDayHorizon }, 
            reminderSent: false 
        });

        for (const licDoc of expiringLicenses) {
            try {
                const userObject = await discordClients[0].users.fetch(licDoc.discordId);
                const warningEmbed = new EmbedBuilder()
                    .setTitle("⚠️ License Expiration Warning")
                    .setDescription(`Your license for **${licDoc.serverName || 'your server'}** is set to expire in less than 3 days.\n\nTo avoid service interruption, please renew at your earliest convenience.`)
                    .setColor('#f59e0b');
                    
                await userObject.send({ embeds: [warningEmbed] });
                
                licDoc.reminderSent = true;
                await licDoc.save();
                console.log(`[CRON] 📤 Dispatched expiry warning to ${licDoc.discordId}`);
            } catch (err) {
                console.error(`[CRON] ❌ Failed to DM user ${licDoc.discordId}: ${err.message}`);
            }
        }
    } catch (queryError) {
        console.error("[CRON] ❌ Expiration query failed:");
        console.error(queryError);
    }
}

/**
 * Task: checkTrustpilotReviewInvites
 * Description: Scans for licenses activated 14 days ago to request feedback.
 */
async function checkTrustpilotReviewInvites() {
    console.log("[CRON] 🕒 Scanning for review eligibility...");
    
    const nowTimestamp = new Date();
    const fourteenDayMark = new Date();
    fourteenDayMark.setDate(nowTimestamp.getDate() - 14);

    try {
        // Eligibility: Active > 14 days, Review not yet requested
        const reviewCandidates = await License.find({
            activatedAt: { $lt: fourteenDayMark },
            reviewRequestSent: false
        });

        for (const targetLic of reviewCandidates) {
            try {
                const userHandle = await discordClients[0].users.fetch(targetLic.discordId);
                
                const reviewEmbed = new EmbedBuilder()
                    .setTitle("🌟 How is Miraidon treating you?")
                    .setColor('#10b981')
                    .setDescription("You have been using Miraidon Trade Services for two weeks! We hope you're enjoying the speed and precision of our bots.\n\nIf you have a moment, would you consider sharing your experience on **Trustpilot**? It helps our community grow significantly.")
                    .addFields({ 
                        name: 'Review Link', 
                        value: 'https://www.trustpilot.com/review/miraidon.ca' 
                    })
                    .setFooter({ text: "Your feedback is vital to us!" });

                await userHandle.send({ embeds: [reviewEmbed] });
                
                targetLic.reviewRequestSent = true;
                await targetLic.save();
                console.log(`[CRON] 📤 Dispatched Trustpilot request to ${targetLic.discordId}`);
            } catch (dmErr) {
                console.error(`[CRON] ❌ Failed to DM review invite to ${targetLic.discordId}`);
                // Mark true to prevent retry loops on dead accounts
                targetLic.reviewRequestSent = true;
                await targetLic.save();
            }
        }
    } catch (reviewErr) {
        console.error("[CRON] ❌ Review query failed:");
        console.error(reviewErr);
    }
}

/**
 * Interval Master
 * Executes background tasks every 60 minutes.
 */
setInterval(function() {
    checkExpirations();
    checkTrustpilotReviewInvites();
}, 1000 * 60 * 60);


// =================================================================================================
//  SECTION 15: BOOTSTRAP AND LISTENER
// =================================================================================================

const FINAL_LISTENING_PORT = process.env.PORT || 10000;

server.listen(FINAL_LISTENING_PORT, function() {
    console.log("================================================================================");
    console.log(`🚀 MIRAIDON TRADE SERVICES [v10.2] READY`);
    console.log(`🌐 PORT: ${FINAL_LISTENING_PORT}`);
    console.log(`🕒 SYSTEM TIME: ${new Date().toISOString()}`);
    console.log("================================================================================");
});
