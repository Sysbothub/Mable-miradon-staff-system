/**
 * =================================================================================================
 * MIRAIDON TRADE SERVICES - MASTER SERVER (v11.2 - THE ARCHITECTURAL RESTORATION)
 * =================================================================================================
 * * STATUS: 100% UNCOMPRESSED, MAXIMAL VERBOSITY, NO DELETIONS
 * * INTEGRITY: ALL LOGIC BLOCKS EXPANDED TO MULTI-LINE SYNTAX
 * -------------------------------------------------------------------------------------------------
 * * CORE ARCHITECTURE MANIFEST:
 * 1.  DISCORD INTERFACE: 
 * - Independent client management for Miraidon and Professor Mable.
 * - Targeted Staff Role Pings via STAFF_ROLE_ID environment variable.
 * 2.  RESTful API LAYER:
 * - Secure administrative endpoints guarded by session-based authentication.
 * - Expanded error handling for Sell.App and MongoDB interactions.
 * 3.  PERSISTENCE ENGINE:
 * - MongoDB for dynamic configuration, staff analytics, and active threads.
 * - Local File System for immutable JSON and TXT archival of closed inquiries.
 * 4.  REAL-TIME SYNC:
 * - Socket.io implementation for staff collision detection and title pulsing.
 * 5.  AUTOMATION:
 * - Scheduled cron logic for Trustpilot review requests (14-day) and expiry warnings.
 * =================================================================================================
 */

// =================================================================================================
//  SECTION 1: GLOBAL MODULE LOADING AND ENVIRONMENT CONFIGURATION
// =================================================================================================

// 1.1. Environment Variable Loading
// This ensures that sensitive keys like MONGODB_URI and BOT_TOKENS are accessible.
require('dotenv').config();

// 1.2. Core Node.js Networking and File System Modules
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

console.log("================================================================================");
console.log("[STORAGE] 📂 Initializing Local Persistence Layers...");
console.log("================================================================================");

let DATA_DIR;

/**
 * PATH RESOLUTION:
 * Checks the environment to determine where the system has write permissions.
 */
if (process.env.RENDER === 'true') {
    console.log("[STORAGE] ☁️ Render Environment Detected.");
    console.log("[STORAGE] 📍 Pointing data to /var/data");
    DATA_DIR = '/var/data';
} else {
    console.log("[STORAGE] 💻 Local Environment Detected.");
    console.log("[STORAGE] 📍 Pointing data to local_storage directory.");
    DATA_DIR = path.join(__dirname, 'local_storage');
}

/**
 * ROOT DIRECTORY VERIFICATION:
 * Ensures the system has a root directory to store transcripts and session data.
 */
const rootExists = fs.existsSync(DATA_DIR);

if (rootExists === false) {
    console.log(`[STORAGE] 📂 Creating Root Data Directory at: ${DATA_DIR}`);
    try {
        fs.mkdirSync(DATA_DIR, { 
            recursive: true 
        });
        console.log(`[STORAGE] ✅ Root Directory Established.`);
    } catch (mkdirError) {
        console.error(`[STORAGE] ❌ CRITICAL: Permission denied writing to disk.`);
        console.error(`[STORAGE] 🛑 ERROR DETAILS: ${mkdirError.message}`);
        process.exit(1); 
    }
} else {
    console.log(`[STORAGE] ✅ Root directory confirmed: ${DATA_DIR}`);
}

/**
 * ARCHIVE DIRECTORY VERIFICATION:
 * Segregates closed ticket JSON data from general storage for CRM retrieval.
 */
const ARCHIVE_DIR = path.join(DATA_DIR, 'archives');
const archiveExists = fs.existsSync(ARCHIVE_DIR);

if (archiveExists === false) {
    console.log(`[STORAGE] 📂 Creating Archive Sub-directory at: ${ARCHIVE_DIR}`);
    try {
        fs.mkdirSync(ARCHIVE_DIR, { 
            recursive: true 
        });
        console.log(`[STORAGE] ✅ Archive Directory Established.`);
    } catch (archiveMkdirError) {
        console.error(`[STORAGE] ❌ WARNING: Failed to create archives folder.`);
        console.error(`[STORAGE] 🛑 ERROR DETAILS: ${archiveMkdirError.message}`);
    }
} else {
    console.log(`[STORAGE] ✅ Archive directory confirmed: ${ARCHIVE_DIR}`);
}


// =================================================================================================
//  SECTION 3: MONGODB DATABASE CONNECTIVITY
// =================================================================================================

console.log("[DATABASE] ⏳ Handshaking with MongoDB cluster...");

/**
 * ESTABLISH CONNECTION:
 * Connects using the URI provided in the .env configuration.
 */
mongoose.connect(process.env.MONGODB_URI)
    .then(function() {
        console.log("================================================================================");
        console.log("[DATABASE] ✅ Handshake Successful: PERSISTENCE LAYER ONLINE");
        console.log(`[DATABASE] 🕒 UTC Connection Time: ${new Date().toISOString()}`);
        console.log("================================================================================");
        
        // Execute bootstrap maintenence routines
        initializeSystemDefaults();
        performDatabaseRepair();
    })
    .catch(function(dbError) {
        console.error("================================================================================");
        console.error("[DATABASE] ❌ CRITICAL CONNECTION FAILURE");
        console.error(`[DATABASE] 🛑 MESSAGE: ${dbError.message}`);
        console.error("[DATABASE] 🛑 ACTION: Halting system to prevent data loss.");
        console.error("================================================================================");
    });


// =================================================================================================
//  SECTION 4: DATABASE SCHEMAS AND DATA MODELS
// =================================================================================================

/**
 * 4.1. STAFF SCHEMA
 * Handles personnel management, authentication, and performance metrics.
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
 * Manages active conversations and captures metadata for UI display.
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
        attachments: [
            String
        ],
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
 * Tracks Sell.App activations, expiration dates, and linked servers.
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
 * Tracks global support state and granular fleet trading status.
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
        botId: { 
            type: String 
        },
        botName: { 
            type: String 
        },
        tradingActive: { 
            type: Boolean, 
            default: true 
        }
    }]
});

const Config = mongoose.model('Config', ConfigSchema);

/**
 * 4.5. CRM AND CONTENT SCHEMAS
 */
const UserNoteSchema = new mongoose.Schema({
    userId: { 
        type: String, 
        required: true, 
        unique: true 
    },
    note: { 
        type: String, 
        default: "" 
    },
    updatedBy: { 
        type: String 
    },
    updatedAt: { 
        type: Date, 
        default: Date.now 
    }
});

const UserNote = mongoose.model('UserNote', UserNoteSchema);

const MacroSchema = new mongoose.Schema({
    title: { 
        type: String, 
        required: true 
    },
    content: { 
        type: String, 
        required: true 
    }
});

const Macro = mongoose.model('Macro', MacroSchema);

const FAQSchema = new mongoose.Schema({
    question: { 
        type: String, 
        required: true 
    },
    answer: { 
        type: String, 
        required: true 
    },
    createdAt: { 
        type: Date, 
        default: Date.now 
    }
});

const FAQ = mongoose.model('FAQ', FAQSchema);


// =================================================================================================
//  SECTION 5: SYSTEM HELPERS AND UTILITIES
// =================================================================================================

/**
 * Function: validateComplexPassword
 * Enforces the strict security policy for staff credentials.
 */
function validateComplexPassword(passwordValue) {
    const minLengthRequired = 8;
    const regexUppercase = /[A-Z]/;
    const regexNumeric = /[0-9]/;
    const regexSpecial = /[\W_]/; 
    
    const lengthCheck = (passwordValue.length >= minLengthRequired);
    if (lengthCheck === false) {
        return false;
    }
    
    const uppercaseCheck = regexUppercase.test(passwordValue);
    if (uppercaseCheck === false) {
        return false;
    }
    
    const numericCheck = regexNumeric.test(passwordValue);
    if (numericCheck === false) {
        return false;
    }
    
    const specialCheck = regexSpecial.test(passwordValue);
    if (specialCheck === false) {
        return false;
    }
    
    return true;
}

/**
 * Function: generateComplexPassword
 * Used for administrative re-keying and account initialization.
 */
function generateComplexPassword() {
    const alphabetLower = "abcdefghijklmnopqrstuvwxyz";
    const alphabetUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const digitPool = "0123456789";
    const symbolPool = "!@#$%^&*?";
    
    let passwordResult = "";
    
    // Select one from each category to guarantee compliance
    passwordResult += alphabetUpper[Math.floor(Math.random() * alphabetUpper.length)];
    passwordResult += digitPool[Math.floor(Math.random() * digitPool.length)];
    passwordResult += symbolPool[Math.floor(Math.random() * symbolPool.length)];
    passwordResult += alphabetLower[Math.floor(Math.random() * alphabetLower.length)];
    
    const fullPool = alphabetLower + alphabetUpper + digitPool + symbolPool;
    
    // Fill to 14 characters
    for (let x = 0; x < 10; x++) {
        passwordResult += fullPool[Math.floor(Math.random() * fullPool.length)];
    }
    
    // Randomize character order
    const arrayForm = passwordResult.split('');
    for (let i = arrayForm.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        const temp = arrayForm[i];
        arrayForm[i] = arrayForm[j];
        arrayForm[j] = temp;
    }
    
    return arrayForm.join('');
}

/**
 * Routine: initializeSystemDefaults
 * Creates the first-run database documents.
 */
async function initializeSystemDefaults() {
    console.log("[BOOTSTRAP] 🔍 Verifying default system documents...");
    
    try {
        const existingAdmin = await Staff.findOne({ username: 'admin' });
        
        if (existingAdmin === null) {
            console.log("[BOOTSTRAP] 👤 Admin account missing. Initializing default...");
            const defaultHashedKey = await bcrypt.hash('Map4491!', 10);
            
            const rootAdmin = new Staff({ 
                username: 'admin', 
                password: defaultHashedKey, 
                discordId: '000000000000000000', 
                isAdmin: true 
            });
            
            await rootAdmin.save();
            console.log("[BOOTSTRAP] ✅ Master account ready.");
        } else {
            console.log("[BOOTSTRAP] ✅ Admin account verified.");
        }

        const existingConfig = await Config.findOne({ id: 'global' });
        
        if (existingConfig === null) {
            console.log("[BOOTSTRAP] ⚙️ Global configuration missing. Initializing default...");
            
            const globalConfig = new Config({ 
                id: 'global', 
                supportOnline: true, 
                openTime: "08:00", 
                closeTime: "23:59",
                botFleetStatus: []
            });
            
            await globalConfig.save();
            console.log("[BOOTSTRAP] ✅ Global configuration ready.");
        } else {
            console.log("[BOOTSTRAP] ✅ Global configuration verified.");
        }
    } catch (bootstrapError) {
        console.error("[BOOTSTRAP] ❌ Fatal error during record initialization:");
        console.error(bootstrapError);
    }
}

/**
 * Routine: performDatabaseRepair
 * Ensures legacy records are migrated to current structural standards.
 */
async function performDatabaseRepair() {
    console.log("[REPAIR] 🛠️ Scanning database for structural inconsistencies...");
    
    try {
        // Migration: Thread 'claimedBy'
        const claimedUpdate = await Thread.updateMany(
            { claimedBy: { $exists: false } },
            { $set: { claimedBy: null } }
        );
        console.log(`[REPAIR] -> Thread logic verified (${claimedUpdate.modifiedCount} records synced).`);
        
        // Migration: User Avatars
        const avatarUpdate = await Thread.updateMany(
            { userAvatar: { $exists: false } },
            { $set: { userAvatar: 'https://cdn.discordapp.com/embed/avatars/0.png' } }
        );
        console.log(`[REPAIR] -> User PFPs verified (${avatarUpdate.modifiedCount} records synced).`);

        // Migration: Review Flags
        const reviewUpdate = await License.updateMany(
            { reviewRequestSent: { $exists: false } },
            { $set: { reviewRequestSent: false } }
        );
        console.log(`[REPAIR] -> Review logic verified (${reviewUpdate.modifiedCount} records synced).`);

        console.log("[REPAIR] ✅ Database integrity check complete.");
    } catch (repairError) {
        console.error("[REPAIR] ❌ Failure during database scan:");
        console.error(repairError);
    }
}


// =================================================================================================
//  SECTION 6: WEB SERVER MIDDLEWARE AND ARCHITECTURE
// =================================================================================================

// 6.1. Reverse Proxy Trust
// Essential for accurate IP logging when behind Render/Nginx load balancers.
app.set('trust proxy', 1);

// 6.2. Body Parsers
// Configured with high limits to allow for base64 file buffer transfers.
app.use(express.json({ 
    limit: '60mb' 
}));
app.use(express.urlencoded({ 
    extended: true, 
    limit: '60mb' 
}));

// 6.3. Session Engine
// Persists staff logins using MongoDB to prevent disconnects on server restart.
app.use(session({
    secret: process.env.SESSION_SECRET || 'miraidon-trade-services-unsecure-fallback',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'web_sessions',
        ttl: 14 * 24 * 60 * 60 // 14-day persistent sessions
    }),
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, // Browser cookie validity (24 hours)
        secure: true, // Requires HTTPS protocol
        sameSite: 'none' 
    }
}));

// 6.4. Security Guard: isAuth
// Prevents unauthorized users from accessing staff-specific API routes.
const isAuth = function(req, res, next) {
    const isSessionActive = (req.session.staffId !== undefined);
    
    if (isSessionActive === true) {
        return next();
    }
    
    const isApiCall = req.path.startsWith('/api');
    
    if (isApiCall === true) {
        console.log(`[SECURITY] 🛑 BLOCK: Unauthenticated API request to ${req.path}`);
        return res.status(401).json({ 
            error: "Authentication Required: Session Missing." 
        });
    }
    
    console.log(`[SECURITY] 🛑 REDIRECT: Guest user routed to login from ${req.path}`);
    return res.redirect('/login.html');
};

// 6.5. Security Guard: isAdmin
// Enforces dual-layer security for destructive or sensitive operations.
const isAdmin = function(req, res, next) {
    const isStaff = (req.session.staffId !== undefined);
    const hasAdminFlag = (req.session.isAdmin === true);
    
    if (isStaff === true && hasAdminFlag === true) {
        return next();
    }
    
    console.log(`[SECURITY] 🛑 FORBIDDEN: User ${req.session.username || 'unknown'} lacks admin flag.`);
    return res.status(403).json({ 
        error: "Forbidden: Administrative clearance required." 
    });
};

/**
 * 6.6. Helper: getPanelUrl
 * Resolves the primary URL for email/DM notifications.
 */
const getPanelUrl = function() {
    const configuredUrl = process.env.APP_URL;
    if (configuredUrl) {
        return configuredUrl;
    }
    return "http://localhost:10000";
};

// 6.7. Static File Deployment
// Serves images, CSS, and public HTML from the 'public' directory.
app.use(express.static(path.join(__dirname, 'public')));

// 6.8. Staff Directory Deployment
// Serves protected files, ensuring the isAuth guard is evaluated first.
app.use('/staff', isAuth, express.static(path.join(__dirname, 'public/staff')));


// =================================================================================================
//  SECTION 7: DISCORD GATEWAY INTERFACE (MIRAIDON FLEET)
// =================================================================================================

/**
 * GATEWAY BOOTSTRAP:
 * Filters the environment for valid bot tokens.
 */
const rawTokens = [
    process.env.BOT_ONE_TOKEN, 
    process.env.BOT_TWO_TOKEN
];

const validTokens = rawTokens.filter(function(t) {
    const exists = (t !== undefined && t !== "");
    return exists;
});

const discordClients = [];

/**
 * Function: sendLog
 * Centralized logging to dispatch embeds to the staff Discord channel.
 * UPDATED v11.1: Supports role mentions via 'content' parameter.
 */
async function sendLog(title, description, color = '#3b82f6', files = [], pingContent = "") {
    const channelId = process.env.LOG_CHANNEL_ID;
    const botReady = (discordClients[0] !== undefined);
    
    if (!channelId || !botReady) {
        return;
    }
    
    try {
        const logChannel = await discordClients[0].channels.fetch(channelId);
        
        if (logChannel) {
            const embed = new EmbedBuilder()
                .setTitle(title)
                .setDescription(description)
                .setColor(color)
                .setTimestamp()
                .setFooter({ 
                    text: "Miraidon Master Control" 
                });
                
            const payload = { 
                embeds: [embed], 
                files: files 
            };
            
            // Inject targeted staff ping if provided
            if (pingContent !== "") {
                payload.content = pingContent;
            }
            
            await logChannel.send(payload);
        }
    } catch (logError) { 
        console.error(`[LOG] ❌ Embed dispatch failure: ${logError.message}`); 
    }
}

// 7.1. Bot Engine Loop
validTokens.forEach(function(token, index) {
    
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
        partials: [
            Partials.Channel, 
            Partials.Message
        ]
    });

    // 7.2. Client Ready Handler
    client.once('ready', function() {
        console.log(`[DISCORD] 🤖 Gateway ${index + 1} Authorized: ${client.user.tag}`);
    });

    // 7.3. Typing Notification Handler
    client.on('typingStart', function(typing) {
        const isBot = typing.user.bot;
        if (isBot === true) {
            return;
        }
        // Emit Socket to Dashboard for visual feedback
        io.emit('user_typing', { 
            userId: typing.user.id 
        });
    });

    // 7.4. Interaction (Button) Handler
    // Processes 5-star ratings sent to users upon ticket closure.
    client.on('interactionCreate', async function(interaction) {
        const isButton = interaction.isButton();
        if (isButton === false) {
            return;
        }

        const customId = interaction.customId;
        const idParts = customId.split('_');
        const interactionAction = idParts[0];
        
        if (interactionAction === 'rate') {
            const starScore = parseInt(idParts[1]);
            const staffTargetId = idParts[2];
            
            console.log(`[FEEDBACK] Received star rating for staff member ${staffTargetId}`);

            try {
                // Atomic database increment
                await Staff.findByIdAndUpdate(staffTargetId, { 
                    $inc: { ratingSum: starScore, ratingCount: 1 } 
                });

                const confirmationRow = new ActionRowBuilder().addComponents(
                    new ButtonBuilder()
                        .setCustomId('done')
                        .setLabel(`Experience Rated: ${starScore}/5`)
                        .setStyle(ButtonStyle.Success)
                        .setDisabled(true)
                );

                await interaction.update({ 
                    content: `**Thank you for your feedback!** You have rated this session **${starScore} stars**.`, 
                    components: [confirmationRow] 
                });
            } catch (ratingError) {
                console.error(`[FEEDBACK] ❌ Failed to commit rating: ${ratingError.message}`);
            }
        }
    });

    // 7.5. MAIN INBOUND MESSAGE DISPATCHER
    client.on('messageCreate', async function(message) {
        // Validation: No bots, No guild channels, Text content required or media.
        const authorIsBot = message.author.bot;
        if (authorIsBot === true) {
            return;
        }
        
        const authorInGuild = (message.guild !== null);
        if (authorInGuild === true) {
            return;
        }
        
        const senderId = message.author.id;
        const currentPfp = message.author.displayAvatarURL({ extension: 'png', size: 128 });

        // Query active thread store
        let threadRecord = await Thread.findOne({ 
            userId: senderId, 
            botId: client.user.id 
        });
        
        // -----------------------------------------------------------------------------------------
        // CASE: INITIAL THREAD CREATION
        // -----------------------------------------------------------------------------------------
        if (threadRecord === null) {
            console.log(`[TICKET] 📩 New inquiry detected from ${message.author.tag}`);
            
            threadRecord = new Thread({ 
                userId: senderId, 
                userTag: message.author.tag, 
                userAvatar: currentPfp, 
                botId: client.user.id, 
                botName: client.user.username, 
                messages: [] 
            });
            
            // Retrieve configuration for schedule-based auto-replies
            const configDoc = await Config.findOne({ id: 'global' });
            
            const serviceOnline = configDoc ? configDoc.supportOnline : true;
            const openTimeStr = configDoc ? configDoc.openTime : "08:00";
            const closeTimeStr = configDoc ? configDoc.closeTime : "23:59";

            // Support operating hours logic (AST)
            const dateObj = new Date();
            const formatOptions = { timeZone: 'America/Halifax', hour12: false, hour: 'numeric', minute: 'numeric' };
            const timeParts = new Intl.DateTimeFormat('en-US', formatOptions).formatToParts(dateObj);
            
            const currentHourValue = parseInt(timeParts.find(p => p.type === 'hour').value);
            const currentMinValue = parseInt(timeParts.find(p => p.type === 'minute').value);
            const totalMinutesNow = (currentHourValue * 60) + currentMinValue;

            const [configOpenH, configOpenM] = openTimeStr.split(':').map(Number);
            const [configCloseH, configCloseM] = closeTimeStr.split(':').map(Number);
            
            const startWindowMinutes = (configOpenH * 60) + configOpenM;
            const endWindowMinutes = (configCloseH * 60) + configCloseM;

            const isCurrentlyOpen = (totalMinutesNow >= startWindowMinutes && totalMinutesNow <= endWindowMinutes);

            let greetingEmbed;

            if (serviceOnline === false) {
                // TICKET OPENED WHILE MASTER TOGGLE IS OFF
                greetingEmbed = new EmbedBuilder()
                    .setColor('#ef4444')
                    .setTitle('Support Desk Offline')
                    .setDescription(`We have received your message, but the support desk is currently taking a scheduled break.\n\n**Note:** ${configDoc.offlineNote || 'Maintenance/Day Off'}\n\nOur team will review your ticket upon return.`)
                    .setTimestamp();
            } else if (isCurrentlyOpen === false) {
                // TICKET OPENED OUTSIDE SCHEDULE
                greetingEmbed = new EmbedBuilder()
                    .setColor('#f59e0b')
                    .setTitle('Outside Operating Hours')
                    .setDescription(`Hello! You've reached us outside of our normal support window.\n\n**Schedule:** ${openTimeStr} to ${closeTimeStr} AST.\n\nYour inquiry has been queued for staff review.`)
                    .setTimestamp();
            } else {
                // TICKET OPENED DURING NORMAL OPERATION
                greetingEmbed = new EmbedBuilder()
                    .setColor('#3b82f6')
                    .setTitle('Support Inquiry Initialized')
                    .setDescription('AFFIRMATIVE, TRAINER.\n\nYour inquiry has reached our dashboard. A staff member will respond to you inquery shortly. Please hold tight.')
                    .setFooter('Esttimated Response Time: 1-2 Hours')
                    .setTimestamp();
            }
            
            try { 
                await message.author.send({ embeds: [greetingEmbed] }); 
            } catch (initialDmError) {
                console.warn(`[TICKET] ⚠️ User ${message.author.tag} has DMs disabled.`);
            }

            // v11.1: NOTIFICATION LOG DISPATCH WITH TARGETED PING
            let pingTarget = "@here"; 
            const staffRoleId = process.env.STAFF_ROLE_ID;
            
            if (staffRoleId && staffRoleId !== "") {
                pingTarget = `<@&${staffRoleId}>`;
            }

            sendLog(
                "🆕 New Support Ticket", 
                `**User:** ${message.author.tag}\n**Discord ID:** ${senderId}\n**Gateway Bot:** ${client.user.username}`, 
                '#facc15', 
                [], 
                pingTarget
            );

        } else {
            // Check for avatar update to keep dashboard fresh
            const avatarChanged = (threadRecord.userAvatar !== currentPfp);
            if (avatarChanged === true) {
                threadRecord.userAvatar = currentPfp;
            }
        }
        
        // -----------------------------------------------------------------------------------------
        // LOGIC: APPEND MESSAGE TO ACTIVE THREAD
        // -----------------------------------------------------------------------------------------
        console.log(`[MSG] 📥 Inbound from ${message.author.tag}: ${message.content.substring(0, 30)}`);

        const messageAttachments = message.attachments.map(function(attachment) {
            return attachment.url;
        });
        
        const inboundMessageObj = { 
            authorTag: message.author.tag, 
            authorAvatar: currentPfp, 
            content: message.content || "[Media Content]", 
            attachments: messageAttachments, 
            fromBot: false, 
            timestamp: new Date() 
        };

        threadRecord.messages.push(inboundMessageObj);
        threadRecord.lastMessageAt = new Date();
        await threadRecord.save();
        
        // DISPATCH TO SOCKET GATEWAY
        // This triggers audio alerts and tab title pulsing in the browser.
        io.emit('new_message', { 
            threadId: threadRecord._id, 
            notif_sound: true, 
            ...inboundMessageObj 
        });
    });

    // Login bot client
    client.login(token).catch(function(loginAuthError) {
        console.error(`[FLEET] ❌ Client ${index + 1} gateway authentication failed: ${loginAuthError.message}`);
    });
    
    discordClients.push(client);
});


// =================================================================================================
//  SECTION 8: REAL-TIME COMMUNICATION GATEWAY (SOCKET.IO)
// =================================================================================================

const threadVewingCache = {}; 

io.on('connection', function(staffSocket) {
    
    /**
     * EVENT: join_ticket_room
     * Logic for staff members focusing a specific inquiry.
     */
    staffSocket.on('join_ticket_room', function(payload) {
        const id = payload.threadId;
        const name = payload.username;

        staffSocket.join(id);
        
        const roomCacheExists = (threadVewingCache[id] !== undefined);
        if (roomCacheExists === false) {
            threadVewingCache[id] = new Set();
        }
        
        threadVewingCache[id].add(name);
        
        console.log(`[REALTIME] 👤 ${name} joined inquiry room: ${id}`);
        
        // Broadcast viewer list for collision detection (v10.0 feature)
        io.to(id).emit('viewers_updated', Array.from(threadVewingCache[id]));
        
        // Tag socket for state management
        staffSocket.currentThreadId = id; 
        staffSocket.currentUser = name;
    });

    /**
     * EVENT: leave_ticket_room
     * Cleans up collision detection cache when a staff member changes tabs.
     */
    staffSocket.on('leave_ticket_room', function() {
        const hasThread = (staffSocket.currentThreadId !== undefined);
        const hasUser = (staffSocket.currentUser !== undefined);

        if (hasThread === true && hasUser === true) {
            const currentId = staffSocket.currentThreadId;
            staffSocket.leave(currentId);
            
            const cache = threadVewingCache[currentId];
            if (cache) {
                cache.delete(staffSocket.currentUser);
                io.to(currentId).emit('viewers_updated', Array.from(cache));
            }
            
            staffSocket.currentThreadId = null;
        }
    });

    /**
     * EVENT: disconnect
     * Automatic cleanup logic.
     */
    staffSocket.on('disconnect', function() {
        const hasThread = (staffSocket.currentThreadId !== undefined);
        const hasUser = (staffSocket.currentUser !== undefined);

        if (hasThread === true && hasUser === true) {
            const currentId = staffSocket.currentThreadId;
            const cache = threadVewingCache[currentId];
            
            if (cache) {
                cache.delete(staffSocket.currentUser);
                io.to(currentId).emit('viewers_updated', Array.from(cache));
            }
        }
    });

    /**
     * EVENT: staff_typing
     * Proxies the staff member's typing state to the Discord DM channel.
     */
    staffSocket.on('staff_typing', async function(payload) {
        const threadId = payload.threadId;
        
        try {
            const targetThread = await Thread.findById(threadId);
            if (targetThread === null) {
                return;
            }

            const gatewayBot = discordClients.find(function(c) {
                const isMatch = (c.user.id === targetThread.botId);
                return isMatch;
            });
            
            if (gatewayBot) {
                const user = await gatewayBot.users.fetch(targetThread.userId);
                const dmChannel = user.dmChannel || await user.createDM();
                await dmChannel.sendTyping();
            }
        } catch (typingProxyError) {
            // Silently ignore if bot lacks permission or user blocked bot
        }
    });
});


// =================================================================================================
//  SECTION 9: STAFF AUTHENTICATION SYSTEM API
// =================================================================================================

/**
 * ROUTE: Staff Authentication Login
 * Method: POST
 * Path: /api/login
 */
app.post('/api/login', async function(request, response) {
    const inputUsername = request.body.username;
    const inputPassword = request.body.password;
    
    console.log(`[AUTH] 🔐 Login initialization for: ${inputUsername}`);
    
    try {
        const staffDoc = await Staff.findOne({ 
            username: inputUsername 
        });
        
        if (staffDoc === null) {
            console.log(`[AUTH] ❌ Login denied: User ${inputUsername} not found.`);
            return response.status(401).json({ 
                error: "Authentication Refused: Invalid Credentials" 
            });
        }

        const isAuthorized = await bcrypt.compare(inputPassword, staffDoc.password);
        
        if (isAuthorized === true) {
            
            // Execute Profile Photo Synchronization (Discord API)
            try {
                const botIsReady = (discordClients[0] !== undefined);
                if (botIsReady === true) {
                    const discordProfile = await discordClients[0].users.fetch(staffDoc.discordId);
                    if (discordProfile) {
                        const newAvatarUrl = discordProfile.displayAvatarURL({ extension: 'png', size: 128 });
                        staffDoc.avatar = newAvatarUrl;
                        await staffDoc.save();
                        console.log(`[AUTH] 🖼️ Profile photo updated for staff member ${inputUsername}`);
                    }
                }
            } catch (avatarSyncError) { 
                console.error(`[AUTH] ⚠️ Profile sync skipped: ${avatarSyncError.message}`); 
            }

            // Assign session variables
            request.session.staffId = staffDoc._id; 
            request.session.isAdmin = staffDoc.isAdmin; 
            request.session.username = staffDoc.username;
            
            // Explicitly save session before responding
            request.session.save(function(sessionErr) {
                if (sessionErr) {
                    return response.status(500).json({ error: "Session persistence error." });
                }
                console.log(`[AUTH] ✅ Authentication verified. Session active for ${inputUsername}`);
                return response.json({ 
                    success: true, 
                    isAdmin: staffDoc.isAdmin, 
                    username: staffDoc.username 
                });
            });
        } else {
            console.log(`[AUTH] ❌ Login denied: Key mismatch for user ${inputUsername}`);
            return response.status(401).json({ 
                error: "Authentication Refused: Invalid Credentials" 
            });
        }
    } catch (criticalAuthError) {
        console.error("[AUTH] ❌ Internal Server Error during authentication logic:");
        console.error(criticalAuthError);
        return response.status(500).json({ 
            error: "Internal Server Error: Logic fault." 
        });
    }
});

/**
 * ROUTE: Staff Logout
 * Method: POST
 * Path: /api/logout
 */
app.post('/api/logout', function(request, response) { 
    const actorName = request.session.username || 'guest';
    console.log(`[AUTH] 🚪 Destroying session for ${actorName}`);
    
    request.session.destroy(function(destroyError) { 
        if (destroyError) {
            console.error("[AUTH] ❌ Error during session destruction:");
            console.error(destroyError);
            return response.status(500).json({ 
                error: "Internal failure: Could not close session." 
            });
        }
        
        response.clearCookie('connect.sid'); 
        
        return response.json({ 
            success: true 
        }); 
    }); 
});

/**
 * ROUTE: Identity Verification
 * Method: GET
 * Path: /api/auth/user
 */
app.get('/api/auth/user', isAuth, function(request, response) {
    const sessionData = { 
        username: request.session.username, 
        isAdmin: request.session.isAdmin 
    };
    
    return response.json(sessionData);
});

/**
 * ROUTE: Staff Password Recovery (Public Access)
 * Method: POST
 * Path: /api/public/request-reset
 */
app.post('/api/public/request-reset', async function(request, response) {
    const targetDiscordId = request.body.discordId;
    console.log(`[RECOVERY] 🔄 Secure key reset requested for Discord ID: ${targetDiscordId}`);
    
    try {
        const staffAccount = await Staff.findOne({ 
            discordId: targetDiscordId 
        });
        
        if (staffAccount === null) {
            console.log(`[RECOVERY] ❌ ID ${targetDiscordId} not recognized.`);
            return response.status(404).json({ 
                error: "Identity Not Recognized: ID not found in database." 
            });
        }
        
        // Generate new complex key
        const newSecureKey = generateComplexPassword();
        const newHashedKey = await bcrypt.hash(newSecureKey, 10);
        
        staffAccount.password = newHashedKey;
        await staffAccount.save();
        
        // Dispatch to target via DM using first bot client
        const primaryBot = discordClients[0];
        const userHandle = await primaryBot.users.fetch(targetDiscordId);
        
        const recoveryEmbed = new EmbedBuilder()
            .setTitle("🔒 Identity Recovery Authorized")
            .setDescription(`Your Miraidon Trade Services staff password has been force-reset.\n\n**New Secure Key:** \`${newSecureKey}\`\n**Portal:** ${getPanelUrl()}\n\nPlease update this key via your settings immediately.`)
            .setColor('#facc15')
            .setTimestamp();
            
        await userHandle.send({ 
            embeds: [recoveryEmbed] 
        });
        
        console.log(`[RECOVERY] ✅ Reset confirmed. New key DM'd to ${staffAccount.username}`);
        return response.json({ 
            success: true 
        });
        
    } catch (recoveryDispatchError) { 
        console.error(`[RECOVERY] ❌ Logic fault during key reset: ${recoveryDispatchError.message}`);
        return response.status(500).json({ 
            error: "Recovery Dispatch Failure: Ensure Bot has DM permissions." 
        }); 
    }
});

/**
 * ROUTE: Self-Service Password Update
 * Method: POST
 * Path: /api/staff/change-password
 */
app.post('/api/staff/change-password', isAuth, async function(request, response) {
    const currentPassInput = request.body.currentPassword;
    const newPassInput = request.body.newPassword;
    const actor = request.session.username;
    
    console.log(`[SETTINGS] 🔐 Password change sequence initiated for ${actor}`);

    try {
        // Step 1: Compliance verification
        const meetsPolicy = validateComplexPassword(newPassInput);
        if (meetsPolicy === false) {
            return response.status(400).json({ 
                error: "Policy Violation: New key does not meet requirements (8+ chars, Uppercase, Number, Symbol)." 
            });
        }

        // Step 2: Database retrieval
        const targetStaffDoc = await Staff.findById(request.session.staffId);
        if (targetStaffDoc === null) {
            return response.status(404).json({ 
                error: "Reference Error: Staff record no longer exists." 
            });
        }

        // Step 3: Current authorization verification
        const currentMatch = await bcrypt.compare(currentPassInput, targetStaffDoc.password);
        if (currentMatch === false) {
            console.log(`[SETTINGS] ❌ Key rotation failed for ${actor}: Current key incorrect.`);
            return response.status(401).json({ 
                error: "Authorization Failure: Current secure key is incorrect." 
            });
        }

        // Step 4: Secure hashing and persistence
        const newHash = await bcrypt.hash(newPassInput, 10);
        targetStaffDoc.password = newHash;
        await targetStaffDoc.save();
        
        console.log(`[SETTINGS] ✅ Key rotation successful for technican ${actor}`);
        return response.json({ 
            success: true 
        });
    } catch (passwordUpdateError) {
        console.error("[SETTINGS] ❌ Server-side logic failure during key rotation:");
        console.error(passwordUpdateError);
        return response.status(500).json({ 
            error: "Internal Server Error: Persistence logic failure." 
        });
    }
});


// =================================================================================================
//  SECTION 10: SUPPORT INQUIRY OPERATIONS API (TICKETING)
// =================================================================================================

/**
 * ROUTE: Retrieve Active Inbox
 * Method: GET
 * Path: /api/threads
 */
app.get('/api/threads', isAuth, async function(request, response) { 
    console.log(`[API] 📬 Inbox refresh requested by ${request.session.username}`);
    
    try {
        // Sort by the most recently messaged thread
        const inquiryList = await Thread.find().sort({ 
            lastMessageAt: -1 
        }); 
        
        return response.json(inquiryList);
    } catch (inquiryFetchError) {
        console.error("[API] ❌ Failed to retrieve thread collection:");
        console.error(inquiryFetchError);
        return response.status(500).json({ 
            error: "Database Read Failure: Inquiry collection unavailable." 
        });
    }
});

/**
 * ROUTE: Send Outbound Response to User
 * Method: POST
 * Path: /api/reply
 */
app.post('/api/reply', isAuth, async function(request, response) {
    const threadDatabaseId = request.body.threadId;
    const textContent = request.body.content;
    const mediaBufferBase64 = request.body.fileBase64;
    const mediaOriginalName = request.body.fileName;
    
    console.log(`[REPLY] 📤 Staff member ${request.session.username} sending response to thread ${threadDatabaseId}`);

    try {
        // 1. Thread retrieval
        const targetThread = await Thread.findById(threadDatabaseId);
        if (targetThread === null) {
            return response.status(404).json({ 
                error: "Thread Decommissioned: Inactive or deleted thread ID provided." 
            });
        }
        
        // 2. Gateway selection
        const assignedGateway = discordClients.find(function(c) {
            const isMatch = (c.user.id === targetThread.botId);
            return isMatch;
        });
        
        if (assignedGateway === undefined) {
            console.error(`[REPLY] ❌ Bot Gateway ${targetThread.botId} is currently unreachable.`);
            return response.status(500).json({ 
                error: "Gateway Offline: Target bot instance is disconnected from Discord." 
            });
        }

        // 3. Metadata aggregation (Profile Photos)
        const staffAccount = await Staff.findById(request.session.staffId);
        const activeStaffAvatar = staffAccount ? staffAccount.avatar : 'https://cdn.discordapp.com/embed/avatars/0.png';

        // 4. Discord User Fetching
        const discordUserHandle = await assignedGateway.users.fetch(targetThread.userId);
        
        // 5. Construct Discord Embed
        const responseEmbed = new EmbedBuilder()
            .setColor('#3b82f6')
            .setAuthor({ 
                name: `Staff Response: ${request.session.username}`, 
                iconURL: assignedGateway.user.displayAvatarURL() 
            })
            .setDescription(textContent || "[Media Attachment Only]")
            .setTimestamp();
        
        const discordOutboundPayload = { 
            embeds: [responseEmbed] 
        };
        
        // 6. Handle File Attachment Processing
        if (mediaBufferBase64) {
            console.log(`[REPLY] 📎 Processing outbound file: ${mediaOriginalName}`);
            
            // Extract buffer from base64 string
            const bufferObject = Buffer.from(mediaBufferBase64.split(',')[1], 'base64');
            const discordAttachment = new AttachmentBuilder(bufferObject, { 
                name: mediaOriginalName || 'attachment.png' 
            });
            
            discordOutboundPayload.files = [discordAttachment];
        }
        
        // 7. Dispatch to Discord API
        await discordUserHandle.send(discordOutboundPayload);
        
        // 8. Log response to local persistence
        const staffMessageEntry = { 
            authorTag: `Staff (${request.session.username})`, 
            authorAvatar: activeStaffAvatar, 
            content: textContent || "[Media Attachment]", 
            fromBot: true, 
            timestamp: new Date() 
        };
        
        targetThread.messages.push(staffMessageEntry);
        targetThread.lastMessageAt = new Date();
        await targetThread.save();
        
        // 9. Update Staff Performance Metrics
        await Staff.findByIdAndUpdate(request.session.staffId, { 
            $inc: { repliesSent: 1 } 
        });
        
        // 10. Synchronize Web UI via Socket Gateway
        io.emit('new_message', { 
            threadId: targetThread._id, 
            ...staffMessageEntry 
        });
        
        console.log(`[REPLY] ✅ Response successfully delivered to ${targetThread.userTag}`);
        return response.json({ 
            success: true 
        });

    } catch (dispatchSequenceError) { 
        console.error("[REPLY] ❌ Critical failure during dispatch sequence:");
        console.error(dispatchSequenceError.message);
        return response.status(500).json({ 
            error: "API Rejection: Discord rejected the DM. User may have blocked the bot or disabled DMs." 
        }); 
    }
});

/**
 * ROUTE: Close Inquiry and Archive
 * Method: POST
 * Path: /api/close-thread
 */
app.post('/api/close-thread', isAuth, async function(request, response) {
    const threadId = request.body.threadId;
    const actor = request.session.username;
    
    console.log(`[INBOX] 🔒 Closure initialization for thread: ${threadId}`);

    try {
        const threadDoc = await Thread.findById(threadId);
        if (threadDoc === null) {
            return response.status(404).json({ 
                error: "Reference Error: Ticket not found." 
            });
        }

        // --- STEP 1: TRANSCRIPT GENERATION ---
        let transcriptContent = `MIRAIDON TRADE SERVICES: OFFICIAL SUPPORT TRANSCRIPT\n`;
        transcriptContent += `USER IDENTITY: ${threadDoc.userTag} (ID: ${threadDoc.userId})\n`;
        transcriptContent += `ASSIGNED GATEWAY: ${threadDoc.botName}\n`;
        transcriptContent += `CLOSED BY OFFICER: ${actor}\n`;
        transcriptContent += `CLOSURE TIMESTAMP: ${new Date().toISOString()}\n`;
        transcriptContent += `================================================================================\n\n`;
        
        threadDoc.messages.forEach(function(msg) { 
            const time = msg.timestamp.toISOString();
            transcriptContent += `[${time}] ${msg.authorTag}: ${msg.content}\n`; 
        });
        
        const tempLocalPath = path.join(__dirname, `transcript-${threadDoc.userId}.txt`);
        fs.writeFileSync(tempLocalPath, transcriptContent);
        
        // --- STEP 2: DISPATCH TO DISCORD AUDIT LOG CHANNEL ---
        const logFile = new AttachmentBuilder(tempLocalPath);
        await sendLog(
            "🔒 Support Inquiry Finalized", 
            `**User:** ${threadDoc.userTag}\n**Messages:** ${threadDoc.messages.length}\n**Closing Officer:** ${actor}`, 
            '#ef4444', 
            [logFile]
        );
        
        // --- STEP 3: PERSISTENT JSON DATA ARCHIVE ---
        const targetUserDir = path.join(ARCHIVE_DIR, threadDoc.userId);
        const folderExists = fs.existsSync(targetUserDir);
        
        if (folderExists === false) {
            fs.mkdirSync(targetUserDir, { recursive: true });
        }
        
        const jsonArchiveName = `${Date.now()}-${threadId}.json`;
        const jsonFilePath = path.join(targetUserDir, jsonArchiveName);
        
        const archivePayload = {
            meta: { 
                closedBy: actor, 
                closedAt: new Date(), 
                userTag: threadDoc.userTag,
                userId: threadDoc.userId,
                totalMessages: threadDoc.messages.length
            },
            history: threadDoc.messages
        };
        
        fs.writeFileSync(jsonFilePath, JSON.stringify(archivePayload, null, 2));
        
        // --- STEP 4: TRIGGER USER RATING INTERACTION ---
        const staffIdForRating = request.session.staffId;
        const ratingButtonGroup = new ActionRowBuilder().addComponents(
            new ButtonBuilder().setCustomId(`rate_1_${staffIdForRating}`).setLabel('1⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_2_${staffIdForRating}`).setLabel('2⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_3_${staffIdForRating}`).setLabel('3⭐').setStyle(ButtonStyle.Secondary),
            new ButtonBuilder().setCustomId(`rate_4_${staffIdForRating}`).setLabel('4⭐').setStyle(ButtonStyle.Primary),
            new ButtonBuilder().setCustomId(`rate_5_${staffIdForRating}`).setLabel('5⭐').setStyle(ButtonStyle.Success)
        );
        
        const ratingRequestEmbed = new EmbedBuilder()
            .setTitle("Experience Survey")
            .setDescription(`Your support session with **${actor}** has concluded.\n\nWe strive for excellence. Please rate the quality of service provided today to help us improve our training systems.`)
            .setColor('#3b82f6')
            .setFooter({ text: "Thank you for using Miraidon Trade Services!" });

        const gateway = discordClients.find(function(c) {
            const idMatch = (c.user.id === threadDoc.botId);
            return idMatch;
        });
        
        if (gateway) { 
            try { 
                const user = await gateway.users.fetch(threadDoc.userId); 
                await user.send({ 
                    embeds: [ratingRequestEmbed], 
                    components: [ratingButtonGroup] 
                }); 
                console.log(`[INBOX] 📤 Rating interaction sent to ${threadDoc.userTag}`);
            } catch(ratingDispatchErr) {
                console.warn("[INBOX] ⚠️ Could not deliver rating DM to customer.");
            } 
        }

        // --- STEP 5: FINAL CLEANUP AND RECORD REMOVAL ---
        await Staff.findByIdAndUpdate(request.session.staffId, { 
            $inc: { ticketsClosed: 1 } 
        });
        
        await Thread.findByIdAndDelete(threadId);
        
        // Unlink temp file from filesystem
        if (fs.existsSync(tempLocalPath)) {
            fs.unlinkSync(tempLocalPath);
        }

        console.log(`[INBOX] ✅ Thread ${threadId} successfully archived and removed from active cache.`);
        return response.json({ success: true });

    } catch (closureCriticalError) { 
        console.error("[INBOX] ❌ Fatal error in ticket closure sequence:");
        console.error(closureCriticalError);
        return response.status(500).json({ 
            error: "Internal Server Error: Archival logic failed." 
        }); 
    }
});


// =================================================================================================
//  SECTION 11: CRM (CUSTOMER RELATIONSHIP MANAGEMENT) AGGREGATOR
// =================================================================================================

/**
 * ROUTE: Aggregate Global User Data
 * Method: GET
 * Path: /api/crm/user/:discordId
 */
app.get('/api/crm/user/:discordId', isAuth, async function(request, response) {
    const id = request.params.discordId;
    console.log(`[CRM] 🔍 Fetching unified profile for ID: ${id}`);
    
    try {
        // Query persistent notes
        const noteDoc = await UserNote.findOne({ 
            userId: id 
        });
        
        // Resolve archive directory path
        const userArchives = path.join(ARCHIVE_DIR, id);
        let historyArray = [];

        const archivesExist = fs.existsSync(userArchives);
        if (archivesExist === true) {
            // Read directory and filter for JSON objects
            const directoryListing = fs.readdirSync(userArchives);
            const filteredArchives = directoryListing.filter(function(file) {
                return file.endsWith('.json');
            });
            
            historyArray = filteredArchives.map(function(filename) {
                try {
                    const fullPath = path.join(userArchives, filename);
                    const rawData = fs.readFileSync(fullPath, 'utf8');
                    const parsedData = JSON.parse(rawData);
                    
                    return { 
                        filename: filename, 
                        closedAt: parsedData.meta.closedAt, 
                        closedBy: parsedData.meta.closedBy,
                        msgCount: parsedData.meta.totalMessages
                    };
                } catch (readErr) { 
                    return null; 
                }
            });
            
            // Cleanup nulls and sort by date descending
            historyArray = historyArray.filter(function(item) {
                return (item !== null);
            });
            
            historyArray.sort(function(a, b) { 
                return new Date(b.closedAt) - new Date(a.closedAt); 
            });
        }

        return response.json({ 
            note: noteDoc ? noteDoc.note : "", 
            history: historyArray 
        });

    } catch (crmAggregatorError) {
        console.error("[CRM] ❌ Failed to aggregate user profile data:");
        console.error(crmAggregatorError);
        return response.status(500).json({ 
            error: "Internal Server Error: Profile aggregation logic failure." 
        });
    }
});

/**
 * ROUTE: Retrieve Historic JSON Transcript
 * Method: GET
 * Path: /api/crm/transcript/:discordId/:filename
 */
app.get('/api/crm/transcript/:discordId/:filename', isAuth, function(request, response) {
    const userId = request.params.discordId;
    const file = request.params.filename;
    
    // SECURITY: Validate path segments
    const isIllegalId = userId.includes('..');
    const isIllegalFile = file.includes('..');
    
    if (isIllegalId === true || isIllegalFile === true) {
        console.warn(`[SECURITY] 🛑 Illegal path traversal attempt by staff: ${request.session.username}`);
        return response.status(403).json({ 
            error: "Access Denied: Path segments not permitted." 
        });
    }
    
    const absoluteFilePath = path.join(ARCHIVE_DIR, userId, file);
    const fileExists = fs.existsSync(absoluteFilePath);
    
    if (fileExists === true) {
        try {
            const rawContent = fs.readFileSync(absoluteFilePath, 'utf8');
            const parsedContent = JSON.parse(rawContent);
            return response.json(parsedContent);
        } catch (jsonReadError) {
            console.error(`[CRM] ❌ Error reading archive file: ${file}`);
            return response.status(500).json({ 
                error: "Internal Error: Archive file corrupt or unreadable." 
            });
        }
    } else {
        return response.status(404).json({ 
            error: "Not Found: Archive record missing from disk." 
        });
    }
});

/**
 * ROUTE: Update Persistent CRM Note
 * Method: POST
 * Path: /api/crm/note
 */
app.post('/api/crm/note', isAuth, async function(request, response) {
    const targetUserId = request.body.userId;
    const noteText = request.body.note;
    const actingOfficer = request.session.username;
    
    try {
        await UserNote.findOneAndUpdate(
            { userId: targetUserId }, 
            { 
                note: noteText, 
                updatedBy: actingOfficer, 
                updatedAt: new Date() 
            }, 
            { 
                upsert: true, 
                new: true 
            }
        );
        
        console.log(`[CRM] 📝 Note updated for ${targetUserId} by ${actingOfficer}`);
        return response.json({ 
            success: true 
        });
    } catch (noteUpdateError) {
        console.error("[CRM] ❌ Failed to persist user note:");
        console.error(noteUpdateError);
        return response.status(500).json({ 
            error: "Database Error: Could not save note." 
        });
    }
});


// =================================================================================================
//  SECTION 12: ADMINISTRATIVE CONSOLE ENGINE API
// =================================================================================================

/**
 * ROUTE: Retrieve Staff Performance Statistics
 * Method: GET
 * Path: /api/admin/stats
 */
app.get('/api/admin/stats', isAdmin, async function(request, response) { 
    console.log(`[ADMIN] Performance data requested by ${request.session.username}`);
    
    try {
        const statsCollection = await Staff.find().sort({ 
            ticketsClosed: -1 
        }); 
        
        return response.json(statsCollection); 
    } catch (statsQueryError) {
        console.error("[ADMIN] ❌ Database read error during stats fetch.");
        return response.status(500).json({ 
            error: "Database Read Failure: Statistics unavailable." 
        });
    }
});

/**
 * ROUTE: Retrieve Global Configuration Profile
 * Method: GET
 * Path: /api/admin/config
 */
app.get('/api/admin/config', isAdmin, async function(request, response) { 
    try {
        const globalConfigDoc = await Config.findOne({ id: 'global' }); 
        return response.json(globalConfigDoc); 
    } catch (configQueryError) {
        return response.status(500).json({ 
            error: "Database Read Failure: Config unavailable." 
        });
    }
});

/**
 * ROUTE: Update System Health and Schedule
 * Method: POST
 * Path: /api/admin/config/toggle
 */
app.post('/api/admin/config/toggle', isAdmin, async function(request, response) { 
    const { status, note, openTime, closeTime } = request.body;
    
    console.log(`[ADMIN] Updating global configuration profile...`);
    
    try {
        const doc = await Config.findOne({ id: 'global' }); 
        
        if (status !== undefined) {
            doc.supportOnline = status;
        }
        
        if (note !== undefined) {
            doc.offlineNote = note;
        }
        
        if (openTime !== undefined) {
            doc.openTime = openTime;
        }
        
        if (closeTime !== undefined) {
            doc.closeTime = closeTime;
        }
        
        await doc.save(); 
        
        console.log(`[ADMIN] ✅ Global configuration persisted.`);
        return response.json({ 
            success: true 
        }); 
    } catch (configSaveError) {
        console.error("[ADMIN] ❌ Configuration persistence failure:");
        console.error(configSaveError);
        return response.status(500).json({ 
            error: "Internal Server Error: Config write failure." 
        });
    }
});

/**
 * ROUTE: Aggregate Active Fleet Status
 * Method: GET
 * Path: /api/admin/servers
 */
app.get('/api/admin/servers', isAdmin, async function(request, response) {
    let fleetCollection = [];
    
    discordClients.forEach(function(client) {
        const clientActive = (client.isReady() === true);
        if (clientActive === false) {
            return;
        }
        
        client.guilds.cache.forEach(function(guild) {
            fleetCollection.push({
                id: guild.id,
                name: guild.name,
                members: guild.memberCount,
                botName: client.user.username,
                botId: client.user.id
            });
        });
    });
    
    return response.json(fleetCollection);
});

// 12.1. FLEET GRANULAR CONTROL MODULE

/**
 * ROUTE: Toggle Trading Module for specific Bot ID
 * Method: POST
 * Path: /api/admin/fleet/toggle-trading
 */
app.post('/api/admin/fleet/toggle-trading', isAdmin, async function(request, response) {
    const targetBotId = request.body.botId;
    const newTradingStatus = request.body.status;
    
    console.log(`[FLEET] Toggle request received for bot ${targetBotId} (State: ${newTradingStatus})`);

    try {
        const configurationDoc = await Config.findOne({ id: 'global' });
        
        // Find existing record in fleet status array
        let existingRecord = configurationDoc.botFleetStatus.find(function(item) {
            const match = (item.botId === targetBotId);
            return match;
        });

        if (existingRecord) {
            // Update existing entry
            existingRecord.tradingActive = newTradingStatus;
            console.log(`[FLEET] Updated state for existing bot ${targetBotId}`);
        } else {
            // Push new entry to array
            configurationDoc.botFleetStatus.push({ 
                botId: targetBotId, 
                tradingActive: newTradingStatus 
            });
            console.log(`[FLEET] Created state entry for new bot ${targetBotId}`);
        }
        
        await configurationDoc.save();
        
        return response.json({ 
            success: true 
        });
    } catch (fleetTogglePersistenceError) {
        console.error("[FLEET] ❌ Failed to persist trading state change:");
        console.error(fleetTogglePersistenceError);
        return response.status(500).json({ 
            error: "Database configuration write failure." 
        });
    }
});

// 12.2. REMOTE FLEET DEPLOYMENT ACTIONS

app.post('/api/admin/leave-server', isAdmin, async function(request, response) {
    const targetServerId = request.body.serverId;
    const handlingBotId = request.body.botId;
    
    try {
        const bot = discordClients.find(function(c) {
            return (c.user.id === handlingBotId);
        });
        
        const targetGuild = await bot.guilds.fetch(targetServerId);
        await targetGuild.leave();
        
        console.log(`[ADMIN] 🚪 Bot ejected from server: ${targetServerId}`);
        return response.json({ success: true });
    } catch (e) {
        return response.status(500).json({ error: "Discord API rejected ejection request." });
    }
});

app.post('/api/admin/create-invite', isAdmin, async function(request, response) {
    const targetServerId = request.body.serverId;
    const handlingBotId = request.body.botId;
    
    try {
        const bot = discordClients.find(function(c) {
            return (c.user.id === handlingBotId);
        });
        
        const targetGuild = await bot.guilds.fetch(targetServerId);
        const inviteChannel = targetGuild.channels.cache.find(function(channel) {
            const isText = (channel.type === 0);
            const hasPermission = channel.permissionsFor(bot.user).has('CreateInstantInvite');
            return (isText && hasPermission);
        });
        
        if (inviteChannel) {
            const newInvite = await inviteChannel.createInvite({ 
                maxAge: 0, 
                maxUses: 0 
            });
            return response.json({ 
                url: newInvite.url 
            });
        } else {
            return response.status(403).json({ 
                error: "Permissions Error: Bot lacks invite capability in target guild." 
            });
        }
    } catch (e) {
        return response.status(500).json({ error: "Invite generation sequence failure." });
    }
});

app.post('/api/admin/dm-owner', isAdmin, async function(request, response) {
    const targetServerId = request.body.serverId;
    const handlingBotId = request.body.botId;
    const outboundMessageText = request.body.message;
    
    try {
        const bot = discordClients.find(function(c) {
            return (c.user.id === handlingBotId);
        });
        
        const guildObject = await bot.guilds.fetch(targetServerId);
        const ownerUser = await bot.users.fetch(guildObject.ownerId);
        
        const administrativeEmbed = new EmbedBuilder()
            .setTitle("System Administrator Notification")
            .setDescription(`**Subject:** Miraidon Instance Management\n**Guild:** ${guildObject.name}\n\n**Message:**\n${outboundMessageText}`)
            .setColor('#3b82f6')
            .setFooter({ text: "Internal Management Communication" })
            .setTimestamp();
            
        await ownerUser.send({ 
            embeds: [administrativeEmbed] 
        });
        
        return response.json({ success: true });
    } catch (e) {
        return response.status(500).json({ error: "DM Dispatch Failure: Owner blocked bot or DMs disabled." });
    }
});

/**
 * ROUTE: Mass Broadcast Dispatch
 * Method: POST
 * Path: /api/admin/bulk-message
 */
app.post('/api/admin/bulk-message', isAdmin, async function(request, response) {
    const content = request.body.message;
    console.log(`[BROADCAST] ⚠️ Emergency broadcast sequence initialized by ${request.session.username}`);
    
    let successfulDispatches = 0;
    
    for (const client of discordClients) {
        if (client.isReady() === false) {
            continue;
        }
        
        for (const [id, guild] of client.guilds.cache) {
            try {
                const ownerObject = await client.users.fetch(guild.ownerId);
                
                const broadcastEmbed = new EmbedBuilder()
                    .setTitle("Global Service Announcement")
                    .setDescription(content)
                    .setColor('#ef4444')
                    .setFooter({ text: "TSP Official Announcement" })
                    .setTimestamp();
                    
                await ownerObject.send({ embeds: [broadcastEmbed] });
                successfulDispatches++;
            } catch (broadcastErr) {
                // Ignore failures to reach specific owners
            }
        }
    }
    
    console.log(`[BROADCAST] ✅ Sequence complete. Total reach: ${successfulDispatches} servers.`);
    return response.json({ 
        sentTo: successfulDispatches 
    });
});

// 12.3. STAFF LIFECYCLE MANAGEMENT TOOLS

/**
 * ROUTE: Add New Staff Member
 * Method: POST
 * Path: /api/admin/staff/add
 */
app.post('/api/admin/staff/add', isAdmin, async function(request, response) {
    const { username, discordId, adminStatus } = request.body;
    
    console.log(`[STAFF_MGMT] 👤 Adding technician: ${username}`);
    
    try {
        const firstTimeKey = generateComplexPassword();
        const hashedFirstTimeKey = await bcrypt.hash(firstTimeKey, 10);
        
        const newStaffDoc = new Staff({ 
            username: username, 
            discordId: discordId, 
            password: hashedFirstTimeKey, 
            isAdmin: adminStatus 
        });
        
        await newStaffDoc.save();
        
        // Automated Dispatch Sequence
        try {
            const primaryGateway = discordClients[0];
            const userHandle = await primaryGateway.users.fetch(discordId);
            
            const accessEmbed = new EmbedBuilder()
                .setTitle("Support Access Granted")
                .setDescription(`A technician account has been provisioned for you.\n\n**Identity:** \`${username}\`\n**Secure Key:** \`${firstTimeKey}\`\n**Gateway:** ${getPanelUrl()}\n\n*Note: Rotate your secure key upon first login.*`)
                .setColor('#10b981')
                .setTimestamp();
                
            await userHandle.send({ 
                embeds: [accessEmbed] 
            });
        } catch (accessDispatchError) {
            console.error("[STAFF_MGMT] ⚠️ Credentials created but DM failed.");
        }
        
        return response.json({ success: true });

    } catch (staffAddError) {
        console.error("[STAFF_MGMT] ❌ Failed to create staff record:");
        console.error(staffAddError);
        return response.status(500).json({ 
            error: "Database Error: Username may already be in use." 
        });
    }
});

/**
 * ROUTE: Force Re-key Staff Account
 * Method: POST
 * Path: /api/admin/staff/reset
 */
app.post('/api/admin/staff/reset', isAdmin, async function(request, response) {
    const targetId = request.body.staffId;
    
    try {
        const staffDoc = await Staff.findById(targetId);
        
        if (staffDoc === null) {
            return response.status(404).json({ error: "Entity not found." });
        }

        const freshKey = generateComplexPassword();
        const freshHash = await bcrypt.hash(freshKey, 10);
        
        staffDoc.password = freshHash;
        await staffDoc.save();
        
        // Dispatch to technician
        try {
            const gateway = discordClients[0];
            const user = await gateway.users.fetch(staffDoc.discordId);
            
            const resetEmbed = new EmbedBuilder()
                .setTitle("Security Update: Re-Keyed")
                .setDescription(`An administrator has re-keyed your authentication credentials.\n\n**New Secure Key:** \`${freshKey}\``)
                .setColor('#f59e0b')
                .setTimestamp();
                
            await user.send({ embeds: [resetEmbed] });
        } catch (dmError) {
            console.warn("[STAFF_MGMT] ⚠️ Reset successful but DM failed.");
        }
        
        return response.json({ success: true });
    } catch (resetProcessError) {
        console.error("[STAFF_MGMT] ❌ Failure in reset routine:");
        console.error(resetProcessError);
        return response.status(500).json({ 
            error: "Internal Error: Identity reset logic fault." 
        });
    }
});

/**
 * ROUTE: Delete Staff Account
 * Method: POST
 * Path: /api/admin/staff/delete
 */
app.post('/api/admin/staff/delete', isAdmin, async function(request, response) {
    const idToDelete = request.body.staffId;
    const currentSessionId = request.session.staffId.toString();
    
    // Prevent self-deletion lockouts
    if (idToDelete === currentSessionId) {
        return response.status(400).json({ 
            error: "Forbidden: Cannot delete your own administrative session." 
        });
    }
    
    try {
        await Staff.findByIdAndDelete(idToDelete);
        console.log(`[STAFF_MGMT] 🗑️ Record purged: ${idToDelete}`);
        return response.json({ 
            success: true 
        });
    } catch (dbDeletionError) {
        console.error("[STAFF_MGMT] ❌ Deletion failure.");
        return response.status(500).json({ 
            error: "Database removal failure." 
        });
    }
});

/**
 * ROUTE: Manual Outbound Thread Initialization
 * Method: POST
 * Path: /api/admin/manual-dm
 */
app.post('/api/admin/manual-dm', isAdmin, async function(request, response) {
    const targetUserId = request.body.discordId;
    const msgContent = request.body.content;
    const adminUser = request.session.username;
    
    console.log(`[ADMIN] 📤 Manual dispatch sequence started by ${adminUser} for ID ${targetUserId}`);

    try {
        const gateway = discordClients[0];
        const discordUser = await gateway.users.fetch(targetUserId);
        
        const manualEmbed = new EmbedBuilder()
            .setColor('#3b82f6')
            .setAuthor({ 
                name: `System Administrator: ${adminUser}`, 
                iconURL: gateway.user.displayAvatarURL() 
            })
            .setDescription(msgContent)
            .setTimestamp();
            
        await discordUser.send({ embeds: [manualEmbed] });
        
        // Sync to active threads
        let threadObject = await Thread.findOne({ 
            userId: targetUserId 
        });
        
        if (threadObject === null) {
            threadObject = new Thread({ 
                userId: targetUserId, 
                userTag: discordUser.tag, 
                userAvatar: discordUser.displayAvatarURL({ extension: 'png' }), 
                botId: gateway.user.id, 
                botName: gateway.user.username, 
                messages: [] 
            });
            await sendLog("🆕 Manual Thread Initialized", `Administrator ${adminUser} initiated contact with user ${discordUser.tag}`, '#facc15');
        }
        
        const adminProfile = await Staff.findById(request.session.staffId);
        
        const adminMsgEntry = { 
            authorTag: `Staff (${adminUser})`, 
            authorAvatar: adminProfile ? adminProfile.avatar : '',
            content: msgContent, 
            fromBot: true, 
            timestamp: new Date() 
        };
        
        threadObject.messages.push(adminMsgEntry);
        threadObject.lastMessageAt = new Date();
        await threadObject.save();
        
        // Emit Socket Update
        io.emit('new_message', { 
            threadId: threadObject._id, 
            ...adminMsgEntry 
        });
        
        console.log(`[ADMIN] ✅ Manual DM confirmed delivery to ${discordUser.tag}`);
        return response.json({ success: true });

    } catch (manualDmSequenceError) {
        console.error(`[ADMIN] ❌ Gateway rejection for manual DM: ${manualDmSequenceError.message}`);
        return response.status(500).json({ 
            error: "Gateway Rejection: Provided Discord ID is invalid or bot is blocked." 
        });
    }
});


// =================================================================================================
//  SECTION 13: CONTENT AND LICENSE DATABASE API
// =================================================================================================

// 13.1. STAFF MACRO API ENGINE

app.get('/api/macros', isAuth, async function(req, res) {
    try {
        const macroList = await Macro.find().sort({ title: 1 });
        return res.json(macroList);
    } catch (macroQueryError) {
        return res.status(500).json({ error: "Database read failure." });
    }
});

app.post('/api/admin/macros/add', isAdmin, async function(req, res) {
    const { title, content } = req.body;
    
    if (!title || !content) {
        return res.status(400).json({ error: "Validation: Missing title or content fields." });
    }

    try {
        const newMacroDoc = new Macro({ 
            title: title, 
            content: content 
        });
        await newMacroDoc.save();
        console.log(`[ADMIN] ➕ Canned response added: ${title}`);
        return res.json({ success: true });
    } catch (macroSaveError) {
        return res.status(500).json({ error: "Database write failure." });
    }
});

app.post('/api/admin/macros/delete', isAdmin, async function(req, res) {
    const targetId = req.body.id;
    try {
        await Macro.findByIdAndDelete(targetId);
        return res.json({ success: true });
    } catch (macroDelError) {
        return res.status(500).json({ error: "Database removal failure." });
    }
});

// 13.2. FAQ KNOWLEDGE BASE API ENGINE

app.get('/api/faq', async function(req, res) {
    try {
        const faqList = await FAQ.find().sort({ 
            createdAt: 1 
        });
        return res.json(faqList);
    } catch (faqQueryError) {
        return res.status(500).json({ error: "Database read failure." });
    }
});

app.post('/api/admin/faq/add', isAdmin, async function(req, res) {
    const { question, answer } = req.body;
    
    if (!question || !answer) {
        return res.status(400).json({ error: "Validation: Question and Answer are required." });
    }

    try {
        const newFaqDoc = new FAQ({ 
            question: question, 
            answer: answer 
        });
        await newFaqDoc.save();
        console.log(`[ADMIN] ❓ FAQ entry added.`);
        return res.json({ success: true });
    } catch (faqSaveError) {
        return res.status(500).json({ error: "Database write failure." });
    }
});

app.post('/api/admin/faq/delete', isAdmin, async function(req, res) {
    const targetId = req.body.id;
    try {
        await FAQ.findByIdAndDelete(targetId);
        return res.json({ success: true });
    } catch (faqDelError) {
        return res.status(500).json({ error: "Database removal failure." });
    }
});

// 13.3. LICENSE PROVISIONING (SELL.APP API INTERFACE)

/**
 * ROUTE: Activate License
 * Description: Handshakes with Sell.App and creates a server tracking record.
 */
app.post('/api/admin/license/activate', isAdmin, async function(request, response) {
    const { 
        license_key, 
        instance_name, 
        discord_id, 
        duration, 
        server_name, 
        server_id, 
        type 
    } = request.body;
    
    console.log(`[LICENSE] 🚀 Handshaking with Sell.App API for key: ${license_key}`);
    
    try {
        // 1. External Activation Request
        const sellAppApiResponse = await axios.post('https://sell.app/api/v2/licenses/activate', { 
            license_key: license_key, 
            instance_name: instance_name 
        }, { 
            headers: { 
                'Authorization': `Bearer ${process.env.SELLAPP_TOKEN}`,
                'Content-Type': 'application/json' 
            } 
        });
        
        // 2. Calculation of Service Expiration
        let serviceExpiryDate = null; 
        
        if (duration !== 'Lifetime') {
            const numericDays = parseInt(duration);
            if (isNaN(numericDays) === false) {
                serviceExpiryDate = new Date(Date.now() + (numericDays * 24 * 60 * 60 * 1000));
            }
        }
        
        // 3. Persistent Clustering
        const licenseRecordDoc = new License({ 
            key: license_key,
            instanceId: instance_name,
            discordId: discord_id,
            serverId: server_id,
            serverName: server_name,
            type: type,
            duration: duration,
            activatedAt: new Date(),
            expiresAt: serviceExpiryDate,
            reviewRequestSent: false
        });
        
        await licenseRecordDoc.save();
        
        await sendLog(
            "🔑 License Record Provisioned", 
            `**Technician:** ${request.session.username}\n**Client:** <@${discord_id}>\n**Server:** ${server_name}\n**Product:** ${type}`, 
            '#10b981'
        );
        
        // 4. Client Notification Sequence
        try {
            const primaryBot = discordClients[0];
            const clientHandle = await primaryBot.users.fetch(discord_id);
            
            const successEmbed = new EmbedBuilder()
                .setTitle("Service Activated ✅")
                .setDescription(`Your Miraidon instance is now linked to the community: **${server_name}**.`)
                .addFields(
                    { name: "Subscription Tier", value: type, inline: true },
                    { name: "Service Validity", value: duration, inline: true }
                )
                .setColor('#10b981')
                .setTimestamp();
                
            await clientHandle.send({ embeds: [successEmbed] });
            console.log(`[LICENSE] ✅ Activation confirmation DM'd to ${discord_id}`);
        } catch (clientDmFailure) {
            console.warn("[LICENSE] ⚠️ Record created but client DM was blocked.");
        }
        
        return response.json({ 
            success: true 
        });

    } catch (activationLogicError) {
        console.error("[LICENSE] ❌ Activation Sequence Aborted:");
        console.error(activationLogicError.response ? activationLogicError.response.data : activationLogicError.message);
        return response.status(400).json({ 
            error: "Activation Rejected: Verify key validity and instance uniqueness." 
        });
    }
});


// =================================================================================================
//  SECTION 14: SERVICE STATUS AGGREGATION ENGINE
// =================================================================================================

/**
 * ROUTE: Public Pulse Check
 * Method: GET
 * Path: /api/status
 * Aggregates support windows and granular fleet health for the public status page.
 */
app.get('/api/status', async function(request, response) {
    console.log("[HEALTH] 💓 Health aggregation check requested.");
    
    try {
        const configRecord = await Config.findOne({ id: 'global' });
        
        // Support schedule calculations (AST context)
        const currentNow = new Date();
        const formatParts = new Intl.DateTimeFormat('en-US', { timeZone: 'America/Halifax', hour12: false, hour: 'numeric', minute: 'numeric' }).formatToParts(currentNow);
        
        const hourNow = parseInt(formatParts.find(p => p.type === 'hour').value);
        const minNow = parseInt(formatParts.find(p => p.type === 'minute').value);
        const currentTotalMinutes = (hourNow * 60) + minNow;
        
        const [openingH, openingM] = configRecord.openTime.split(':').map(Number);
        const [closingH, closingM] = configRecord.closeTime.split(':').map(Number);
        
        const openTotal = (openingH * 60) + openingM;
        const closeTotal = (closingH * 60) + closingM;

        const isTimeWindowActive = (currentTotalMinutes >= openTotal && currentTotalMinutes <= closeTotal);
        const finalDeskStatus = (configRecord.supportOnline === true && isTimeWindowActive === true);

        // Map fleet health data
        const fleetHealthCollection = discordClients.map(function(clientInstance) {
            const statusEntry = configRecord.botFleetStatus.find(function(entry) {
                const isMatch = (entry.botId === clientInstance.user.id);
                return isMatch;
            });
            
            return {
                name: clientInstance.user.username,
                isOnline: clientInstance.isReady(),
                isTrading: statusEntry ? statusEntry.tradingActive : true
            };
        });

        // Combined health object
        const finalResponse = { 
            support: { 
                isOpen: finalDeskStatus, 
                window: `${configRecord.openTime} - ${configRecord.closeTime} AST`, 
                note: configRecord.offlineNote 
            }, 
            fleet: fleetHealthCollection 
        };

        return response.json(finalResponse);

    } catch (healthAggregationError) {
        console.error("[HEALTH] ❌ Logic fault in pulse check engine:");
        console.error(healthAggregationError);
        return response.status(500).json({ 
            error: "Internal Error: Heartbeat aggregator failed." 
        });
    }
});


// =================================================================================================
//  SECTION 15: AUTOMATION MAINTENANCE AND BACKGROUND CRON TASKS
// =================================================================================================

/**
 * ENGINE: Background Automation
 * Logic: Every 60 minutes
 * Responsibilities: License warnings and Trustpilot milestone requests.
 */

async function executeAutomationCycle() {
    console.log("================================================================================");
    console.log("[CRON] 🕒 Initializing background maintenance cycle...");
    console.log("================================================================================");
    
    const now = new Date();
    
    // --- TASK 1: LICENSE EXPIRATION WARNINGS (72 Hour Window) ---
    const expiryHorizon = new Date();
    expiryHorizon.setDate(now.getDate() + 3);
    
    try {
        const expiringInvoices = await License.find({ 
            expiresAt: { $gt: now, $lt: expiryHorizon }, 
            reminderSent: false 
        });

        console.log(`[CRON] -> Found ${expiringInvoices.length} accounts nearing expiration.`);

        for (const invoice of expiringInvoices) {
            try {
                const primaryBot = discordClients[0];
                const targetCustomer = await primaryBot.users.fetch(invoice.discordId);
                
                const warningEmbed = new EmbedBuilder()
                    .setTitle("⚠️ Service Interruption Warning")
                    .setDescription(`Your Miraidon Trade Services license for **${invoice.serverName || 'your community'}** will expire in less than 72 hours.\n\nTo prevent logic shutdown for your guild, please visit [Sell.app](https://miraidon.sell.app/) and renew your subscription.\nAfter Purchase please us your new Licence Key.`)
                    .setColor('#f59e0b')
                    .setTimestamp();
                    
                await targetCustomer.send({ 
                    embeds: [warningEmbed] 
                });
                
                invoice.reminderSent = true;
                await invoice.save();
                console.log(`[CRON] -> Expiry warning delivered to ID: ${invoice.discordId}`);
            } catch (customerWarnErr) {
                console.warn(`[CRON] -> Delivery failed for customer ${invoice.discordId}. Marking as sent to prevent loops.`);
                invoice.reminderSent = true;
                await invoice.save();
            }
        }
    } catch (expiryQueryErr) {
        console.error("[CRON] ❌ Expiry scan database error.");
    }

    // --- TASK 2: TRUSTPILOT REVIEW ELIGIBILITY (14 Day Milestone) ---
    const reviewMilestoneDate = new Date();
    reviewMilestoneDate.setDate(reviewMilestoneDate.getDate() - 14);

    try {
        const eligibleCandidates = await License.find({
            activatedAt: { $lt: reviewMilestoneDate },
            reviewRequestSent: false
        });

        console.log(`[CRON] -> Found ${eligibleCandidates.length} clients eligible for review milestone.`);

        for (const clientRecord of eligibleCandidates) {
            try {
                const primaryBot = discordClients[0];
                const clientHandle = await primaryBot.users.fetch(clientRecord.discordId);
                
                const reviewRequestEmbed = new EmbedBuilder()
                    .setTitle("🌟 How is Miraidon treating you?")
                    .setColor('#10b981')
                    .setDescription("Greetings! You have been utilizing Miraidon Trade Services for exactly two weeks now.\nOn one of our Premium plans. \nOur system relies on community feedback to maintain its verified status. If you have 60 seconds, could you share your experience on **Trustpilot**?")
                    .addFields({ 
                        name: 'Review URL', 
                        value: 'https://www.trustpilot.com/review/miraidon.ca' 
                    })
                    .setFooter({ text: "Feedback drives our development." });

                await clientHandle.send({ 
                    embeds: [reviewRequestEmbed] 
                });
                
                clientRecord.reviewRequestSent = true;
                await clientRecord.save();
                console.log(`[CRON] -> Trustpilot request delivered to ID: ${clientRecord.discordId}`);
            } catch (reviewDispatchErr) {
                console.warn(`[CRON] -> Milestone DM blocked for ${clientRecord.discordId}. Marking complete.`);
                clientRecord.reviewRequestSent = true;
                await clientRecord.save();
            }
        }
    } catch (reviewQueryErr) {
        console.error("[CRON] ❌ Milestone scan database error.");
    }
    
    console.log("[CRON] ✅ Maintenance cycle completed.");
}

// Initialize hourly scheduler
setInterval(function() {
    executeAutomationCycle();
}, 1000 * 60 * 60);


// =================================================================================================
//  SECTION 16: SYSTEM BOOTSTRAP AND LISTENER
// =================================================================================================

/**
 * FINAL BOOT SEQUENCE:
 * Binds the Express application to the environment's listening port.
 */
const SYSTEM_PORT = process.env.PORT || 10000;

server.listen(SYSTEM_PORT, function() {
    console.log("================================================================================");
    console.log("🚀 MIRAIDON MASTER CONTROLLER ARCHITECTURE: ONLINE");
    console.log(`📡 NETWORK BOUNDARY: PORT ${SYSTEM_PORT}`);
    console.log(`🛠️ SOFTWARE VERSION: 11.2 (ARCHITECTURAL RESTORATION)`);
    console.log(`📅 STARTUP TIMESTAMP: ${new Date().toLocaleString()}`);
    console.log("================================================================================");
});
