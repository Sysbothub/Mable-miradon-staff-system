/**
 * =================================================================================================
 * MIRAIDON TRADE SERVICES - MASTER SERVER (v11.6 - FULL ARCHITECTURAL RESTORATION)
 * =================================================================================================
 * * STATUS: 100% UNCOMPRESSED, MAXIMAL VERBOSITY, NO DELETIONS
 * * LINE COUNT TARGET: 2,500+
 * -------------------------------------------------------------------------------------------------
 * * CORE ARCHITECTURE:
 * 1.  DISCORD INTERFACE: Multi-bot handling for Miraidon and Professor Mable.
 * 2.  RESTful API: Secure endpoints with full error verbosity.
 * 3.  PERSISTENCE: MongoDB for dynamic data, Local FS for transcripts.
 * 4.  REAL-TIME: Socket.io for bi-directional staff-user synchronization.
 * =================================================================================================
 */

// =================================================================================================
//  SECTION 1: MODULE LOADING AND GLOBAL CONFIGURATION
// =================================================================================================

// 1.1. Environment Variable Configuration
// Loads all sensitive keys from the root .env file.
const dotenv = require('dotenv');
dotenv.config();

// 1.2. Core Node.js Networking and File System Modules
const fs = require('fs');
const path = require('path');
const http = require('http');

// 1.3. Web Framework and Utilities
const express = require('express');
const axios = require('axios');
const bcrypt = require('bcrypt');

// 1.4. Real-time Communication
const socketIo = require('socket.io');

// 1.5. Database and Session Management
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');

// 1.6. Discord SDK Components for Gateway Interaction
const discordJs = require('discord.js');

const Client = discordJs.Client;
const GatewayIntentBits = discordJs.GatewayIntentBits;
const Partials = discordJs.Partials;
const EmbedBuilder = discordJs.EmbedBuilder;
const ChannelType = discordJs.ChannelType;
const AttachmentBuilder = discordJs.AttachmentBuilder;
const ActionRowBuilder = discordJs.ActionRowBuilder;
const ButtonBuilder = discordJs.ButtonBuilder;
const ButtonStyle = discordJs.ButtonStyle;

// 1.7. Application Instance Initialization
const app = express();
const server = http.createServer(app);
const io = new socketIo.Server(server);


// =================================================================================================
//  SECTION 2: PERSISTENT DISK STORAGE ARCHITECTURE
// =================================================================================================

console.log("================================================================================");
console.log("[STORAGE_ENGINE] 📂 Verifying persistence layers...");
console.log("================================================================================");

let DATA_DIR;

/**
 * PATH RESOLUTION LOGIC:
 * Determines the mount point for persistent data based on the deployment environment.
 */
const isRenderEnv = (process.env.RENDER === 'true');

if (isRenderEnv === true) 
{
    console.log("[STORAGE_ENGINE] ☁️ Production environment (Render.com) detected.");
    DATA_DIR = '/var/data';
} 
else 
{
    console.log("[STORAGE_ENGINE] 💻 Development environment (Local) detected.");
    DATA_DIR = path.join(__dirname, 'local_storage');
}

/**
 * ROOT DIRECTORY CHECK:
 * Ensures the system has a valid location to write transcripts and logs.
 */
const rootExists = fs.existsSync(DATA_DIR);

if (rootExists === false) 
{
    console.log(`[STORAGE_ENGINE] 📂 Creating root data directory at: ${DATA_DIR}`);
    try 
    {
        fs.mkdirSync(DATA_DIR, { recursive: true });
        console.log(`[STORAGE_ENGINE] ✅ Root Directory Created.`);
    } 
    catch (mkdirError) 
    {
        console.error(`[STORAGE_ENGINE] ❌ CRITICAL: Storage initialization failed.`);
        console.error(`[STORAGE_ENGINE] 🛑 Error: ${mkdirError.message}`);
        process.exit(1); 
    }
} 
else 
{
    console.log(`[STORAGE_ENGINE] ✅ Root Directory verified: ${DATA_DIR}`);
}

/**
 * ARCHIVE DIRECTORY CHECK:
 * Segregates closed ticket transcripts into a dedicated sub-folder.
 */
const ARCHIVE_DIR = path.join(DATA_DIR, 'archives');
const archiveExists = fs.existsSync(ARCHIVE_DIR);

if (archiveExists === false) 
{
    console.log(`[STORAGE_ENGINE] 📂 Creating archive directory at: ${ARCHIVE_DIR}`);
    try 
    {
        fs.mkdirSync(ARCHIVE_DIR, { recursive: true });
        console.log(`[STORAGE_ENGINE] ✅ Archive Directory Created.`);
    } 
    catch (archiveError) 
    {
        console.error(`[STORAGE_ENGINE] ❌ WARNING: Failed to create archives folder.`);
        console.error(`[STORAGE_ENGINE] 🛑 Error: ${archiveError.message}`);
    }
} 
else 
{
    console.log(`[STORAGE_ENGINE] ✅ Archive Directory verified: ${ARCHIVE_DIR}`);
}


// =================================================================================================
//  SECTION 3: MONGODB DATABASE PERSISTENCE HANDSHAKE
// =================================================================================================

console.log("[DATABASE_ENGINE] ⏳ Handshaking with MongoDB cluster...");

/**
 * ESTABLISH CONNECTION:
 * Connects to the URI provided in the .env file.
 */
const mongoUri = process.env.MONGODB_URI;

mongoose.connect(mongoUri)
    .then(function() 
    {
        console.log("================================================================================");
        console.log("[DATABASE_ENGINE] ✅ Connection Status: ESTABLISHED");
        console.log(`[DATABASE_ENGINE] 🕒 Handshake Timestamp: ${new Date().toLocaleString()}`);
        console.log("================================================================================");
        
        // Execute bootstrap sequences
        initializeSystemDefaults();
        performDatabaseRepair();
    })
    .catch(function(dbError) 
    {
        console.error("================================================================================");
        console.error("[DATABASE_ENGINE] ❌ CRITICAL HANDSHAKE FAILURE");
        console.error(`[DATABASE_ENGINE] 🛑 REASON: ${dbError.message}`);
        console.error("================================================================================");
    });


// =================================================================================================
//  SECTION 4: DATABASE SCHEMAS AND DATA MODELS
// =================================================================================================

/**
 * 4.1. STAFF SCHEMA
 * Handles personnel credentials and performance analytics.
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
 * Represents an active inquiry between a trainer and the staff panel.
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
 * Tracks activated premium/rental keys.
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
 * Global system states and granular bot fleet toggles.
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
 * 4.5. CRM AND CONTENT MODELS
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
//  SECTION 5: SYSTEM SECURITY HELPERS AND INITIALIZATION
// =================================================================================================

/**
 * Function: validateComplexPassword
 * Enforces the 8-character complex security policy.
 */
function validateComplexPassword(passwordValue) 
{
    const minimumLen = 8;
    const uppercaseRegex = /[A-Z]/;
    const numericRegex = /[0-9]/;
    const specialRegex = /[\W_]/; 
    
    const lengthCheck = (passwordValue.length >= minimumLen);
    if (lengthCheck === false) 
    {
        return false;
    }
    
    const hasCapital = uppercaseRegex.test(passwordValue);
    if (hasCapital === false) 
    {
        return false;
    }
    
    const hasNumber = numericRegex.test(passwordValue);
    if (hasNumber === false) 
    {
        return false;
    }
    
    const hasSymbol = specialRegex.test(passwordValue);
    if (hasSymbol === false) 
    {
        return false;
    }
    
    return true;
}

/**
 * Function: generateComplexPassword
 * Random key generator for administrative re-keying actions.
 */
function generateComplexPassword() 
{
    const lower = "abcdefghijklmnopqrstuvwxyz";
    const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const nums = "0123456789";
    const syms = "!@#$%^&*?";
    
    let resultStr = "";
    
    // Explicit injection
    resultStr += upper[Math.floor(Math.random() * upper.length)];
    resultStr += nums[Math.floor(Math.random() * nums.length)];
    resultStr += syms[Math.floor(Math.random() * syms.length)];
    resultStr += lower[Math.floor(Math.random() * lower.length)];
    
    const pool = lower + upper + nums + syms;
    
    for (let x = 0; x < 12; x++) 
    {
        resultStr += pool[Math.floor(Math.random() * pool.length)];
    }
    
    const arr = resultStr.split('');
    
    for (let i = arr.length - 1; i > 0; i--) 
    {
        const j = Math.floor(Math.random() * (i + 1));
        const temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
    
    const finalKey = arr.join('');
    return finalKey;
}

/**
 * Routine: initializeSystemDefaults
 * Creates root administrative and configuration documents on first boot.
 */
async function initializeSystemDefaults() 
{
    console.log("[BOOTSTRAP] 🔍 Verifying initialization documents...");
    
    try 
    {
        const adminFound = await Staff.findOne({ username: 'admin' });
        
        if (adminFound === null) 
        {
            console.log("[BOOTSTRAP] 👤 Creating root admin account...");
            const hash = await bcrypt.hash('Map4491!', 10);
            
            const adminDoc = new Staff({ 
                username: 'admin', 
                password: hash, 
                discordId: '000000000000000000', 
                isAdmin: true 
            });
            
            await adminDoc.save();
            console.log("[BOOTSTRAP] ✅ Root admin created.");
        }

        const configFound = await Config.findOne({ id: 'global' });
        
        if (configFound === null) 
        {
            console.log("[BOOTSTRAP] ⚙️ Creating global configuration profile...");
            
            const configDoc = new Config({ 
                id: 'global', 
                supportOnline: true, 
                openTime: "08:00", 
                closeTime: "23:59",
                botFleetStatus: []
            });
            
            await configDoc.save();
            console.log("[BOOTSTRAP] ✅ Global config ready.");
        }
    } 
    catch (e) 
    {
        console.error("[BOOTSTRAP] ❌ Initialization Error:", e.message);
    }
}

/**
 * Routine: performDatabaseRepair
 * Syncs legacy data fields with current schema version.
 */
async function performDatabaseRepair() 
{
    console.log("[REPAIR] 🛠️ Verifying database integrity...");
    
    try 
    {
        await Thread.updateMany(
            { claimedBy: { $exists: false } },
            { $set: { claimedBy: null } }
        );
        
        await Thread.updateMany(
            { userAvatar: { $exists: false } },
            { $set: { userAvatar: 'https://cdn.discordapp.com/embed/avatars/0.png' } }
        );

        await License.updateMany(
            { reviewRequestSent: { $exists: false } },
            { $set: { reviewRequestSent: false } }
        );

        console.log("[REPAIR] ✅ Structural verification complete.");
    } 
    catch (e) 
    {
        console.error("[REPAIR] ❌ Failure during database scan.");
    }
}


// =================================================================================================
//  SECTION 6: EXPRESS WEB SERVER AND SESSION MIDDLEWARE
// =================================================================================================

// 6.1. Networking Configuration
app.set('trust proxy', 1);

// 6.2. Inbound Data Body Parsers
app.use(express.json({ limit: '60mb' }));
app.use(express.urlencoded({ extended: true, limit: '60mb' }));

// 6.3. Session Persistence Architecture
const sessionConfig = {
    secret: process.env.SESSION_SECRET || 'miraidon-master-key-security-unset',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'staff_panel_sessions',
        ttl: 14 * 24 * 60 * 60 
    }),
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, 
        secure: true, 
        sameSite: 'none' 
    }
};

app.use(session(sessionConfig));

/**
 * 6.4. Guard: isAuth
 * Middleware to restrict staff API routes to logged-in users only.
 */
const isAuth = function(req, res, next) 
{
    const staffIdExists = (req.session.staffId !== undefined);
    
    if (staffIdExists === true) 
    {
        return next();
    }
    
    const pathRequested = req.path;
    const isApiRequest = pathRequested.startsWith('/api');
    
    if (isApiRequest === true) 
    {
        const errObj = { error: "Authentication required." };
        return res.status(401).json(errObj);
    }
    
    return res.redirect('/login.html');
};

/**
 * 6.5. Guard: isAdmin
 * Higher-level restriction for destructive or administrative actions.
 */
const isAdmin = function(req, res, next) 
{
    const hasStaffSession = (req.session.staffId !== undefined);
    const hasAdminPermission = (req.session.isAdmin === true);
    
    if (hasStaffSession === true && hasAdminPermission === true) 
    {
        return next();
    }
    
    const errObj = { error: "Administrative clearance required." };
    return res.status(403).json(errObj);
};

// 6.6. Static Directory Mapping
// Primary public directory
app.use(express.static(path.join(__dirname, 'public')));

// Protected staff directory
app.use('/staff', isAuth, express.static(path.join(__dirname, 'public/staff')));


// =================================================================================================
//  SECTION 7: DISCORD GATEWAY INTERFACE (MIRAIDON FLEET)
// =================================================================================================

/**
 * GATEWAY BOOTSTRAP:
 * Filters the environment for bot tokens.
 */
const botTokensRawList = [
    process.env.BOT_ONE_TOKEN, 
    process.env.BOT_TWO_TOKEN
];

const botTokensValidatedList = botTokensRawList.filter(function(token) 
{
    const tokenExists = (token !== undefined && token !== null && token !== "");
    return tokenExists;
});

const clientsCollection = [];

/**
 * Function: sendLog
 * UPDATED v11.1: Supports role mentions via environmental STAFF_ROLE_ID.
 */
async function sendLog(title, description, colorCode = '#3b82f6', fileArray = [], mentionContent = "") 
{
    const logChannelId = process.env.LOG_CHANNEL_ID;
    const botReady = (clientsCollection[0] !== undefined);
    
    if (!logChannelId || !botReady) 
    {
        return;
    }
    
    try 
    {
        const channel = await clientsCollection[0].channels.fetch(logChannelId);
        
        if (channel) 
        {
            const embed = new EmbedBuilder()
                .setTitle(title)
                .setDescription(description)
                .setColor(colorCode)
                .setTimestamp()
                .setFooter({ text: "System Audit Log" });
                
            const dispatchPayload = { 
                embeds: [embed], 
                files: fileArray 
            };
            
            if (mentionContent !== "") 
            {
                dispatchPayload.content = mentionContent;
            }
            
            await channel.send(dispatchPayload);
        }
    } 
    catch (e) 
    { 
        console.error(`[LOG] ❌ Failed to dispatch embed: ${e.message}`); 
    }
}

// 7.1. Bot Engine Loop
botTokensValidatedList.forEach(function(tokenValue, gatewayIndex) 
{
    const clientInstance = new Client({
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

    // 7.2. Lifecycle: Authorization
    clientInstance.once('ready', function() 
    {
        console.log(`[GATEWAY] 🤖 AUTHORIZED: Bot Client ${gatewayIndex + 1} (${clientInstance.user.tag})`);
    });

    // 7.3. Event: Client Composition (Typing)
    clientInstance.on('typingStart', function(typing) 
    {
        const userIsBot = typing.user.bot;
        if (userIsBot === true) 
        {
            return;
        }
        io.emit('user_typing', { userId: typing.user.id });
    });

    // 7.4. Event: Interaction Handling (Review Interaction)
    clientInstance.on('interactionCreate', async function(interaction) 
    {
        const isButton = interaction.isButton();
        if (isButton === false) 
        {
            return;
        }

        const idString = interaction.customId;
        const idArray = idString.split('_');
        const actionType = idArray[0];
        
        if (actionType === 'rate') 
        {
            const scoreValue = parseInt(idArray[1]);
            const staffDbId = idArray[2];
            
            console.log(`[ANALYTICS] 🌟 Received ${scoreValue}-star rating for ${staffDbId}`);

            try 
            {
                await Staff.findByIdAndUpdate(staffDbId, { 
                    $inc: { 
                        ratingSum: scoreValue, 
                        ratingCount: 1 
                    } 
                });

                const confirmationRow = new ActionRowBuilder().addComponents(
                    new ButtonBuilder()
                        .setCustomId('logged')
                        .setLabel(`Experience Rated: ${scoreValue}/5`)
                        .setStyle(ButtonStyle.Success)
                        .setDisabled(true)
                );

                await interaction.update({ 
                    content: `**Feedback Recorded.** You've rated this session **${scoreValue} stars**.`, 
                    components: [confirmationRow] 
                });
            } 
            catch (writeErr) 
            {
                console.error(`[ANALYTICS] ❌ Failed to commit rating.`);
            }
        }
    });

    // -----------------------------------------------------------------------------------------
    // 7.5. MAIN INBOUND MESSAGE LISTENER (REPAIRED & VERBOSE)
    // -----------------------------------------------------------------------------------------
    clientInstance.on('messageCreate', async function(message) 
    {
        // 1. Validation: No bots and No Guild messages (DMs only).
        const fromBot = message.author.bot;
        if (fromBot === true) 
        {
            return;
        }
        
        const inGuild = (message.guild !== null);
        if (inGuild === true) 
        {
            return;
        }
        
        console.log(`[GATEWAY] 📥 Packet from ${message.author.tag}`);
        
        const discordUserId = message.author.id;
        const currentPfpUrl = message.author.displayAvatarURL({ extension: 'png', size: 128 });

        try 
        {
            // STEP 1: Query database for existing inquiry
            let threadRecord = await Thread.findOne({ 
                userId: discordUserId, 
                botId: clientInstance.user.id 
            });
            
            // STEP 2: Handle Initial Contact
            if (threadRecord === null) 
            {
                console.log(`[ENGINE] 🏗️ Initializing document for trainer ${message.author.tag}`);
                
                threadRecord = new Thread({ 
                    userId: discordUserId, 
                    userTag: message.author.tag, 
                    userAvatar: currentPfpUrl, 
                    botId: clientInstance.user.id, 
                    botName: clientInstance.user.username, 
                    messages: [] 
                });
                
                // STEP 3: Generate Auto-Reply Logic
                const configDoc = await Config.findOne({ id: 'global' });
                
                const isManualOffline = (configDoc ? configDoc.supportOnline === false : false);
                const openTimeStr = configDoc ? configDoc.openTime : "08:00";
                const closeTimeStr = configDoc ? configDoc.closeTime : "23:59";

                // Schedule logic (AST)
                const now = new Date();
                const astFormat = { timeZone: 'America/Halifax', hour12: false, hour: 'numeric', minute: 'numeric' };
                const timeString = new Intl.DateTimeFormat('en-US', astFormat).format(now);
                const [hNow, mNow] = timeString.split(':').map(Number);
                const elapsedMin = (hNow * 60) + mNow;

                const [hOpen, mOpen] = openTimeStr.split(':').map(Number);
                const [hClose, mClose] = closeTimeStr.split(':').map(Number);
                const limitOpen = (hOpen * 60) + mOpen;
                const limitClose = (hClose * 60) + mClose;

                const isWithinWindow = (elapsedMin >= limitOpen && elapsedMin <= limitClose);

                let replyEmbed;

                if (isManualOffline === true) 
                {
                    replyEmbed = new EmbedBuilder()
                        .setColor('#ef4444')
                        .setTitle('Support Terminal: Offline')
                        .setDescription(`The desk is currently on a scheduled break.\n\n**Note:** ${configDoc.offlineNote || 'Unscheduled Maintenance.'}\nYour Inquiry has been received and will be responded to by the next avaialble agent.`)
                        .setTimestamp();
                } 
                else if (isWithinWindow === false) 
                {
                    replyEmbed = new EmbedBuilder()
                        .setColor('#f59e0b')
                        .setTitle('Support Terminal: Closed')
                        .setDescription(`Outside of response window: **${openTimeStr} - ${closeTimeStr} AST**. Your Inquiry has been received and will be responded to when office hours resume.`)
                        .setTimestamp();
                } 
                else 
                {
                    replyEmbed = new EmbedBuilder()
                        .setColor('#3b82f6')
                        .setTitle('Support Ticket Received.')
                        .setDescription('Thank you for your inquiry. Your request has been received, and a member of our support team will follow up with you as soon as possible.')
                        .setFooter('Estimated Response Time 1-2 Hours\nBusiness Hours  **${openTimeStr} - ${closeTimeStr} AST**')
                        .setTimestamp();
                }
                
                // DISPATCH DM
                const authorObject = message.author;
                await authorObject.send({ embeds: [replyEmbed] }).catch(function() {
                    console.warn(`[ENGINE] ⚠️ DM failed for ${message.author.tag}`);
                });

                // DISPATCH STAFF PING (v11.1)
                let pingString = "@here";
                const roleId = process.env.STAFF_ROLE_ID;
                if (roleId && roleId !== "") 
                {
                    pingString = `<@&${roleId}>`;
                }

                await sendLog(
                    "🆕 New Ticket Created", 
                    `**User:** ${message.author.tag}\n**Bot:** ${clientInstance.user.username}`, 
                    '#facc15', 
                    [], 
                    pingString
                );
            } 
            else 
            {
                // Sync PFP if changed
                if (threadRecord.userAvatar !== currentPfpUrl) 
                {
                    threadRecord.userAvatar = currentPfpUrl;
                }
            }
            
            // STEP 4: Capture Message Data
            const atts = message.attachments.map(function(a) { 
                return a.url; 
            });
            
            const messageObject = { 
                authorTag: message.author.tag, 
                authorAvatar: currentPfpUrl, 
                content: message.content || "[Media Attachment]", 
                attachments: atts, 
                fromBot: false, 
                timestamp: new Date() 
            };

            // STEP 5: Persistence
            threadRecord.messages.push(messageObject);
            threadRecord.lastMessageAt = new Date();
            await threadRecord.save();
            
            // STEP 6: Real-time UI synchronization
            const webPayload = { 
                threadId: threadRecord._id, 
                notif_sound: true, 
                ...messageObject 
            };
            io.emit('new_message', webPayload);
            
            console.log(`[ENGINE] ✅ Sync SUCCESS for inquiry: ${message.author.tag}`);

        } 
        catch (e) 
        {
            console.error("[ENGINE] ❌ Critical failure during message listener:");
            console.error(e);
        }
    });

    clientInstance.login(tokenValue).catch(function(err) 
    { 
        console.error(`[GATEWAY] ❌ Client ${gatewayIndex + 1} Login Failed.`); 
    });
    
    clientsCollection.push(clientInstance);
});


// =================================================================================================
//  SECTION 8: REAL-TIME COMMUNICATION GATEWAY (SOCKET.IO)
// =================================================================================================

const roomMembersCache = {}; 

io.on('connection', function(socketInstance) 
{
    /**
     * EVENT: join_ticket_room
     * Collision detection initialization for staff.
     */
    socketInstance.on('join_ticket_room', function(payload) 
    {
        const threadId = payload.threadId;
        const name = payload.username;

        socketInstance.join(threadId);
        
        const exists = (roomMembersCache[threadId] !== undefined);
        if (exists === false) 
        {
            roomMembersCache[threadId] = new Set();
        }
        roomMembersCache[threadId].add(name);
        
        // Update presence list for current room
        const presenceArray = Array.from(roomMembersCache[threadId]);
        io.to(threadId).emit('viewers_updated', presenceArray);
        
        socketInstance.currentThreadId = threadId; 
        socketInstance.currentUser = name;
    });

    /**
     * EVENT: leave_ticket_room
     */
    const cleanupPresenceFunction = function() 
    { 
        const tid = socketInstance.currentThreadId;
        const usr = socketInstance.currentUser;

        if (tid && usr) 
        {
            const cache = roomMembersCache[tid];
            if (cache) 
            {
                cache.delete(usr);
                const updatedList = Array.from(cache);
                io.to(tid).emit('viewers_updated', updatedList);
            }
        }
    };
    
    socketInstance.on('leave_ticket_room', cleanupPresenceFunction);
    socketInstance.on('disconnect', cleanupPresenceFunction);
    
    /**
     * EVENT: staff_typing
     * Proxies visual feedback to Discord DM.
     */
    socketInstance.on('staff_typing', async function(payload) 
    {
        try 
        {
            const doc = await Thread.findById(payload.threadId);
            if (doc !== null) 
            {
                const gateway = clientsCollection.find(function(c) { 
                    return (c.user.id === doc.botId); 
                });
                
                if (gateway) 
                {
                    const user = await gateway.users.fetch(doc.userId);
                    const chan = user.dmChannel || await user.createDM();
                    await chan.sendTyping();
                }
            }
        } 
        catch(e) { }
    });
});


// =================================================================================================
//  SECTION 9: STAFF AUTHENTICATION API
// =================================================================================================

/**
 * ROUTE: Staff Login
 * POST /api/login
 */
app.post('/api/login', async function(req, res) 
{
    const u = req.body.username;
    const p = req.body.password;
    
    try 
    {
        const userDoc = await Staff.findOne({ username: u });
        
        if (userDoc === null) 
        {
            const err = { error: "Access Denied: Identity not recognized." };
            return res.status(401).json(err);
        }

        const authorized = await bcrypt.compare(p, userDoc.password);
        
        if (authorized === true) 
        {
            // Synchronize Profile Photo
            try 
            {
                if (clientsCollection[0]) 
                {
                    const profile = await clientsCollection[0].users.fetch(userDoc.discordId);
                    userDoc.avatar = profile.displayAvatarURL({ extension: 'png' });
                    await userDoc.save();
                }
            } 
            catch (pfpErr) { }

            req.session.staffId = userDoc._id; 
            req.session.isAdmin = userDoc.isAdmin; 
            req.session.username = userDoc.username;
            
            req.session.save(function() 
            {
                const success = { 
                    success: true, 
                    isAdmin: userDoc.isAdmin, 
                    username: userDoc.username 
                };
                return res.json(success);
            });
        } 
        else 
        {
            const err = { error: "Access Denied: Identity not recognized." };
            return res.status(401).json(err);
        }
    } 
    catch (e) 
    {
        return res.status(500).json({ error: "Internal Auth Error" });
    }
});

/**
 * ROUTE: Staff Logout
 */
app.post('/api/logout', function(req, res) 
{
    req.session.destroy(function() 
    {
        res.clearCookie('connect.sid');
        return res.json({ success: true });
    });
});

/**
 * ROUTE: Get Session Identity
 */
app.get('/api/auth/user', isAuth, function(req, res) 
{
    const payload = { 
        username: req.session.username, 
        isAdmin: req.session.isAdmin 
    };
    return res.json(payload);
});

/**
 * ROUTE: Secure Key Reset (Public)
 */
app.post('/api/public/request-reset', async function(req, res) 
{
    const id = req.body.discordId;
    
    try 
    {
        const staff = await Staff.findOne({ discordId: id });
        if (staff === null) 
        { 
            return res.status(404).json({ error: "ID mismatch." }); 
        }
        
        const k = generateComplexPassword();
        staff.password = await bcrypt.hash(k, 10);
        await staff.save();
        
        const primary = clientsCollection[0];
        const user = await primary.users.fetch(id);
        
        const resetEmbed = new EmbedBuilder()
            .setTitle("🔒 Terminal Restoration Sequence")
            .setDescription(`Identity re-keyed.\n\n**Key:** \`${k}\``)
            .setColor('#facc15');
            
        await user.send({ embeds: [resetEmbed] });
        return res.json({ success: true });
    } 
    catch (e) 
    {
        return res.status(500).json({ error: "Dispatch failed." });
    }
});

/**
 * ROUTE: Change Password (Self-Service)
 */
app.post('/api/staff/change-password', isAuth, async function(req, res) 
{
    const oldKey = req.body.currentPassword;
    const newKey = req.body.newPassword;
    
    try 
    {
        if (validateComplexPassword(newKey) === false) 
        {
            const err = { error: "Weak Key: Must meet complexity policy." };
            return res.status(400).json(err);
        }
        
        const doc = await Staff.findById(req.session.staffId);
        const matches = await bcrypt.compare(oldKey, doc.password);
        
        if (matches === false) 
        { 
            return res.status(401).json({ error: "Old key mismatch." }); 
        }
        
        doc.password = await bcrypt.hash(newKey, 10);
        await doc.save();
        return res.json({ success: true });
    } 
    catch (e) 
    {
        return res.status(500).json({ error: "Update failure." });
    }
});


// =================================================================================================
//  SECTION 10: SUPPORT OPERATIONS API (TICKETING CORE)
// =================================================================================================

/**
 * ROUTE: List Inbox
 */
app.get('/api/threads', isAuth, async function(req, res) 
{
    try 
    {
        const inbox = await Thread.find().sort({ lastMessageAt: -1 });
        return res.json(inbox);
    } 
    catch (e) 
    { 
        return res.status(500).json({ error: "DB error." }); 
    }
});

/**
 * ROUTE: Outbound Reply
 */
app.post('/api/reply', isAuth, async function(req, res) 
{
    const id = req.body.threadId;
    const content = req.body.content;
    const file = req.body.fileBase64;
    const fileName = req.body.fileName;
    
    try 
    {
        const thread = await Thread.findById(id);
        const bot = clientsCollection.find(function(c) { return (c.user.id === thread.botId); });
        const staff = await Staff.findById(req.session.staffId);
        
        const user = await bot.users.fetch(thread.userId);
        
        const embed = new EmbedBuilder()
            .setColor('#3b82f6')
            .setAuthor({ 
                name: `Staff Member: ${req.session.username}`, 
                iconURL: bot.user.displayAvatarURL() 
            })
            .setDescription(content || "[Attachment]")
            .setTimestamp();
            
        const payload = { embeds: [embed] };
        
        if (file) 
        {
            const buffer = Buffer.from(file.split(',')[1], 'base64');
            const attachment = new AttachmentBuilder(buffer, { name: fileName });
            payload.files = [attachment];
        }
        
        await user.send(payload);
        
        const entry = { 
            authorTag: `Staff (${req.session.username})`, 
            authorAvatar: staff ? staff.avatar : '', 
            content: content || "[Attachment]", 
            fromBot: true, 
            timestamp: new Date() 
        };
        
        thread.messages.push(entry);
        thread.lastMessageAt = new Date();
        await thread.save();
        
        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { repliesSent: 1 } });
        
        io.emit('new_message', { 
            threadId: thread._id, 
            ...entry 
        });
        
        return res.json({ success: true });
    } 
    catch (e) 
    {
        return res.status(500).json({ error: "Dispatch failed." });
    }
});

/**
 * ROUTE: Archive Inquiry
 */
app.post('/api/close-thread', isAuth, async function(req, res) 
{
    const id = req.body.threadId;
    const officer = req.session.username;
    
    try 
    {
        const thread = await Thread.findById(id);
        if (thread === null) { return res.sendStatus(404); }

        let transcript = `OFFICIAL TRANSCRIPT: ${thread.userTag}\nOfficer: ${officer}\n\n`;
        thread.messages.forEach(function(m) {
            transcript += `[${m.timestamp.toISOString()}] ${m.authorTag}: ${m.content}\n`;
        });
        
        const logPath = path.join(__dirname, `tmp-${thread.userId}.txt`);
        fs.writeFileSync(logPath, transcript);
        
        const logAtt = new AttachmentBuilder(logPath);
        await sendLog("🔒 Archive Logged", `User: ${thread.userTag}`, '#ef4444', [logAtt]);
        
        const userFolder = path.join(ARCHIVE_DIR, thread.userId);
        if (fs.existsSync(userFolder) === false) { fs.mkdirSync(userFolder, { recursive: true }); }
        fs.writeFileSync(path.join(userFolder, `${Date.now()}-${thread._id}.json`), JSON.stringify(thread));
        
        const bot = clientsCollection.find(function(c) { return (c.user.id === thread.botId); });
        
        if (bot) 
        {
            const row = new ActionRowBuilder().addComponents(
                new ButtonBuilder().setCustomId(`rate_1_${req.session.staffId}`).setLabel('1⭐').setStyle(ButtonStyle.Secondary),
                new ButtonBuilder().setCustomId(`rate_2_${req.session.staffId}`).setLabel('2⭐').setStyle(ButtonStyle.Secondary),
                new ButtonBuilder().setCustomId(`rate_3_${req.session.staffId}`).setLabel('3⭐').setStyle(ButtonStyle.Secondary),
                new ButtonBuilder().setCustomId(`rate_4_${req.session.staffId}`).setLabel('4⭐').setStyle(ButtonStyle.Primary),
                new ButtonBuilder().setCustomId(`rate_5_${req.session.staffId}`).setLabel('5⭐').setStyle(ButtonStyle.Success)
            );
            
            try 
            { 
                const u = await bot.users.fetch(thread.userId); 
                await u.send({ 
                    content: "Please rate your experience with staff today:", 
                    components: [row] 
                }); 
            } 
            catch(err) { }
        }

        await Staff.findByIdAndUpdate(req.session.staffId, { $inc: { ticketsClosed: 1 } });
        await Thread.findByIdAndDelete(id);
        
        if (fs.existsSync(logPath)) { fs.unlinkSync(logPath); }
        return res.json({ success: true });
    } 
    catch (e) 
    {
        return res.status(500).json({ error: "Archival process failed." });
    }
});


// =================================================================================================
//  SECTION 11: CRM AND ADMIN API (VERBOSE)
// =================================================================================================

/**
 * ROUTE: Aggregation of User Intel
 */
app.get('/api/crm/user/:discordId', isAuth, async function(req, res) 
{
    const id = req.params.discordId;
    
    try 
    {
        const note = await UserNote.findOne({ userId: id });
        const dir = path.join(ARCHIVE_DIR, id);
        let history = [];
        
        if (fs.existsSync(dir)) 
        {
            history = fs.readdirSync(dir).map(function(file) {
                try {
                    const raw = fs.readFileSync(path.join(dir, file));
                    const json = JSON.parse(raw);
                    return { 
                        filename: file, 
                        closedAt: json.meta?.closedAt || json.lastMessageAt 
                    };
                } catch(e) { return null; }
            }).filter(function(x) { return (x !== null); });
        }
        
        const payload = { 
            note: note ? note.note : "", 
            history: history 
        };
        return res.json(payload);
    } 
    catch (e) 
    { 
        return res.status(500).json({ error: "CRM failure." }); 
    }
});

/**
 * ROUTE: Retrieve Transcript
 */
app.get('/api/crm/transcript/:id/:file', isAuth, function(req, res) 
{
    const p = path.join(ARCHIVE_DIR, req.params.id, req.params.file);
    
    if (fs.existsSync(p)) 
    { 
        const raw = fs.readFileSync(p);
        return res.json(JSON.parse(raw)); 
    }
    
    return res.status(404).json({ error: "Missing record." });
});

/**
 * ROUTE: Update Trainer Note
 */
app.post('/api/crm/note', isAuth, async function(req, res) 
{
    try 
    {
        await UserNote.findOneAndUpdate(
            { userId: req.body.userId }, 
            { note: req.body.note, updatedBy: req.session.username }, 
            { upsert: true }
        );
        return res.json({ success: true });
    } 
    catch (e) 
    { 
        return res.status(500).json({ error: "Save error." }); 
    }
});

/**
 * ROUTE: Performance Stats
 */
app.get('/api/admin/stats', isAdmin, async function(req, res) 
{
    try 
    { 
        const stats = await Staff.find().sort({ ticketsClosed: -1 });
        return res.json(stats); 
    } 
    catch (e) 
    { 
        return res.status(500).json({ error: "Read failure." }); 
    }
});

/**
 * ROUTE: Global Configuration
 */
app.get('/api/admin/config', isAdmin, async function(req, res) 
{
    try 
    { 
        const cfg = await Config.findOne({ id: 'global' });
        return res.json(cfg); 
    } 
    catch (e) 
    { 
        return res.status(500).json({ error: "Read failure." }); 
    }
});

/**
 * ROUTE: Support Toggle
 */
app.post('/api/admin/config/toggle', isAdmin, async function(req, res) 
{
    try 
    {
        const cfg = await Config.findOne({ id: 'global' });
        if (req.body.status !== undefined) { cfg.supportOnline = req.body.status; }
        if (req.body.note !== undefined) { cfg.offlineNote = req.body.note; }
        if (req.body.openTime) { cfg.openTime = req.body.openTime; }
        if (req.body.closeTime) { cfg.closeTime = req.body.closeTime; }
        await cfg.save();
        return res.json({ success: true });
    } 
    catch (e) 
    { 
        return res.status(500).json({ error: "Persistence error." }); 
    }
});

/**
 * ROUTE: Server Fleet Listing
 */
app.get('/api/admin/servers', isAdmin, async function(req, res) 
{
    let inventory = [];
    clientsCollection.forEach(function(c) 
    {
        if (c.isReady()) 
        {
            c.guilds.cache.forEach(function(g) 
            {
                inventory.push({ 
                    id: g.id, 
                    name: g.name, 
                    members: g.memberCount, 
                    botName: c.user.username, 
                    botId: c.user.id 
                });
            });
        }
    });
    return res.json(inventory);
});

/**
 * ROUTE: Trading Module Toggle
 */
app.post('/api/admin/fleet/toggle-trading', isAdmin, async function(req, res) 
{
    try 
    {
        const cfg = await Config.findOne({ id: 'global' });
        let targetBot = cfg.botFleetStatus.find(function(x) { 
            return (x.botId === req.body.botId); 
        });
        
        if (targetBot) 
        { 
            targetBot.tradingActive = req.body.status; 
        }
        else 
        { 
            cfg.botFleetStatus.push({ 
                botId: req.body.botId, 
                tradingActive: req.body.status 
            }); 
        }
        
        await cfg.save();
        return res.json({ success: true });
    } 
    catch (e) 
    { 
        return res.status(500).json({ error: "Update failure." }); 
    }
});


// =================================================================================================
//  SECTION 12: PUBLIC STATUS AGGREGATION AND AUTOMATION MAINTENANCE
// =================================================================================================

/**
 * ROUTE: Public Heartbeat
 */
app.get('/api/status', async function(req, res) 
{
    try 
    {
        const cfg = await Config.findOne({ id: 'global' });
        const now = new Date();
        const parts = new Intl.DateTimeFormat('en-US', { timeZone: 'America/Halifax', hour12: false, hour: 'numeric', minute: 'numeric' }).formatToParts(now);
        
        const hNow = parseInt(parts.find(function(x){ return (x.type === 'hour'); }).value);
        const mNow = parseInt(parts.find(function(x){ return (x.type === 'minute'); }).value);
        const curMin = (hNow * 60) + mNow;
        
        const [oH, oM] = cfg.openTime.split(':').map(Number);
        const [cH, cM] = cfg.closeTime.split(':').map(Number);
        const isOpen = (cfg.supportOnline && (curMin >= (oH*60+oM) && curMin <= (cH*60+cM)));

        const fleetHeartbeat = clientsCollection.map(function(bot) 
        {
            const botConf = cfg.botFleetStatus.find(function(x){ return (x.botId === bot.user.id); });
            return { 
                name: bot.user.username, 
                online: bot.isReady(), 
                tradingActive: botConf ? botConf.tradingActive : true 
            };
        });

        const payload = { 
            support: { 
                isOpen: isOpen, 
                window: `${cfg.openTime} - ${cfg.closeTime} AST`, 
                note: cfg.offlineNote 
            }, 
            fleet: fleetHeartbeat 
        };
        return res.json(payload);
    } 
    catch (e) 
    { 
        return res.status(500).json({ error: "Pulse failure." }); 
    }
});

/**
 * ENGINE: Background Automation
 */
setInterval(async function() 
{
    console.log("[AUTOMATION] 🕒 Cycle Initialized.");
    const ts = new Date();
    
    // License Warnings (3 Days)
    const horizon = new Date();
    horizon.setDate(ts.getDate() + 3);
    
    const expiringInvoices = await License.find({ 
        expiresAt: { $gt: ts, $lt: horizon }, 
        reminderSent: false 
    });

    for (const invoice of expiringInvoices) 
    {
        try 
        {
            const handle = await clientsCollection[0].users.fetch(invoice.discordId);
            await handle.send("⚠️ Your subscription expires in less than 72 hours.");
            invoice.reminderSent = true;
            await invoice.save();
        } catch(e) { }
    }
    
    // Trustpilot Review Request (14 Days)
    const milestone = new Date();
    milestone.setDate(ts.getDate() - 14);
    
    const candidates = await License.find({ 
        activatedAt: { $lt: milestone }, 
        reviewRequestSent: false 
    });

    for (const c of candidates) 
    {
        try 
        {
            const handle = await clientsCollection[0].users.fetch(c.discordId);
            await handle.send("🌟 Hope you are enjoying the service! Review us: https://www.trustpilot.com/review/miraidon.ca");
            c.reviewRequestSent = true;
            await c.save();
        } catch(e) { }
    }
}, 3600000);


// =================================================================================================
//  SECTION 13: BOOTSTRAP AND LISTENER
// =================================================================================================

const LISTENING_PORT = process.env.PORT || 10000;

server.listen(LISTENING_PORT, function() 
{
    console.log("================================================================================");
    console.log(`🚀 MASTER ENGINE v11.6 [ARCHITECTURAL RESTORATION] ACTIVE`);
    console.log(`📡 NETWORK BOUNDARY: PORT ${LISTENING_PORT}`);
    console.log("================================================================================");
});
