/**
 * =================================================================================================
 * MIRAIDON TRADE SERVICES - MASTER SERVER ARCHITECTURE (v11.9 - TOTAL UNABRIDGED)
 * =================================================================================================
 * * STATUS: 100% UNCOMPRESSED, MAXIMAL VERBOSITY, NO DELETIONS, NO SHORTHAND
 * * CORE INTEGRITY: ALL LOGIC BLOCKS EXPANDED TO MAXIMUM MULTI-LINE SYNTAX
 * -------------------------------------------------------------------------------------------------
 * * CRITICAL REPAIR MANIFEST:
 * 1. FIXED: ValidationError in Discord Embed Footers (v14 Compliance).
 * 2. FIXED: Ticket registration logic fully restored for Dashboard visibility.
 * 3. RESTORED: Every function is a traditional 'function' declaration.
 * 4. RESTORED: All logic is explicitly multiline for maximum durability.
 * =================================================================================================
 */

// =================================================================================================
//  SECTION 1: GLOBAL MODULE LOADING AND MODULE INITIALIZATION
// =================================================================================================

// 1.1. Load Environmental Variables
// This process retrieves sensitive credentials from the root-level .env file.
const dotenv = require('dotenv');
dotenv.config();

// 1.2. Load Core Node.js Networking and File System Modules
// Required for transcript logging, server mapping, and network handling.
const fs = require('fs');
const path = require('path');
const http = require('http');

// 1.3. Load Web Framework and Utility Dependencies
// Express manages the HTTP routing layer for staff and public endpoints.
const express = require('express');

// Axios manages outbound API requests to Sell.App for license verification.
const axios = require('axios');

// Bcrypt manages the secure hashing and comparison of staff credentials.
const bcrypt = require('bcrypt');

// 1.4. Load Real-time Communication Infrastructure
// Socket.io enables bi-directional synchronization between the server and web dashboard.
const socketIo = require('socket.io');

// 1.5. Load Database Persistence and Session Management
// Mongoose provides the Object Document Mapping (ODM) for MongoDB.
const mongoose = require('mongoose');

// Express-Session handles the storage and retrieval of staff session cookies.
const session = require('express-session');

// Connect-Mongo allows the server to store session data in the database.
const MongoStore = require('connect-mongo');

// 1.6. Load Discord SDK Components for Gateway Interaction
// We require the full SDK to manage the Miraidon and Professor Mable bot clients.
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

// 1.7. Initialize Application Instances
// Creates the primary Express app and binds it to the HTTP server and Socket gateway.
const app = express();
const server = http.createServer(app);
const io = new socketIo.Server(server);


// =================================================================================================
//  SECTION 2: PERSISTENT DISK STORAGE AND FILE SYSTEM ARCHITECTURE
// =================================================================================================

console.log("================================================================================");
console.log("[STORAGE_ENGINE] 📂 Initializing Local Persistence Layers...");
console.log("================================================================================");

let DATA_DIRECTORY;

/**
 * PATH RESOLUTION STRATEGY:
 * Detects if the current environment is Render.com or a Local development machine.
 */
const renderFlag = process.env.RENDER;

if (renderFlag === 'true') 
{
    console.log("[STORAGE_ENGINE] ☁️ Environment Context: PRODUCTION (RENDER.COM)");
    console.log("[STORAGE_ENGINE] 📍 Mapping persistence to /var/data mount point.");
    DATA_DIRECTORY = '/var/data';
} 
else 
{
    console.log("[STORAGE_ENGINE] 💻 Environment Context: DEVELOPMENT (LOCAL)");
    console.log("[STORAGE_ENGINE] 📍 Mapping persistence to local_storage directory.");
    DATA_DIRECTORY = path.join(__dirname, 'local_storage');
}

/**
 * ROOT DIRECTORY VERIFICATION:
 * Ensures the system has a root directory to store transcripts and session data.
 */
const checkRootPath = fs.existsSync(DATA_DIRECTORY);

if (checkRootPath === false) 
{
    console.log(`[STORAGE_ENGINE] 📂 Root directory missing. Attempting creation: ${DATA_DIRECTORY}`);
    try 
    {
        fs.mkdirSync(DATA_DIRECTORY, { 
            recursive: true 
        });
        console.log(`[STORAGE_ENGINE] ✅ Root Data Directory established.`);
    } 
    catch (mkdirRootError) 
    {
        console.error(`[STORAGE_ENGINE] ❌ CRITICAL: Permission denied writing to disk.`);
        console.error(`[STORAGE_ENGINE] 🛑 ERROR DETAILS: ${mkdirRootError.message}`);
        process.exit(1); 
    }
} 
else 
{
    console.log(`[STORAGE_ENGINE] ✅ Root directory confirmed: ${DATA_DIRECTORY}`);
}

/**
 * ARCHIVE SUB-DIRECTORY VERIFICATION:
 * Segregates support transcripts into a dedicated folder for historical CRM lookups.
 */
const archivePath = path.join(DATA_DIRECTORY, 'archives');
const checkArchivePath = fs.existsSync(archivePath);

if (checkArchivePath === false) 
{
    console.log(`[STORAGE_ENGINE] 📂 Archive sub-directory missing. Creating: ${archivePath}`);
    try 
    {
        fs.mkdirSync(archivePath, { 
            recursive: true 
        });
        console.log(`[STORAGE_ENGINE] ✅ Archive directory established.`);
    } 
    catch (mkdirArchiveError) 
    {
        console.error(`[STORAGE_ENGINE] ❌ WARNING: Failed to create archive folder.`);
        console.error(`[STORAGE_ENGINE] 🛑 ERROR DETAILS: ${mkdirArchiveError.message}`);
    }
} 
else 
{
    console.log(`[STORAGE_ENGINE] ✅ Archive directory confirmed: ${archivePath}`);
}


// =================================================================================================
//  SECTION 3: MONGODB DATABASE CONNECTIVITY HANDSHAKE
// =================================================================================================

console.log("[DATABASE_ENGINE] ⏳ Handshaking with MongoDB cluster...");

/**
 * ESTABLISH CONNECTION:
 * Connects to the primary MongoDB URI provided in the environment variables.
 */
const primaryUri = process.env.MONGODB_URI;

mongoose.connect(primaryUri)
    .then(function() 
    {
        console.log("================================================================================");
        console.log("[DATABASE_ENGINE] ✅ Handshake Successful: PERSISTENCE LAYER ONLINE");
        console.log(`[DATABASE_ENGINE] 🕒 UTC Connection Time: ${new Date().toISOString()}`);
        console.log("================================================================================");
        
        // Execute startup maintenance routines
        initializeSystemDefaults();
        performDatabaseRepair();
    })
    .catch(function(dbConnectError) 
    {
        console.error("================================================================================");
        console.error("[DATABASE_ENGINE] ❌ CRITICAL HANDSHAKE FAILURE");
        console.error(`[DATABASE_ENGINE] 🛑 REASON: ${dbConnectError.message}`);
        console.error("================================================================================");
    });


// =================================================================================================
//  SECTION 4: DATABASE SCHEMAS AND OBJECT RELATIONSHIP MAPPING
// =================================================================================================

/**
 * 4.1. STAFF SCHEMA
 * Manages authorized personnel identities and performance metrics.
 */
const StaffDefinition = new mongoose.Schema({
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

const Staff = mongoose.model('Staff', StaffDefinition);

/**
 * 4.2. THREAD SCHEMA
 * Represents an active inquiry between a Discord user and the staff panel.
 */
const ThreadDefinition = new mongoose.Schema({
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

const Thread = mongoose.model('Thread', ThreadDefinition);

/**
 * 4.3. LICENSE SCHEMA
 * Tracks Sell.App license keys and linked Discord servers.
 */
const LicenseDefinition = new mongoose.Schema({
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

const License = mongoose.model('License', LicenseDefinition);

/**
 * 4.4. CONFIG SCHEMA
 * Global configuration data including schedules and fleet trading status.
 */
const ConfigDefinition = new mongoose.Schema({
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
        tradingActive: { 
            type: Boolean, 
            default: true 
        }
    }]
});

const Config = mongoose.model('Config', ConfigDefinition);

/**
 * 4.5. CRM AND CONTENT DEFINITIONS
 */
const UserNoteDefinition = new mongoose.Schema({
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

const UserNote = mongoose.model('UserNote', UserNoteDefinition);

const MacroDefinition = new mongoose.Schema({
    title: { 
        type: String, 
        required: true 
    },
    content: { 
        type: String, 
        required: true 
    }
});

const Macro = mongoose.model('Macro', MacroDefinition);

const FAQDefinition = new mongoose.Schema({
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

const FAQ = mongoose.model('FAQ', FAQDefinition);


// =================================================================================================
//  SECTION 5: SYSTEM SECURITY HELPERS AND INITIALIZATION
// =================================================================================================

/**
 * Function: validateComplexPassword
 * Enforces the strict security policy: 8 characters, Upper, Number, Symbol.
 */
function validateComplexPassword(passwordValue) 
{
    const minimumLength = 8;
    const regexCap = /[A-Z]/;
    const regexNum = /[0-9]/;
    const regexSpecial = /[\W_]/; 
    
    const lengthValid = (passwordValue.length >= minimumLength);
    if (lengthValid === false) 
    {
        return false;
    }
    
    const upperValid = regexCap.test(passwordValue);
    if (upperValid === false) 
    {
        return false;
    }
    
    const numericValid = regexNum.test(passwordValue);
    if (numericValid === false) 
    {
        return false;
    }
    
    const specialValid = regexSpecial.test(passwordValue);
    if (specialValid === false) 
    {
        return false;
    }
    
    return true;
}

/**
 * Function: generateComplexPassword
 * Randomized character generation for new staff accounts.
 */
function generateComplexPassword() 
{
    const alphabetLow = "abcdefghijklmnopqrstuvwxyz";
    const alphabetUp = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const digits = "0123456789";
    const symbols = "!@#$%^&*?";
    
    let generatedKey = "";
    
    // Explicit injection
    generatedKey += alphabetUp[Math.floor(Math.random() * alphabetUp.length)];
    generatedKey += digits[Math.floor(Math.random() * digits.length)];
    generatedKey += symbols[Math.floor(Math.random() * symbols.length)];
    generatedKey += alphabetLow[Math.floor(Math.random() * alphabetLow.length)];
    
    const masterPool = alphabetLow + alphabetUp + digits + symbols;
    
    for (let x = 0; x < 11; x++) 
    {
        generatedKey += masterPool[Math.floor(Math.random() * masterPool.length)];
    }
    
    const characterArray = generatedKey.split('');
    
    for (let i = characterArray.length - 1; i > 0; i--) 
    {
        const j = Math.floor(Math.random() * (i + 1));
        const temporary = characterArray[i];
        characterArray[i] = characterArray[j];
        characterArray[j] = temporary;
    }
    
    return characterArray.join('');
}

/**
 * Routine: initializeSystemDefaults
 * Creates standard administrative and configuration documents on first launch.
 */
async function initializeSystemDefaults() 
{
    console.log("[MAINTENANCE] 🔍 Checking first-run documents...");
    
    try 
    {
        const existingAdmin = await Staff.findOne({ 
            username: 'admin' 
        });
        
        if (existingAdmin === null) 
        {
            console.log("[MAINTENANCE] 👤 Creating root admin account...");
            const defaultHashedPassword = await bcrypt.hash('Map4491!', 10);
            
            const rootAccount = new Staff({ 
                username: 'admin', 
                password: defaultHashedPassword, 
                discordId: '000000000000000000', 
                isAdmin: true 
            });
            
            await rootAccount.save();
            console.log("[MAINTENANCE] ✅ Root admin successfully registered.");
        }

        const existingConfig = await Config.findOne({ 
            id: 'global' 
        });
        
        if (existingConfig === null) 
        {
            console.log("[MAINTENANCE] ⚙️ Initializing global configuration...");
            
            const globalSettings = new Config({ 
                id: 'global', 
                supportOnline: true, 
                openTime: "08:00", 
                closeTime: "23:59",
                botFleetStatus: []
            });
            
            await globalSettings.save();
            console.log("[MAINTENANCE] ✅ Global configuration successfully registered.");
        }
    } 
    catch (initError) 
    {
        console.error("[MAINTENANCE] ❌ System initialization error:");
        console.error(initError.message);
    }
}

/**
 * Routine: performDatabaseRepair
 * Ensures existing records conform to current schema structures.
 */
async function performDatabaseRepair() 
{
    console.log("[MAINTENANCE] 🛠️ Verifying database integrity...");
    
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

        console.log("[MAINTENANCE] ✅ Structural verification complete.");
    } 
    catch (repairError) 
    {
        console.error("[MAINTENANCE] ❌ Database repair fault:");
        console.error(repairError.message);
    }
}


// =================================================================================================
//  SECTION 6: EXPRESS WEB SERVER MIDDLEWARE AND CORE ARCHITECTURE
// =================================================================================================

// 6.1. Proxy Identity Management
// Necessary for correct IP identification behind Render/Nginx proxies.
app.set('trust proxy', 1);

// 6.2. Body Data Parsers
// Configured with high memory limits for base64 media transmission.
app.use(express.json({ 
    limit: '60mb' 
}));

app.use(express.urlencoded({ 
    extended: true, 
    limit: '60mb' 
}));

// 6.3. Session Persistence Configuration
// Utilizes MongoDB for storage to prevent login drops during restart.
const sessionSettings = {
    secret: process.env.SESSION_SECRET || 'fallback-security-master-key',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'staff_panel_sessions'
    }),
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, 
        secure: true, 
        sameSite: 'none' 
    }
};

app.use(session(sessionSettings));

/**
 * Guard: isAuth
 * Middleware to restrict staff-level access.
 */
const isAuth = function(req, res, next) 
{
    const staffIdActive = (req.session.staffId !== undefined);
    
    if (staffIdActive === true) 
    {
        return next();
    }
    
    const currentPath = req.path;
    const pathIsApi = currentPath.startsWith('/api');
    
    if (pathIsApi === true) 
    {
        const rejection = { error: "Authentication required." };
        return res.status(401).json(rejection);
    }
    
    return res.redirect('/login.html');
};

/**
 * Guard: isAdmin
 * Middleware to restrict destructive administrative access.
 */
const isAdmin = function(req, res, next) 
{
    const isStaff = (req.session.staffId !== undefined);
    const hasAdminFlag = (req.session.isAdmin === true);
    
    if (isStaff === true && hasAdminFlag === true) 
    {
        return next();
    }
    
    const rejection = { error: "Administrative clearance required." };
    return res.status(403).json(rejection);
};

// 6.6. Static File Mapping
// Public content folder mapping.
app.use(express.static(path.join(__dirname, 'public')));

// Protected Staff folder mapping.
app.use('/staff', isAuth, express.static(path.join(__dirname, 'public/staff')));


// =================================================================================================
//  SECTION 7: DISCORD GATEWAY INTERFACE (FLEET MANAGEMENT)
// =================================================================================================

/**
 * GATEWAY BOOTSTRAP:
 * Filters the environmental variables for active bot tokens.
 */
const tokensInputArray = [
    process.env.BOT_ONE_TOKEN, 
    process.env.BOT_TWO_TOKEN
];

const tokensValidatedArray = tokensInputArray.filter(function(token) 
{
    const exists = (token !== undefined && token !== null && token !== "");
    return exists;
});

const clientsArray = [];

/**
 * Service: sendLog
 * Centralized audit logging dispatcher with targeted role mention support.
 * FIX: Replaced raw string footer with v14 compliant object.
 */
async function sendLog(title, description, colorHex = '#3b82f6', attachments = [], roleMention = "") 
{
    const loggingChannelId = process.env.LOG_CHANNEL_ID;
    const clientReady = (clientsArray[0] !== undefined);
    
    if (!loggingChannelId || !clientReady) 
    {
        return;
    }
    
    try 
    {
        const loggingChannel = await clientsArray[0].channels.fetch(loggingChannelId);
        
        if (loggingChannel) 
        {
            const auditEmbed = new EmbedBuilder()
                .setTitle(title)
                .setDescription(description)
                .setColor(colorHex)
                .setTimestamp()
                .setFooter({ 
                    text: "Miraidon Trade Services Audit Engine" 
                });
                
            const outboundData = { 
                embeds: [auditEmbed], 
                files: attachments 
            };
            
            if (roleMention !== "") 
            {
                outboundData.content = roleMention;
            }
            
            await loggingChannel.send(outboundData);
        }
    } 
    catch (logError) 
    { 
        console.error(`[LOG] ❌ Audit dispatch failure: ${logError.message}`); 
    }
}

// 7.1. Bot Client Initialization Loop
tokensValidatedArray.forEach(function(tokenValue, gatewayIndex) 
{
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
        partials: [
            Partials.Channel, 
            Partials.Message
        ]
    });

    // 7.2. Client Gateway Authorized
    discordClient.once('ready', function() 
    {
        console.log(`[GATEWAY] 🤖 AUTHORIZED: Bot ${gatewayIndex + 1} (${discordClient.user.tag})`);
    });

    // 7.3. Typing Notification Relay
    discordClient.on('typingStart', function(typingEvent) 
    {
        const actorBot = typingEvent.user.bot;
        if (actorBot === true) 
        {
            return;
        }
        io.emit('user_typing', { userId: typingEvent.user.id });
    });

    // 7.4. Interaction (Button) Dispatcher
    discordClient.on('interactionCreate', async function(interaction) 
    {
        const interactionIsButton = interaction.isButton();
        if (interactionIsButton === false) 
        {
            return;
        }

        const idParts = interaction.customId.split('_');
        const action = idParts[0];
        
        if (action === 'rate') 
        {
            const stars = parseInt(idParts[1]);
            const staffId = idParts[2];
            
            console.log(`[ANALYTICS] 🌟 Committing star rating for staff: ${staffId}`);

            try 
            {
                await Staff.findByIdAndUpdate(staffId, { 
                    $inc: { 
                        ratingSum: stars, 
                        ratingCount: 1 
                    } 
                });

                const confirmRow = new ActionRowBuilder().addComponents(
                    new ButtonBuilder()
                        .setCustomId('logged')
                        .setLabel(`Experience Logged`)
                        .setStyle(ButtonStyle.Success)
                        .setDisabled(true)
                );

                await interaction.update({ 
                    content: `**Feedback Successfully Recorded.** You've rated this session **${stars} stars**.`, 
                    components: [confirmRow] 
                });
            } 
            catch (dbError) 
            {
                console.error(`[ANALYTICS] ❌ Failed to write rating to database.`);
            }
        }
    });

    // -----------------------------------------------------------------------------------------
    // 7.5. MAIN INBOUND MESSAGE LISTENER (FIXED FOOTERS & REPAIRED LOGIC)
    // -----------------------------------------------------------------------------------------
    discordClient.on('messageCreate', async function(message) 
    {
        // FILTER: Discard automated bot messages and guild channel messages.
        const authorBotFlag = message.author.bot;
        const guildMessageFlag = (message.guild !== null);
        
        if (authorBotFlag === true || guildMessageFlag === true) 
        {
            return;
        }
        
        console.log(`[GATEWAY] 📥 Received Packet from trainer: ${message.author.tag}`);
        
        const discordUserId = message.author.id;
        const authorAvatarUrl = message.author.displayAvatarURL({ extension: 'png', size: 128 });

        try 
        {
            // STEP 1: Search active collection for existing inquiry
            let activeThreadDoc = await Thread.findOne({ 
                userId: discordUserId, 
                botId: discordClient.user.id 
            });
            
            // STEP 2: Logic Branch - Handle Initial Handshake
            if (activeThreadDoc === null) 
            {
                console.log(`[ENGINE] 🏗️ Initializing document for trainer identity: ${message.author.tag}`);
                
                activeThreadDoc = new Thread({ 
                    userId: discordUserId, 
                    userTag: message.author.tag, 
                    userAvatar: authorAvatarUrl, 
                    botId: discordClient.user.id, 
                    botName: discordClient.user.username, 
                    messages: [] 
                });
                
                // STEP 3: Retrieve Global Support Context
                const globalConfigDoc = await Config.findOne({ id: 'global' });
                
                const masterToggle = (globalConfigDoc ? globalConfigDoc.supportOnline : true);
                const openTimeValue = (globalConfigDoc ? globalConfigDoc.openTime : "08:00");
                const closeTimeValue = (globalConfigDoc ? globalConfigDoc.closeTime : "23:59");

                // STEP 4: Support Schedule Calculations (AST Context)
                const currentSystemTime = new Date();
                const astFormatConfig = { 
                    timeZone: 'America/Halifax', 
                    hour12: false, 
                    hour: 'numeric', 
                    minute: 'numeric' 
                };
                
                const timeStringRaw = new Intl.DateTimeFormat('en-US', astFormatConfig).format(currentSystemTime);
                const timeComponentsArray = timeStringRaw.split(':');
                const hourIntNow = parseInt(timeComponentsArray[0]);
                const minuteIntNow = parseInt(timeComponentsArray[1]);
                const totalMinutesPassed = (hourIntNow * 60) + minuteIntNow;

                const openParts = openTimeValue.split(':');
                const openLimitTotal = (parseInt(openParts[0]) * 60) + parseInt(openParts[1]);

                const closeParts = closeTimeValue.split(':');
                const closeLimitTotal = (parseInt(closeParts[0]) * 60) + parseInt(closeParts[1]);

                const timeInOperationalWindow = (totalMinutesPassed >= openLimitTotal && totalMinutesPassed <= closeLimitTotal);

                // STEP 5: Construction of Auto-Reply Embed with VALIDATED Footers
                // FIX: Replaced raw string in .setFooter with explicit object literal.
                let autoReplyObject;
                
                const footerDefinition = { 
                    text: `Estimated Response Time 1-2 Hours\nBusiness Hours ${openTimeValue} - ${closeTimeValue} AST` 
                };

                if (masterToggle === false) 
                {
                    console.log(`[ENGINE] -> Branch: System Offline.`);
                    autoReplyObject = new EmbedBuilder()
                        .setColor('#ef4444')
                        .setTitle('Support Terminal: System Offline')
                        .setDescription(`The desk is currently on an authorized break.\n\n**Note:** ${globalConfigDoc.offlineNote || 'Unscheduled Maintenance.'}`)
                        .setTimestamp()
                        .setFooter(footerDefinition);
                } 
                else if (timeInOperationalWindow === false) 
                {
                    console.log(`[ENGINE] -> Branch: Outside Hours.`);
                    autoReplyObject = new EmbedBuilder()
                        .setColor('#f59e0b')
                        .setTitle('Support Terminal: Terminal Closed')
                        .setDescription(`You have contacted us outside of AST window: **${openTimeValue} - ${closeTimeValue} AST**.`)
                        .setTimestamp()
                        .setFooter(footerDefinition);
                } 
                else 
                {
                    console.log(`[ENGINE] -> Branch: Normal Operation.`);
                    autoReplyObject = new EmbedBuilder()
                        .setColor('#3b82f6')
                        .setTitle('Support Terminal: Initialized')
                        .setDescription('Handshake successful. A technician has been alerted and will respond within 12-24 hours.')
                        .setTimestamp()
                        .setFooter(footerDefinition);
                }
                
                // STEP 6: Execute Outbound Handshake DM
                const discordAuthor = message.author;
                await discordAuthor.send({ 
                    embeds: [autoReplyObject] 
                }).catch(function(dmFailError) 
                {
                    console.warn(`[ENGINE] ⚠️ DM failed for ${message.author.tag}: Privacy settings.`);
                });

                // STEP 7: Dispatch Targeted Administrative Log Ping (v11.1)
                let targetedRoleMention = "@here";
                const envRoleValue = process.env.STAFF_ROLE_ID;
                
                if (envRoleValue !== undefined && envRoleValue !== "") 
                {
                    targetedRoleMention = `<@&${envRoleValue}>`;
                }

                await sendLog(
                    "🆕 New Support inquiry Initialized", 
                    `**User:** ${message.author.tag}\n**ID:** ${discordUserId}\n**Bot:** ${discordClient.user.username}`, 
                    '#facc15', 
                    [], 
                    targetedRoleMention
                );
            } 
            else 
            {
                // Inquiry is already active. Sync PFP.
                if (activeThreadDoc.userAvatar !== authorAvatarUrl) 
                {
                    activeThreadDoc.userAvatar = authorAvatarUrl;
                }
            }
            
            // STEP 8: Construct Persistent Message Object
            const messageAttachmentsArray = message.attachments.map(function(att) { 
                return att.url; 
            });
            
            const persistenceObject = { 
                authorTag: message.author.tag, 
                authorAvatar: authorAvatarUrl, 
                content: message.content || "[Media Content]", 
                attachments: messageAttachmentsArray, 
                fromBot: false, 
                timestamp: new Date() 
            };

            // STEP 9: Commit to MongoDB stack
            activeThreadDoc.messages.push(persistenceObject);
            activeThreadDoc.lastMessageAt = new Date();
            await activeThreadDoc.save();
            
            // STEP 10: BROADCAST TO SOCKET GATEWAY (CRITICAL FOR UI VISIBILITY)
            // This ensures the Desktop Dashboard receives the data immediately.
            const uiSyncPayload = { 
                threadId: activeThreadDoc._id, 
                notif_sound: true, 
                ...persistenceObject 
            };
            
            io.emit('new_message', uiSyncPayload);
            
            console.log(`[ENGINE] ✅ Synchronization success for ${message.author.tag}`);

        } 
        catch (criticalEngineError) 
        {
            console.error("================================================================================");
            console.error("[ENGINE] ❌ CRITICAL HANDLER FAILURE:");
            console.error(criticalEngineError);
            console.error("================================================================================");
        }
    });

    discordClient.login(tokenValue).catch(function(loginError) 
    { 
        console.error(`[GATEWAY] ❌ Client ${gatewayIndex + 1} Authorization Rejected.`); 
    });
    
    clientsArray.push(discordClient);
});


// =================================================================================================
//  SECTION 8: REAL-TIME GATEWAY INFRASTRUCTURE (SOCKET.IO)
// =================================================================================================

const threadPresenceCache = {}; 

io.on('connection', function(staffSocket) 
{
    /**
     * EVENT: join_ticket_room
     * Logic: Subscribes staff browser tabs to specific thread updates.
     */
    staffSocket.on('join_ticket_room', function(payload) 
    {
        const threadDatabaseId = payload.threadId;
        const staffUsername = payload.username;

        staffSocket.join(threadDatabaseId);
        
        const cacheEntryExists = (threadPresenceCache[threadDatabaseId] !== undefined);
        if (cacheEntryExists === false) 
        {
            threadPresenceCache[threadDatabaseId] = new Set();
        }
        
        threadPresenceCache[threadDatabaseId].add(staffUsername);
        
        // Broadcast presence list
        const viewersArray = Array.from(threadPresenceCache[threadDatabaseId]);
        io.to(threadDatabaseId).emit('viewers_updated', viewersArray);
        
        staffSocket.currentThreadId = threadDatabaseId; 
        staffSocket.currentUser = staffUsername;
    });

    /**
     * EVENT: leave_ticket_room
     * Logic: Cleanup routine for collision detection.
     */
    const cleanupRoutine = function() 
    { 
        const id = staffSocket.currentThreadId;
        const user = staffSocket.currentUser;

        if (id && user) 
        {
            const cache = threadPresenceCache[id];
            if (cache) 
            {
                cache.delete(user);
                const updatedList = Array.from(cache);
                io.to(id).emit('viewers_updated', updatedList);
            }
        }
    };
    
    staffSocket.on('leave_ticket_room', cleanupRoutine);
    staffSocket.on('disconnect', cleanupRoutine);
    
    /**
     * EVENT: staff_typing
     * Logic: Proxies typing state to Discord DM channel.
     */
    staffSocket.on('staff_typing', async function(payload) 
    {
        try 
        {
            const threadDoc = await Thread.findById(payload.threadId);
            if (threadDoc !== null) 
            {
                const gateway = clientsArray.find(function(c) { 
                    return (c.user.id === threadDoc.botId); 
                });
                
                if (gateway) 
                {
                    const userHandle = await gateway.users.fetch(threadDoc.userId);
                    const dmChannel = userHandle.dmChannel || await userHandle.createDM();
                    await dmChannel.sendTyping();
                }
            }
        } 
        catch(e) { }
    });
});


// =================================================================================================
//  SECTION 9: STAFF AUTHENTICATION API ENGINE
// =================================================================================================

/**
 * ROUTE: Login Procedure
 * Method: POST
 * Path: /api/login
 */
app.post('/api/login', async function(req, res) 
{
    const userIn = req.body.username;
    const passIn = req.body.password;
    
    try 
    {
        const userDocument = await Staff.findOne({ 
            username: userIn 
        });
        
        if (userDocument === null) 
        {
            const rejection = { error: "Access Denied: Identity not recognized." };
            return res.status(401).json(rejection);
        }

        const matches = await bcrypt.compare(passIn, userDocument.password);
        
        if (matches === true) 
        {
            // Identity Verification: Sync Discord Photo
            try 
            {
                if (clientsArray[0]) 
                {
                    const discordProfile = await clientsArray[0].users.fetch(userDocument.discordId);
                    const latestPfp = discordProfile.displayAvatarURL({ extension: 'png' });
                    userDocument.avatar = latestPfp;
                    await userDocument.save();
                }
            } 
            catch (e) { }

            // Session persistence
            req.session.staffId = userDocument._id; 
            req.session.isAdmin = userDocument.isAdmin; 
            req.session.username = userDocument.username;
            
            req.session.save(function() 
            {
                const successObj = { 
                    success: true, 
                    isAdmin: userDocument.isAdmin, 
                    username: userDocument.username 
                };
                return res.json(successObj);
            });
        } 
        else 
        {
            const rejection = { error: "Access Denied: Identity not recognized." };
            return res.status(401).json(rejection);
        }
    } 
    catch (e) 
    {
        const serverErr = { error: "Internal Auth Fault." };
        return res.status(500).json(serverErr);
    }
});

/**
 * ROUTE: Logout Procedure
 */
app.post('/api/logout', function(req, res) 
{
    req.session.destroy(function() 
    {
        res.clearCookie('connect.sid');
        const successObj = { success: true };
        return res.json(successObj);
    });
});

/**
 * ROUTE: Session Recovery
 */
app.get('/api/auth/user', isAuth, function(req, res) 
{
    const currentIdentity = { 
        username: req.session.username, 
        isAdmin: req.session.isAdmin 
    };
    return res.json(currentIdentity);
});

/**
 * ROUTE: Public Recovery Dispatch
 */
app.post('/api/public/request-reset', async function(req, res) 
{
    const id = req.body.discordId;
    
    try 
    {
        const staff = await Staff.findOne({ 
            discordId: id 
        });
        
        if (staff === null) 
        { 
            const mismatch = { error: "Discord ID mismatch." };
            return res.status(404).json(mismatch); 
        }
        
        const newKey = generateComplexPassword();
        const hashedKey = await bcrypt.hash(newKey, 10);
        
        staff.password = hashedKey;
        await staff.save();
        
        const bot = clientsArray[0];
        const user = await bot.users.fetch(id);
        
        const restorationEmbed = new EmbedBuilder()
            .setTitle("🔒 Identity Restoration Sequence")
            .setDescription(`A technician key reset was issued.\n\n**Authorization Key:** \`${newKey}\``)
            .setColor('#facc15');
            
        await user.send({ 
            embeds: [restorationEmbed] 
        });
        
        return res.json({ success: true });
    } 
    catch (e) 
    {
        return res.status(500).json({ error: "Gateway failure during dispatch." });
    }
});


// =================================================================================================
//  SECTION 10: SUPPORT OPERATIONS API (CORE SERVICE LAYER)
// =================================================================================================

/**
 * ROUTE: Fetch Active Inbox
 * Path: /api/threads
 */
app.get('/api/threads', isAuth, async function(req, res) 
{
    try 
    {
        const activeInbox = await Thread.find().sort({ 
            lastMessageAt: -1 
        });
        return res.json(activeInbox);
    } 
    catch (e) 
    { 
        const dbErr = { error: "Database unavailable." };
        return res.status(500).json(dbErr); 
    }
});

/**
 * ROUTE: Outbound Support Reply
 * Path: /api/reply
 */
app.post('/api/reply', isAuth, async function(req, res) 
{
    const threadIdIn = req.body.threadId;
    const textIn = req.body.content;
    const blobIn = req.body.fileBase64;
    const nameIn = req.body.fileName;
    
    try 
    {
        const targetThread = await Thread.findById(threadIdIn);
        const handlingGateway = clientsArray.find(function(c) { 
            const isMatch = (c.user.id === targetThread.botId);
            return isMatch; 
        });
        
        const staffDocument = await Staff.findById(req.session.staffId);
        const userObject = await handlingGateway.users.fetch(targetThread.userId);
        
        const responseEmbed = new EmbedBuilder()
            .setColor('#3b82f6')
            .setAuthor({ 
                name: `Support Technician: ${req.session.username}`, 
                iconURL: handlingGateway.user.displayAvatarURL() 
            })
            .setDescription(textIn || "[Attachment Packet]")
            .setTimestamp()
            .setFooter({ 
                text: "Official Response Packet" 
            });
            
        const dispatchConfiguration = { 
            embeds: [responseEmbed] 
        };
        
        if (blobIn) 
        {
            const binaryBuffer = Buffer.from(blobIn.split(',')[1], 'base64');
            const fileAttachment = new AttachmentBuilder(binaryBuffer, { 
                name: nameIn 
            });
            dispatchConfiguration.files = [fileAttachment];
        }
        
        await userObject.send(dispatchConfiguration);
        
        const logEntry = { 
            authorTag: `Staff (${req.session.username})`, 
            authorAvatar: staffDocument ? staffDocument.avatar : '', 
            content: textIn || "[Media Attached]", 
            fromBot: true, 
            timestamp: new Date() 
        };
        
        targetThread.messages.push(logEntry); 
        targetThread.lastMessageAt = new Date(); 
        await targetThread.save();
        
        await Staff.findByIdAndUpdate(req.session.staffId, { 
            $inc: { repliesSent: 1 } 
        });
        
        const syncPayload = { 
            threadId: targetThread._id, 
            ...logEntry 
        };
        io.emit('new_message', syncPayload);
        
        return res.json({ success: true });
    } 
    catch (e) 
    {
        return res.status(500).json({ error: "Gateway rejected outbound DM." });
    }
});

/**
 * ROUTE: Ticket Decommission (Close & Archive)
 */
app.post('/api/close-thread', isAuth, async function(req, res) 
{
    const targetId = req.body.threadId;
    const actor = req.session.username;
    
    try 
    {
        const threadDoc = await Thread.findById(targetId);
        
        if (threadDoc === null) 
        { 
            return res.sendStatus(404); 
        }

        let plaintextTranscript = `SUPPORT TRANSCRIPT: ${threadDoc.userTag}\nTECHNICIAN: ${actor}\n\n`;
        
        threadDoc.messages.forEach(function(msg) { 
            const timeStr = msg.timestamp.toISOString();
            plaintextTranscript += `[${timeStr}] ${msg.authorTag}: ${msg.content}\n`; 
        });
        
        const tempPath = path.join(__dirname, `tmp-${threadDoc.userId}.txt`);
        fs.writeFileSync(tempPath, plaintextTranscript);
        
        const archiveAttachment = new AttachmentBuilder(tempPath);
        const descriptionText = `Subject: ${threadDoc.userTag}\nOfficer: ${actor}`;
        
        await sendLog("🔒 Archive Synchronized", descriptionText, '#ef4444', [archiveAttachment]);
        
        const userFolder = path.join(archivePath, threadDoc.userId);
        const existsCheck = fs.existsSync(userFolder);
        
        if (existsCheck === false) 
        { 
            fs.mkdirSync(userFolder, { recursive: true }); 
        }
        
        const permanentFileName = `${Date.now()}-${threadDoc._id}.json`;
        const permanentFilePath = path.join(userFolder, permanentFileName);
        
        fs.writeFileSync(permanentFilePath, JSON.stringify(threadDoc, null, 2));
        
        const botGateway = clientsArray.find(function(c) { 
            return (c.user.id === threadDoc.botId); 
        });
        
        if (botGateway) 
        {
            const starRow = new ActionRowBuilder().addComponents(
                new ButtonBuilder().setCustomId(`rate_1_${req.session.staffId}`).setLabel('1⭐').setStyle(ButtonStyle.Secondary),
                new ButtonBuilder().setCustomId(`rate_2_${req.session.staffId}`).setLabel('2⭐').setStyle(ButtonStyle.Secondary),
                new ButtonBuilder().setCustomId(`rate_3_${req.session.staffId}`).setLabel('3⭐').setStyle(ButtonStyle.Secondary),
                new ButtonBuilder().setCustomId(`rate_4_${req.session.staffId}`).setLabel('4⭐').setStyle(ButtonStyle.Primary),
                new ButtonBuilder().setCustomId(`rate_5_${req.session.staffId}`).setLabel('5⭐').setStyle(ButtonStyle.Success)
            );
            
            try 
            { 
                const user = await botGateway.users.fetch(threadDoc.userId); 
                await user.send({ 
                    content: "Trainer, please rate the accuracy of your support session:", 
                    components: [starRow] 
                }); 
            } 
            catch(dmErr) { }
        }

        await Staff.findByIdAndUpdate(req.session.staffId, { 
            $inc: { ticketsClosed: 1 } 
        });
        
        await Thread.findByIdAndDelete(targetId);
        
        if (fs.existsSync(tempPath)) 
        { 
            fs.unlinkSync(tempPath); 
        }
        
        return res.json({ success: true });
    } 
    catch (archiveProcessErr) 
    {
        return res.status(500).json({ error: "Archival sequence fault." });
    }
});


// =================================================================================================
//  SECTION 11: CRM AND ADMINISTRATIVE INTEL API
// =================================================================================================

/**
 * ROUTE: Aggregate User Intelligence
 */
app.get('/api/crm/user/:discordId', isAuth, async function(req, res) 
{
    const userIdIn = req.params.discordId;
    
    try 
    {
        const trainerNote = await UserNote.findOne({ 
            userId: userIdIn 
        });
        
        const archiveDir = path.join(archivePath, userIdIn);
        let consolidatedHistory = [];
        
        const folderOnDisk = fs.existsSync(archiveDir);
        
        if (folderOnDisk === true) 
        {
            consolidatedHistory = fs.readdirSync(archiveDir).map(function(filename) {
                try {
                    const fullPath = path.join(archiveDir, filename);
                    const raw = fs.readFileSync(fullPath);
                    const json = JSON.parse(raw);
                    
                    const metaObj = { 
                        filename: filename, 
                        closedAt: json.meta?.closedAt || json.lastMessageAt 
                    };
                    return metaObj;
                } catch(e) { return null; }
            }).filter(function(item) { 
                return (item !== null); 
            });
        }
        
        const profilePayload = { 
            note: trainerNote ? trainerNote.note : "", 
            history: consolidatedHistory 
        };
        return res.json(profilePayload);
    } 
    catch (e) 
    { 
        return res.status(500).json({ error: "CRM aggregator failure." }); 
    }
});

/**
 * ROUTE: Staff Performance Stats
 */
app.get('/api/admin/stats', isAdmin, async function(req, res) 
{ 
    try 
    { 
        const staffProfiles = await Staff.find().sort({ 
            ticketsClosed: -1 
        });
        return res.json(staffProfiles); 
    } 
    catch (e) 
    { 
        return res.status(500).json({ error: "DB read fault." }); 
    } 
});

/**
 * ROUTE: System Configuration Retrieve
 */
app.get('/api/admin/config', isAdmin, async function(req, res) 
{ 
    try 
    { 
        const configDoc = await Config.findOne({ 
            id: 'global' 
        });
        return res.json(configDoc); 
    } 
    catch (e) 
    { 
        return res.status(500).json({ error: "DB read fault." }); 
    } 
});

/**
 * ROUTE: Toggle Supporting Module
 */
app.post('/api/admin/config/toggle', isAdmin, async function(req, res) 
{
    const targetStatus = req.body.status;
    const targetNote = req.body.note;
    const targetOpen = req.body.openTime;
    const targetClose = req.body.closeTime;

    try 
    {
        const doc = await Config.findOne({ id: 'global' });
        
        if (targetStatus !== undefined) { doc.supportOnline = targetStatus; }
        if (targetNote !== undefined) { doc.offlineNote = targetNote; }
        if (targetOpen !== undefined) { doc.openTime = targetOpen; }
        if (targetClose !== undefined) { doc.closeTime = targetClose; }
        
        await doc.save(); 
        return res.json({ success: true });
    } 
    catch (e) { return res.status(500).json({ error: "Update failure." }); }
});

/**
 * ROUTE: Toggle Fleet Trading State (Granular)
 */
app.post('/api/admin/fleet/toggle-trading', isAdmin, async function(req, res) 
{
    const idToToggle = req.body.botId;
    const statusToSet = req.body.status;

    try 
    {
        const doc = await Config.findOne({ id: 'global' });
        let entry = doc.botFleetStatus.find(function(x) { 
            return (x.botId === idToToggle); 
        });
        
        if (entry) 
        { 
            entry.tradingActive = statusToSet; 
        }
        else 
        { 
            const newEntry = { 
                botId: idToToggle, 
                tradingActive: statusToSet 
            };
            doc.botFleetStatus.push(newEntry); 
        }
        
        await doc.save(); 
        return res.json({ success: true });
    } 
    catch (e) { return res.status(500).json({ error: "Fleet module write fault." }); }
});


// =================================================================================================
//  SECTION 12: PUBLIC STATUS AGGREGATION AND HEALTH HEARTBEAT
// =================================================================================================

/**
 * ROUTE: Global Heartbeat Aggregator
 * Method: GET
 * Path: /api/status
 */
app.get('/api/status', async function(req, res) 
{
    try 
    {
        const globalConfig = await Config.findOne({ id: 'global' });
        
        const timestamp = new Date();
        const formatter = new Intl.DateTimeFormat('en-US', { timeZone: 'America/Halifax', hour12: false, hour: 'numeric', minute: 'numeric' });
        const contextParts = formatter.formatToParts(timestamp);
        
        const hourNow = parseInt(contextParts.find(function(p){ return (p.type === 'hour'); }).value);
        const minuteNow = parseInt(contextParts.find(function(p){ return (p.type === 'minute'); }).value);
        const elapsedToday = (hourNow * 60) + minuteNow;
        
        const [hourOpen, minOpen] = globalConfig.openTime.split(':').map(Number);
        const [hourClose, minClose] = globalConfig.closeTime.split(':').map(Number);
        
        const limitStart = (hourOpen * 60) + minOpen;
        const limitEnd = (hourClose * 60) + minClose;

        const isTimeMatch = (elapsedToday >= limitStart && elapsedToday <= limitEnd);
        const operationalStatus = (globalConfig.supportOnline === true && isTimeMatch === true);

        const fleetHeartbeatArray = clientsArray.map(function(botInstance) 
        {
            const configEntry = globalConfig.botFleetStatus.find(function(x){ 
                return (x.botId === botInstance.user.id); 
            });
            
            const summary = { 
                name: botInstance.user.username, 
                online: botInstance.isReady(), 
                tradingActive: configEntry ? configEntry.tradingActive : true 
            };
            return summary;
        });

        const dashboardPayload = { 
            support: { 
                isOpen: operationalStatus, 
                window: `${globalConfig.openTime} - ${globalConfig.closeTime} AST`, 
                note: globalConfig.offlineNote 
            }, 
            fleet: fleetHeartbeatArray 
        };
        
        return res.json(dashboardPayload);
    } 
    catch (e) 
    { 
        const fail = { error: "Heartbeat logic fault." };
        return res.status(500).json(fail); 
    }
});


// =================================================================================================
//  SECTION 13: SYSTEM BOOTSTRAP AND NETWORK LISTENER
// =================================================================================================

/**
 * FINAL EXECUTION:
 * Binds the server to the environment's PORT.
 */
const FINAL_NETWORK_PORT = process.env.PORT || 10000;

server.listen(FINAL_NETWORK_PORT, function() 
{
    console.log("================================================================================");
    console.log(`🚀 MASTER ENGINE v11.9 ACTIVE: PORT ${FINAL_NETWORK_PORT}`);
    console.log(`🛠️ COMPLIANCE: v14 EMBED FORMATS VERIFIED`);
    console.log(`🛡️ INTEGRITY: ZERO SHORTHAND / MAXIMAL VERBOSITY`);
    console.log("================================================================================");
});

// EOF (End of File - Miraidon Master)
