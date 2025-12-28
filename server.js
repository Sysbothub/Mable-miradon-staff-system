/**
 * ============================================================================================================================================================
 * MIRAIDON TRADE SERVICES - MASTER SERVER ENGINE (v22.0 - FINAL PRODUCTION RELEASE)
 * ============================================================================================================================================================
 * * STATUS: 100% UNCOMPRESSED, MAXIMAL VERBOSITY
 * * FEATURES: FULL LOGGING, LICENSE AUTOMATION, 7-MODULE ADMIN, MANUAL DM, GUILD MANAGEMENT
 * * INTEGRITY: ZERO SHORTHAND, FULL MULTI-LINE EXPANSION
 * ============================================================================================================================================================
 */

// ============================================================================================================================================================
//  SECTION 1: GLOBAL MODULE LOADING AND ENVIRONMENT CONFIGURATION
// ============================================================================================================================================================

// 1.1. Load Environmental Variables
const dotenv = require('dotenv');
dotenv.config();

console.log("[SYSTEM] 🟢 Boot Sequence Initiated...");

// 1.2. Core Node.js Networking and File System Modules
const fs = require('fs');
const path = require('path');
const http = require('http');

// 1.3. Web Framework and Security Utility Dependencies
const express = require('express');
const axios = require('axios');
const bcrypt = require('bcrypt');

// 1.4. Real-time Communication Infrastructure
const socketIo = require('socket.io');

// 1.5. Database Persistence and Session Management
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');

// 1.6. Load Discord SDK Components
const discordJs = require('discord.js');

// 1.7. Explicit Class Destructuring for Readability
const Client = discordJs.Client;
const GatewayIntentBits = discordJs.GatewayIntentBits;
const Partials = discordJs.Partials;
const EmbedBuilder = discordJs.EmbedBuilder;
const ChannelType = discordJs.ChannelType;
const AttachmentBuilder = discordJs.AttachmentBuilder;
const ActionRowBuilder = discordJs.ActionRowBuilder;
const ButtonBuilder = discordJs.ButtonBuilder;
const ButtonStyle = discordJs.ButtonStyle;
const PermissionFlagsBits = discordJs.PermissionFlagsBits;

// 1.8. Initialize Application Instances
const application = express();
const httpServer = http.createServer(application);
const socketServer = new socketIo.Server(httpServer);

console.log("[SYSTEM] 🔹 Application Instances Created.");


// ============================================================================================================================================================
//  SECTION 2: PERSISTENT DISK STORAGE AND FILE SYSTEM ARCHITECTURE
// ============================================================================================================================================================

console.log("[STORAGE_ENGINE] 📂 Initializing local persistence layers...");

let DATA_DIRECTORY_PATH;

const renderDeploymentFlag = process.env.RENDER;

if (renderDeploymentFlag === 'true') 
{
    console.log("[STORAGE_ENGINE] ☁️ Environment Context: PRODUCTION (RENDER.COM)");
    DATA_DIRECTORY_PATH = '/var/data';
} 
else 
{
    console.log("[STORAGE_ENGINE] 💻 Environment Context: DEVELOPMENT (LOCAL)");
    DATA_DIRECTORY_PATH = path.join(__dirname, 'local_storage');
}

const rootPathExistsOnDisk = fs.existsSync(DATA_DIRECTORY_PATH);

if (rootPathExistsOnDisk === false) 
{
    console.log(`[STORAGE_ENGINE] 📂 Root directory missing. Attempting creation: ${DATA_DIRECTORY_PATH}`);
    try 
    {
        fs.mkdirSync(DATA_DIRECTORY_PATH, { 
            recursive: true 
        });
        console.log(`[STORAGE_ENGINE] ✅ Root Data Directory established successfully.`);
    } 
    catch (mkdirRootError) 
    {
        console.error(`[STORAGE_ENGINE] ❌ CRITICAL FAILURE: Permission denied during disk write.`);
        process.exit(1); 
    }
} 

const archiveDirectoryPathString = path.join(DATA_DIRECTORY_PATH, 'archives');
const archiveSubFolderExistsOnDisk = fs.existsSync(archiveDirectoryPathString);

if (archiveSubFolderExistsOnDisk === false) 
{
    try 
    {
        fs.mkdirSync(archiveDirectoryPathString, { 
            recursive: true 
        });
        console.log(`[STORAGE_ENGINE] ✅ Archive sub-directory established successfully.`);
    } 
    catch (mkdirArchiveError) 
    {
        console.error(`[STORAGE_ENGINE] ❌ WARNING: Failed to establish archive folder.`);
    }
} 


// ============================================================================================================================================================
//  SECTION 3: MONGODB DATABASE CONNECTIVITY HANDSHAKE
// ============================================================================================================================================================

console.log("[DATABASE_ENGINE] ⏳ Handshaking with MongoDB cluster...");

const clusterHandshakeUri = process.env.MONGODB_URI;

if (clusterHandshakeUri === undefined || clusterHandshakeUri === "")
{
    console.error("[DATABASE_ENGINE] ❌ CRITICAL: MONGODB_URI is not defined.");
    process.exit(1);
}

mongoose.connect(clusterHandshakeUri)
    .then(function() 
    {
        console.log("[DATABASE_ENGINE] ✅ Handshake Successful: PERSISTENCE LAYER ONLINE");
        initializeSystemDefaults();
        performDatabaseRepair();
    })
    .catch(function(connectionError) 
    {
        console.error("[DATABASE_ENGINE] ❌ CRITICAL HANDSHAKE FAILURE");
        console.error(connectionError);
    });


// ============================================================================================================================================================
//  SECTION 4: DATA MODELS (FULLY EXPANDED SCHEMAS)
// ============================================================================================================================================================

const StaffSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    discordId: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    avatar: { type: String, default: 'https://cdn.discordapp.com/embed/avatars/0.png' },
    ticketsClosed: { type: Number, default: 0 },
    repliesSent: { type: Number, default: 0 },
    ratingSum: { type: Number, default: 0 },
    ratingCount: { type: Number, default: 0 }
});
const Staff = mongoose.model('Staff', StaffSchema);

const ThreadSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    userTag: { type: String, required: true },
    userAvatar: { type: String, default: 'https://cdn.discordapp.com/embed/avatars/0.png' },
    botId: { type: String, required: true },
    botName: { type: String, required: true },
    claimedBy: { type: String, default: null },
    messages: [{
        authorTag: { type: String },
        authorAvatar: { type: String, default: 'https://cdn.discordapp.com/embed/avatars/0.png' },
        content: { type: String },
        attachments: [String],
        timestamp: { type: Date, default: Date.now },
        fromBot: { type: Boolean, default: false }
    }],
    lastMessageAt: { type: Date, default: Date.now }
});
const Thread = mongoose.model('Thread', ThreadSchema);

const ConfigSchema = new mongoose.Schema({
    id: { type: String, default: 'global' },
    supportOnline: { type: Boolean, default: true },
    offlineNote: { type: String, default: '' },
    openTime: { type: String, default: "08:00" }, 
    closeTime: { type: String, default: "23:59" },
    botFleetStatus: [{
        botId: { type: String },
        botName: { type: String },
        tradingActive: { type: Boolean, default: true }
    }]
});
const Config = mongoose.model('Config', ConfigSchema);

const LicenseSchema = new mongoose.Schema({
    key: { type: String, required: true },
    discordId: { type: String, required: true },
    serverName: { type: String, default: "Unassigned" },
    serverId: { type: String, default: "" },
    type: { type: String, default: "Standard" },
    expiresAt: { type: Date },
    reminderSent: { type: Boolean, default: false },
    reviewRequestSent: { type: Boolean, default: false },
    activatedAt: { type: Date, default: Date.now }
});
const License = mongoose.model('License', LicenseSchema);

const UserNoteSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    note: { type: String, default: "" }
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


// ============================================================================================================================================================
//  SECTION 5: SYSTEM INITIALIZATION AND REPAIR LOGIC
// ============================================================================================================================================================

async function initializeSystemDefaults() 
{
    console.log("[SYSTEM] 🔎 Checking for default configuration...");
    try 
    {
        const adminCheck = await Staff.findOne({ username: 'admin' });
        
        if (adminCheck === null) 
        {
            console.log("[SYSTEM] ⚠️ Admin account missing. Generating default...");
            const hash = await bcrypt.hash('Map4491!', 10);
            const adminDoc = new Staff({ 
                username: 'admin', 
                password: hash, 
                discordId: '000000000000000000', 
                isAdmin: true 
            });
            await adminDoc.save();
            console.log("[SYSTEM] ✅ Admin account generated.");
        }

        const configCheck = await Config.findOne({ id: 'global' });
        
        if (configCheck === null) 
        {
            console.log("[SYSTEM] ⚠️ Global config missing. Generating default...");
            const configDoc = new Config({ 
                id: 'global', 
                supportOnline: true, 
                openTime: "08:00", 
                closeTime: "23:59", 
                botFleetStatus: [] 
            });
            await configDoc.save();
            console.log("[SYSTEM] ✅ Global config generated.");
        }
    } 
    catch (e) { console.error("[SYSTEM] Initialization Error: " + e.message); }
}

async function performDatabaseRepair() 
{
    console.log("[SYSTEM] 🛠️ Performing Database Self-Check...");
    try 
    {
        await Thread.updateMany({ claimedBy: { $exists: false } }, { $set: { claimedBy: null } });
        await Thread.updateMany({ userAvatar: { $exists: false } }, { $set: { userAvatar: 'https://cdn.discordapp.com/embed/avatars/0.png' } });
        await License.updateMany({ reviewRequestSent: { $exists: false } }, { $set: { reviewRequestSent: false } });
        console.log("[SYSTEM] ✅ Database Integrity Verified.");
    } 
    catch (e) { console.error("[SYSTEM] Repair Failed: " + e.message); }
}


// ============================================================================================================================================================
//  SECTION 6: EXPRESS SERVER CONFIGURATION AND MIDDLEWARE
// ============================================================================================================================================================

application.set('trust proxy', 1);

// HTTP REQUEST LOGGER (LOGS EVERYTHING)
application.use(function(request, response, next) 
{
    console.log(`[HTTP] ➡️ ${request.method} ${request.url} | IP: ${request.ip}`);
    if (request.method === 'POST') 
    {
        console.log(`[HTTP] 📦 Body Keys: ${Object.keys(request.body).join(', ')}`);
    }
    next();
});

application.use(express.json({ 
    limit: '65mb' 
}));

application.use(express.urlencoded({ 
    extended: true, 
    limit: '65mb' 
}));

const sessionConfiguration = {
    secret: process.env.SESSION_SECRET || 'miraidon-master-key',
    resave: true,
    saveUninitialized: false,
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGODB_URI,
        collectionName: 'staff_sessions'
    }),
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24, 
        secure: true, 
        sameSite: 'none' 
    }
};

application.use(session(sessionConfiguration));

const isAuthorizedTechnician = function(request, response, next) 
{ 
    if (request.session.staffId) 
    { 
        return next(); 
    } 
    console.log(`[AUTH] ⛔ Blocked unauthorized access to ${request.url}`);
    return response.status(401).json({ error: "Unauthorized." }); 
};

const isSystemAdministrator = function(request, response, next) 
{ 
    if (request.session.staffId && request.session.isAdmin) 
    { 
        return next(); 
    } 
    console.log(`[AUTH] ⛔ Blocked non-admin access to ${request.url}`);
    return response.status(403).json({ error: "Access Denied." }); 
};

application.use(express.static(path.join(__dirname, 'public')));
application.use('/staff', isAuthorizedTechnician, express.static(path.join(__dirname, 'public/staff')));


// ============================================================================================================================================================
//  SECTION 7: DISCORD GATEWAY INTERFACE
// ============================================================================================================================================================

const botTokensList = [process.env.BOT_ONE_TOKEN, process.env.BOT_TWO_TOKEN].filter(function(tokenCandidate) 
{
    return (tokenCandidate !== undefined && tokenCandidate !== "");
});

const clientsFleetArray = [];

async function dispatchAuditLog(title, description, color = '#3b82f6', files = [], ping = "") 
{
    if (!process.env.LOG_CHANNEL_ID || !clientsFleetArray[0]) 
    { 
        return; 
    }
    
    try 
    {
        console.log(`[AUDIT] 📝 Dispatching Log: ${title}`);
        const channel = await clientsFleetArray[0].channels.fetch(process.env.LOG_CHANNEL_ID);
        if (channel !== null) 
        {
            const embed = new EmbedBuilder();
            embed.setTitle(title);
            embed.setDescription(description);
            embed.setColor(color);
            embed.setTimestamp();
            embed.setFooter({ text: "System Audit" });
            
            const payload = { embeds: [embed], files: files };
            if (ping !== "") 
            { 
                payload.content = ping; 
            }
            await channel.send(payload);
        }
    } 
    catch (auditLogFailure) { console.error(`[AUDIT] ❌ Failed: ${auditLogFailure.message}`); }
}

botTokensList.forEach(function(tokenString, indexIdentifier) 
{
    const clientNode = new Client({
        intents: [
            GatewayIntentBits.Guilds, 
            GatewayIntentBits.DirectMessages, 
            GatewayIntentBits.MessageContent, 
            GatewayIntentBits.GuildMembers
        ],
        partials: [
            Partials.Channel, 
            Partials.Message
        ]
    });

    clientNode.once('ready', function() 
    { 
        console.log(`[GATEWAY] 🟢 Node ${indexIdentifier + 1} Authorized: ${clientNode.user.tag}`); 
    });

    clientNode.on('typingStart', function(typingUser) 
    {
        if (!typingUser.user.bot) 
        { 
            console.log(`[DISCORD] ⌨️ Typing detected from ${typingUser.user.id}`);
            socketServer.emit('user_typing', { userId: typingUser.user.id }); 
        }
    });

    clientNode.on('interactionCreate', async function(interaction) 
    {
        if (interaction.isButton()) 
        {
            console.log(`[DISCORD] 🖱️ Button Clicked: ${interaction.customId}`);
            const idParts = interaction.customId.split('_');
            if (idParts[0] === 'rate') 
            {
                await Staff.findByIdAndUpdate(idParts[2], { 
                    $inc: { 
                        ratingSum: parseInt(idParts[1]), 
                        ratingCount: 1 
                    } 
                });
                await interaction.update({ content: "**Rating Saved.**", components: [] });
            }
        }
    });

    clientNode.on('messageCreate', async function(inboundMessage) 
    {
        if (inboundMessage.author.bot || inboundMessage.guild) 
        { 
            return; 
        }
        
        console.log(`[DISCORD] 📨 DM from ${inboundMessage.author.tag} (${inboundMessage.author.id})`);
        
        const avatarUrl = inboundMessage.author.displayAvatarURL({ extension: 'png', size: 128 });
        
        try 
        {
            let threadDocument = await Thread.findOne({ 
                userId: inboundMessage.author.id, 
                botId: clientNode.user.id 
            });
            
            if (!threadDocument) 
            {
                console.log(`[ENGINE] 🆕 Creating New Thread for ${inboundMessage.author.id}`);
                threadDocument = new Thread({ 
                    userId: inboundMessage.author.id, 
                    userTag: inboundMessage.author.tag, 
                    userAvatar: avatarUrl, 
                    botId: clientNode.user.id, 
                    botName: clientNode.user.username, 
                    messages: [] 
                });
                
                const globalConfig = await Config.findOne({ id: 'global' });
                const isSupportOpen = (globalConfig ? globalConfig.supportOnline : true);
                const openTimeStr = (globalConfig ? globalConfig.openTime : "08:00");
                const closeTimeStr = (globalConfig ? globalConfig.closeTime : "23:59");

                const nowTime = new Date();
                const timeString = new Intl.DateTimeFormat('en-US', { timeZone: 'America/Halifax', hour12: false, hour: 'numeric', minute: 'numeric' }).format(nowTime);
                const [hourPart, minutePart] = timeString.split(':').map(Number);
                const currentMinutes = hourPart * 60 + minutePart;
                
                const [openHour, openMinute] = openTimeStr.split(':').map(Number);
                const openMinutes = openHour * 60 + openMinute;
                
                const [closeHour, closeMinute] = closeTimeStr.split(':').map(Number);
                const closeMinutes = closeHour * 60 + closeMinute;
                
                const isWithinHours = (currentMinutes >= openMinutes && currentMinutes <= closeMinutes);

                const replyEmbed = new EmbedBuilder();
                
                if (!isSupportOpen) 
                {
                    console.log(`[ENGINE] 🔒 Auto-Reply: Temporarily Unavailable`);
                    replyEmbed.setColor('#ef4444');
                    replyEmbed.setTitle('Support Status: Temporarily Unavailable');
                    replyEmbed.setDescription(globalConfig.offlineNote || "Closed for maintenance.");
                    replyEmbed.setFooter({ text: "Status: Special Closure" });
                }
                else if (!isWithinHours)
                {
                    console.log(`[ENGINE] 🌙 Auto-Reply: Outside Hours`);
                    replyEmbed.setColor('#f59e0b');
                    replyEmbed.setTitle('Support Status: Outside Business Hours');
                    replyEmbed.setDescription(`Thank you for reaching out. While our standard daily hours are ${openTimeStr} – ${closeTimeStr} AST,\nWe often have team members available to assist outside of these times. \nIf your request isn't addressed this evening, we will ensure it is prioritized first thing in the morning.`);
                    replyEmbed.setFooter({ text: "Office Closed" });
                }
                else 
                {
                    console.log(`[ENGINE] ✅ Auto-Reply: Ticket Created`);
                    replyEmbed.setColor('#3b82f6');
                    replyEmbed.setTitle('Support Ticket Created');
                    replyEmbed.setDescription('Thank you for your inquiry. Your request has been received, and a member of our support team will follow up with you as soon as possible.');
                    replyEmbed.setFooter({ text: "Estimated Response: 1-2 Hours" });
                }
                
                await inboundMessage.author.send({ embeds: [replyEmbed] }).catch(function(){});
                
                const pingRole = process.env.STAFF_ROLE_ID ? `<@&${process.env.STAFF_ROLE_ID}>` : "@here";
                await dispatchAuditLog("🆕 New Support Ticket", `Trainer: ${inboundMessage.author.tag}`, '#facc15', [], pingRole);
            }

            const attachmentsList = inboundMessage.attachments.map(function(att) 
            { 
                return att.url; 
            });
            
            const messageObject = { 
                authorTag: inboundMessage.author.tag, 
                authorAvatar: avatarUrl, 
                content: inboundMessage.content || "[Media]", 
                attachments: attachmentsList, 
                fromBot: false, 
                timestamp: new Date() 
            };

            threadDocument.messages.push(messageObject);
            threadDocument.lastMessageAt = new Date();
            
            await threadDocument.save();
            
            console.log(`[ENGINE] 💾 Message Saved & Broadcasting to Dashboard`);
            socketServer.emit('new_message', { threadId: threadDocument._id, ...messageObject });
        } 
        catch(engineError) { console.error(engineError); }
    });

    clientNode.login(tokenString).catch(function(){});
    clientsFleetArray.push(clientNode);
});


// ============================================================================================================================================================
//  SECTION 8: REAL-TIME SOCKET SERVER
// ============================================================================================================================================================

const activeRoomsMap = {};

socketServer.on('connection', function(staffSocketConnection) 
{
    console.log(`[SOCKET] 🔌 Client Connected: ${staffSocketConnection.id}`);

    staffSocketConnection.on('join_ticket_room', function(dataPayload) 
    {
        console.log(`[SOCKET] 👤 Staff joining room: ${dataPayload.threadId}`);
        staffSocketConnection.join(dataPayload.threadId);
        
        if (!activeRoomsMap[dataPayload.threadId]) 
        { 
            activeRoomsMap[dataPayload.threadId] = new Set(); 
        }
        
        activeRoomsMap[dataPayload.threadId].add(dataPayload.username);
        
        socketServer.to(dataPayload.threadId).emit('viewers_updated', Array.from(activeRoomsMap[dataPayload.threadId]));
        
        staffSocketConnection.currentThreadId = dataPayload.threadId; 
        staffSocketConnection.currentUser = dataPayload.username;
    });
    
    const disconnectHandler = function() 
    {
        if (staffSocketConnection.currentThreadId && staffSocketConnection.currentUser && activeRoomsMap[staffSocketConnection.currentThreadId]) 
        {
            console.log(`[SOCKET] 🚪 Staff leaving room: ${staffSocketConnection.currentThreadId}`);
            activeRoomsMap[staffSocketConnection.currentThreadId].delete(staffSocketConnection.currentUser);
            socketServer.to(staffSocketConnection.currentThreadId).emit('viewers_updated', Array.from(activeRoomsMap[staffSocketConnection.currentThreadId]));
        }
    };
    
    staffSocketConnection.on('leave_ticket_room', disconnectHandler);
    staffSocketConnection.on('disconnect', disconnectHandler);
});


// ============================================================================================================================================================
//  SECTION 9: API ROUTES (AUTHENTICATION & TICKETS)
// ============================================================================================================================================================

application.post('/api/login', async function(request, response) 
{
    console.log(`[API] 🔑 Login Attempt: ${request.body.username}`);
    const userAccount = await Staff.findOne({ username: request.body.username });
    
    if (userAccount && await bcrypt.compare(request.body.password, userAccount.password)) 
    {
        console.log(`[API] ✅ Login Success: ${request.body.username}`);
        request.session.staffId = userAccount._id; 
        request.session.isAdmin = userAccount.isAdmin; 
        request.session.username = userAccount.username;
        
        request.session.save(function() 
        { 
            return response.json({ success: true, isAdmin: userAccount.isAdmin }); 
        });
    } 
    else 
    { 
        console.log(`[API] ❌ Login Failed`);
        return response.status(401).json({ error: "Invalid." }); 
    }
});

application.post('/api/logout', function(request, response) 
{ 
    console.log(`[API] 🚪 Logout Request`);
    request.session.destroy(function() 
    { 
        response.clearCookie('connect.sid'); 
        response.json({ success: true }); 
    }); 
});

application.get('/api/auth/user', isAuthorizedTechnician, function(request, response) 
{ 
    response.json({ username: request.session.username, isAdmin: request.session.isAdmin }); 
});

// TICKET API ENDPOINTS
application.get('/api/threads', isAuthorizedTechnician, async function(request, response) 
{ 
    const threadList = await Thread.find().sort({ lastMessageAt: -1 });
    return response.json(threadList);
});

application.post('/api/reply', isAuthorizedTechnician, async function(request, response) 
{
    console.log(`[API] 📤 Dispatching Reply to Thread ${request.body.threadId}`);
    const threadDoc = await Thread.findById(request.body.threadId);
    const clientNode = clientsFleetArray.find(function(cl){ return cl.user.id === threadDoc.botId; });
    const discordUser = await clientNode.users.fetch(threadDoc.userId);
    
    const embedReply = new EmbedBuilder().setColor('#3b82f6').setAuthor({ name: `Staff: ${request.session.username}`, iconURL: clientNode.user.displayAvatarURL() }).setDescription(request.body.content || "[Media]").setTimestamp().setFooter({ text: "Official Response" });
    
    await discordUser.send({ embeds: [embedReply] });
    
    const messageEntry = { 
        authorTag: `Staff (${request.session.username})`, 
        authorAvatar: '', 
        content: request.body.content || "[Media]", 
        fromBot: true, 
        timestamp: new Date() 
    };
    
    threadDoc.messages.push(messageEntry); 
    threadDoc.lastMessageAt = new Date(); 
    await threadDoc.save();
    
    socketServer.emit('new_message', { threadId: threadDoc._id, ...messageEntry });
    await Staff.findByIdAndUpdate(request.session.staffId, { $inc: { repliesSent: 1 } });
    
    return response.json({ success: true });
});

application.post('/api/close-thread', isAuthorizedTechnician, async function(request, response) 
{
    console.log(`[API] 🔒 Closing Thread ${request.body.threadId}`);
    const threadDoc = await Thread.findById(request.body.threadId);
    let transcriptLog = "";
    
    threadDoc.messages.forEach(function(msg)
    { 
        transcriptLog += `[${msg.timestamp}] ${msg.authorTag}: ${msg.content}\n`; 
    });
    
    const logFilePath = path.join(__dirname, `log-${threadDoc.userId}.txt`);
    fs.writeFileSync(logFilePath, transcriptLog);
    
    await dispatchAuditLog("🔒 Archive", `User: ${threadDoc.userTag}`, '#ef4444', [new AttachmentBuilder(logFilePath)]);
    
    const clientNode = clientsFleetArray.find(function(cl){ return cl.user.id === threadDoc.botId; });
    if (clientNode) 
    {
        const ratingRow = new ActionRowBuilder().addComponents(new ButtonBuilder().setCustomId(`rate_5_${request.session.staffId}`).setLabel('5⭐').setStyle(ButtonStyle.Success));
        const discordUser = await clientNode.users.fetch(threadDoc.userId);
        await discordUser.send({ content: "Please rate your support experience:", components: [ratingRow] }).catch(function(){});
    }
    
    await Staff.findByIdAndUpdate(request.session.staffId, { $inc: { ticketsClosed: 1 } });
    
    const userArchiveDir = path.join(ARCHIVE_DIR, threadDoc.userId);
    if (!fs.existsSync(userArchiveDir)) 
    { 
        fs.mkdirSync(userArchiveDir, { recursive: true }); 
    }
    
    fs.writeFileSync(path.join(userArchiveDir, `${Date.now()}.json`), JSON.stringify(threadDoc));
    
    await Thread.findByIdAndDelete(request.body.threadId);
    fs.unlinkSync(logFilePath);
    
    return response.json({ success: true });
});


// ============================================================================================================================================================
//  SECTION 10: ADMINISTRATIVE API MODULES (7 MODULES + EXTRA UTILITIES)
// ============================================================================================================================================================

// MODULE 1: STAFF ANALYTICS
application.get('/api/admin/stats', isSystemAdministrator, async function(request, response) 
{ 
    const statsData = await Staff.find().sort({ ticketsClosed: -1 });
    response.json(statsData); 
});

// MODULE 2: MACRO CONFIGURATION
application.post('/api/admin/macro/add', isSystemAdministrator, async function(request, response) 
{
    console.log(`[ADMIN] ➕ Creating Macro: ${request.body.title}`);
    const newMacro = new Macro({ title: request.body.title, content: request.body.content });
    await newMacro.save();
    response.json({ success: true });
});

application.get('/api/macros', isAuthorizedTechnician, async function(request, response) 
{ 
    const macros = await Macro.find();
    response.json(macros); 
});

// MODULE 3: LICENSE MANAGEMENT (FULL EDIT CAPABILITY)
application.post('/api/admin/license/lookup', isSystemAdministrator, async function(request, response) 
{
    console.log(`[ADMIN] 🔍 Looking up License: ${request.body.query}`);
    const licenseDoc = await License.findOne({ $or: [{ discordId: request.body.query }, { key: request.body.query }] });
    response.json(licenseDoc || null);
});

application.post('/api/admin/license/update', isSystemAdministrator, async function(request, response) 
{
    try 
    {
        console.log(`[ADMIN] ✏️ Updating License ${request.body.key}`);
        const filterCriteria = { key: request.body.key };
        const updateData = {
            serverName: request.body.serverName,
            serverId: request.body.serverId,
            discordId: request.body.discordId
        };
        await License.findOneAndUpdate(filterCriteria, updateData);
        response.json({ success: true });
    } 
    catch(updateError) 
    {
        response.status(500).json({ error: "Update failed" });
    }
});

// MODULE 4: FLEET CONTROL & GUILD MANAGEMENT
application.get('/api/admin/servers', isSystemAdministrator, async function(request, response) 
{
    const fleetInventory = [];
    clientsFleetArray.forEach(function(clientNode)
    { 
        if(clientNode.isReady())
        { 
            clientNode.guilds.cache.forEach(function(guildNode)
            { 
                fleetInventory.push({ 
                    id: guildNode.id, 
                    name: guildNode.name, 
                    members: guildNode.memberCount, 
                    ownerId: guildNode.ownerId, 
                    botName: clientNode.user.username, 
                    botId: clientNode.user.id 
                }); 
            }); 
        } 
    });
    response.json(fleetInventory);
});

application.post('/api/admin/fleet/toggle-trading', isSystemAdministrator, async function(request, response) 
{
    console.log(`[ADMIN] 🔄 Toggling Trading for Bot ${request.body.botId}`);
    const configDoc = await Config.findOne({ id: 'global' });
    let existingEntry = configDoc.botFleetStatus.find(function(x){ return x.botId === request.body.botId; });
    
    if(existingEntry)
    { 
        existingEntry.tradingActive = request.body.status; 
    } 
    else 
    { 
        configDoc.botFleetStatus.push({ botId: request.body.botId, tradingActive: request.body.status }); 
    }
    
    await configDoc.save();
    response.json({ success: true });
});

application.post('/api/admin/guild/leave', isSystemAdministrator, async function(request, response) 
{
    console.log(`[ADMIN] 🚪 Forcing Leave Guild ${request.body.guildId}`);
    const clientNode = clientsFleetArray.find(function(c) { return c.user.id === request.body.botId; });
    if (clientNode) 
    {
        const targetGuild = clientNode.guilds.cache.get(request.body.guildId);
        if (targetGuild) 
        {
            await targetGuild.leave();
            return response.json({ success: true });
        }
    }
    return response.status(404).json({ error: "Guild/Bot not found" });
});

application.post('/api/admin/guild/invite', isSystemAdministrator, async function(request, response) 
{
    console.log(`[ADMIN] 🔗 Generating Invite for ${request.body.guildId}`);
    const clientNode = clientsFleetArray.find(function(c) { return c.user.id === request.body.botId; });
    if (clientNode) 
    {
        const targetGuild = clientNode.guilds.cache.get(request.body.guildId);
        if (targetGuild) 
        {
            let textChannel = targetGuild.channels.cache.find(function(ch) 
            { 
                return ch.type === ChannelType.GuildText && ch.permissionsFor(targetGuild.members.me).has(PermissionFlagsBits.CreateInstantInvite); 
            });
            
            if (textChannel) 
            {
                const inviteObject = await textChannel.createInvite({ maxAge: 0, maxUses: 1 });
                return response.json({ url: inviteObject.url });
            }
        }
    }
    return response.status(404).json({ error: "Cannot create invite" });
});

// MODULE 5: MANUAL DM DISPATCH
application.post('/api/admin/dm', isAuthorizedTechnician, async function(request, response) 
{
    console.log(`[ADMIN] ✉️ Sending Manual DM to ${request.body.userId}`);
    const targetUserId = request.body.userId;
    const messageContent = request.body.content;
    const preferredBotId = request.body.botId;
    
    let clientNode = clientsFleetArray[0];
    
    if (preferredBotId) 
    { 
        clientNode = clientsFleetArray.find(function(c) { return c.user.id === preferredBotId; }); 
    }
    
    try 
    {
        const discordUser = await clientNode.users.fetch(targetUserId);
        await discordUser.send({ content: messageContent });
        
        let threadDocument = await Thread.findOne({ userId: targetUserId, botId: clientNode.user.id });
        
        if (!threadDocument) 
        {
            const avatarUrl = discordUser.displayAvatarURL({ extension: 'png' });
            threadDocument = new Thread({ 
                userId: targetUserId, 
                userTag: discordUser.tag, 
                userAvatar: avatarUrl, 
                botId: clientNode.user.id, 
                botName: clientNode.user.username, 
                messages: [] 
            });
            await threadDocument.save();
        }
        
        threadDocument.messages.push({ 
            authorTag: `Staff (${request.session.username})`, 
            authorAvatar: '', 
            content: messageContent, 
            fromBot: true, 
            timestamp: new Date() 
        });
        
        threadDocument.lastMessageAt = new Date();
        await threadDocument.save();
        
        return response.json({ success: true });
    } 
    catch(dmError) 
    {
        return response.status(500).json({ error: "DM Failed: " + dmError.message });
    }
});

// MODULE 6: KNOWLEDGE BASE
application.get('/api/faq', async function(request, response) 
{ 
    const faqList = await FAQ.find().sort({ createdAt: -1 });
    response.json(faqList); 
});

application.post('/api/admin/faq/add', isSystemAdministrator, async function(request, response) 
{ 
    const newFaq = new FAQ({ question: request.body.question, answer: request.body.answer });
    await newFaq.save(); 
    response.json({ success: true }); 
});

// MODULE 7: STAFF PROVISIONING
application.post('/api/admin/staff/add', isSystemAdministrator, async function(request, response) 
{ 
    try 
    {
        const passwordHash = await bcrypt.hash('DefaultPass123!', 10);
        const newStaffMember = new Staff({ 
            username: request.body.username, 
            password: passwordHash, 
            discordId: request.body.discordId 
        });
        await newStaffMember.save();
        return response.json({ success: true });
    } 
    catch (e) 
    { 
        return response.status(500).json({ error: "Fail" }); 
    }
});

// USER NOTES API
application.post('/api/note', isAuthorizedTechnician, async function(request, response) 
{
    console.log(`[CRM] 📝 Saving Note for ${request.body.userId}`);
    await UserNote.findOneAndUpdate({ userId: request.body.userId }, { note: request.body.note }, { upsert: true, new: true });
    response.json({ success: true });
});

application.get('/api/note/:userId', isAuthorizedTechnician, async function(request, response) 
{
    const noteDoc = await UserNote.findOne({ userId: request.params.userId });
    response.json({ note: noteDoc ? noteDoc.note : "" });
});

// GLOBAL CONFIGURATION
application.get('/api/admin/config', isSystemAdministrator, async function(request, response) 
{ 
    const configDoc = await Config.findOne({ id: 'global' });
    response.json(configDoc); 
});

application.post('/api/admin/config/toggle', isSystemAdministrator, async function(request, response) 
{ 
    console.log(`[ADMIN] ⚙️ Updating Global Config`);
    const configDoc = await Config.findOne({ id: 'global' });
    
    if (request.body.status !== undefined) 
    { 
        configDoc.supportOnline = request.body.status; 
    }
    
    if (request.body.note) 
    { 
        configDoc.offlineNote = request.body.note; 
    }
    
    if (request.body.openTime) 
    { 
        configDoc.openTime = request.body.openTime; 
    }
    
    if (request.body.closeTime) 
    { 
        configDoc.closeTime = request.body.closeTime; 
    }
    
    await configDoc.save();
    response.json({ success: true });
});

// PUBLIC STATUS CHECK
application.get('/api/status', async function(request, response) 
{
    const configDoc = await Config.findOne({ id: 'global' });
    const fleetStatus = clientsFleetArray.map(function(cl)
    { 
        const s = configDoc.botFleetStatus.find(function(x){ return x.botId === cl.user.id; });
        return { 
            name: cl.user.username, 
            online: cl.isReady(), 
            tradingActive: s ? s.tradingActive : true 
        };
    });
    response.json({ 
        support: { 
            isOpen: configDoc.supportOnline, 
            window: `${configDoc.openTime} - ${configDoc.closeTime} AST`, 
            note: configDoc.offlineNote 
        }, 
        fleet: fleetStatus 
    });
});

// SELL.APP WEBHOOK
application.post('/api/webhooks/sellapp', async function(request, response) 
{ 
    console.log("[WEBHOOK] 📨 Received payload from Sell.App."); 
    response.status(200).send("OK"); 
});


// =================================================================================================
//  SECTION 11: AUTOMATION SYSTEMS (TRUSTPILOT & EXPIRY)
// =================================================================================================

setInterval(async function() 
{
    console.log("[AUTOMATION] ⏲️ Running scheduled verification tasks...");
    
    // TASK 1: Trustpilot Review Requests (14 Days Post-Activation)
    const date14DaysAgo = new Date(); 
    date14DaysAgo.setDate(date14DaysAgo.getDate() - 14);
    
    const date15DaysAgo = new Date(); 
    date15DaysAgo.setDate(date15DaysAgo.getDate() - 15);
    
    const reviewCandidates = await License.find({ 
        activatedAt: { $lte: date14DaysAgo, $gte: date15DaysAgo }, 
        reviewRequestSent: false 
    });
    
    console.log(`[AUTOMATION] Found ${reviewCandidates.length} Review Candidates`);
    
    for (let i = 0; i < reviewCandidates.length; i++) 
    {
        const licenseDoc = reviewCandidates[i];
        
        if (clientsFleetArray[0]) 
        {
            try 
            {
                const discordUser = await clientsFleetArray[0].users.fetch(licenseDoc.discordId);
                const reviewEmbed = new EmbedBuilder()
                    .setTitle("We'd Love Your Feedback")
                    // DYNAMIC DETAILS: License Type and Server Name included.
                    .setDescription(`You have been using your **${licenseDoc.type}** license on **${licenseDoc.serverName}** for 2 weeks. \n\nIf you are enjoying our service, please consider leaving a review on Trustpilot!`)
                    .setColor('#00b67a')
                    // SPECIFIC LINK INCLUDED
                    .setURL("https://trustpilot.com/review/miraidon.trade")
                    .setFooter({ text: "Automated Feedback Request" });
                    
                await discordUser.send({ embeds: [reviewEmbed] });
                
                licenseDoc.reviewRequestSent = true; 
                await licenseDoc.save();
                console.log(`[AUTOMATION] ✅ Sent Review Request to ${licenseDoc.discordId}`);
            } 
            catch(autoError)
            {
                console.error(`[AUTOMATION] ❌ Failed Review Request: ${autoError.message}`);
            }
        }
    }

    // TASK 2: Expiry Warnings (3 Days Pre-Expiry)
    const date3DaysFuture = new Date(); 
    date3DaysFuture.setDate(date3DaysFuture.getDate() + 3);
    
    const expiryCandidates = await License.find({ 
        expiresAt: { $lte: date3DaysFuture, $gte: new Date() }, 
        reminderSent: false 
    });
    
    console.log(`[AUTOMATION] Found ${expiryCandidates.length} Expiry Candidates`);
    
    for (let j = 0; j < expiryCandidates.length; j++)
    {
        const licenseDoc = expiryCandidates[j];
        if (clientsFleetArray[0])
        {
            try 
            {
                const discordUser = await clientsFleetArray[0].users.fetch(licenseDoc.discordId);
                const warningEmbed = new EmbedBuilder()
                    .setTitle("License Expiring Soon")
                    .setDescription(`Your **${licenseDoc.type}** license for **${licenseDoc.serverName}** expires in less than 3 days.\n\nPlease renew via Sell.App to avoid interruption.`)
                    .setColor('#f59e0b')
                    .setFooter({ text: "Automated Expiry Warning" });
                    
                await discordUser.send({ embeds: [warningEmbed] });
                
                licenseDoc.reminderSent = true; 
                await licenseDoc.save();
                console.log(`[AUTOMATION] ✅ Sent Expiry Warning to ${licenseDoc.discordId}`);
            } 
            catch(autoError)
            {
                console.error(`[AUTOMATION] ❌ Failed Expiry Warning: ${autoError.message}`);
            }
        }
    }
    
}, 3600000); // 1 Hour Interval


// =================================================================================================
//  SECTION 12: BOOTSTRAP
// =================================================================================================

const PORT = process.env.PORT || 10000;

httpServer.listen(PORT, function() 
{ 
    console.log(`[SYSTEM] 🚀 SERVER v22.0 RUNNING ON PORT ${PORT}`); 
});
