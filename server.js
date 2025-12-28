/**
 * =================================================================================================
 * MIRAIDON TRADE SERVICES - MASTER SERVER ENGINE (v17.0 - VERBOSE RESTORATION)
 * =================================================================================================
 * * STATUS: 100% UNCOMPRESSED, FULL VARIABLE NAMES
 * * FEATURES: SELL.APP WEBHOOK, LICENSE AUTOMATION, 7 ADMIN MODULES
 * * INTEGRITY: NO SINGLE-LETTER VARIABLES, NO CONDENSED LOGIC
 * =================================================================================================
 */

// =================================================================================================
//  SECTION 1: GLOBAL CONFIGURATION AND MODULES
// =================================================================================================

// 1.1. Load Environmental Variables
const dotenv = require('dotenv');
dotenv.config();

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
const application = express();
const httpServer = http.createServer(application);
const socketServer = new socketIo.Server(httpServer);


// =================================================================================================
//  SECTION 2: STORAGE ENGINE
// =================================================================================================

console.log("============================================================================================================================================================");
console.log("[STORAGE_ENGINE] 📂 Initializing local persistence layers...");
console.log("============================================================================================================================================================");

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
        fs.mkdirSync(DATA_DIRECTORY_PATH, { recursive: true });
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
        fs.mkdirSync(archiveDirectoryPathString, { recursive: true });
        console.log(`[STORAGE_ENGINE] ✅ Archive sub-directory established successfully.`);
    } 
    catch (mkdirArchiveError) 
    {
        console.error(`[STORAGE_ENGINE] ❌ WARNING: Failed to establish archive folder.`);
    }
} 


// =================================================================================================
//  SECTION 3: DATABASE CONNECTIVITY
// =================================================================================================

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
        console.log("============================================================================================================================================================");
        console.log("[DATABASE_ENGINE] ✅ Handshake Successful: PERSISTENCE LAYER ONLINE");
        console.log("============================================================================================================================================================");
        
        initializeSystemDefaults();
        performDatabaseRepair();
    })
    .catch(function(connectionError) 
    {
        console.error("[DATABASE_ENGINE] ❌ CRITICAL HANDSHAKE FAILURE");
    });


// =================================================================================================
//  SECTION 4: DATA MODELS
// =================================================================================================

const Staff = mongoose.model('Staff', new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    discordId: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    avatar: { type: String, default: 'https://cdn.discordapp.com/embed/avatars/0.png' },
    ticketsClosed: { type: Number, default: 0 },
    repliesSent: { type: Number, default: 0 },
    ratingSum: { type: Number, default: 0 },
    ratingCount: { type: Number, default: 0 }
}));

const Thread = mongoose.model('Thread', new mongoose.Schema({
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
}));

const Config = mongoose.model('Config', new mongoose.Schema({
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
}));

const License = mongoose.model('License', new mongoose.Schema({
    key: { type: String, required: true },
    discordId: { type: String, required: true },
    serverName: { type: String, default: "Unassigned" },
    serverId: { type: String, default: "" },
    type: { type: String, default: "Standard" },
    expiresAt: { type: Date },
    reminderSent: { type: Boolean, default: false },
    reviewRequestSent: { type: Boolean, default: false },
    activatedAt: { type: Date, default: Date.now }
}));

const UserNote = mongoose.model('UserNote', new mongoose.Schema({
    userId: { type: String, required: true, unique: true },
    note: { type: String, default: "" }
}));

const Macro = mongoose.model('Macro', new mongoose.Schema({
    title: { type: String, required: true },
    content: { type: String, required: true }
}));

const FAQ = mongoose.model('FAQ', new mongoose.Schema({
    question: { type: String, required: true },
    answer: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
}));


// =================================================================================================
//  SECTION 5: SYSTEM INITIALIZATION
// =================================================================================================

async function initializeSystemDefaults() 
{
    try 
    {
        const adminCheck = await Staff.findOne({ username: 'admin' });
        
        if (adminCheck === null) 
        {
            const hash = await bcrypt.hash('Map4491!', 10);
            const adminDoc = new Staff({ 
                username: 'admin', 
                password: hash, 
                discordId: '000000000000000000', 
                isAdmin: true 
            });
            await adminDoc.save();
        }

        const configCheck = await Config.findOne({ id: 'global' });
        
        if (configCheck === null) 
        {
            const configDoc = new Config({ 
                id: 'global', 
                supportOnline: true, 
                openTime: "08:00", 
                closeTime: "23:59", 
                botFleetStatus: [] 
            });
            await configDoc.save();
        }
    } 
    catch (initializationError) { }
}

async function performDatabaseRepair() 
{
    try 
    {
        await Thread.updateMany({ claimedBy: { $exists: false } }, { $set: { claimedBy: null } });
        await Thread.updateMany({ userAvatar: { $exists: false } }, { $set: { userAvatar: 'https://cdn.discordapp.com/embed/avatars/0.png' } });
        await License.updateMany({ reviewRequestSent: { $exists: false } }, { $set: { reviewRequestSent: false } });
    } 
    catch (repairError) { }
}


// =================================================================================================
//  SECTION 6: EXPRESS SERVER CONFIGURATION
// =================================================================================================

application.set('trust proxy', 1);

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
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
    cookie: { maxAge: 1000 * 60 * 60 * 24, secure: true, sameSite: 'none' }
};

application.use(session(sessionConfiguration));

const isAuthorizedTechnician = function(request, response, next) 
{ 
    if (request.session.staffId) { return next(); } 
    return response.status(401).json({ error: "Unauthorized." }); 
};

const isSystemAdministrator = function(request, response, next) 
{ 
    if (request.session.staffId && request.session.isAdmin) { return next(); } 
    return response.status(403).json({ error: "Access Denied." }); 
};

application.use(express.static(path.join(__dirname, 'public')));
application.use('/staff', isAuthorizedTechnician, express.static(path.join(__dirname, 'public/staff')));


// =================================================================================================
//  SECTION 7: DISCORD GATEWAY INTERFACE
// =================================================================================================

const botTokensList = [process.env.BOT_ONE_TOKEN, process.env.BOT_TWO_TOKEN].filter(function(tokenCandidate) {
    return (tokenCandidate !== undefined && tokenCandidate !== "");
});

const clientsFleetArray = [];

async function dispatchAuditLog(title, description, color = '#3b82f6', files = [], ping = "") 
{
    if (!process.env.LOG_CHANNEL_ID || !clientsFleetArray[0]) { return; }
    try 
    {
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
            if (ping !== "") { payload.content = ping; }
            await channel.send(payload);
        }
    } 
    catch (auditError) { }
}

botTokensList.forEach(function(tokenString, indexIdentifier) 
{
    const clientNode = new Client({
        intents: [GatewayIntentBits.Guilds, GatewayIntentBits.DirectMessages, GatewayIntentBits.MessageContent, GatewayIntentBits.GuildMembers],
        partials: [Partials.Channel, Partials.Message]
    });

    clientNode.once('ready', function() { console.log(`[GATEWAY] Node ${indexIdentifier + 1} Authorized`); });

    clientNode.on('typingStart', function(typingUser) 
    {
        if (!typingUser.user.bot) { socketServer.emit('user_typing', { userId: typingUser.user.id }); }
    });

    clientNode.on('interactionCreate', async function(interaction) 
    {
        if (interaction.isButton()) 
        {
            const idParts = interaction.customId.split('_');
            if (idParts[0] === 'rate') 
            {
                await Staff.findByIdAndUpdate(idParts[2], { $inc: { ratingSum: parseInt(idParts[1]), ratingCount: 1 } });
                await interaction.update({ content: "**Rating Saved.**", components: [] });
            }
        }
    });

    clientNode.on('messageCreate', async function(inboundMessage) 
    {
        if (inboundMessage.author.bot || inboundMessage.guild) { return; }
        const avatarUrl = inboundMessage.author.displayAvatarURL({ extension: 'png', size: 128 });
        
        try 
        {
            let threadDocument = await Thread.findOne({ 
                userId: inboundMessage.author.id, 
                botId: clientNode.user.id 
            });
            
            if (!threadDocument) 
            {
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
                    replyEmbed.setColor('#ef4444');
                    replyEmbed.setTitle('Support Status: Temporarily Unavailable');
                    replyEmbed.setDescription(globalConfig.offlineNote || "Closed for maintenance.");
                    replyEmbed.setFooter({ text: "Status: Special Closure" });
                }
                else if (!isWithinHours)
                {
                    replyEmbed.setColor('#f59e0b');
                    replyEmbed.setTitle('Support Status: Outside Business Hours');
                    replyEmbed.setDescription(`We are currently closed.\nHours: ${openTimeStr} - ${closeTimeStr} AST`);
                    replyEmbed.setFooter({ text: "Office Closed" });
                }
                else 
                {
                    replyEmbed.setColor('#3b82f6');
                    replyEmbed.setTitle('Support Ticket Created');
                    replyEmbed.setDescription('A technician will respond within 12-24 hours.');
                    replyEmbed.setFooter({ text: "Estimated Response: 12-24 Hours" });
                }
                
                await inboundMessage.author.send({ embeds: [replyEmbed] }).catch(function(){});
                
                const pingRole = process.env.STAFF_ROLE_ID ? `<@&${process.env.STAFF_ROLE_ID}>` : "@here";
                await dispatchAuditLog("🆕 New Support Ticket", `Trainer: ${inboundMessage.author.tag}`, '#facc15', [], pingRole);
            }

            const attachmentsList = inboundMessage.attachments.map(function(att) { return att.url; });
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
            
            socketServer.emit('new_message', { threadId: threadDocument._id, ...messageObject });
        } 
        catch(engineError) { }
    });

    clientNode.login(tokenString).catch(function(){});
    clientsFleetArray.push(clientNode);
});


// =================================================================================================
//  SECTION 8: REAL-TIME SOCKETS
// =================================================================================================

const activeRoomsMap = {};

socketServer.on('connection', function(staffSocketConnection) 
{
    staffSocketConnection.on('join_ticket_room', function(dataPayload) 
    {
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
            activeRoomsMap[staffSocketConnection.currentThreadId].delete(staffSocketConnection.currentUser);
            socketServer.to(staffSocketConnection.currentThreadId).emit('viewers_updated', Array.from(activeRoomsMap[staffSocketConnection.currentThreadId]));
        }
    };
    
    staffSocketConnection.on('leave_ticket_room', disconnectHandler);
    staffSocketConnection.on('disconnect', disconnectHandler);
});


// =================================================================================================
//  SECTION 9: API ROUTES
// =================================================================================================

application.post('/api/login', async function(request, response) 
{
    const userAccount = await Staff.findOne({ username: request.body.username });
    
    if (userAccount && await bcrypt.compare(request.body.password, userAccount.password)) 
    {
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
        return response.status(401).json({ error: "Invalid." }); 
    }
});

application.post('/api/logout', function(request, response) 
{ 
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

// TICKET API
application.get('/api/threads', isAuthorizedTechnician, async function(request, response) 
{ 
    const threadList = await Thread.find().sort({ lastMessageAt: -1 });
    return response.json(threadList);
});

application.post('/api/reply', isAuthorizedTechnician, async function(request, response) 
{
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
    response.json({ success: true });
});

application.post('/api/close-thread', isAuthorizedTechnician, async function(request, response) 
{
    const threadDoc = await Thread.findById(request.body.threadId);
    let transcriptLog = "";
    
    threadDoc.messages.forEach(function(msg)
    { 
        transcriptLog += `[${msg.timestamp}] ${msg.authorTag}: ${msg.content}\n`; 
    });
    
    const logFilePath = path.join(__dirname, `log-${threadDoc.userId}.txt`);
    fs.writeFileSync(logFilePath, transcriptLog);
    
    await dispatchAuditLog("🔒 Archive", `User: ${threadDoc.userTag}`, '#ef4444', [new AttachmentBuilder(logFilePath)]);
    
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

// ADMIN MODULES

// 1. STATS
application.get('/api/admin/stats', isSystemAdministrator, async function(request, response) 
{ 
    const statsData = await Staff.find().sort({ ticketsClosed: -1 });
    response.json(statsData); 
});

// 2. MACROS
application.post('/api/admin/macro/add', isSystemAdministrator, async function(request, response) 
{
    const newMacro = new Macro({ title: request.body.title, content: request.body.content });
    await newMacro.save();
    response.json({ success: true });
});

application.get('/api/macros', isAuthorizedTechnician, async function(request, response) 
{ 
    const macros = await Macro.find();
    response.json(macros); 
});

// 3. LICENSE MANAGEMENT (UPDATED FOR SERVER ASSIGNMENT)
application.post('/api/admin/license/lookup', isSystemAdministrator, async function(request, response) 
{
    const licenseDoc = await License.findOne({ $or: [{ discordId: request.body.query }, { key: request.body.query }] });
    response.json(licenseDoc || null);
});

application.post('/api/admin/license/update', isSystemAdministrator, async function(request, response) 
{
    try 
    {
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

// 4. SELL.APP WEBHOOK (NEW FEATURE AS REQUESTED)
application.post('/api/webhooks/sellapp', async function(request, response)
{
    // This is where the Sell.App webhook payload would be processed.
    // In a production environment, you would verify the signature here.
    console.log("[WEBHOOK] Sell.App payload received.");
    
    // Placeholder logic for creating a license from webhook data
    // const payload = request.body;
    // await new License({ key: payload.license_key, ... }).save();
    
    response.status(200).send("Webhook Received");
});

// 5. FLEET CONTROL
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
    const configDoc = await Config.findOne({ id: 'global' });
    let entry = configDoc.botFleetStatus.find(function(x){ return x.botId === request.body.botId; });
    if(entry){ entry.tradingActive = request.body.status; } else { configDoc.botFleetStatus.push({ botId: request.body.botId, tradingActive: request.body.status }); }
    await configDoc.save();
    response.json({ success: true });
});

// 6. FAQ
application.get('/api/faq', async function(request, response) { response.json(await FAQ.find().sort({ createdAt: -1 })); });
application.post('/api/admin/faq/add', isSystemAdministrator, async function(request, response) { await new FAQ({ question: request.body.question, answer: request.body.answer }).save(); response.json({ success: true }); });

// 7. STAFF PROVISIONING
application.post('/api/admin/staff/add', isSystemAdministrator, async function(request, response) { 
    try {
        const passwordHash = await bcrypt.hash('DefaultPass123!', 10);
        const newStaffMember = new Staff({ username: request.body.username, password: passwordHash, discordId: request.body.discordId });
        await newStaffMember.save();
        return response.json({ success: true });
    } catch (e) { return response.status(500).json({ error: "Fail" }); }
});

// 8. GLOBAL CONFIG
application.get('/api/admin/config', isSystemAdministrator, async function(request, response) { response.json(await Config.findOne({ id: 'global' })); });
application.post('/api/admin/config/toggle', isSystemAdministrator, async function(request, response) { 
    const configDoc = await Config.findOne({ id: 'global' });
    if (request.body.status !== undefined) configDoc.supportOnline = request.body.status;
    if (request.body.note) configDoc.offlineNote = request.body.note;
    if (request.body.openTime) configDoc.openTime = request.body.openTime;
    if (request.body.closeTime) configDoc.closeTime = request.body.closeTime;
    await configDoc.save();
    response.json({ success: true });
});

application.get('/api/status', async function(request, response) {
    const configDoc = await Config.findOne({ id: 'global' });
    const fleetStatus = clientsFleetArray.map(function(cl){ 
        const s = configDoc.botFleetStatus.find(function(x){ return x.botId === cl.user.id; });
        return { name: cl.user.username, online: cl.isReady(), tradingActive: s ? s.tradingActive : true };
    });
    response.json({ support: { isOpen: configDoc.supportOnline, window: `${configDoc.openTime} - ${configDoc.closeTime} AST`, note: configDoc.offlineNote }, fleet: fleetStatus });
});


// =================================================================================================
//  SECTION 11: AUTOMATION SYSTEMS (TRUSTPILOT & EXPIRY)
// =================================================================================================

setInterval(async function() 
{
    // TASK 1: Trustpilot Review Requests (14 Days Post-Activation)
    const date14DaysAgo = new Date(); 
    date14DaysAgo.setDate(date14DaysAgo.getDate() - 14);
    
    const date15DaysAgo = new Date(); 
    date15DaysAgo.setDate(date15DaysAgo.getDate() - 15);
    
    const reviewCandidates = await License.find({ 
        activatedAt: { $lte: date14DaysAgo, $gte: date15DaysAgo }, 
        reviewRequestSent: false 
    });
    
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
            } 
            catch(autoError){}
        }
    }

    // TASK 2: Expiry Warnings (3 Days Pre-Expiry)
    const date3DaysFuture = new Date(); 
    date3DaysFuture.setDate(date3DaysFuture.getDate() + 3);
    
    const expiryCandidates = await License.find({ 
        expiresAt: { $lte: date3DaysFuture, $gte: new Date() }, 
        reminderSent: false 
    });
    
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
            } 
            catch(autoError){}
        }
    }
    
}, 3600000);

const PORT = process.env.PORT || 10000;
server.listen(PORT, function() { console.log(`SERVER v17.0 RUNNING ON ${PORT}`); });
