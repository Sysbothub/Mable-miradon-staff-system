/**
 * ============================================================================================================================================================
 * MIRAIDON TRADE SERVICES - MASTER SERVER ENGINE (v13.1 - LOGIC CORRECTION BUILD)
 * ============================================================================================================================================================
 * * STATUS: 100% UNCOMPRESSED, MAXIMAL VERBOSITY
 * * CORRECTION: "ESTIMATED RESPONSE TIME" FOOTER REMOVED FROM OFFLINE/CLOSED STATES
 * * INTEGRITY: ZERO SHORTHAND, FULL MULTI-LINE EXPANSION
 * ============================================================================================================================================================
 */

// ============================================================================================================================================================
//  SECTION 1: GLOBAL MODULE LOADING AND ENVIRONMENT CONFIGURATION
// ============================================================================================================================================================

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
const app = express();
const server = http.createServer(app);
const io = new socketIo.Server(server);


// ============================================================================================================================================================
//  SECTION 2: PERSISTENT DISK STORAGE AND FILE SYSTEM ARCHITECTURE
// ============================================================================================================================================================

console.log("============================================================================================================================================================");
console.log("[STORAGE_ENGINE] 📂 Initializing local persistence layers...");
console.log("============================================================================================================================================================");

let DATA_DIRECTORY_PATH;

// Determine storage path based on environment
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

// Verify Root Directory
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

// Verify Archive Directory
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


// ============================================================================================================================================================
//  SECTION 4: DATA MODELS (UNABRIDGED)
// ============================================================================================================================================================

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
    serverName: { type: String },
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


// ============================================================================================================================================================
//  SECTION 5: SYSTEM INITIALIZATION
// ============================================================================================================================================================

async function initializeSystemDefaults() 
{
    console.log("[MAINTENANCE] 🔍 Validating system defaults...");
    
    try 
    {
        const adminCheck = await Staff.findOne({ username: 'admin' });
        if (adminCheck === null) 
        {
            console.log("[MAINTENANCE] 👤 Creating root admin account...");
            const hashedKey = await bcrypt.hash('Map4491!', 10);
            
            const adminDoc = new Staff({ 
                username: 'admin', 
                password: hashedKey, 
                discordId: '000000000000000000', 
                isAdmin: true 
            });
            await adminDoc.save();
        }

        const configCheck = await Config.findOne({ id: 'global' });
        if (configCheck === null) 
        {
            console.log("[MAINTENANCE] ⚙️ Creating global config...");
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
    catch (e) { }
}

async function performDatabaseRepair() 
{
    console.log("[MAINTENANCE] 🛠️ Structural verification...");
    
    try 
    {
        await Thread.updateMany({ claimedBy: { $exists: false } }, { $set: { claimedBy: null } });
        await Thread.updateMany({ userAvatar: { $exists: false } }, { $set: { userAvatar: 'https://cdn.discordapp.com/embed/avatars/0.png' } });
        await License.updateMany({ reviewRequestSent: { $exists: false } }, { $set: { reviewRequestSent: false } });
    } 
    catch (e) { }
}


// ============================================================================================================================================================
//  SECTION 6: EXPRESS SERVER CONFIGURATION
// ============================================================================================================================================================

app.set('trust proxy', 1);

app.use(express.json({ 
    limit: '65mb' 
}));

app.use(express.urlencoded({ 
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

app.use(session(sessionConfiguration));

const isAuthorizedTechnician = function(request, response, next) 
{
    if (request.session.staffId !== undefined) 
    {
        return next();
    }
    
    if (request.path.startsWith('/api')) 
    {
        return response.status(401).json({ error: "Session missing." });
    }
    
    return response.redirect('/login.html');
};

const isSystemAdministrator = function(request, response, next) 
{
    if (request.session.staffId !== undefined && request.session.isAdmin === true) 
    {
        return next();
    }
    
    return response.status(403).json({ error: "Level-2 Clearance Required." });
};

app.use(express.static(path.join(__dirname, 'public')));
app.use('/staff', isAuthorizedTechnician, express.static(path.join(__dirname, 'public/staff')));


// ============================================================================================================================================================
//  SECTION 7: DISCORD GATEWAY (FLEET ENGINE)
// ============================================================================================================================================================

const envTokens = [
    process.env.BOT_ONE_TOKEN, 
    process.env.BOT_TWO_TOKEN
];

const validTokens = envTokens.filter(function(t) 
{
    return (t !== undefined && t !== "");
});

const clientsFleetArray = [];

async function dispatchAuditLog(title, description, color = '#3b82f6', files = [], ping = "") 
{
    if (process.env.LOG_CHANNEL_ID === undefined || clientsFleetArray[0] === undefined) 
    {
        return;
    }
    
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
            
            const footerObj = { text: "System Audit" };
            embed.setFooter(footerObj);
                
            const payload = { embeds: [embed], files: files };
            if (ping !== "") 
            {
                payload.content = ping;
            }
            await channel.send(payload);
        }
    } 
    catch (e) { }
}

validTokens.forEach(function(token, idx) 
{
    const client = new Client({
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

    client.once('ready', function() 
    {
        console.log(`[GATEWAY] Node ${idx + 1} Authorized: ${client.user.tag}`);
    });

    client.on('typingStart', function(typing) 
    {
        if (typing.user.bot === false) 
        {
            io.emit('user_typing', { userId: typing.user.id });
        }
    });

    // -----------------------------------------------------------------------------------------
    // 7.5. MESSAGE LISTENER (LOGIC CORRECTED)
    // -----------------------------------------------------------------------------------------
    client.on('messageCreate', async function(message) 
    {
        if (message.author.bot === true || message.guild !== null) 
        {
            return;
        }
        
        console.log(`[GATEWAY] 📥 Message from: ${message.author.tag}`);
        
        const userId = message.author.id;
        const avatar = message.author.displayAvatarURL({ extension: 'png', size: 128 });

        try 
        {
            let thread = await Thread.findOne({ 
                userId: userId, 
                botId: client.user.id 
            });
            
            if (thread === null) 
            {
                console.log(`[ENGINE] 🏗️ Initializing record for ID ${userId}`);
                
                thread = new Thread({ 
                    userId: userId, 
                    userTag: message.author.tag, 
                    userAvatar: avatar, 
                    botId: client.user.id, 
                    botName: client.user.username, 
                    messages: [] 
                });
                
                const config = await Config.findOne({ id: 'global' });
                
                const isOpen = (config ? config.supportOnline : true);
                const openTime = (config ? config.openTime : "08:00");
                const closeTime = (config ? config.closeTime : "23:59");

                // Time Calculation
                const now = new Date();
                const options = { timeZone: 'America/Halifax', hour12: false, hour: 'numeric', minute: 'numeric' };
                const timeStr = new Intl.DateTimeFormat('en-US', options).format(now);
                const parts = timeStr.split(':');
                const nowMins = (parseInt(parts[0]) * 60) + parseInt(parts[1]);

                const openParts = openTime.split(':');
                const openMins = (parseInt(openParts[0]) * 60) + parseInt(openParts[1]);

                const closeParts = closeTime.split(':');
                const closeMins = (parseInt(closeParts[0]) * 60) + parseInt(closeParts[1]);

                const inWindow = (nowMins >= openMins && nowMins <= closeMins);

                const replyEmbed = new EmbedBuilder();
                
                // --- LOGIC CORRECTION START ---
                // "The Estimated response time thing should ONLY be sent when support is open"
                
                if (isOpen === false) 
                {
                    // PATH: OFFLINE
                    replyEmbed.setColor('#ef4444');
                    replyEmbed.setTitle('Support Office is Currently Closed');
                    replyEmbed.setDescription(config.offlineNote || 'Maintenance Mode.');
                    replyEmbed.setFooter('Your message  has been logged and the Next available agent will respond As soon as the Office Reopens.');
                    replyEmbed.setTimestamp();
                    
                    const offlineFooter = { text: "System Status: OFFLINE" };
                    replyEmbed.setFooter(offlineFooter);
                } 
                else if (inWindow === false) 
                {
                    // PATH: CLOSED (OUTSIDE HOURS)
                    replyEmbed.setColor('#f59e0b');
                    replyEmbed.setTitle('Support has Closed for the Day');
                    replyEmbed.setDescription(`You have reached us outside of Business hours.\n\n**Our Business Hours are :** ${openTime} to ${closeTime} AST.\nYour message has been Logged and we will respond during Regular Buiness Hours.`);
                    replyEmbed.setTimestamp();
                    
                    const closedFooter = { text: `Business Hours: ${openTime} - ${closeTime} AST` };
                    replyEmbed.setFooter(closedFooter);
                } 
                else 
                {
                    // PATH: OPEN (NORMAL OPERATION)
                    replyEmbed.setColor('#3b82f6');
                    replyEmbed.setTitle('Support Initialized');
                    replyEmbed.setDescription('Thank you for your inquiry. Your request has been received, and a member of our support team will follow up with you as soon as possible.');
                    replyEmbed.setTimestamp();
                    
                    // THIS IS THE ONLY PLACE "ESTIMATED RESPONSE" APPEARS
                    const openFooter = { text: "Estimated Response: 1-2 Hours" };
                    replyEmbed.setFooter(openFooter);
                }
                // --- LOGIC CORRECTION END ---
                
                await message.author.send({ embeds: [replyEmbed] }).catch(function(){});
                
                let ping = "@here";
                if (process.env.STAFF_ROLE_ID) 
                {
                    ping = `<@&${process.env.STAFF_ROLE_ID}>`;
                }
                
                await dispatchAuditLog("🆕 New Support Ticket", `Trainer: ${message.author.tag}`, '#facc15', [], ping);
            } 
            else 
            {
                if (thread.userAvatar !== avatar) 
                {
                    thread.userAvatar = avatar;
                }
            }
            
            const attachments = message.attachments.map(function(a) { 
                return a.url; 
            });
            
            const messageObj = { 
                authorTag: message.author.tag, 
                authorAvatar: avatar, 
                content: message.content || "[Media]", 
                attachments: attachments, 
                fromBot: false, 
                timestamp: new Date() 
            };

            thread.messages.push(messageObj);
            thread.lastMessageAt = new Date();
            
            await thread.save();
            
            io.emit('new_message', { 
                threadId: thread._id, 
                notif_sound: true, 
                ...messageObj 
            });
            
            console.log(`[ENGINE] ✅ Sync Complete: ${message.author.tag}`);
        } 
        catch (err) 
        {
            console.error("[ENGINE] Critical Error: " + err.message);
        }
    });

    client.login(token).catch(function(){});
    clientsFleetArray.push(client);
});


// ============================================================================================================================================================
//  SECTION 8: REAL-TIME SOCKETS
// ============================================================================================================================================================

const activeRooms = {}; 

io.on('connection', function(socket) 
{
    socket.on('join_ticket_room', function(data) 
    {
        const id = data.threadId;
        const name = data.username;
        
        socket.join(id);
        
        if (activeRooms[id] === undefined) 
        {
            activeRooms[id] = new Set();
        }
        activeRooms[id].add(name);
        
        io.to(id).emit('viewers_updated', Array.from(activeRooms[id]));
        
        socket.currentThreadId = id; 
        socket.currentUser = name;
    });

    const leave = function() 
    { 
        const id = socket.currentThreadId;
        const user = socket.currentUser;
        
        if (id && user) 
        {
            const room = activeRooms[id];
            if (room) 
            {
                room.delete(user);
                io.to(id).emit('viewers_updated', Array.from(room));
            }
        }
    };
    
    socket.on('leave_ticket_room', leave);
    socket.on('disconnect', leave);
});


// ============================================================================================================================================================
//  SECTION 9: API ROUTES (AUTHENTICATION)
// ============================================================================================================================================================

app.post('/api/login', async function(req, res) 
{
    const user = await Staff.findOne({ username: req.body.username });
    
    if (user === null) 
    {
        return res.status(401).json({ error: "Identity Mismatch." });
    }

    const valid = await bcrypt.compare(req.body.password, user.password);
    
    if (valid === true) 
    {
        req.session.staffId = user._id; 
        req.session.isAdmin = user.isAdmin; 
        req.session.username = user.username;
        
        req.session.save(function() 
        { 
            return res.json({ success: true, isAdmin: user.isAdmin, username: user.username }); 
        });
    } 
    else 
    { 
        return res.status(401).json({ error: "Invalid credentials." }); 
    }
});

app.post('/api/logout', function(req, res) 
{ 
    req.session.destroy(function() 
    { 
        res.clearCookie('connect.sid'); 
        return res.json({ success: true }); 
    }); 
});

app.get('/api/auth/user', isAuthorizedTechnician, function(req, res) 
{ 
    return res.json({ username: req.session.username, isAdmin: req.session.isAdmin }); 
});


// ============================================================================================================================================================
//  SECTION 10: TICKET MANAGEMENT API
// ============================================================================================================================================================

app.get('/api/threads', isAuthorizedTechnician, async function(req, res) 
{ 
    const list = await Thread.find().sort({ 
        lastMessageAt: -1 
    });
    return res.json(list);
});

app.post('/api/reply', isAuthorizedTechnician, async function(req, res) 
{
    const id = req.body.threadId;
    const txt = req.body.content;
    
    try 
    {
        const doc = await Thread.findById(id);
        const client = clientsFleetArray.find(function(c) 
        { 
            return (c.user.id === doc.botId); 
        });
        
        const user = await client.users.fetch(doc.userId);
        
        const embed = new EmbedBuilder();
        embed.setColor('#3b82f6');
        embed.setAuthor({ name: `Staff: ${req.session.username}`, iconURL: client.user.displayAvatarURL() });
        embed.setDescription(txt || "[Media]");
        embed.setTimestamp();
        
        const footer = { text: "Official Response" };
        embed.setFooter(footer);
        
        await user.send({ embeds: [embed] });
        
        const entry = { 
            authorTag: `Staff (${req.session.username})`, 
            authorAvatar: '', 
            content: txt || "[Media]", 
            fromBot: true, 
            timestamp: new Date() 
        };
        
        doc.messages.push(entry); 
        doc.lastMessageAt = new Date(); 
        await doc.save();
        
        io.emit('new_message', { threadId: doc._id, ...entry });
        return res.json({ success: true });
    } 
    catch (e) 
    {
        return res.status(500).json({ error: "Dispatch failed." });
    }
});

app.post('/api/close-thread', isAuthorizedTechnician, async function(req, res) 
{
    const id = req.body.threadId;
    
    try 
    {
        const doc = await Thread.findById(id);
        
        let transcript = "TRANSCRIPT\n\n";
        doc.messages.forEach(function(m) 
        {
            transcript += `[${m.timestamp}] ${m.authorTag}: ${m.content}\n`;
        });
        
        const p = path.join(__dirname, `audit-${doc.userId}.txt`);
        fs.writeFileSync(p, transcript);
        
        await dispatchAuditLog("🔒 Archive", `User: ${doc.userTag}`, '#ef4444', [new AttachmentBuilder(p)]);
        
        const dir = path.join(archiveDirectoryPathString, doc.userId);
        if (!fs.existsSync(dir)) 
        {
            fs.mkdirSync(dir, { recursive: true });
        }
        
        fs.writeFileSync(path.join(dir, `${Date.now()}.json`), JSON.stringify(doc));
        
        await Thread.findByIdAndDelete(id);
        fs.unlinkSync(p);
        
        return res.json({ success: true });
    } 
    catch (e) 
    {
        return res.status(500).json({ error: "Archival failed." });
    }
});


// ============================================================================================================================================================
//  SECTION 11: FLEET & ADMIN API
// ============================================================================================================================================================

app.get('/api/admin/servers', isSystemAdministrator, async function(req, res) 
{
    const inventory = [];
    
    for (let i = 0; i < clientsFleetArray.length; i++)
    {
        const client = clientsFleetArray[i];
        if (client.isReady())
        {
            client.guilds.cache.forEach(function(g) 
            {
                inventory.push({ 
                    id: g.id, 
                    name: g.name, 
                    members: g.memberCount, 
                    botName: client.user.username, 
                    botId: client.user.id 
                });
            });
        }
    }
    
    return res.json(inventory);
});

app.post('/api/admin/fleet/toggle-trading', isSystemAdministrator, async function(req, res) 
{
    const config = await Config.findOne({ id: 'global' });
    const botId = req.body.botId;
    const status = req.body.status;
    
    let entry = config.botFleetStatus.find(function(x) 
    { 
        return (x.botId === botId); 
    });
    
    if (entry) 
    { 
        entry.tradingActive = status; 
    }
    else 
    { 
        config.botFleetStatus.push({ botId: botId, tradingActive: status }); 
    }
    
    await config.save();
    return res.json({ success: true });
});

app.get('/api/status', async function(req, res) 
{
    const config = await Config.findOne({ id: 'global' });
    const fleet = clientsFleetArray.map(function(c) 
    {
        const s = config.botFleetStatus.find(function(x) { 
            return (x.botId === c.user.id); 
        });
        
        return { 
            name: c.user.username, 
            online: c.isReady(), 
            tradingActive: s ? s.tradingActive : true 
        };
    });
    
    return res.json({ 
        support: { 
            isOpen: config.supportOnline, 
            window: `${config.openTime} - ${config.closeTime} AST` 
        }, 
        fleet: fleet 
    });
});


// ============================================================================================================================================================
//  SECTION 12: BOOTSTRAP
// ============================================================================================================================================================

const PORT = process.env.PORT || 10000;

server.listen(PORT, function() 
{
    console.log("============================================================================================================================================================");
    console.log(`🚀 MASTER ENGINE v13.1 ONLINE [PORT ${PORT}]`);
    console.log("============================================================================================================================================================");
});
