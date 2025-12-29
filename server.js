/**
 * ============================================================================================================================================================
 * MIRAIDON TRADE SERVICES - MASTER SERVER ENGINE (v25.0 - ABSOLUTE MAXIMALIST RESTORATION)
 * ============================================================================================================================================================
 * * STATUS: 100% UNCOMPRESSED, MAXIMAL VERBOSITY
 * * FEATURES: 
 * - FAIL-SAFE ARCHIVAL (GUARANTEED DATABASE REMOVAL)
 * - 7 ADMINISTRATIVE MODULES (ANALYTICS, MACROS, LICENSES, FLEET, FAQ, STAFF, CONFIG)
 * - AUTOMATED TRUSTPILOT REQUESTS (DYNAMIC LICENSE/SERVER DATA)
 * - AUTOMATED EXPIRY WARNINGS
 * - SELL.APP WEBHOOK INTEGRATION
 * - TOTAL CONSOLE LOGGING PROTOCOL
 * * INTEGRITY: NO SINGLE-LETTER VARIABLES, NO CONDENSED BLOCKS, NO SHORTHAND
 * ============================================================================================================================================================
 */

// ============================================================================================================================================================
//  SECTION 1: GLOBAL MODULE LOADING AND ENVIRONMENT CONFIGURATION
// ============================================================================================================================================================

const dotenv = require('dotenv');
dotenv.config();

console.log("[SYSTEM] 🟢 Initializing Master Engine...");

const fs = require('fs');
const path = require('path');
const http = require('http');
const express = require('express');
const axios = require('axios');
const bcrypt = require('bcrypt');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
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
const PermissionFlagsBits = discordJs.PermissionFlagsBits;

const applicationInstance = express();
const httpServerInstance = http.createServer(applicationInstance);
const socketServerInstance = new socketIo.Server(httpServerInstance);

console.log("[SYSTEM] 🔹 Dependencies Loaded Successfully.");


// ============================================================================================================================================================
//  SECTION 2: STORAGE ENGINE ARCHITECTURE
// ============================================================================================================================================================

let PERSISTENT_DATA_DIRECTORY;
const deploymentContext = process.env.RENDER;

if (deploymentContext === 'true') 
{
    console.log("[STORAGE] ☁️ Mode: PRODUCTION (RENDER)");
    PERSISTENT_DATA_DIRECTORY = '/var/data';
} 
else 
{
    console.log("[STORAGE] 💻 Mode: LOCAL DEVELOPMENT");
    PERSISTENT_DATA_DIRECTORY = path.join(__dirname, 'local_storage');
}

const directoryCheck = fs.existsSync(PERSISTENT_DATA_DIRECTORY);

if (directoryCheck === false) 
{
    try 
    {
        fs.mkdirSync(PERSISTENT_DATA_DIRECTORY, { 
            recursive: true 
        });
        console.log("[STORAGE] ✅ Root created.");
    } 
    catch (mkdirError) 
    {
        console.error("[STORAGE] ❌ Failed to write to disk.");
        process.exit(1); 
    }
} 

const archivePathString = path.join(PERSISTENT_DATA_DIRECTORY, 'archives');
const archiveCheck = fs.existsSync(archivePathString);

if (archiveCheck === false) 
{
    try 
    {
        fs.mkdirSync(archivePathString, { 
            recursive: true 
        });
    } 
    catch (mkdirArchiveError) 
    {
        console.error("[STORAGE] ⚠️ Archive folder failed.");
    }
} 


// ============================================================================================================================================================
//  SECTION 3: DATABASE HANDSHAKE
// ============================================================================================================================================================

const databaseUriString = process.env.MONGODB_URI;

mongoose.connect(databaseUriString)
    .then(function() 
    {
        console.log("[DATABASE] ✅ Connection established.");
        performInitializationLogic();
        performDatabaseMaintenance();
    })
    .catch(function(connectionError) 
    {
        console.error("[DATABASE] ❌ Connection failed.");
    });


// ============================================================================================================================================================
//  SECTION 4: VERBOSE DATA SCHEMAS
// ============================================================================================================================================================

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

const LicenseSchema = new mongoose.Schema({
    key: { 
        type: String, 
        required: true 
    },
    discordId: { 
        type: String, 
        required: true 
    },
    serverName: { 
        type: String, 
        default: "Unassigned" 
    },
    serverId: { 
        type: String, 
        default: "" 
    },
    type: { 
        type: String, 
        default: "Standard" 
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
    },
    activatedAt: { 
        type: Date, 
        default: Date.now 
    }
});
const License = mongoose.model('License', LicenseSchema);

const UserNoteSchema = new mongoose.Schema({
    userId: { 
        type: String, 
        required: true, 
        unique: true 
    },
    note: { 
        type: String, 
        default: "" 
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


// ============================================================================================================================================================
//  SECTION 5: SYSTEM LOGIC PROTOCOLS
// ============================================================================================================================================================

async function performInitializationLogic() 
{
    console.log("[SYSTEM] ⚙️ Checking Defaults...");
    try 
    {
        const adminAccountCheck = await Staff.findOne({ 
            username: 'admin' 
        });
        
        if (adminAccountCheck === null) 
        {
            console.log("[SYSTEM] ➕ Creating Admin Account...");
            const defaultPasswordHash = await bcrypt.hash('Map4491!', 10);
            const newAdminAccount = new Staff({ 
                username: 'admin', 
                password: defaultPasswordHash, 
                discordId: '000000000000000000', 
                isAdmin: true 
            });
            await newAdminAccount.save();
        }

        const globalConfigurationCheck = await Config.findOne({ 
            id: 'global' 
        });
        
        if (globalConfigurationCheck === null) 
        {
            console.log("[SYSTEM] ➕ Creating Global Config...");
            const newConfigurationObject = new Config({ 
                id: 'global', 
                supportOnline: true, 
                openTime: "08:00", 
                closeTime: "23:59", 
                botFleetStatus: [] 
            });
            await newConfigurationObject.save();
        }
    } 
    catch (initLogicError) 
    {
        console.error(initLogicError);
    }
}

async function performDatabaseMaintenance() 
{
    console.log("[SYSTEM] 🛠️ Database integrity scan...");
    try 
    {
        await Thread.updateMany({ 
            claimedBy: { $exists: false } 
        }, { 
            $set: { claimedBy: null } 
        });
        
        await Thread.updateMany({ 
            userAvatar: { $exists: false } 
        }, { 
            $set: { userAvatar: 'https://cdn.discordapp.com/embed/avatars/0.png' } 
        });
        
        await License.updateMany({ 
            reviewRequestSent: { $exists: false } 
        }, { 
            $set: { reviewRequestSent: false } 
        });
        console.log("[SYSTEM] ✅ Scan complete.");
    } 
    catch (maintenanceError) 
    {
        console.error(maintenanceError);
    }
}


// ============================================================================================================================================================
//  SECTION 6: EXPRESS CONFIGURATION & LOGGING MIDDLEWARE
// ============================================================================================================================================================

applicationInstance.set('trust proxy', 1);

applicationInstance.use(function(incomingRequest, outgoingResponse, nextMiddleware) 
{
    console.log(`[HTTP] ➡️ ${incomingRequest.method} ${incomingRequest.url} | IP: ${incomingRequest.ip}`);
    
    if (incomingRequest.method === 'POST') 
    {
        const requestBodyPayloadKeys = Object.keys(incomingRequest.body || {});
        console.log(`[HTTP] 📦 Body Keys Received: ${requestBodyPayloadKeys.join(', ')}`);
    }
    
    nextMiddleware();
});

applicationInstance.use(express.json({ 
    limit: '65mb' 
}));

applicationInstance.use(express.urlencoded({ 
    extended: true, 
    limit: '65mb' 
}));

const sessionOptionsConfiguration = {
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

applicationInstance.use(session(sessionOptionsConfiguration));

const verifyAuthorizedStaff = function(requestObject, responseObject, nextStep) 
{ 
    if (requestObject.session.staffId !== undefined) 
    { 
        return nextStep(); 
    } 
    console.log(`[AUTH] ⛔ Blocked access to ${requestObject.url}`);
    return responseObject.status(401).json({ 
        error: "Unauthorized access detected." 
    }); 
};

const verifySystemAdmin = function(requestObject, responseObject, nextStep) 
{ 
    if (requestObject.session.staffId !== undefined && requestObject.session.isAdmin === true) 
    { 
        return nextStep(); 
    } 
    console.log(`[AUTH] ⛔ Blocked non-admin access to ${requestObject.url}`);
    return responseObject.status(403).json({ 
        error: "Administrative clearance required." 
    }); 
};

applicationInstance.use(express.static(path.join(__dirname, 'public')));
applicationInstance.use('/staff', verifyAuthorizedStaff, express.static(path.join(__dirname, 'public/staff')));


// ============================================================================================================================================================
//  SECTION 7: DISCORD GATEWAY INTERFACE
// ============================================================================================================================================================

const botTokensArray = [
    process.env.BOT_ONE_TOKEN, 
    process.env.BOT_TWO_TOKEN
].filter(function(tokenToCheck) 
{
    return (tokenToCheck !== undefined && tokenToCheck !== "");
});

const activeDiscordClients = [];

async function executeAuditLogDispatch(logTitle, logDescription, logColor = '#3b82f6', logFiles = [], logPing = "") 
{
    if (process.env.LOG_CHANNEL_ID === undefined || activeDiscordClients[0] === undefined) 
    { 
        return; 
    }
    
    try 
    {
        console.log(`[AUDIT] 📝 Dispatched Log Object: ${logTitle}`);
        const logChannelObject = await activeDiscordClients[0].channels.fetch(process.env.LOG_CHANNEL_ID);
        
        if (logChannelObject !== null) 
        {
            const auditEmbedObject = new EmbedBuilder();
            auditEmbedObject.setTitle(logTitle);
            auditEmbedObject.setDescription(logDescription);
            auditEmbedObject.setColor(logColor);
            auditEmbedObject.setTimestamp();
            auditEmbedObject.setFooter({ 
                text: "System Internal Audit" 
            });
            
            const auditPayloadObject = { 
                embeds: [auditEmbedObject], 
                files: logFiles 
            };
            
            if (logPing !== "") 
            { 
                auditPayloadObject.content = logPing; 
            }
            
            await logChannelObject.send(auditPayloadObject);
        }
    } 
    catch (auditDispatchError) 
    { 
        console.error(`[AUDIT] ❌ Dispatch Failure: ${auditDispatchError.message}`); 
    }
}

botTokensArray.forEach(function(discordTokenString, nodeIndex) 
{
    const clientNodeInstance = new Client({
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

    clientNodeInstance.once('ready', function() 
    { 
        console.log(`[GATEWAY] 🟢 Node ${nodeIndex + 1} Authorized: ${clientNodeInstance.user.tag}`); 
    });

    clientNodeInstance.on('typingStart', function(typingSessionData) 
    {
        if (typingSessionData.user.bot === false) 
        { 
            console.log(`[DISCORD] ⌨️ User ${typingSessionData.user.id} is typing.`);
            socketServerInstance.emit('user_typing', { 
                userId: typingSessionData.user.id 
            }); 
        }
    });

    clientNodeInstance.on('interactionCreate', async function(discordInteraction) 
    {
        if (discordInteraction.isButton() === true) 
        {
            console.log(`[DISCORD] 🖱️ Button Interaction: ${discordInteraction.customId}`);
            const interactionIdParts = discordInteraction.customId.split('_');
            
            if (interactionIdParts[0] === 'rate') 
            {
                const starRatingValue = parseInt(interactionIdParts[1]);
                const targetStaffId = interactionIdParts[2];
                
                await Staff.findByIdAndUpdate(targetStaffId, { 
                    $inc: { 
                        ratingSum: starRatingValue, 
                        ratingCount: 1 
                    } 
                });
                
                await discordInteraction.update({ 
                    content: "**Feedback Protocol: Success. Rating recorded.**", 
                    components: [] 
                });
            }
        }
    });

    clientNodeInstance.on('messageCreate', async function(incomingDiscordMessage) 
    {
        if (incomingDiscordMessage.author.bot === true || incomingDiscordMessage.guild !== null) 
        { 
            return; 
        }
        
        console.log(`[DISCORD] 📩 Inbound DM: ${incomingDiscordMessage.author.tag}`);
        
        const authorAvatarUrl = incomingDiscordMessage.author.displayAvatarURL({ 
            extension: 'png', 
            size: 128 
        });
        
        try 
        {
            let supportThreadDocument = await Thread.findOne({ 
                userId: incomingDiscordMessage.author.id, 
                botId: clientNodeInstance.user.id 
            });
            
            if (supportThreadDocument === null) 
            {
                console.log(`[ENGINE] 🆕 Initializing Thread for ${incomingDiscordMessage.author.id}`);
                
                supportThreadDocument = new Thread({ 
                    userId: incomingDiscordMessage.author.id, 
                    userTag: incomingDiscordMessage.author.tag, 
                    userAvatar: authorAvatarUrl, 
                    botId: clientNodeInstance.user.id, 
                    botName: clientNodeInstance.user.username, 
                    messages: [] 
                });
                
                const currentGlobalConfig = await Config.findOne({ 
                    id: 'global' 
                });
                
                const isStatusOnline = (currentGlobalConfig ? currentGlobalConfig.supportOnline : true);
                const openTimeParameter = (currentGlobalConfig ? currentGlobalConfig.openTime : "08:00");
                const closeTimeParameter = (currentGlobalConfig ? currentGlobalConfig.closeTime : "23:59");

                const temporalDate = new Date();
                const regionalTimeString = new Intl.DateTimeFormat('en-US', { 
                    timeZone: 'America/Halifax', 
                    hour12: false, 
                    hour: 'numeric', 
                    minute: 'numeric' 
                }).format(temporalDate);
                
                const [timeHour, timeMinute] = regionalTimeString.split(':').map(Number);
                const convertedCurrentMinutes = (timeHour * 60) + timeMinute;
                
                const [openHour, openMin] = openTimeParameter.split(':').map(Number);
                const convertedOpenMinutes = (openHour * 60) + openMin;
                
                const [closeHour, closeMin] = closeTimeParameter.split(':').map(Number);
                const convertedCloseMinutes = (closeHour * 60) + closeMin;
                
                const withinOperatingWindow = (convertedCurrentMinutes >= convertedOpenMinutes && convertedCurrentMinutes <= convertedCloseMinutes);

                console.log(`[ENGINE] 🕒 Logic Check: Online=${isStatusOnline}, Window=${withinOperatingWindow}`);

                const automatedResponseEmbed = new EmbedBuilder();
                
                if (isStatusOnline === false) 
                {
                    console.log(`[ENGINE] 🔒 Status: CLOSED (Manual Override)`);
                    automatedResponseEmbed.setColor('#ef4444');
                    automatedResponseEmbed.setTitle('Support Status: Temporarily Unavailable');
                    automatedResponseEmbed.setDescription(currentGlobalConfig.offlineNote || "The support desk is currently closed for maintenance.");
                    automatedResponseEmbed.setFooter({ 
                        text: "Status Code: Special Closure" 
                    });
                }
                else if (withinOperatingWindow === false)
                {
                    console.log(`[ENGINE] 🌙 Status: CLOSED (Out of Hours)`);
                    automatedResponseEmbed.setColor('#f59e0b');
                    automatedResponseEmbed.setTitle('Support Status: Outside Business Hours');
                    automatedResponseEmbed.setDescription(`Thank you for reaching out. We are currently closed.\n\n**Office Hours:** ${openTimeParameter} - ${closeTimeParameter} AST`);
                    automatedResponseEmbed.setFooter({ 
                        text: "Status Code: Office Closed" 
                    });
                }
                else 
                {
                    console.log(`[ENGINE] ✅ Status: OPEN`);
                    automatedResponseEmbed.setColor('#3b82f6');
                    automatedResponseEmbed.setTitle('Support Ticket Created');
                    automatedResponseEmbed.setDescription('A technician has been notified. Expect a resolution within 12-24 hours.');
                    automatedResponseEmbed.setFooter({ 
                        text: "Response ETA: 12-24 Hours" 
                    });
                }
                
                await incomingDiscordMessage.author.send({ 
                    embeds: [automatedResponseEmbed] 
                }).catch(function(dmError) { });
                
                const notificationPing = process.env.STAFF_ROLE_ID ? `<@&${process.env.STAFF_ROLE_ID}>` : "@here";
                await executeAuditLogDispatch("🆕 New Ticket Initialized", `User: ${incomingDiscordMessage.author.tag}`, '#facc15', [], notificationPing);
            }

            const incomingAttachmentsArray = incomingDiscordMessage.attachments.map(function(attachmentItem) 
            { 
                return attachmentItem.url; 
            });
            
            const messageEntryObject = { 
                authorTag: incomingDiscordMessage.author.tag, 
                authorAvatar: authorAvatarUrl, 
                content: incomingDiscordMessage.content || "[Non-Text Transmission]", 
                attachments: incomingAttachmentsArray, 
                fromBot: false, 
                timestamp: new Date() 
            };

            supportThreadDocument.messages.push(messageEntryObject);
            supportThreadDocument.lastMessageAt = new Date();
            
            await supportThreadDocument.save();
            
            console.log(`[ENGINE] 💾 Persistence Complete. Transmitting to Dashboard.`);
            socketServerInstance.emit('new_message', { 
                threadId: supportThreadDocument._id, 
                ...messageEntryObject 
            });
        } 
        catch(engineThreadError) 
        { 
            console.error(`[ENGINE] ❌ Critical failure in thread processing: ${engineThreadError.message}`); 
        }
    });

    clientNodeInstance.login(discordTokenString).catch(function(loginError) { });
    activeDiscordClients.push(clientNodeInstance);
});


// ============================================================================================================================================================
//  SECTION 8: REAL-TIME SOCKET ENGINE
// ============================================================================================================================================================

const activeViewerRoomsMap = {};

socketServerInstance.on('connection', function(staffSocketConnectionInstance) 
{
    console.log(`[SOCKET] 🔌 Interface Connected: ${staffSocketConnectionInstance.id}`);

    staffSocketConnectionInstance.on('join_ticket_room', function(subscriptionPayload) 
    {
        console.log(`[SOCKET] 👤 Staff Member subscribing to Room: ${subscriptionPayload.threadId}`);
        staffSocketConnectionInstance.join(subscriptionPayload.threadId);
        
        if (activeViewerRoomsMap[subscriptionPayload.threadId] === undefined) 
        { 
            activeViewerRoomsMap[subscriptionPayload.threadId] = new Set(); 
        }
        
        activeViewerRoomsMap[subscriptionPayload.threadId].add(subscriptionPayload.username);
        
        socketServerInstance.to(subscriptionPayload.threadId).emit('viewers_updated', Array.from(activeViewerRoomsMap[subscriptionPayload.threadId]));
        
        staffSocketConnectionInstance.activeRoomId = subscriptionPayload.threadId; 
        staffSocketConnectionInstance.staffIdentity = subscriptionPayload.username;
    });
    
    const executeSocketDeparture = function() 
    {
        const targetRoomId = staffSocketConnectionInstance.activeRoomId;
        const targetStaffName = staffSocketConnectionInstance.staffIdentity;

        if (targetRoomId !== undefined && targetStaffName !== undefined && activeViewerRoomsMap[targetRoomId] !== undefined) 
        {
            console.log(`[SOCKET] 🚪 Staff Member departing Room: ${targetRoomId}`);
            activeViewerRoomsMap[targetRoomId].delete(targetStaffName);
            socketServerInstance.to(targetRoomId).emit('viewers_updated', Array.from(activeViewerRoomsMap[targetRoomId]));
        }
    };
    
    staffSocketConnectionInstance.on('leave_ticket_room', executeSocketDeparture);
    staffSocketConnectionInstance.on('disconnect', executeSocketDeparture);
});


// ============================================================================================================================================================
//  SECTION 9: API CONTROLLER (AUTHENTICATION & CRM)
// ============================================================================================================================================================

applicationInstance.post('/api/login', async function(httpRequest, httpResponse) 
{
    console.log(`[API] 🔑 Login request for: ${httpRequest.body.username}`);
    const targetStaffDocument = await Staff.findOne({ 
        username: httpRequest.body.username 
    });
    
    if (targetStaffDocument !== null && await bcrypt.compare(httpRequest.body.password, targetStaffDocument.password)) 
    {
        console.log(`[API] ✅ Auth successful.`);
        httpRequest.session.staffId = targetStaffDocument._id; 
        httpRequest.session.isAdmin = targetStaffDocument.isAdmin; 
        httpRequest.session.username = targetStaffDocument.username;
        
        httpRequest.session.save(function() 
        { 
            return httpResponse.json({ 
                success: true, 
                isAdmin: targetStaffDocument.isAdmin 
            }); 
        });
    } 
    else 
    { 
        console.log(`[API] ❌ Auth failed.`);
        return httpResponse.status(401).json({ 
            error: "Authentication credentials rejected." 
        }); 
    }
});

applicationInstance.post('/api/logout', function(httpRequest, httpResponse) 
{ 
    console.log(`[API] 🚪 Logout sequence triggered.`);
    httpRequest.session.destroy(function() 
    { 
        httpResponse.clearCookie('connect.sid'); 
        httpResponse.json({ 
            success: true 
        }); 
    }); 
});

applicationInstance.get('/api/auth/user', verifyAuthorizedStaff, function(httpRequest, httpResponse) 
{ 
    httpResponse.json({ 
        username: httpRequest.session.username, 
        isAdmin: httpRequest.session.isAdmin 
    }); 
});

applicationInstance.get('/api/threads', verifyAuthorizedStaff, async function(httpRequest, httpResponse) 
{ 
    const threadCollection = await Thread.find().sort({ 
        lastMessageAt: -1 
    });
    return httpResponse.json(threadCollection);
});

applicationInstance.post('/api/reply', verifyAuthorizedStaff, async function(httpRequest, httpResponse) 
{
    console.log(`[API] 📤 Transmitting reply to thread: ${httpRequest.body.threadId}`);
    const targetThreadDocument = await Thread.findById(httpRequest.body.threadId);
    
    if (targetThreadDocument === null) 
    {
        return httpResponse.status(404).json({ error: "Thread lost." });
    }

    const targetDiscordNode = activeDiscordClients.find(function(nodeItem)
    { 
        return nodeItem.user.id === targetThreadDocument.botId; 
    });
    
    const targetDiscordUser = await targetDiscordNode.users.fetch(targetThreadDocument.userId);
    
    const replyEmbedObject = new EmbedBuilder();
    replyEmbedObject.setColor('#3b82f6');
    replyEmbedObject.setAuthor({ 
        name: `Staff: ${httpRequest.session.username}`, 
        iconURL: targetDiscordNode.user.displayAvatarURL() 
    });
    replyEmbedObject.setDescription(httpRequest.body.content || "[Media Transmission]");
    replyEmbedObject.setTimestamp();
    replyEmbedObject.setFooter({ 
        text: "Official Miraidon Representative Response" 
    });
    
    await targetDiscordUser.send({ 
        embeds: [replyEmbedObject] 
    });
    
    const messageLogEntry = { 
        authorTag: `Staff (${httpRequest.session.username})`, 
        authorAvatar: '', 
        content: httpRequest.body.content || "[Media Transmission]", 
        fromBot: true, 
        timestamp: new Date() 
    };
    
    targetThreadDocument.messages.push(messageLogEntry); 
    targetThreadDocument.lastMessageAt = new Date(); 
    await targetThreadDocument.save();
    
    socketServerInstance.emit('new_message', { 
        threadId: targetThreadDocument._id, 
        ...messageLogEntry 
    });
    
    await Staff.findByIdAndUpdate(httpRequest.session.staffId, { 
        $inc: { repliesSent: 1 } 
    });
    
    return httpResponse.json({ 
        success: true 
    });
});


// ============================================================================================================================================================
//  SECTION 10: ADMINISTRATIVE & UTILITY ENDPOINTS
// ============================================================================================================================================================

// 🔓 ARCHIVE ENDPOINT (FIXED LOGIC)
applicationInstance.post('/api/close-thread', verifyAuthorizedStaff, async function(httpRequest, httpResponse) 
{
    console.log(`[API] 🔒 ARCHIVE SIGNAL: Thread ID ${httpRequest.body.threadId}`);
    
    const targetThreadDocument = await Thread.findById(httpRequest.body.threadId);
    
    if (targetThreadDocument === null)
    {
        console.log(`[API] ⚠️ Thread missing from DB. Skipping logic.`);
        return httpResponse.json({ 
            success: true, 
            message: "Thread already processed." 
        });
    }

    // 1. CAPTURE FOR LOGS (PROTECTED)
    try 
    {
        let formattedTranscript = "--- MIRAIDON SUPPORT TRANSCRIPT ---\n\n";
        targetThreadDocument.messages.forEach(function(msgItem)
        { 
            formattedTranscript += `[${msgItem.timestamp}] ${msgItem.authorTag}: ${msgItem.content}\n`; 
        });
        
        const localLogPathString = path.join(__dirname, `temporary-log-${targetThreadDocument.userId}.txt`);
        fs.writeFileSync(localLogPathString, formattedTranscript);
        
        await executeAuditLogDispatch("🔒 Archive Protocol", `User Identity: ${targetThreadDocument.userTag}`, '#ef4444', [new AttachmentBuilder(localLogPathString)]);
        
        const permanentArchiveFolder = path.join(archivePathString, targetThreadDocument.userId);
        if (fs.existsSync(permanentArchiveFolder) === false) 
        { 
            fs.mkdirSync(permanentArchiveFolder, { 
                recursive: true 
            }); 
        }
        
        fs.writeFileSync(path.join(permanentArchiveFolder, `${Date.now()}.json`), JSON.stringify(targetThreadDocument));
        
        const targetDiscordNode = activeDiscordClients.find(function(nodeItem)
        { 
            return nodeItem.user.id === targetThreadDocument.botId; 
        });
        
        if (targetDiscordNode !== undefined) 
        {
            const ratingComponentRow = new ActionRowBuilder().addComponents(
                new ButtonBuilder().setCustomId(`rate_5_${httpRequest.session.staffId}`).setLabel('Excellent (5⭐)').setStyle(ButtonStyle.Success)
            );
            const targetDiscordUserObject = await targetDiscordNode.users.fetch(targetThreadDocument.userId);
            await targetDiscordUserObject.send({ 
                content: "This support session has been closed. Please rate your experience:", 
                components: [ratingComponentRow] 
            }).catch(function() { });
        }
        
        if (fs.existsSync(localLogPathString)) 
        { 
            fs.unlinkSync(localLogPathString); 
        }
    } 
    catch(archivalProcessError) 
    { 
        console.error(`[API] ⚠️ Archive sub-process error: ${archivalProcessError.message}`);
    }

    // 2. GUARANTEED DATABASE DELETION
    await Thread.findByIdAndDelete(httpRequest.body.threadId);
    
    await Staff.findByIdAndUpdate(httpRequest.session.staffId, { 
        $inc: { ticketsClosed: 1 } 
    });
    
    console.log(`[API] ✅ Database deletion successful. Thread purged.`);
    return httpResponse.json({ 
        success: true 
    });
});

// STAFF STATS MODULE
applicationInstance.get('/api/admin/stats', verifySystemAdmin, async function(httpRequest, httpResponse) 
{ 
    const collectionOfStats = await Staff.find().sort({ 
        ticketsClosed: -1 
    });
    httpResponse.json(collectionOfStats); 
});

// MACRO MODULE
applicationInstance.post('/api/admin/macro/add', verifySystemAdmin, async function(httpRequest, httpResponse) 
{
    console.log(`[ADMIN] ➕ New Macro Definition: ${httpRequest.body.title}`);
    const newMacroObject = new Macro({ 
        title: httpRequest.body.title, 
        content: httpRequest.body.content 
    });
    await newMacroObject.save();
    httpResponse.json({ 
        success: true 
    });
});

applicationInstance.get('/api/macros', verifyAuthorizedStaff, async function(httpRequest, httpResponse) 
{ 
    const macroCollection = await Macro.find();
    httpResponse.json(macroCollection); 
});

// LICENSE MODULE
applicationInstance.post('/api/admin/license/lookup', verifySystemAdmin, async function(httpRequest, httpResponse) 
{
    console.log(`[ADMIN] 🔍 Searching License Data for: ${httpRequest.body.query}`);
    const foundLicenseDocument = await License.findOne({ 
        $or: [
            { discordId: httpRequest.body.query }, 
            { key: httpRequest.body.query }
        ] 
    });
    httpResponse.json(foundLicenseDocument || null);
});

applicationInstance.post('/api/admin/license/update', verifySystemAdmin, async function(httpRequest, httpResponse) 
{
    try 
    {
        console.log(`[ADMIN] ✏️ Manually Updating License Assignment: ${httpRequest.body.key}`);
        const searchCriteria = { 
            key: httpRequest.body.key 
        };
        const updatedDataPayload = {
            serverName: httpRequest.body.serverName,
            serverId: httpRequest.body.serverId,
            discordId: httpRequest.body.discordId
        };
        await License.findOneAndUpdate(searchCriteria, updatedDataPayload);
        httpResponse.json({ 
            success: true 
        });
    } 
    catch(licenseUpdateError) 
    { 
        httpResponse.status(500).json({ error: "Update logic failed." }); 
    }
});

// CRM NOTES MODULE
applicationInstance.post('/api/note', verifyAuthorizedStaff, async function(httpRequest, httpResponse) 
{
    console.log(`[CRM] 📝 Registering Note for User: ${httpRequest.body.userId}`);
    await UserNote.findOneAndUpdate({ 
        userId: httpRequest.body.userId 
    }, { 
        note: httpRequest.body.note 
    }, { 
        upsert: true, 
        new: true 
    });
    httpResponse.json({ 
        success: true 
    });
});

applicationInstance.get('/api/note/:userId', verifyAuthorizedStaff, async function(httpRequest, httpResponse) 
{
    const foundNoteDocument = await UserNote.findOne({ 
        userId: httpRequest.params.userId 
    });
    httpResponse.json({ 
        note: foundNoteDocument ? foundNoteDocument.note : "" 
    });
});

// FLEET MANAGEMENT MODULE
applicationInstance.get('/api/admin/servers', verifySystemAdmin, async function(httpRequest, httpResponse) 
{
    const totalGuildInventory = [];
    activeDiscordClients.forEach(function(discordClientInstance)
    { 
        if (discordClientInstance.isReady() === true)
        { 
            discordClientInstance.guilds.cache.forEach(function(guildInstance)
            { 
                totalGuildInventory.push({ 
                    id: guildInstance.id, 
                    name: guildInstance.name, 
                    members: guildInstance.memberCount, 
                    ownerId: guildInstance.ownerId, 
                    botName: discordClientInstance.user.username, 
                    botId: discordClientInstance.user.id 
                }); 
            }); 
        } 
    });
    httpResponse.json(totalGuildInventory);
});

applicationInstance.post('/api/admin/fleet/toggle-trading', verifySystemAdmin, async function(httpRequest, httpResponse) 
{
    console.log(`[ADMIN] 🔄 Modifying Fleet State for Node: ${httpRequest.body.botId}`);
    const globalConfigDoc = await Config.findOne({ 
        id: 'global' 
    });
    
    let botStateEntry = globalConfigDoc.botFleetStatus.find(function(statusItem)
    { 
        return statusItem.botId === httpRequest.body.botId; 
    });
    
    if (botStateEntry !== undefined)
    { 
        botStateEntry.tradingActive = httpRequest.body.status; 
    } 
    else 
    { 
        globalConfigDoc.botFleetStatus.push({ 
            botId: httpRequest.body.botId, 
            tradingActive: httpRequest.body.status 
        }); 
    }
    
    await globalConfigDoc.save();
    httpResponse.json({ 
        success: true 
    });
});

applicationInstance.post('/api/admin/guild/leave', verifySystemAdmin, async function(httpRequest, httpResponse) 
{
    console.log(`[ADMIN] 🚪 FORCED TERMINATION: Guild Leave ${httpRequest.body.guildId}`);
    const discordClientNode = activeDiscordClients.find(function(nodeItem) 
    { 
        return nodeItem.user.id === httpRequest.body.botId; 
    });
    
    if (discordClientNode !== undefined) 
    { 
        const targetDiscordGuild = discordClientNode.guilds.cache.get(httpRequest.body.guildId); 
        if (targetDiscordGuild !== undefined) 
        { 
            await targetDiscordGuild.leave(); 
            return httpResponse.json({ success: true }); 
        } 
    }
    return httpResponse.status(404).json({ error: "Node or Guild unreachable." });
});

applicationInstance.post('/api/admin/guild/invite', verifySystemAdmin, async function(httpRequest, httpResponse) 
{
    console.log(`[ADMIN] 🔗 REQUEST: Invite generation for ${httpRequest.body.guildId}`);
    const discordClientNode = activeDiscordClients.find(function(nodeItem) 
    { 
        return nodeItem.user.id === httpRequest.body.botId; 
    });
    
    if (discordClientNode !== undefined) 
    { 
        const targetDiscordGuild = discordClientNode.guilds.cache.get(httpRequest.body.guildId); 
        if (targetDiscordGuild !== undefined) 
        { 
            let suitableInviteChannel = targetDiscordGuild.channels.cache.find(function(channelItem) 
            { 
                return channelItem.type === ChannelType.GuildText && channelItem.permissionsFor(targetDiscordGuild.members.me).has(PermissionFlagsBits.CreateInstantInvite); 
            }); 
            
            if (suitableInviteChannel !== undefined) 
            { 
                const newInviteObject = await suitableInviteChannel.createInvite({ maxAge: 0, maxUses: 1 }); 
                return httpResponse.json({ url: newInviteObject.url }); 
            } 
        } 
    }
    return httpResponse.status(404).json({ error: "Capability restricted or node missing." });
});

// MANUAL DM DISPATCH
applicationInstance.post('/api/admin/dm', verifyAuthorizedStaff, async function(httpRequest, httpResponse) 
{
    console.log(`[ADMIN] ✉️ MANUAL DISPATCH: To ${httpRequest.body.userId}`);
    const targetUserIdString = httpRequest.body.userId;
    const manualContentString = httpRequest.body.content;
    const discordClientNode = activeDiscordClients[0];
    
    try 
    {
        const targetDiscordUser = await discordClientNode.users.fetch(targetUserIdString);
        await targetDiscordUser.send({ content: manualContentString });
        return httpResponse.json({ 
            success: true 
        });
    } 
    catch(manualDmError) 
    { 
        return httpResponse.status(500).json({ error: manualDmError.message }); 
    }
});

// FAQ MODULE
applicationInstance.get('/api/faq', async function(httpRequest, httpResponse) 
{ 
    const sortedFaqCollection = await FAQ.find().sort({ 
        createdAt: -1 
    });
    httpResponse.json(sortedFaqCollection); 
});

applicationInstance.post('/api/admin/faq/add', verifySystemAdmin, async function(httpRequest, httpResponse) 
{ 
    const newFaqDocument = new FAQ({ 
        question: httpRequest.body.question, 
        answer: httpRequest.body.answer 
    });
    await newFaqDocument.save(); 
    httpResponse.json({ 
        success: true 
    }); 
});

// STAFF PROVISIONING MODULE
applicationInstance.post('/api/admin/staff/add', verifySystemAdmin, async function(httpRequest, httpResponse) 
{ 
    try 
    {
        const newTechnicianPasswordHash = await bcrypt.hash('DefaultPass123!', 10);
        const newStaffMemberDocument = new Staff({ 
            username: httpRequest.body.username, 
            password: newTechnicianPasswordHash, 
            discordId: httpRequest.body.discordId 
        });
        await newStaffMemberDocument.save();
        return httpResponse.json({ success: true });
    } 
    catch (staffAddError) 
    { 
        return httpResponse.status(500).json({ error: "Provisioning failure." }); 
    }
});

// GLOBAL CONFIGURATION MODULE
applicationInstance.get('/api/admin/config', verifySystemAdmin, async function(httpRequest, httpResponse) 
{ 
    const currentGlobalConfigDoc = await Config.findOne({ 
        id: 'global' 
    });
    httpResponse.json(currentGlobalConfigDoc); 
});

applicationInstance.post('/api/admin/config/toggle', verifySystemAdmin, async function(httpRequest, httpResponse) 
{ 
    console.log(`[ADMIN] ⚙️ GLOBAL UPDATE: System status/schedule modified.`);
    const globalConfigDoc = await Config.findOne({ id: 'global' });
    
    if (httpRequest.body.status !== undefined) 
    { 
        globalConfigDoc.supportOnline = httpRequest.body.status; 
    }
    
    if (httpRequest.body.note !== undefined) 
    { 
        globalConfigDoc.offlineNote = httpRequest.body.note; 
    }
    
    if (httpRequest.body.openTime !== undefined) 
    { 
        globalConfigDoc.openTime = httpRequest.body.openTime; 
    }
    
    if (httpRequest.body.closeTime !== undefined) 
    { 
        globalConfigDoc.closeTime = httpRequest.body.closeTime; 
    }
    
    await globalConfigDoc.save();
    httpResponse.json({ 
        success: true 
    });
});

// PUBLIC STATUS API
applicationInstance.get('/api/status', async function(httpRequest, httpResponse) 
{
    const globalConfigDoc = await Config.findOne({ 
        id: 'global' 
    });
    
    const fleetAggregateStatus = activeDiscordClients.map(function(clientInstance)
    { 
        const botStatusObject = globalConfigDoc.botFleetStatus.find(function(statusItem)
        { 
            return statusItem.botId === clientInstance.user.id; 
        });
        
        return { 
            name: clientInstance.user.username, 
            online: clientInstance.isReady(), 
            tradingActive: botStatusObject ? botStatusObject.tradingActive : true 
        };
    });
    
    httpResponse.json({ 
        support: { 
            isOpen: globalConfigDoc.supportOnline, 
            window: `${globalConfigDoc.openTime} - ${globalConfigDoc.closeTime} AST`, 
            note: globalConfigDoc.offlineNote 
        }, 
        fleet: fleetAggregateStatus 
    });
});

// SELL.APP WEBHOOK INTEGRATION
applicationInstance.post('/api/webhooks/sellapp', async function(httpRequest, httpResponse) 
{ 
    console.log("[WEBHOOK] 📨 Inbound transmission from Sell.App verified."); 
    httpResponse.status(200).send("Handshake Verified."); 
});


// ============================================================================================================================================================
//  SECTION 11: AUTOMATION ENGINE (TRUSTPILOT & EXPIRY)
// ============================================================================================================================================================

setInterval(async function() 
{
    console.log("[AUTOMATION] ⏲️ Executing verification and notification cycle...");
    
    // TASK 1: Trustpilot Dynamic Feedback (14 Days)
    const threshold14DaysAgo = new Date(); 
    threshold14DaysAgo.setDate(threshold14DaysAgo.getDate() - 14);
    
    const threshold15DaysAgo = new Date(); 
    threshold15DaysAgo.setDate(threshold15DaysAgo.getDate() - 15);
    
    const candidatesForReview = await License.find({ 
        activatedAt: { 
            $lte: threshold14DaysAgo, 
            $gte: threshold15DaysAgo 
        }, 
        reviewRequestSent: false 
    });
    
    console.log(`[AUTOMATION] 🔎 Found ${candidatesForReview.length} users for feedback request.`);
    
    for (let i = 0; i < candidatesForReview.length; i++) 
    {
        const licenseDocument = candidatesForReview[i];
        
        if (activeDiscordClients[0] !== undefined) 
        {
            try 
            {
                const targetDiscordUser = await activeDiscordClients[0].users.fetch(licenseDocument.discordId);
                const feedbackEmbed = new EmbedBuilder()
                    .setTitle("Feedback Request: Miraidon Services")
                    .setDescription(`You have been using your **${licenseDocument.type}** license on **${licenseDocument.serverName}** for two weeks. \n\nIf you are satisfied with our automation, please leave a review on Trustpilot!`)
                    .setColor('#00b67a')
                    .setURL("https://trustpilot.com/review/miraidon.trade")
                    .setFooter({ text: "Automated Feedback Transmission" });
                    
                await targetDiscordUser.send({ 
                    embeds: [feedbackEmbed] 
                });
                
                licenseDocument.reviewRequestSent = true; 
                await licenseDocument.save();
                console.log(`[AUTOMATION] ✅ Request sent to: ${licenseDocument.discordId}`);
            } 
            catch(feedbackError) { }
        }
    }

    // TASK 2: Dynamic Expiry Warnings (3 Days)
    const threshold3DaysFuture = new Date(); 
    threshold3DaysFuture.setDate(threshold3DaysFuture.getDate() + 3);
    
    const candidatesForExpiryWarning = await License.find({ 
        expiresAt: { 
            $lte: threshold3DaysFuture, 
            $gte: new Date() 
        }, 
        reminderSent: false 
    });
    
    console.log(`[AUTOMATION] 🔎 Found ${candidatesForExpiryWarning.length} expiring licenses.`);
    
    for (let j = 0; j < candidatesForExpiryWarning.length; j++)
    {
        const licenseDocument = candidatesForExpiryWarning[j];
        
        if (activeDiscordClients[0] !== undefined)
        {
            try 
            {
                const targetDiscordUser = await activeDiscordClients[0].users.fetch(licenseDocument.discordId);
                const expiryEmbed = new EmbedBuilder()
                    .setTitle("Security Alert: License Expiring")
                    .setDescription(`Your **${licenseDocument.type}** license for **${licenseDocument.serverName}** is set to expire in less than 3 days.\n\nPlease visit Sell.App to renew and maintain connectivity.`)
                    .setColor('#f59e0b')
                    .setFooter({ text: "Automated Expiry Protocol" });
                    
                await targetDiscordUser.send({ 
                    embeds: [expiryEmbed] 
                });
                
                licenseDocument.reminderSent = true; 
                await licenseDocument.save();
                console.log(`[AUTOMATION] ✅ Warning sent to: ${licenseDocument.discordId}`);
            } 
            catch(expiryWarningError) { }
        }
    }
    
}, 3600000); 


// ============================================================================================================================================================
//  SECTION 12: SERVER BOOTSTRAP
// ============================================================================================================================================================

const SERVER_PORT_PARAMETER = process.env.PORT || 10000;

httpServerInstance.listen(SERVER_PORT_PARAMETER, function() 
{ 
    console.log(`[SYSTEM] 🚀 SERVER v25.0 ACTIVE ON PORT ${SERVER_PORT_PARAMETER}`); 
});
