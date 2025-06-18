const express = require('express')
const { v4: uuidv4 } = require('uuid')
const http = require('http')
const https = require('https')
const WebSocket = require('ws')
const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const { MongoClient } = require('mongodb')
require('dotenv').config()

const app = express()

// Create server based on environment
let server;
if (process.env.NODE_ENV === 'production') {
    // In production (e.g. Render), the SSL/TLS is handled by the platform
    server = http.createServer(app)
} else {
    // For local development, use regular HTTP
    server = http.createServer(app)
}

const wss = new WebSocket.Server({ 
    server,
    // Handle both upgrade events for ws and wss
    handleProtocols: (protocols, req) => {
        return protocols[0]
    }
})

// Initialize chats and users from file if they exist
let chats = new Map()
let users = new Map()
let userKeys = new Map() // Store user public keys in memory for fast access

// Use Render's persistent storage in production, local storage in development
const DATA_DIR = process.env.NODE_ENV === 'production' 
    ? '/opt/render/project/src/data'
    : path.join(__dirname, 'data')

// Create data directory if it doesn't exist
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true })
}

const CHATS_FILE = path.join(DATA_DIR, 'chats.json')
const USERS_FILE = path.join(DATA_DIR, 'users.json')

// MongoDB setup
const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/chatapp';
const client = new MongoClient(mongoUri);
let db;

// Connect to MongoDB
async function connectDB() {
    try {
        await client.connect();
        db = client.db();
        console.log('Connected to MongoDB');
        
        // Create indexes for better query performance
        await db.collection('chats').createIndex({ createdAt: 1 });
        await db.collection('chats').createIndex({ name: 'text' });
    } catch (error) {
        console.error('MongoDB connection error:', error);
        process.exit(1);
    }
}

function loadData() {
    try {
        if (fs.existsSync(CHATS_FILE)) {
            const data = JSON.parse(fs.readFileSync(CHATS_FILE, 'utf8'))
            chats = new Map(Object.entries(data))
            console.log(`Successfully loaded ${chats.size} chats from file`)
        } else {
            console.log('No existing chats file found, starting with empty chat list')
        }

        if (fs.existsSync(USERS_FILE)) {
            const data = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'))
            users = new Map(Object.entries(data))
            // Load public keys from user data into memory
            for (const [userId, userData] of users.entries()) {
                if (userData.publicKey) {
                    userKeys.set(userId, userData.publicKey)
                }
            }
            console.log(`Successfully loaded ${users.size} users from file`)
        } else {
            console.log('No existing users file found, starting with empty user list')
        }
    } catch (error) {
        console.error('Error loading data:', error)
        chats = new Map()
        users = new Map()
        userKeys = new Map()
    }
}

// Save data to files
function saveData() {
    try {
        const chatsData = Object.fromEntries(chats)
        fs.writeFileSync(CHATS_FILE, JSON.stringify(chatsData, null, 2))
        console.log(`Successfully saved ${chats.size} chats to file`)

        const usersData = Object.fromEntries(users)
        fs.writeFileSync(USERS_FILE, JSON.stringify(usersData, null, 2))
        console.log(`Successfully saved ${users.size} users to file`)
    } catch (error) {
        console.error('Error saving data:', error)
        // Try to create backups
        try {
            const timestamp = Date.now()
            if (fs.existsSync(CHATS_FILE)) {
                fs.copyFileSync(CHATS_FILE, `${CHATS_FILE}.backup-${timestamp}`)
            }
            if (fs.existsSync(USERS_FILE)) {
                fs.copyFileSync(USERS_FILE, `${USERS_FILE}.backup-${timestamp}`)
            }
            console.log('Created backups of data files')
        } catch (backupError) {
            console.error('Failed to create backups:', backupError)
        }
    }
}

// Load data when server starts
loadData()

app.use(express.static('public'))
app.use(express.json())

// Get all chats
app.get('/chats', (req, res) => {
    const chatList = Array.from(chats.entries()).map(([id, chat]) => ({
        id,
        name: chat.name,
        createdAt: chat.createdAt,
        messageCount: chat.messages.length
    }))
    res.json(chatList)
})

// Search chats
app.get('/search-chats', (req, res) => {
    const query = req.query.q?.toLowerCase() || '';
    
    if (!query) {
        return res.json([]);
    }

    const searchResults = Array.from(chats.entries())
        .map(([id, chat]) => {
            // Search in chat name
            const nameMatch = chat.name.toLowerCase().includes(query);
            
            // Search in messages
            const messageMatches = chat.messages.some(msg => 
                msg.content?.toLowerCase().includes(query)
            );

            // If either name or messages match, return the chat
            if (nameMatch || messageMatches) {
                return {
                    id,
                    name: chat.name,
                    createdAt: chat.createdAt,
                    messageCount: chat.messages.length,
                    // Include preview of matching messages
                    preview: messageMatches ? 
                        chat.messages
                            .filter(msg => msg.content?.toLowerCase().includes(query))
                            .map(msg => ({
                                content: msg.content,
                                sender: msg.sender,
                                timestamp: msg.timestamp
                            }))
                            .slice(0, 3) // Only show up to 3 matching messages
                        : []
                };
            }
            return null;
        })
        .filter(result => result !== null);

    res.json(searchResults);
});

// Delete a chat
app.delete('/api/chats/:chatId', async (req, res) => {
    try {
        const chatId = req.params.chatId;
        console.log('Attempting to delete chat:', chatId);
        
        // Delete from MongoDB
        const result = await db.collection('chats').deleteOne({ id: chatId });
        
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Chat not found' });
        }
        
        console.log('Chat deleted successfully from MongoDB');
        res.status(200).json({ message: 'Chat deleted successfully' });
    } catch (error) {
        console.error('Error deleting chat:', error);
        res.status(500).json({ error: 'Failed to delete chat' });
    }
});

// Function to get recent chats (within last 24 hours)
function getRecentChats() {
    const twentyFourHoursAgo = Date.now() - (24 * 60 * 60 * 1000);
    const recentChats = [];
    
    for (const [id, chat] of chats.entries()) {
        if (chat.createdAt && chat.createdAt > twentyFourHoursAgo) {
            recentChats.push({
                id,
                name: chat.name,
                createdAt: chat.createdAt,
                // Calculate how long ago the chat was created
                timeAgo: getTimeAgo(chat.createdAt)
                });
            }
        }

    // Sort by newest first
    return recentChats.sort((a, b) => b.createdAt - a.createdAt);
}

// Helper function to format time ago
function getTimeAgo(timestamp) {
    const seconds = Math.floor((Date.now() - timestamp) / 1000);
    
    if (seconds < 60) return 'just now';
    
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes} minute${minutes !== 1 ? 's' : ''} ago`;
    
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours} hour${hours !== 1 ? 's' : ''} ago`;
    
    return 'yesterday';
}

// Function to generate a unique ID
function generateUniqueId() {
    return crypto.randomBytes(16).toString('hex');
}

// Function to save chat metadata
function saveChatMetadata(chatId, chatData) {
    const chatDir = path.join(DATA_DIR, chatId);
    if (!fs.existsSync(chatDir)) {
        fs.mkdirSync(chatDir);
    }
    fs.writeFileSync(
        path.join(chatDir, 'metadata.json'),
        JSON.stringify(chatData, null, 2)
    );
}

// Function to load chat metadata
function loadChatMetadata(chatId) {
    const metadataPath = path.join(DATA_DIR, chatId, 'metadata.json');
    if (fs.existsSync(metadataPath)) {
        try {
            return JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
        } catch (error) {
            console.error(`Error loading chat ${chatId}:`, error);
            return null;
        }
    }
    return null;
}

// Load existing chats on startup
function loadExistingChats() {
    console.log('Loading existing chats...');
    const chatDirs = fs.readdirSync(DATA_DIR);
    
    for (const chatId of chatDirs) {
        const metadata = loadChatMetadata(chatId);
        if (metadata) {
            chats.set(chatId, metadata);
            console.log(`Loaded chat: ${metadata.name} (created ${new Date(metadata.createdAt).toLocaleString()})`);
        }
    }
    console.log(`Loaded ${chats.size} chats`);
}

// Create chat endpoint
app.post('/create-chat', async (req, res) => {
    const chatName = req.body.name;
    if (!chatName) {
        return res.status(400).json({ error: 'Chat name is required' });
    }

    const chatId = generateUniqueId();
    const chat = {
            id: chatId,
        name: chatName,
            messages: [],
        createdAt: Date.now()
    };
    
    try {
        await db.collection('chats').insertOne(chat);
        console.log(`Created new chat: ${chatName} (${chatId}) at ${new Date(chat.createdAt).toLocaleString()}`);
        res.json({ id: chatId, name: chatName });
    } catch (error) {
        console.error('Error creating chat:', error);
        res.status(500).json({ error: 'Failed to create chat' });
    }
});

// Get recent chats endpoint
app.get('/api/recent-chats', async (req, res) => {
    try {
        const twentyFourHoursAgo = Date.now() - (24 * 60 * 60 * 1000);
        
        const recentChats = await db.collection('chats')
            .find({ createdAt: { $gt: twentyFourHoursAgo } })
            .sort({ createdAt: -1 })
            .toArray();

        const formattedChats = recentChats.map(chat => ({
            id: chat.id,
            name: chat.name,
            createdAt: chat.createdAt,
            timeAgo: getTimeAgo(chat.createdAt)
        }));

        console.log(`Found ${formattedChats.length} recent chats (within last 24 hours)`);
        console.log('Recent chats:', formattedChats.map(chat => `${chat.name} (${chat.timeAgo})`));
        res.json(formattedChats);
    } catch (error) {
        console.error('Error getting recent chats:', error);
        res.status(500).json({ error: 'Failed to get recent chats' });
    }
});

// Search chats endpoint
app.get('/api/search-chats', async (req, res) => {
    try {
        const query = req.query.q?.toLowerCase() || '';
        if (!query) {
            return res.json([]);
        }

        const results = await db.collection('chats')
            .find({ name: { $regex: query, $options: 'i' } })
            .sort({ createdAt: -1 })
            .toArray();

        const formattedResults = results.map(chat => ({
            id: chat.id,
            name: chat.name,
            createdAt: chat.createdAt
        }));

        res.json(formattedResults);
    } catch (error) {
        console.error('Error searching chats:', error);
        res.status(500).json({ error: 'Failed to search chats' });
    }
});

// Load chats on startup
loadExistingChats();

// Add new endpoints for user management
app.post('/register-user', (req, res) => {
    const { name } = req.body
    if (!name) {
        return res.status(400).json({ error: 'Name is required' })
    }

    const userId = uuidv4()
    users.set(userId, { name, createdAt: Date.now() })
    saveData()
    
    res.json({ userId, name })
})

app.get('/user/:userId', (req, res) => {
    const { userId } = req.params
    const user = users.get(userId)
    
    if (!user) {
        return res.status(404).json({ error: 'User not found' })
    }
    
    res.json({ userId, name: user.name })
})

// WebSocket connection handling
wss.on('connection', async (ws) => {
    console.log('New WebSocket connection');
    let chatID;
    let userId;

    ws.on('message', async (message) => {
        try {
            const data = JSON.parse(message);
            console.log('Received WebSocket message:', data.type);

            if (data.type === 'join') {
                chatID = data.chatID;
                userId = data.userId;
                ws.chatID = chatID;
                ws.userId = userId;

                console.log(`User ${userId} joining chat ${chatID}`);

                // Load chat history from MongoDB
                const chat = await db.collection('chats').findOne({ id: chatID });
                if (chat) {
                    console.log(`Sending chat history for ${chat.name} (${chat.messages?.length || 0} messages)`);
                    ws.send(JSON.stringify({
                        type: 'history',
                        messages: chat.messages || [],
                        chatName: chat.name
                    }));
                }
            } else if (data.type === 'message') {
                // Add message to MongoDB
                const message = {
                    id: data.id || generateUniqueId(),
                    sender: data.sender,
                    content: data.content,
                    timestamp: Date.now(),
                    encrypted: data.encrypted,
                    userId: userId
                };

                await db.collection('chats').updateOne(
                    { id: chatID },
                    { 
                        $push: { 
                            messages: message
                        }
                    }
                );
                
                // Broadcast to all clients
                wss.clients.forEach((client) => {
                    if (client.readyState === WebSocket.OPEN && client.chatID === chatID) {
                        client.send(JSON.stringify({
                            type: 'message',
                            message
                        }));
                    }
                });
            } else if (data.type === 'delete_message') {
                // Remove message from MongoDB
                await db.collection('chats').updateOne(
                    { id: chatID },
                    { 
                        $pull: { 
                            messages: { id: data.messageId }
                        }
                    }
                );
                
                // Broadcast deletion to all clients
                wss.clients.forEach((client) => {
                    if (client.readyState === WebSocket.OPEN && client.chatID === chatID) {
                        client.send(JSON.stringify({
                            type: 'message_deleted',
                            messageId: data.messageId
                        }));
                    }
                });
            }
        } catch (error) {
            console.error('Error handling WebSocket message:', error);
        }
    });

    ws.on('close', () => {
        console.log(`WebSocket connection closed for user ${userId} in chat ${chatID}`);
    });
});

// Get chat messages endpoint
app.get('/api/chats/:chatId', async (req, res) => {
    try {
        const chatId = req.params.chatId;
        const chat = await db.collection('chats').findOne({ id: chatId });
        
        if (!chat) {
            return res.status(404).json({ error: 'Chat not found' });
        }
        
        res.json({
            id: chat.id,
            name: chat.name,
            messages: chat.messages || [],
            createdAt: chat.createdAt
        });
    } catch (error) {
        console.error('Error getting chat:', error);
        res.status(500).json({ error: 'Failed to get chat' });
    }
});

// Get chat details endpoint
app.get('/api/chat/:chatId', async (req, res) => {
    try {
        const chatId = req.params.chatId;
        console.log('Fetching chat with ID:', chatId);
        
        const chat = await db.collection('chats').findOne({ id: chatId });
        console.log('Found chat:', chat ? `${chat.name} (${chat.id})` : 'null');
        
            if (!chat) {
            console.log('Chat not found in MongoDB');
            return res.status(404).json({ error: 'Chat not found' });
        }
        
        const response = {
            id: chat.id,
            name: chat.name,
            messages: chat.messages || [],
            createdAt: chat.createdAt
        };
        console.log('Sending chat data:', {
            id: response.id,
            name: response.name,
            messageCount: response.messages.length,
            createdAt: new Date(response.createdAt).toISOString()
        });
        
        res.json(response);
    } catch (error) {
        console.error('Error getting chat:', error);
        res.status(500).json({ error: 'Failed to get chat' });
    }
});

// Debug endpoint to list all chats in MongoDB
app.get('/api/debug/chats', async (req, res) => {
    try {
        const chats = await db.collection('chats').find({}).toArray();
        console.log('All chats in MongoDB:', chats.map(chat => ({
            id: chat.id,
            name: chat.name,
            messageCount: chat.messages ? chat.messages.length : 0
        })));
        res.json(chats);
    } catch (error) {
        console.error('Error listing chats:', error);
        res.status(500).json({ error: 'Failed to list chats' });
    }
});

// Get all chats with pagination
app.get('/api/all-chats', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        // Get total count of chats
        const totalChats = await db.collection('chats').countDocuments();
        
        // Get paginated chats
        const chats = await db.collection('chats')
            .find({})
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit)
            .toArray();

        res.json({
            chats: chats.map(chat => ({
                id: chat.id,
                name: chat.name,
                createdAt: chat.createdAt
            })),
            hasMore: skip + chats.length < totalChats
        });
    } catch (error) {
        console.error('Error getting all chats:', error);
        res.status(500).json({ error: 'Failed to get chats' });
    }
});

// Connect to MongoDB and start the server
const PORT = process.env.PORT || 3000;
connectDB().then(() => {
    server.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
});
