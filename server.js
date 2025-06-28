const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;
const mongoUri = process.env.MONGODB_URI;

if (!mongoUri) {
    console.error('MONGODB_URI environment variable is not set');
    process.exit(1);
}

let db;

// Connect to MongoDB
async function connectToMongoDB() {
    try {
        const client = new MongoClient(mongoUri);
        await client.connect();
        db = client.db();
        console.log('Connected to MongoDB successfully');
    } catch (error) {
        console.error('Failed to connect to MongoDB:', error);
        process.exit(1);
    }
}

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed'), false);
        }
    }
});

// Utility functions
function generateId() {
    return Math.random().toString(36).substr(2, 9);
}

function generateSecretCode() {
    const words = ['apple', 'banana', 'cherry', 'dragon', 'eagle', 'forest', 'galaxy', 'harbor', 'island', 'jungle'];
    return words[Math.floor(Math.random() * words.length)] + Math.floor(Math.random() * 1000);
}

// Socket.IO connection handling
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    socket.on('join-chat', (chatId) => {
        socket.join(chatId);
        console.log(`User ${socket.id} joined chat ${chatId}`);
    });

    socket.on('leave-chat', (chatId) => {
        socket.leave(chatId);
        console.log(`User ${socket.id} left chat ${chatId}`);
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});

// Routes

// Home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Register user
app.post('/register-user', async (req, res) => {
    try {
        const { displayName, userId, profilePic } = req.body;

        if (!displayName || displayName.trim().length < 2) {
            return res.status(400).json({ error: 'Display name must be at least 2 characters' });
        }

        const trimmedName = displayName.trim();
        if (trimmedName.length > 32) {
            return res.status(400).json({ error: 'Display name must be 32 characters or less' });
        }

        const reservedNames = ['admin', 'moderator', 'support', 'administrator', 'mod', 'help', 'system'];
        if (reservedNames.includes(trimmedName.toLowerCase())) {
            return res.status(400).json({ error: 'This display name is reserved' });
        }

        const usersCollection = db.collection('users');
        const finalUserId = userId || generateId();
        const secretCode = generateSecretCode();

        const userData = {
            userId: finalUserId,
            displayName: trimmedName,
            secretCode: secretCode,
            profilePic: profilePic || null,
            createdAt: new Date(),
            starredChats: []
        };

        // Check if user already exists
        const existingUser = await usersCollection.findOne({ userId: finalUserId });
        if (existingUser) {
            // Update existing user
            await usersCollection.updateOne(
                { userId: finalUserId },
                { $set: { displayName: trimmedName, profilePic: profilePic || existingUser.profilePic } }
            );
        } else {
            // Create new user
            await usersCollection.insertOne(userData);
        }

        res.json({
            userId: finalUserId,
            displayName: trimmedName,
            secretCode: secretCode,
            profilePic: profilePic
        });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// Find user (for sign-in)
app.get('/api/find-user', async (req, res) => {
    try {
        const { displayName, code } = req.query;
        
        if (!displayName || !code) {
            return res.status(400).json({ error: 'Display name and code are required' });
        }

        const usersCollection = db.collection('users');
        const user = await usersCollection.findOne({
            displayName: displayName,
            secretCode: code
        });

        if (!user) {
            return res.status(404).json({ error: 'User not found or incorrect code' });
        }

        res.json({
            userId: user.userId,
            name: user.displayName,
            profilePic: user.profilePic
        });
    } catch (error) {
        console.error('Error finding user:', error);
        res.status(500).json({ error: 'Failed to find user' });
    }
});

// Upload profile picture
app.post('/upload-profile-pic', upload.single('profilePic'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Convert to base64 data URL
        const base64 = req.file.buffer.toString('base64');
        const dataUrl = `data:${req.file.mimetype};base64,${base64}`;

        res.json({ url: dataUrl });
    } catch (error) {
        console.error('Error uploading profile picture:', error);
        res.status(500).json({ error: 'Failed to upload profile picture' });
    }
});

// Create chat
app.post('/create-chat', async (req, res) => {
    try {
        const { name, isPrivate = false, members = [] } = req.body;

        if (!name || name.trim().length === 0) {
            return res.status(400).json({ error: 'Chat name is required' });
        }

        const chatId = generateId();
        const chatData = {
            id: chatId,
            name: name.trim(),
            isPrivate: isPrivate,
            members: members,
            createdAt: new Date(),
            messages: []
        };

        const chatsCollection = db.collection('chats');
        await chatsCollection.insertOne(chatData);

        res.json({ id: chatId, name: chatData.name });
    } catch (error) {
        console.error('Error creating chat:', error);
        res.status(500).json({ error: 'Failed to create chat' });
    }
});

// Get recent chats
app.get('/api/recent-chats', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 10;
        const chatsCollection = db.collection('chats');
        
        const chats = await chatsCollection
            .find({})
            .sort({ createdAt: -1 })
            .limit(limit)
            .toArray();

        res.json(chats);
    } catch (error) {
        console.error('Error fetching recent chats:', error);
        res.status(500).json({ error: 'Failed to fetch recent chats' });
    }
});

// Get all chats with pagination
app.get('/api/all-chats', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 12;
        const skip = (page - 1) * limit;

        const chatsCollection = db.collection('chats');
        
        const chats = await chatsCollection
            .find({})
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit + 1) // Get one extra to check if there are more
            .toArray();

        const hasMore = chats.length > limit;
        if (hasMore) {
            chats.pop(); // Remove the extra chat
        }

        res.json({ chats, hasMore });
    } catch (error) {
        console.error('Error fetching all chats:', error);
        res.status(500).json({ error: 'Failed to fetch chats' });
    }
});

// Search chats
app.get('/api/search-chats', async (req, res) => {
    try {
        const query = req.query.q;
        if (!query) {
            return res.status(400).json({ error: 'Search query is required' });
        }

        const chatsCollection = db.collection('chats');
        const chats = await chatsCollection
            .find({ name: { $regex: query, $options: 'i' } })
            .sort({ createdAt: -1 })
            .toArray();

        res.json(chats);
    } catch (error) {
        console.error('Error searching chats:', error);
        res.status(500).json({ error: 'Failed to search chats' });
    }
});

// Get chat info
app.get('/api/chat/:chatId', async (req, res) => {
    try {
        const { chatId } = req.params;
        const chatsCollection = db.collection('chats');
        
        const chat = await chatsCollection.findOne({ id: chatId });
        if (!chat) {
            return res.status(404).json({ error: 'Chat not found' });
        }

        res.json(chat);
    } catch (error) {
        console.error('Error fetching chat:', error);
        res.status(500).json({ error: 'Failed to fetch chat' });
    }
});

// Get chat messages
app.get('/api/chat/:chatId/messages', async (req, res) => {
    try {
        const { chatId } = req.params;
        const chatsCollection = db.collection('chats');
        
        const chat = await chatsCollection.findOne({ id: chatId });
        if (!chat) {
            return res.status(404).json({ error: 'Chat not found' });
        }

        res.json(chat.messages || []);
    } catch (error) {
        console.error('Error fetching messages:', error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

// Send message
app.post('/api/chat/:chatId/messages', async (req, res) => {
    try {
        const { chatId } = req.params;
        const { content, userId, userName, encrypted = false } = req.body;

        if (!content || !userId || !userName) {
            return res.status(400).json({ error: 'Content, userId, and userName are required' });
        }

        const messageId = generateId();
        const message = {
            id: messageId,
            content: content,
            userId: userId,
            userName: userName,
            timestamp: Date.now(),
            encrypted: encrypted,
            reactions: {}
        };

        const chatsCollection = db.collection('chats');
        const result = await chatsCollection.updateOne(
            { id: chatId },
            { $push: { messages: message } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Chat not found' });
        }

        // Emit to all users in the chat
        io.to(chatId).emit('new-message', message);

        res.json(message);
    } catch (error) {
        console.error('Error sending message:', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});

// Update message
app.put('/api/chat/:chatId/messages/:messageId', async (req, res) => {
    try {
        const { chatId, messageId } = req.params;
        const { content, userId } = req.body;

        if (!content || !userId) {
            return res.status(400).json({ error: 'Content and userId are required' });
        }

        const chatsCollection = db.collection('chats');
        const result = await chatsCollection.updateOne(
            { id: chatId, 'messages.id': messageId, 'messages.userId': userId },
            { $set: { 'messages.$.content': content, 'messages.$.edited': true } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Message not found or unauthorized' });
        }

        // Get updated message
        const chat = await chatsCollection.findOne({ id: chatId });
        const updatedMessage = chat.messages.find(m => m.id === messageId);

        // Emit to all users in the chat
        io.to(chatId).emit('message-updated', updatedMessage);

        res.json(updatedMessage);
    } catch (error) {
        console.error('Error updating message:', error);
        res.status(500).json({ error: 'Failed to update message' });
    }
});

// Delete message
app.delete('/api/chat/:chatId/messages/:messageId', async (req, res) => {
    try {
        const { chatId, messageId } = req.params;
        const { userId } = req.body;

        if (!userId) {
            return res.status(400).json({ error: 'userId is required' });
        }

        const chatsCollection = db.collection('chats');
        const result = await chatsCollection.updateOne(
            { id: chatId },
            { $pull: { messages: { id: messageId, userId: userId } } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Chat not found' });
        }

        // Emit to all users in the chat
        io.to(chatId).emit('message-deleted', messageId);

        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// Add reaction to message
app.post('/api/chat/:chatId/messages/:messageId/reactions', async (req, res) => {
    try {
        const { chatId, messageId } = req.params;
        const { reaction, userId } = req.body;

        if (!reaction || !userId) {
            return res.status(400).json({ error: 'Reaction and userId are required' });
        }

        const chatsCollection = db.collection('chats');
        
        // Add user to reaction
        const result = await chatsCollection.updateOne(
            { id: chatId, 'messages.id': messageId },
            { $addToSet: { [`messages.$.reactions.${reaction}`]: userId } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Chat or message not found' });
        }

        // Emit to all users in the chat
        io.to(chatId).emit('reaction-added', { messageId, reaction, userId });

        res.json({ success: true });
    } catch (error) {
        console.error('Error adding reaction:', error);
        res.status(500).json({ error: 'Failed to add reaction' });
    }
});

// Delete chat
app.delete('/api/chats/:chatId', async (req, res) => {
    try {
        const { chatId } = req.params;
        const chatsCollection = db.collection('chats');
        
        const result = await chatsCollection.deleteOne({ id: chatId });
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Chat not found' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting chat:', error);
        res.status(500).json({ error: 'Failed to delete chat' });
    }
});

// Star/unstar chat
app.post('/api/user/:userId/star', async (req, res) => {
    try {
        const { userId } = req.params;
        const { chatId } = req.body;

        if (!chatId) {
            return res.status(400).json({ error: 'chatId is required' });
        }

        const usersCollection = db.collection('users');
        const result = await usersCollection.updateOne(
            { userId: userId },
            { $addToSet: { starredChats: chatId } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error starring chat:', error);
        res.status(500).json({ error: 'Failed to star chat' });
    }
});

app.post('/api/user/:userId/unstar', async (req, res) => {
    try {
        const { userId } = req.params;
        const { chatId } = req.body;

        if (!chatId) {
            return res.status(400).json({ error: 'chatId is required' });
        }

        const usersCollection = db.collection('users');
        const result = await usersCollection.updateOne(
            { userId: userId },
            { $pull: { starredChats: chatId } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error unstarring chat:', error);
        res.status(500).json({ error: 'Failed to unstar chat' });
    }
});

// Get starred chats
app.get('/api/user/:userId/starred-chats', async (req, res) => {
    try {
        const { userId } = req.params;
        const usersCollection = db.collection('users');
        const chatsCollection = db.collection('chats');

        const user = await usersCollection.findOne({ userId: userId });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const starredChatIds = user.starredChats || [];
        if (starredChatIds.length === 0) {
            return res.json([]);
        }

        const chats = await chatsCollection
            .find({ id: { $in: starredChatIds } })
            .sort({ createdAt: -1 })
            .toArray();

        res.json(chats);
    } catch (error) {
        console.error('Error fetching starred chats:', error);
        res.status(500).json({ error: 'Failed to fetch starred chats' });
    }
});

// Find or create private chat
app.get('/api/private-chat', async (req, res) => {
    try {
        const { user1, user2 } = req.query;
        
        if (!user1 || !user2) {
            return res.status(400).json({ error: 'Both user1 and user2 are required' });
        }

        const chatsCollection = db.collection('chats');
        
        // Look for existing private chat between these users
        const existingChat = await chatsCollection.findOne({
            isPrivate: true,
            $or: [
                { members: [user1, user2] },
                { members: [user2, user1] }
            ]
        });

        if (existingChat) {
            return res.json({ chatId: existingChat.id });
        }

        res.status(404).json({ error: 'Private chat not found' });
    } catch (error) {
        console.error('Error finding private chat:', error);
        res.status(500).json({ error: 'Failed to find private chat' });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// Start server
async function startServer() {
    try {
        await connectToMongoDB();
        server.listen(PORT, () => {
            console.log(`Server running on port ${PORT}`);
            console.log(`Socket.IO server ready`);
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

startServer();