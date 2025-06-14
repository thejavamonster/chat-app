const express = require('express')
const { v4: uuidv4 } = require('uuid')
const http = require('http')
const https = require('https')
const WebSocket = require('ws')
const fs = require('fs')
const path = require('path')

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
const CHATS_FILE = path.join(__dirname, 'chats.json')
const USERS_FILE = path.join(__dirname, 'users.json')

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

// Delete a chat
app.delete('/delete-chat/:chatId', (req, res) => {
    const chatId = req.params.chatId;
    console.log('Attempting to delete chat:', chatId);
    
    if (chats.has(chatId)) {
        chats.delete(chatId);
        saveData();
        console.log('Chat deleted successfully');
        res.status(200).json({ message: 'Chat deleted successfully' });
    } else {
        console.log('Chat not found for deletion');
        res.status(404).json({ error: 'Chat not found' });
    }
})

app.post('/create-chat', (req, res) => {
    const chatID = uuidv4()
    const chatName = req.body.name || 'Unnamed Chat'
    chats.set(chatID, {
        name: chatName,
        createdAt: Date.now(),
        messages: []
    })
    saveData()
    res.json({ chatID, url: `/chat.html?chatID=${chatID}` })
})

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

wss.on('connection', (ws, req) => {
    let chatID
    let userId
    let userPublicKey

    console.log('New WebSocket connection established');

    ws.on('close', () => {
        console.log(`WebSocket connection closed for user ${userId} in chat ${chatID}`);
    });

    ws.on('error', (error) => {
        console.error(`WebSocket error for user ${userId} in chat ${chatID}:`, error);
    });

    ws.on('message', msg => {
        const data = JSON.parse(msg)
        if (data.type === 'join') {
            chatID = data.chatID
            userId = data.userId
            userPublicKey = data.publicKey
            ws.chatID = chatID
            ws.userId = userId
            
            console.log(`User ${userId} joining chat ${chatID}`);
            console.log(`Total active connections: ${wss.clients.size}`);
            
            // Store user's public key both in memory and with user data
            if (userPublicKey) {
                console.log(`Storing public key for user ${userId}: ${userPublicKey.substring(0, 20)}...`);
                userKeys.set(userId, userPublicKey)
                const user = users.get(userId)
                if (user) {
                    user.publicKey = userPublicKey
                    saveData() // Save to disk immediately
                }
            }
            
            const chat = chats.get(chatID)
            const user = users.get(userId)
            
            if (chat) {
                // Get active users in the chat (users with open WebSocket connections)
                const activeUsers = Array.from(wss.clients)
                    .filter(client => client.readyState === WebSocket.OPEN && 
                                    client.chatID === chatID && 
                                    client.userId !== userId)
                    .map(client => client.userId);

                console.log(`Active users in chat ${chatID}:`, activeUsers);
                console.log(`Total users in chat: ${activeUsers.length + 1}`);

                // Get public keys of active users
                const recipientPublicKey = activeUsers.length > 0 ? userKeys.get(activeUsers[0]) : null;
                console.log(`Recipient public key for user ${userId}: ${recipientPublicKey ? recipientPublicKey.substring(0, 20) + '...' : 'none'}`);

                ws.send(JSON.stringify({ 
                    type: 'history', 
                    messages: chat.messages,
                    chatName: chat.name,
                    userName: user ? user.name : 'Anonymous',
                    recipientPublicKey
                }))

                // Notify other users about the new user's public key
                if (userPublicKey) {
                    console.log(`Broadcasting public key for user ${userId} to other users in chat ${chatID}`);
                    let broadcastCount = 0;
                    wss.clients.forEach(client => {
                        if (client.readyState === WebSocket.OPEN && 
                            client.chatID === chatID && 
                            client.userId !== userId) {
                            client.send(JSON.stringify({
                                type: 'recipient_public_key',
                                publicKey: userPublicKey
                            }))
                            broadcastCount++;
                        }
                    })
                    console.log(`Broadcasted public key to ${broadcastCount} users`);
                }
            }
        } else if (data.type === 'message') {
            const chat = chats.get(chatID)
            if (!chat) {
                console.warn(`Chat ${chatID} not found. Ignoring message.`)
                return
            }

            // Get active users in the chat
            const activeUsers = Array.from(wss.clients)
                .filter(client => client.readyState === WebSocket.OPEN && 
                                client.chatID === chatID && 
                                client.userId !== userId)
                .map(client => client.userId);

            console.log(`Active users when sending message:`, activeUsers);

            // Get the recipient's public key
            const recipientPublicKey = activeUsers.length > 0 ? userKeys.get(activeUsers[0]) : null;

            // If we have a recipient but no public key, request it
            if (activeUsers.length > 0 && !recipientPublicKey) {
                console.log(`No public key found for recipient ${activeUsers[0]}, requesting it...`);
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN && 
                        client.chatID === chatID && 
                        client.userId === activeUsers[0]) {
                        client.send(JSON.stringify({
                            type: 'request_public_key'
                        }))
                    }
                })
            }

            const user = users.get(userId)
            const message = {
                id: data.id || uuidv4(),
                timestamp: Date.now(),
                sender: user ? user.name : 'Anonymous',
                userId: userId
            }

            // If message is encrypted and there are active recipients, store encrypted data
            if (data.encrypted && activeUsers.length > 0) {
                message.encrypted = data.encrypted
            } else {
                // Store plaintext if no encryption or no recipients
                message.content = data.content
            }

            console.log('Created new message:', message);
            
            chat.messages.push(message)
            saveData()
            
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN && client.chatID === chatID) {
                    client.send(JSON.stringify({ 
                        type: 'message', 
                        message,
                        encrypted: activeUsers.length > 0 ? data.encrypted : null // Only send encrypted data if there are recipients
                    }))
                }
            })
        } else if (data.type === 'delete_message') {
            console.log('Received delete request:', data);
            const chat = chats.get(chatID)
            if (!chat) {
                console.warn(`Chat ${chatID} not found. Ignoring delete request.`)
                return
            }

            // Find and remove the message
            const messageIndex = chat.messages.findIndex(m => m.id === data.messageId)
            console.log('Message index to delete:', messageIndex);
            if (messageIndex !== -1) {
                chat.messages.splice(messageIndex, 1)
                saveData()
                console.log('Message deleted and saved');
                
                // Notify all clients about the deletion
                wss.clients.forEach(client => {
                    if (client.readyState === WebSocket.OPEN && client.chatID === chatID) {
                        console.log('Notifying client about deletion');
                        client.send(JSON.stringify({ 
                            type: 'message_deleted', 
                            messageId: data.messageId 
                        }))
                    }
                })
            } else {
                console.warn('Message not found for deletion:', data.messageId);
            }
        }
    })
})

server.listen(3000)
