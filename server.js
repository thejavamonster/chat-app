const express = require('express')
const { v4: uuidv4 } = require('uuid')
const http = require('http')
const WebSocket = require('ws')
const fs = require('fs')
const path = require('path')

const app = express()
const server = http.createServer(app)
const wss = new WebSocket.Server({ server })

// Initialize chats from file if it exists
let chats = new Map()
const CHATS_FILE = path.join(__dirname, 'chats.json')

try {
    if (fs.existsSync(CHATS_FILE)) {
        const data = JSON.parse(fs.readFileSync(CHATS_FILE, 'utf8'))
        chats = new Map(Object.entries(data))
    }
} catch (error) {
    console.error('Error loading chats:', error)
}

// Save chats to file
function saveChats() {
    try {
        const data = Object.fromEntries(chats)
        fs.writeFileSync(CHATS_FILE, JSON.stringify(data, null, 2))
    } catch (error) {
        console.error('Error saving chats:', error)
    }
}

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
        saveChats();
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
    saveChats()
    res.json({ chatID, url: `/chat.html?chatID=${chatID}` })
})

wss.on('connection', (ws, req) => {
    let chatID

    ws.on('message', msg => {
        const data = JSON.parse(msg)
        if (data.type === 'join') {
            chatID = data.chatID
            ws.chatID = chatID
            const chat = chats.get(chatID)
            if (chat) {
                ws.send(JSON.stringify({ 
                    type: 'history', 
                    messages: chat.messages,
                    chatName: chat.name
                }))
            }
        } else if (data.type === 'message') {
            const chat = chats.get(chatID)
            if (!chat) {
                console.warn(`Chat ${chatID} not found. Ignoring message.`)
                return
            }

            const message = {
                id: uuidv4(),
                content: data.content,
                timestamp: Date.now(),
                sender: data.sender || 'Anonymous'
            }
            console.log('Created new message:', message);
            
            chat.messages.push(message)
            saveChats()
            
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN && client.chatID === chatID) {
                    client.send(JSON.stringify({ type: 'message', message }))
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
                saveChats()
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
