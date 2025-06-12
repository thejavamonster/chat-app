const express = require('express')
const { v4: uuidv4 } = require('uuid')
const http = require('http')
const WebSocket = require('ws')

const app = express()
const server = http.createServer(app)
const wss = new WebSocket.Server({ server })

const chats = new Map()

app.use(express.static('public'))
app.use(express.json())

app.post('/create-chat', (req, res) => {
  const chatID = uuidv4()
  chats.set(chatID, [])
  res.json({ chatID, url: `/chat.html?chatID=${chatID}` })
})

wss.on('connection', (ws, req) => {
  let chatID

  ws.on('message', msg => {
    const data = JSON.parse(msg)
    if (data.type === 'join') {
      chatID = data.chatID
      ws.chatID = chatID
      ws.send(JSON.stringify({ type: 'history', messages: chats.get(chatID) || [] }))
     } else if (data.type === 'message') {
        const message = {
            content: data.content,
            timestamp: Date.now(),
            sender: data.sender || 'Anonymous'
        }
        if (!chats.has(chatID)) {
          console.warn(`Chat ${chatID} not found. Ignoring message.`);
          return;
        }
        chats.get(chatID).push(message);
        
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN && client.chatID === chatID) {
            client.send(JSON.stringify({ type: 'message', message }))
            }
        })
        }
  })
})

server.listen(3000)
