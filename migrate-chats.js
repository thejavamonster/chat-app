require('dotenv').config();
const { MongoClient } = require('mongodb');
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, 'data');
const mongoUri = process.env.MONGODB_URI;

async function migrateChats() {
    const client = new MongoClient(mongoUri);
    
    try {
        await client.connect();
        console.log('Connected to MongoDB');
        
        const db = client.db();
        const chatsCollection = db.collection('chats');
        
        // Read all chat files
        const files = fs.readdirSync(DATA_DIR);
        const chatFiles = files.filter(f => f.endsWith('.json') && f !== 'users.json' && f !== 'chats.json');
        
        console.log(`Found ${chatFiles.length} chat files to migrate`);
        
        for (const file of chatFiles) {
            try {
                const chatData = JSON.parse(fs.readFileSync(path.join(DATA_DIR, file), 'utf8'));
                if (!chatData.id) {
                    chatData.id = file.replace('.json', '');
                }
                if (!chatData.createdAt) {
                    chatData.createdAt = Date.now();
                }
                
                // Check if chat already exists in MongoDB
                const existingChat = await chatsCollection.findOne({ id: chatData.id });
                if (!existingChat) {
                    await chatsCollection.insertOne(chatData);
                    console.log(`Migrated chat: ${chatData.name} (${chatData.id})`);
                } else {
                    console.log(`Chat already exists in MongoDB: ${chatData.name} (${chatData.id})`);
                }
            } catch (error) {
                console.error(`Error migrating chat file ${file}:`, error);
            }
        }
        
        // Also check the chats.json file if it exists
        if (fs.existsSync(path.join(DATA_DIR, 'chats.json'))) {
            try {
                const chatsData = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'chats.json'), 'utf8'));
                for (const [chatId, chatData] of Object.entries(chatsData)) {
                    if (!chatData.id) {
                        chatData.id = chatId;
                    }
                    if (!chatData.createdAt) {
                        chatData.createdAt = Date.now();
                    }
                    
                    // Check if chat already exists in MongoDB
                    const existingChat = await chatsCollection.findOne({ id: chatData.id });
                    if (!existingChat) {
                        await chatsCollection.insertOne(chatData);
                        console.log(`Migrated chat from chats.json: ${chatData.name} (${chatData.id})`);
                    } else {
                        console.log(`Chat already exists in MongoDB: ${chatData.name} (${chatData.id})`);
                    }
                }
            } catch (error) {
                console.error('Error migrating chats.json:', error);
            }
        }
        
        console.log('Migration completed!');
    } catch (error) {
        console.error('Migration failed:', error);
    } finally {
        await client.close();
    }
}

migrateChats().catch(console.error); 
