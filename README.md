# Enkryptonite Chat

A secure, real-time chat application with end-to-end encryption capabilities.

## Features

- 🔐 **End-to-End Encryption**: Messages are encrypted using advanced cryptographic protocols
- 💬 **Real-time Messaging**: Instant message delivery using WebSocket connections
- 👥 **Private & Group Chats**: Support for both private conversations and group discussions
- ⭐ **Starred Chats**: Mark important conversations for quick access
- 🔍 **Search Functionality**: Find chats and messages quickly
- 🎨 **Modern UI**: Clean, responsive design with smooth animations
- 🔒 **Secure Authentication**: User registration with optional profile pictures
- 📱 **Mobile Friendly**: Responsive design that works on all devices

## Technology Stack

- **Backend**: Node.js, Express.js, Socket.IO
- **Database**: MongoDB
- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Encryption**: Web Crypto API with ECDH key exchange and AES-GCM
- **File Upload**: Multer for profile picture handling

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- MongoDB database
- npm or yarn package manager

### Installation

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/enkryptonite-chat.git
cd enkryptonite-chat
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables:
Create a `.env` file in the root directory with:
```
MONGODB_URI=your_mongodb_connection_string
PORT=3000
```

4. Start the application:
```bash
npm start
```

For development with auto-restart:
```bash
npm run dev
```

5. Open your browser and navigate to `http://localhost:3000`

## Usage

1. **First Time Setup**: Visit the welcome page to create your profile
2. **Create Chats**: Start new conversations or join existing ones
3. **Send Messages**: Type and send messages in real-time
4. **Enable Encryption**: Use the E2EE features for secure communication
5. **Manage Chats**: Star important chats, search conversations, and organize your messages

## Security Features

- **ECDH Key Exchange**: Secure key agreement protocol
- **AES-GCM Encryption**: Authenticated encryption for message content
- **Nonce Management**: Prevents replay attacks
- **Input Validation**: Comprehensive validation of all user inputs
- **Secure Storage**: Encrypted local storage of sensitive data

## API Endpoints

- `POST /register-user` - Register a new user
- `GET /api/all-chats` - Get all available chats
- `GET /api/search-chats` - Search for specific chats
- `POST /create-chat` - Create a new chat room
- `DELETE /api/chats/:id` - Delete a chat (owner only)
- `POST /api/user/:id/star` - Star a chat
- `POST /api/user/:id/unstar` - Unstar a chat

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the ISC License - see the LICENSE file for details.

## Acknowledgments

- Built with ❤️ using modern web technologies
- Powered by Bolt.new for rapid development
- Inspired by the need for secure, private communication

---

**Made with Bolt.new** - The fastest way to build and deploy web applications.