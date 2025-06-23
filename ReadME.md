# Chat App

A real-time chat application with end-to-end encryption.

## Features

- End-to-end encrypted messaging
- Private conversations
- Star your favorite chats
- No registration required
- Instant setup
- Profile pictures
- File sharing

## Deployment on Render

### Environment Variables

Set these environment variables in your Render dashboard:

1. **MONGODB_URI** (Required for production)
   - For MongoDB Atlas: `mongodb+srv://username:password@cluster.mongodb.net/chatapp`
   - For local development: `mongodb://localhost:27017/chatapp`

2. **NODE_ENV** (Optional)
   - Set to `production` for production deployment
   - Defaults to `development` if not set

3. **PORT** (Optional)
   - Render will automatically set this
   - Defaults to 3000 if not set

### Build Command

```bash
npm install
```

### Start Command

```bash
npm start
```

## Troubleshooting

### 500 Error on User Registration

If you encounter a 500 error when creating a profile, check:

1. **MongoDB Connection**: Ensure your `MONGODB_URI` is correctly set
2. **File Permissions**: The app will automatically fall back to in-memory storage if MongoDB is unavailable
3. **Environment Variables**: Make sure all required environment variables are set in Render

### File Upload Issues

The app includes fallback mechanisms for file uploads. If the primary upload directory fails, it will automatically use a fallback directory.

## Local Development

1. Clone the repository
2. Install dependencies: `npm install`
3. Set up MongoDB locally or use MongoDB Atlas
4. Create a `.env` file with your configuration
5. Run: `npm run dev`

## Architecture

- **Backend**: Node.js with Express
- **Database**: MongoDB (with fallback to file storage)
- **Real-time**: WebSocket connections
- **Encryption**: End-to-end encryption for messages
- **File Storage**: Local file system with fallback mechanisms 
