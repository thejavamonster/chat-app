async function findOrCreatePrivateChat(otherUserId, otherUserName) {
    const myUserId = localStorage.getItem('userId');
    const myUserName = localStorage.getItem('userName');

    if (!myUserId || !myUserName) {
        alert('You must be logged in to start a private message.');
        return null;
    }

    try {
        // Try to find an existing private chat
        const res = await fetch(`/api/private-chat?user1=${myUserId}&user2=${otherUserId}`);
        if (res.ok) {
            const data = await res.json();
            if (data.chatId) return data.chatId;
        }
        // If not found, create one
        const chatName = `Private: ${myUserName} & ${otherUserName}`;
        const createRes = await fetch('/create-chat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: chatName, isPrivate: true, members: [myUserId, otherUserId] })
        });
        if (createRes.ok) {
            const chat = await createRes.json();
            return chat.id;
        } else {
            console.error('Failed to create private chat:', await createRes.text());
            throw new Error('Server failed to create chat.');
        }
    } catch (err) {
        alert('Failed to start private chat.');
        console.error("Error in findOrCreatePrivateChat:", err);
        return null;
    }
}

let starredChatIds = new Set();

async function toggleStar(chatId, event) {
    if (event) {
        event.stopPropagation();
    }
    const userId = localStorage.getItem('userId');
    if (!userId) {
        alert('Please set your name first.');
        return;
    }

    const isStarred = starredChatIds.has(chatId);
    const endpoint = isStarred ? 'unstar' : 'star';

    try {
        const response = await fetch(`/api/user/${userId}/${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chatId })
        });

        if (!response.ok) {
            if (response.status === 404) {
                console.log('User not found, cannot star/unstar chat');
                return;
            }
            throw new Error(`Failed to ${endpoint} chat`);
        }

        if (isStarred) {
            starredChatIds.delete(chatId);
        } else {
            starredChatIds.add(chatId);
        }
        
        // After toggling, we need to reload the lists on the current page.
        // The page itself should define how to reload its content.
        if (typeof refreshChatLists === 'function') {
            refreshChatLists();
        }

    } catch (error) {
        console.error('Error toggling star:', error);
        alert('Could not update star status.');
    }
}

async function fetchStarredChatIds() {
    const userId = localStorage.getItem('userId');
    if (!userId) {
        console.log('No userId found in localStorage, skipping starred chats fetch');
        starredChatIds = new Set();
        return;
    }

    try {
        const res = await fetch(`/api/user/${userId}/starred-chats`);
        if (!res.ok) {
            if (res.status === 404) {
                console.log('User not found, clearing starred chats');
                starredChatIds = new Set();
                return;
            }
            throw new Error('Failed to fetch starred chats');
        }
        const chats = await res.json();
        starredChatIds = new Set(chats.map(chat => chat.id || chat._id));
    } catch (err) {
        console.error('Could not fetch starred chat IDs:', err);
        starredChatIds = new Set();
    }
} 
