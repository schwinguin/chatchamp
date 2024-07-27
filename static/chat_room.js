// Cache busting function
function appendCacheBuster(url) {
    const version = '1.0.0'; // This should be dynamically set to your app version or a unique hash
    return `${url}?v=${version}`;
}

document.addEventListener("DOMContentLoaded", function() {
    var coll = document.getElementsByClassName("collapsible");
    for (var i = 0; i < coll.length; i++) {
        coll[i].addEventListener("click", function() {
            this.classList.toggle("active");
            var content = this.nextElementSibling;
            if (content.style.display === "block") {
                content.style.display = "none";
            } else {
                content.style.display = "block";
            }
        });
    }
    const emojiButton = document.getElementById('emoji-button');
    const emojiPicker = document.getElementById('emoji-picker');
    const messageInput = document.getElementById('message-input');
    const emojiSearch = document.getElementById('emoji-search');
    emojiButton.addEventListener('click', () => {
        emojiPicker.style.display = emojiPicker.style.display === 'none' ? 'block' : 'none';
    });
    emojiPicker.addEventListener('click', (event) => {
        if (event.target.classList.contains('emoji')) {
            messageInput.value += event.target.textContent;
            emojiPicker.style.display = 'none';
        }
    });
    document.addEventListener('click', (event) => {
        if (!emojiPicker.contains(event.target) && event.target !== emojiButton) {
            emojiPicker.style.display = 'none';
        }
    });
    emojiSearch.addEventListener('input', (event) => {
        const searchTerm = event.target.value.toLowerCase();
        const emojis = emojiPicker.querySelectorAll('.emoji');
        emojis.forEach(emoji => {
            const emojiText = emoji.textContent;
            emoji.style.display = emojiText.includes(searchTerm) ? 'inline-block' : 'none';
        });
    });
});

var socket = io();
var current_user = "{{ current_user.username }}";
var room_id = "{{ room.id }}";
var typingTimeout;
var shouldAutoScroll = true;
var usersInVoiceChat = new Set();
socket.emit('join', {'room_id': room_id});
socket.on('connect', function() {
    console.log('Connected to Socket.IO server');
});
socket.on('message', function(msg) {
    addMessageToDom(msg);
});
socket.on('typing', function(data) {
    var typingIndicator = document.getElementById('typing');
    if (typingIndicator) {
        typingIndicator.textContent = data.username + ' is typing...';
        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(function() {
            typingIndicator.textContent = '';
        }, 2000);
    }
});
socket.on('user_joined', function(data) {
    updateUserList(data.username, true);
    checkUserCount();
});
socket.on('user_left', function(data) {
    updateUserList(data.username, false);
    checkUserCount();
});
socket.on('online_users', function(data) {
    clearUserList();
    data.forEach(username => updateUserList(username, true));
    checkUserCount();
});
socket.on('voice_user_joined', function(data) {
    console.log('Voice user joined:', data.username);
    usersInVoiceChat.add(data.username);
    updateUserList(data.username, true);
});
socket.on('voice_user_left', function(data) {
    console.log('Voice user left:', data.username);
    usersInVoiceChat.delete(data.username);
    updateUserList(data.username, true);
});
document.getElementById('message-input').onkeypress = function(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        sendMessage();
    }
};
document.getElementById('send-button').onclick = function() {
    sendMessage();
};
function sendMessage() {
    var input = document.getElementById('message-input');
    var messageContent = input.value.trim();
    if (messageContent !== "") {
        socket.emit('message', {content: messageContent, room_id: room_id});
        input.value = '';
        if (shouldAutoScroll) {
            scrollToBottom();
        }
    }
}
document.getElementById('message-input').oninput = function() {
    socket.emit('typing', {room_id: room_id});
};
document.getElementById('messages').onscroll = function() {
    var messagesContainer = document.getElementById('messages');
    shouldAutoScroll = messagesContainer.scrollTop + messagesContainer.clientHeight >= messagesContainer.scrollHeight - 10;
};
function updateUserList(username, isConnected) {
    console.log('Updating user list for:', username, 'Connected:', isConnected);
    var users = document.getElementById('users');
    var user = document.getElementById('user-' + username);
    if (isConnected) {
        if (!user) {
            user = document.createElement('li');
            user.id = 'user-' + username;
            user.className = 'list-group-item';
            users.appendChild(user);
        }
        user.textContent = username + (usersInVoiceChat.has(username) ? ' (Voice)' : ' (Online)');
    } else {
        if (user) {
            user.remove();
        }
    }
}
function clearUserList() {
    var users = document.getElementById('users');
    users.innerHTML = '';
}
function leaveRoom() {
    socket.emit('leave', {room_id: room_id});
    clearUserList();
    window.location.href = "/";
}
function addLineBreaks(str, maxLineLength) {
    let result = '';
    let lineLength = 0;
    for (let i = 0; i < str.length; i++) {
        result += str[i];
        lineLength++;
        if (lineLength >= maxLineLength && str[i] === ' ') {
            result += '\n';
            lineLength = 0;
        }
    }
    return result;
}
function addMessageToDom(msg, scroll = true) {
    var messages = document.getElementById('messages');
    var message = document.createElement('div');
    message.className = 'message ' + (msg.username === current_user ? 'my-message' : 'other-message');
    message.id = 'message-' + msg.id;
    const formattedContent = addLineBreaks(msg.content, 40);
    if (msg.username === current_user) {
        message.innerHTML = '<div class="message-content">' +
                                '<span class="content">' + formattedContent + '</span>' +
                                '<small class="timestamp">' + msg.timestamp + '</small>' +
                            '</div>' +
                            '<div class="message-buttons">' +
                                '<button class="btn btn-secondary btn-sm" onclick="editMessage(' + msg.id + ', \'' + msg.content + '\')">Edit</button>' +
                                '<button class="btn btn-danger btn-sm" onclick="deleteMessage(' + msg.id + ')">Delete</button>' +
                            '</div>';
    } else {
        message.innerHTML = '<div class="message-content">' +
                                '<span class="username">' + msg.username + '</span>' +
                                '<span class="content">' + formattedContent + '</span>' +
                                '<small class="timestamp">' + msg.timestamp + '</small>' +
                            '</div>';
    }
    if (msg.link_preview) {
        var linkPreview = document.createElement('div');
        linkPreview.className = 'link-preview';
        if (msg.link_preview.image) {
            var previewImage = document.createElement('img');
            previewImage.src = msg.link_preview.image;
            previewImage.alt = 'Preview image';
            previewImage.className = 'preview-image';
            linkPreview.appendChild(previewImage);
        }
        var previewText = document.createElement('div');
        previewText.className = 'preview-text';
        var previewTitle = document.createElement('strong');
        previewTitle.textContent = msg.link_preview.title;
        previewText.appendChild(previewTitle);
        var previewDescription = document.createElement('p');
        previewDescription.textContent = msg.link_preview.description;
        previewText.appendChild(previewDescription);
        linkPreview.appendChild(previewText);
        message.querySelector('.message-content').appendChild(linkPreview);
    }
    if (msg.file_path) {
        var fileLink = document.createElement('div');
        fileLink.className = 'file-link';
        if (msg.file_path.endsWith('png') || msg.file_path.endsWith('jpg') || msg.file_path.endsWith('jpeg') || msg.file_path.endsWith('gif')) {
            var imagePreview = document.createElement('img');
            imagePreview.src = appendCacheBuster('/uploads/' + msg.file_path);
            imagePreview.alt = 'Image preview';
            imagePreview.className = 'file-preview';
            fileLink.appendChild(imagePreview);
        } else if (msg.file_path.endsWith('mp3')) {
            var audioPreview = document.createElement('audio');
            audioPreview.controls = true;
            audioPreview.innerHTML = '<source src="' + appendCacheBuster('/uploads/' + msg.file_path) + '" type="audio/mpeg">Your browser does not support the audio element.';
            fileLink.appendChild(audioPreview);
        } else if (msg.file_path.endsWith('mp4')) {
            var videoPreview = document.createElement('video');
            videoPreview.controls = true;
            videoPreview.className = 'file-preview';
            videoPreview.innerHTML = '<source src="' + appendCacheBuster('/uploads/' + msg.file_path) + '" type="video/mp4">Your browser does not support the video element.';
            fileLink.appendChild(videoPreview);
        } else {
            var fileAnchor = document.createElement('a');
            fileAnchor.href = appendCacheBuster('/uploads/' + msg.file_path);
            fileAnchor.target = '_blank';
            fileAnchor.textContent = msg.file_path;
            fileLink.appendChild(fileAnchor);
        }
        message.querySelector('.message-content').appendChild(fileLink);
    }
    messages.appendChild(message);
    if (shouldAutoScroll && scroll) {
        scrollToBottom();
    }
}
function scrollToBottom() {
    var messages = document.getElementById('messages');
    messages.scrollTop = messages.scrollHeight;
}
function editMessage(messageId, currentContent) {
    var newContent = prompt("Edit your message:", currentContent);
    if (newContent !== null && newContent !== currentContent) {
        socket.emit('edit_message', { id: messageId, content: newContent });
    }
}
function deleteMessage(messageId) {
    if (confirm("Are you sure you want to delete this message?")) {
        console.log('Sending delete message request for ID: ' + messageId);
        socket.emit('delete_message', { id: messageId, room_id: room_id });
    }
}
socket.on('edit_message', function(data) {
    console.log('Received edit message event for ID:', data.id);
    var messageElement = document.getElementById('message-' + data.id);
    if (messageElement) {
        var contentElement = messageElement.querySelector('.content');
        contentElement.textContent = data.content;
    }
});
socket.on('delete_message', function(data) {
    console.log('Received delete message event for ID:', data.id);
    var messageElement = document.getElementById('message-' + data.id);
    if (messageElement) {
        messageElement.remove();
    } else {
        console.log('Message element not found for ID: ' + data.id);
    }
});
function fetchMessages() {
    fetch(`/api/messages/${room_id}`)
        .then(response => {
            console.log('Response status:', response.status);
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(messages => {
            var messagesContainer = document.getElementById('messages');
            messagesContainer.innerHTML = '';
            messages.forEach(msg => addMessageToDom(msg, false));
            if (shouldAutoScroll) {
                scrollToBottom();
            }
        })
        .catch(error => {
            console.error('Error fetching messages:', error);
        });
}

window.addEventListener('beforeunload', function() {
    var messagesContainer = document.getElementById('messages');
    sessionStorage.setItem('scrollPosition', messagesContainer.scrollTop);
});
window.addEventListener('load', function() {
    var scrollPosition = sessionStorage.getItem('scrollPosition');
    if (scrollPosition) {
        var messagesContainer = document.getElementById('messages');
        messagesContainer.scrollTop = scrollPosition;
        shouldAutoScroll = messagesContainer.scrollTop + messagesContainer.clientHeight >= messagesContainer.scrollHeight - 10;
    }
});
document.getElementById('file-input').onchange = function() {
    var file = this.files[0];
    if (file) {
        var formData = new FormData();
        formData.append('file', file);
        fetch('/upload', {
            method: 'POST',
            body: formData
        }).then(response => response.json())
          .then(data => {
              if (data.filename) {
                  socket.emit('message', { content: 'File uploaded: ' + data.filename, room_id: room_id, file_path: data.filename });
              } else {
                  alert('File upload failed');
              }
          }).catch(error => {
              console.error('Error uploading file:', error);
              alert('File upload failed');
          });
    } else {
        alert('No file selected');
    }
};
// Voice chat logic
var peers = {};
var localStream = null;
var startVoiceChatBtn = document.getElementById('start-voice-chat');
var muteVoiceChatBtn = document.getElementById('mute-voice-chat');
var leaveVoiceChatBtn = document.getElementById('leave-voice-chat');
var remoteAudio = document.getElementById('remote-audio');
var audioMeter = document.getElementById('audio-meter');
var audioMeterContext = audioMeter.getContext('2d');
var audioContext = null;
var audioAnalyser = null;
var audioDataArray = null;
var isInitiator = false;
startVoiceChatBtn.onclick = function() {
    console.log('Start Voice Chat button clicked');
    startVoiceChat();
};
muteVoiceChatBtn.onclick = function() {
    muteUnmuteVoiceChat();
};
leaveVoiceChatBtn.onclick = function() {
    leaveVoiceChat();
};
function startVoiceChat() {
    console.log('Attempting to start voice chat...');
    navigator.mediaDevices.getUserMedia({ audio: true })
        .then(stream => {
            console.log('Audio stream obtained');
            localStream = stream;
            startVoiceChatBtn.style.display = 'none';
            muteVoiceChatBtn.style.display = 'inline-block';
            leaveVoiceChatBtn.style.display = 'inline-block';
            audioMeter.style.display = 'block';
            document.getElementById('voice-chat-bar').classList.add('active');
            setupAudioMeter(stream);
            isInitiator = true;
            socket.emit('voice_signal', { room_id: room_id, username: current_user, signal: null });
            socket.emit('voice_user_joined', { username: current_user });
        })
        .catch(err => {
            console.error('Error getting audio stream:', err);
            alert('Error accessing audio stream. Please check your device settings.');
        });
}
function muteUnmuteVoiceChat() {
    if (localStream) {
        var audioTracks = localStream.getAudioTracks();
        if (audioTracks.length > 0) {
            var isMuted = !audioTracks[0].enabled;
            audioTracks[0].enabled = !isMuted;
            muteVoiceChatBtn.textContent = isMuted ? 'Unmute' : 'Mute';
        }
    }
}
function leaveVoiceChat() {
    if (localStream) {
        localStream.getTracks().forEach(track => track.stop());
        localStream = null;
    }
    for (let peer of Object.values(peers)) {
        peer.destroy();
    }
    peers = {};
    socket.emit('voice_disconnected', { room_id: room_id, username: current_user });
    startVoiceChatBtn.style.display = 'inline-block';
    muteVoiceChatBtn.style.display = 'none';
    leaveVoiceChatBtn.style.display = 'none';
    audioMeter.style.display = 'none';
    remoteAudio.srcObject = null;
    isInitiator = false;
    document.getElementById('voice-chat-bar').classList.remove('active');
    socket.emit('voice_user_left', { username: current_user });
}
function setupAudioMeter(stream) {
    audioContext = new (window.AudioContext || window.webkitAudioContext)();
    audioAnalyser = audioContext.createAnalyser();
    var source = audioContext.createMediaStreamSource(stream);
    source.connect(audioAnalyser);
    audioAnalyser.fftSize = 256;
    var bufferLength = audioAnalyser.frequencyBinCount;
    audioDataArray = new Uint8Array(bufferLength);
    function drawMeter() {
        requestAnimationFrame(drawMeter);
        audioAnalyser.getByteFrequencyData(audioDataArray);
        audioMeterContext.clearRect(0, 0, audioMeter.width, audioMeter.height);
        var barWidth = (audioMeter.width / bufferLength) * 2.5;
        var barHeight;
        var x = 0;
        for (var i = 0; i < bufferLength; i++) {
            barHeight = audioDataArray[i] / 2;
            audioMeterContext.fillStyle = 'rgb(' + (barHeight + 100) + ',50,50)';
            audioMeterContext.fillRect(x, audioMeter.height - barHeight / 2, barWidth, barHeight);
            x += barWidth + 1;
        }
    }
    drawMeter();
}
function handleDeviceChange() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
        console.error('enumerateDevices is not supported.');
        alert('Device enumeration not supported. Please use a different browser.');
        return;
    }
    navigator.mediaDevices.enumerateDevices().then(devices => {
        const audioInputSelect = document.getElementById('input-source');
        const audioOutputSelect = document.getElementById('output-source');
        audioInputSelect.innerHTML = '';
        audioOutputSelect.innerHTML = '';
        let hasAudioInput = false;
        let hasAudioOutput = false;
        devices.forEach(device => {
            if (device.kind === 'audioinput') {
                const option = document.createElement('option');
                option.value = device.deviceId;
                option.text = device.label || `Microphone ${audioInputSelect.length + 1}`;
                audioInputSelect.appendChild(option);
                hasAudioInput = true;
            } else if (device.kind === 'audiooutput') {
                const option = document.createElement('option');
                option.value = device.deviceId;
                option.text = device.label || `Speaker ${audioOutputSelect.length + 1}`;
                audioOutputSelect.appendChild(option);
                hasAudioOutput = true;
            }
        });
        if (!hasAudioInput) {
            const option = document.createElement('option');
            option.text = 'No audio input devices found';
            option.disabled = true;
            audioInputSelect.appendChild(option);
        }
        if (!hasAudioOutput) {
            const option = document.createElement('option');
            option.text = 'No audio output devices found';
            option.disabled = true;
            audioOutputSelect.appendChild(option);
        }
    }).catch(err => console.error('Error enumerating devices:', err));
}
function changeInputSource() {
    const audioInputSelect = document.getElementById('input-source');
    const selectedDeviceId = audioInputSelect.value;
    navigator.mediaDevices.getUserMedia({
        audio: {
            deviceId: selectedDeviceId ? { exact: selectedDeviceId } : undefined
        }
    }).then(stream => {
        if (localStream) {
            localStream.getTracks().forEach(track => track.stop());
        }
        localStream = stream;
        stream.getTracks().forEach(track => {
            for (let peer of Object.values(peers)) {
                peer.addTrack(track, stream);
            }
        });
        setupAudioMeter(stream);
    }).catch(err => console.error('Error changing input source:', err));
}
function changeOutputSource() {
    const audioOutputSelect = document.getElementById('output-source');
    const selectedDeviceId = audioOutputSelect.value;
    if (typeof remoteAudio.sinkId !== 'undefined') {
        remoteAudio.setSinkId(selectedDeviceId).then(() => {
            console.log(`Audio output device set to ${selectedDeviceId}`);
        }).catch(err => console.error('Error changing output source:', err));
    } else {
        console.warn('Browser does not support output device selection.');
    }
}
function changeInputVolume() {
    const inputVolume = document.getElementById('input-volume').value;
    if (localStream) {
        const audioTracks = localStream.getAudioTracks();
        if (audioTracks.length > 0) {
            audioTracks[0].applyConstraints({
                advanced: [{ volume: inputVolume / 100 }]
            }).then(() => {
                console.log(`Input volume set to ${inputVolume}`);
            }).catch(err => console.error('Error changing input volume:', err));
        }
    }
}
function changeOutputVolume() {
    const outputVolume = document.getElementById('output-volume').value;
    remoteAudio.volume = outputVolume / 100;
    console.log(`Output volume set to ${outputVolume}`);
}
document.getElementById('input-source').onchange = changeInputSource;
document.getElementById('output-source').onchange = changeOutputSource;
document.getElementById('input-volume').oninput = changeInputVolume;
document.getElementById('output-volume').oninput = changeOutputVolume;
if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
    navigator.mediaDevices.enumerateDevices().then(handleDeviceChange);
    navigator.mediaDevices.ondevicechange = handleDeviceChange;
} else {
    console.error('enumerateDevices is not supported.');
    alert('Device enumeration not supported. Please use a different browser.');
}
socket.on('voice_signal', function(data) {
    console.log('Received voice signal', data);
    handleVoiceSignal(data);
});
socket.on('voice_disconnected', function(data) {
    console.log('Voice disconnected', data);
    if (peers[data.username]) {
        peers[data.username].destroy();
        delete peers[data.username];
    }
    usersInVoiceChat.delete(data.username);
    updateUserList(data.username, true);
});
socket.on('force_voice_disconnect', function(data) {
    console.log('Force voice disconnect for', data);
    leaveVoiceChat();
});
function handleVoiceSignal(data) {
    const { username, signal } = data;
    if (signal === null) {
        console.log('User joined voice chat:', username);
        usersInVoiceChat.add(username);
    } else if (!signal) {
        console.log('User left voice chat:', username);
        usersInVoiceChat.delete(username);
    }
    updateUserList(username, true);
    if (!peers[username]) {
        const peer = new SimplePeer({
            initiator: isInitiator,
            trickle: false,
            stream: localStream
        });
        peer.on('signal', function(signal) {
            console.log('Sending signal', signal);
            socket.emit('voice_signal', { room_id: room_id, username: current_user, signal: signal });
        });
        peer.on('stream', function(stream) {
            console.log('Received remote stream', stream);
            remoteAudio.srcObject = stream;
            remoteAudio.play().catch(error => {
                console.error('Error playing remote audio:', error);
            });
        });
        peer.on('close', function() {
            console.log('Peer connection closed');
            delete peers[username];
        });
        peer.on('error', function(err) {
            console.error('Peer error:', err);
            peer.destroy();
        });
        peers[username] = peer;
        if (signal) {
            peers[username].signal(signal);
        }
    } else {
        if (signal) {
            peers[username].signal(signal);
        }
    }
}
function checkUserCount() {
    var userCount = document.getElementById('users').children.length;
    var startVoiceChatBtn = document.getElementById('start-voice-chat');
    if (userCount > 1) {
        startVoiceChatBtn.disabled = false;
    } else {
        startVoiceChatBtn.disabled = true;
        if (userCount === 1 && localStream) {
            leaveVoiceChat();
        }
    }
}
