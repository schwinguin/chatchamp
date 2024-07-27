# Chat Application

This repository contains the code for a chat application built with Flask and Socket.IO. The application supports real-time messaging, user authentication, file uploads, email notifications, and admin management features.

## Features

- Real-Time Messaging
The core of the application allows users to engage in real-time messaging within various chat rooms. The use of Socket.IO facilitates instant communication.

- User Authentication
Users can register and log in to the application. The authentication process includes user approval by an admin and the ability to manage user sessions securely.

- File Uploads
The application supports uploading different types of files, including text, images, videos, and audio files, enhancing the chat experience.

- Email Notifications
Email notifications can be sent for various events, such as user registration or room creation. This feature is integrated using the smtplib module.

- Admin Management
Admins have access to additional features, including user management, room management, server settings, and generating SSL certificates for secure communication.

## Prerequisites

- Python 3.x
- SQLite
- Node.js and npm (for front-end dependencies)

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/schwinguin/chatchamp.git
    cd chat-app
    ```

2. Create and activate a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use venv\Scripts\activate
    ```

3. Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

4. Install front-end dependencies:
    ```bash
    npm install
    ```

5. Create an instance folder and the SQLite database:
    ```bash
    mkdir instance
    ```

6. Create a `settings.json` file in the instance folder with the following content:
    ```json
    {
      "host": "0.0.0.0",
      "port": "5554",
      "debug": true,
      "ssl": false,
      "cert_file": "",
      "key_file": "",
      "auto_user_approval": false,
      "mail_server": "smtp.example.com",
      "mail_port": 587,
      "mail_username": "your-email@example.com",
      "mail_password": "your-email-password",
      "mail_use_tls": true,
      "mail_use_ssl": false,
      "senders_name": "Your Name",
      "notification_email": "notify@example.com"
    }
    ```

## Usage

Initialize the database and start the server:
```bash
python chatChamp.py

```
Open a web browser and navigate to http://localhost:5554 to access the application.

## Routes
- / - Home page (requires login)
- /login - User login
- /register - User registration
- /logout - User logout
- /create_room - Create a new chat room (requires login)
- /join_room/<int:room_id> - Join an existing chat room (requires login)
- /admin - Admin dashboard (requires admin login)
- /admin/send_test_email - Send a test email (admin only)
- /api/messages/<int:room_id> - Get messages for a specific room (requires login)
- /cached_messages/<int:room_id> - Get cached messages for a specific room (requires login)
- /upload - Upload a file (requires login)
- /uploads/ - Download an uploaded file (requires login)
- /admin/save_settings - Save server settings (admin only)
- /admin/load_settings - Load server settings (admin only)
- /admin/start_server - Start the server (admin only)
- /admin/stop_server - Stop the server (admin only)
- /admin/load_notification_settings - Load notification settings (admin only)
- /admin/save_notification_settings - Save notification settings (admin only)
- /admin/load_mail_settings - Load mail settings (admin only)
- /admin/save_mail_settings - Save mail settings (admin only)
- /admin/rooms - Manage chat rooms (admin only)
- /admin/rooms/<int:room_id> - Delete a chat room (admin only)
- /admin/users - Manage users (admin only)
- /admin/users/<int:user_id> - Update or delete a user (admin only)
- /admin/users/<int:user_id>/update_username - Update user's username (admin only)
- /admin/users/<int:user_id>/update_password - Update user's password (admin only)
- /admin/files - Manage files (admin only)
- /api/user_counts - Get user counts for each room (requires login)

## WebSocket Events
- join - Join a chat room
- leave - Leave a chat room
- message - Send a message to a chat room
- typing - Notify when a user is typing
- delete_message - Delete a message
- edit_message - Edit a message
- connect - Handle user connection
- disconnect - Handle user disconnection
- voice_signal - Handle voice chat signal
- voice_disconnected - Handle voice chat disconnection

## Contributing
Feel free to contribute by opening issues or submitting pull requests.
