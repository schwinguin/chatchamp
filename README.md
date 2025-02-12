![chatChamp](https://github.com/user-attachments/assets/4b7c671f-a37a-4224-ab1e-f305556062eb)


## chatChamp - Voice Chat Server

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
    cd chatchamp
    ```

2. Create and activate a virtual environment:
    ```bash
    python3 -m venv myenv
    source myenv/bin/activate  # On Windows, use myenv\Scripts\activate
    ```

3. Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Initialize the database and start the server with:
```bash
python3 chatChamp_Server.py

```
Open a web browser and navigate to http://localhost:5554 to access the application.

## Default login credentials

- Username: admin
- Password: password

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
