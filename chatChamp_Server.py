# chatChamp_Server.py
import os
import threading
import logging
import eventlet
import eventlet.wsgi
import json
import emoji
import bleach
import requests
import smtplib
from email.message import EmailMessage
from email_validator import validate_email, EmailNotValidError
from datetime import datetime, timedelta, timezone
from logging import StreamHandler
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_cors import CORS
from flask_caching import Cache
from bs4 import BeautifulSoup
from sqlalchemy.orm import Session
import admin  # Import the admin module

# Import models from models.py
from models import User, ChatRoom, Message, db

# Flask application setup
app = Flask(__name__, instance_relative_config=True)
CORS(app)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(app.instance_path, "chat.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['CACHE_TYPE'] = 'simple'
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure the instance folder exists
os.makedirs(app.instance_path, exist_ok=True)
# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)  # Initialize the SQLAlchemy instance with the app
cache = Cache(app)
socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp3', 'mp4', 'wav', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/admin/send_test_email', methods=['POST'])
@login_required
def send_test_email():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.json
    to_email = data.get('to_email', '')
    subject = data.get('subject', 'Test Email')
    body = data.get('body', 'This is a test email.')

    result = admin.send_email(to_email, subject, body)
    return jsonify({'message': result})

@app.route('/')
@login_required
def index():
    rooms = ChatRoom.query.all()
    rooms_with_counts = []
    for room in rooms:
        room_id = room.id
        user_count = room_user_counts.get(room_id, 0)
        rooms_with_counts.append({
            'id': room.id,
            'name': room.name,
            'background_image': room.background_image,
            'password_hash': room.password_hash,
            'user_count': user_count
        })
    return render_template('index.html', rooms=rooms_with_counts)

@app.route('/create_room', methods=['GET', 'POST'])
@login_required
def create_room():
    if request.method == 'POST':
        room_name = request.form['room_name']
        background_image = request.files['background_image']
        room_password = request.form['room_password']
        
        if ChatRoom.query.filter_by(name=room_name).first():
            flash('Room already exists')
        else:
            background_image_filename = None
            if background_image and allowed_file(background_image.filename):
                background_image_filename = secure_filename(background_image.filename)
                background_image.save(os.path.join(app.config['UPLOAD_FOLDER'], background_image_filename))
            
            try:
                room = ChatRoom(name=room_name, background_image=background_image_filename)
                if room_password:
                    room.set_password(room_password)
                db.session.add(room)
                db.session.commit()
                return redirect(url_for('index'))
            except Exception as e:
                db.session.rollback()
                flash('Error creating room: ' + str(e))
    
    return render_template('create_room.html')

@app.route('/join_room/<int:room_id>', methods=['GET', 'POST'])
@login_required
def join_room_view(room_id):
    room = ChatRoom.query.get_or_404(room_id)
    if room.password_hash:
        if request.method == 'POST':
            room_password = request.form['room_password']
            if not room.check_password(room_password):
                flash('Incorrect password')
                return redirect(url_for('index'))
        else:
            flash('This room requires a password')
            return redirect(url_for('index'))
    
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp.asc()).all()
    return render_template('chat_room.html', room=room, messages=messages)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.is_approved:
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash('Your account is not yet approved. Please wait for an administrator to approve your account.')
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
        else:
            try:
                with open("settings.json", "r") as f:
                    settings = json.load(f)
                auto_user_approval = settings.get('auto_user_approval', False)
                user = User(username=username, is_approved=auto_user_approval)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()

                if settings.get("notify_on_new_user", False):
                    admin.send_notification_email("New User Registration", f"A new user '{username}' has registered and needs approval.")

                flash('Registration successful, please wait for approval' if not auto_user_approval else 'Registration successful, you can now login')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('Error registering user: ' + str(e))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/api/messages/<int:room_id>', methods=['GET'])
@login_required
def get_messages(room_id):
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp.asc()).all()
    messages_data = [{'id': msg.id, 'username': msg.username, 'content': msg.content, 'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'link_preview': msg.link_preview, 'file_path': msg.file_path} for msg in messages]
    return jsonify(messages_data)

@cache.cached(timeout=60, key_prefix='messages_room_')
@app.route('/cached_messages/<int:room_id>', methods=['GET'])
@login_required
def cached_get_messages(room_id):
    messages = Message.query.filter_by(room_id=room_id).order_by(Message.timestamp.asc()).all()
    messages_data = [{'id': msg.id, 'username': msg.username, 'content': msg.content, 'timestamp': msg.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'link_preview': msg.link_preview, 'file_path': msg.file_path} for msg in messages]
    return jsonify(messages_data)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # Ensure the upload folder exists before saving the file
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return jsonify({'filename': filename})
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin')
@login_required
def admin_page():
    if not current_user.is_admin:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    return render_template('admin.html')

@app.route('/admin/generate_certificate', methods=['POST'])
@login_required
def admin_generate_certificate_route():
    return admin.admin_generate_certificate()

@app.route('/admin/save_settings', methods=['POST'])
@login_required
def admin_save_settings_route():
    return admin.admin_save_settings()

@app.route('/admin/start_server', methods=['POST'])
@login_required
def admin_start_server_route():
    return admin.admin_start_server(app)

@app.route('/admin/stop_server', methods=['POST'])
@login_required
def admin_stop_server_route():
    return admin.admin_stop_server()

@app.route('/admin/load_settings', methods=['GET'])
@login_required
def admin_load_settings_route():
    return admin.admin_load_settings()

@app.route('/admin/rooms', methods=['GET', 'POST'])
@login_required
def manage_rooms_route():
    return admin.manage_rooms()

@app.route('/admin/rooms/<int:room_id>', methods=['DELETE'])
@login_required
def delete_room_route(room_id):
    return admin.delete_room(room_id)

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users_route():
    return admin.manage_users()

@app.route('/admin/users/<int:user_id>', methods=['PUT', 'DELETE'])
@login_required
def update_or_delete_user_route(user_id):
    return admin.update_or_delete_user(user_id)

@app.route('/admin/users/<int:user_id>/update_username', methods=['POST'])
@login_required
def update_username_route(user_id):
    return admin.update_username(user_id)

@app.route('/admin/users/<int:user_id>/update_password', methods=['POST'])
@login_required
def update_password_route(user_id):
    return admin.update_password(user_id)

@app.route('/admin/files', methods=['GET', 'DELETE'])
@login_required
def manage_files_route():
    return admin.manage_files()

@app.route('/admin/load_notification_settings', methods=['GET'])
@login_required
def admin_load_notification_settings_route():
    return admin.admin_load_notification_settings()

@app.route('/admin/save_notification_settings', methods=['POST'])
@login_required
def admin_save_notification_settings_route():
    return admin.admin_save_notification_settings()

@app.route('/admin/load_mail_settings', methods=['GET'])
@login_required
def admin_load_mail_settings_route():
    return admin.admin_load_mail_settings()

@app.route('/admin/save_mail_settings', methods=['POST'])
@login_required
def admin_save_mail_settings_route():
    return admin.admin_save_mail_settings()

rooms = {}  # Dictionary to track users in rooms
room_user_counts = {}  # Dictionary to track user counts in rooms
voice_chat_peers = {}  # Global dictionary to track voice chat participants

@socketio.on('join')
@login_required
def on_join(data):
    room_id = data['room_id']
    join_room(room_id)
    print(f"{current_user.username} joined room {room_id}")
    if room_id not in rooms:
        rooms[room_id] = []
        room_user_counts[room_id] = 0

    if current_user.username not in rooms[room_id]:
        rooms[room_id].append(current_user.username)
        room_user_counts[room_id] += 1

    emit('user_joined', {'username': current_user.username}, room=room_id)
    emit('update_user_count', {'room_id': room_id, 'count': room_user_counts[room_id]}, broadcast=True)
    emit('online_users', rooms[room_id], room=room_id)


@socketio.on('leave')
@login_required
def on_leave(data):
    room_id = data['room_id']
    leave_room(room_id)
    if room_id in rooms and current_user.username in rooms[room_id]:
        rooms[room_id].remove(current_user.username)
        room_user_counts[room_id] = max(0, room_user_counts[room_id] - 1)
        emit('user_left', {'username': current_user.username}, room=room_id)
        emit('update_user_count', {'room_id': room_id, 'count': room_user_counts[room_id]}, broadcast=True)
        emit('online_users', rooms[room_id], room=room_id)

def fetch_link_preview(url):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        title = soup.find('title').text if soup.find('title') else url
        description = ''
        if soup.find('meta', attrs={'name': 'description'}):
            description = soup.find('meta', attrs={'name': 'description'})['content']
        elif soup.find('meta', attrs={'property': 'og:description'}):
            description = soup.find('meta', attrs={'property': 'og:description'})['content']

        image = ''
        if soup.find('meta', attrs={'property': 'og:image'}):
            image = soup.find('meta', attrs={'property': 'og:image'})['content']

        return {'title': title, 'description': description, 'image': image, 'url': url}
    except requests.RequestException as e:
        print(f"Error fetching link preview: {e}")
        return {'title': url, 'description': '', 'image': '', 'url': url}

@socketio.on('message')
@login_required
def handle_message(msg):
    room_id = msg['room_id']
    content = msg['content']
    file_path = msg.get('file_path')

    # Sanitize the content
    safe_content = bleach.clean(content)

    # Convert emoji shortcuts to actual emojis
    safe_content_with_emojis = emoji.emojize(safe_content)

    link_preview = None
    words = safe_content_with_emojis.split()
    for word in words:
        if word.startswith('http://') or word.startswith('https://'):
            link_preview = fetch_link_preview(word)
            break

    message = Message(username=current_user.username, content=safe_content_with_emojis, room_id=room_id, link_preview=link_preview, file_path=file_path)
    db.session.add(message)
    db.session.commit()

    emit('message', {
        'id': message.id,
        'username': current_user.username,
        'content': safe_content_with_emojis,
        'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'link_preview': link_preview,
        'file_path': file_path
    }, room=room_id)


@socketio.on('typing')
@login_required
def handle_typing(data):
    emit('typing', {'username': current_user.username}, room=data['room_id'])

@socketio.on('delete_message')
@login_required
def handle_delete_message(data):
    message_id = data['id']
    print(f"Deleting message ID: {message_id}")
    message = Message.query.get(message_id)
    if message and message.username == current_user.username:
        room_id = message.room_id
        if message.file_path:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], message.file_path)
            if os.path.exists(file_path):
                os.remove(file_path)
        print(f"Emitting delete_message for ID: {message_id} to room {room_id}")
        emit('delete_message', {'id': message_id}, room=room_id)
        db.session.delete(message)
        db.session.commit()
        print(f"Message ID: {message_id} deleted and committed to database")
    else:
        print(f"Message ID: {message_id} not found or user not authorized")

@socketio.on('edit_message')
@login_required
def handle_edit_message(data):
    message_id = data['id']
    print(f"Editing message ID: {message_id}")
    message = Message.query.get(message_id)
    if message and message.username == current_user.username:
        room_id = message.room_id
        message.content = data['content']
        print(f"Emitting edit_message for ID: {message_id} with content: {data['content']} to room {room_id}")
        emit('edit_message', {'id': message_id, 'content': data['content']}, room=room_id)
        db.session.commit()
        print(f"Message ID: {message_id} edited and committed to database")
    else:
        print(f"Message ID: {message_id} not found or user not authorized")


@socketio.on('connect')
@login_required
def handle_connect():
    current_user.session_id = request.sid
    db.session.commit()
    for room_id in rooms:
        if current_user.username in rooms[room_id]:
            emit('user_connected', {'username': current_user.username}, room=room_id)
            emit('online_users', rooms[room_id], room=room_id)

@app.route('/api/user_counts', methods=['GET'])
@login_required
def get_user_counts():
    room_counts = [{'room_id': room_id, 'count': count} for room_id, count in room_user_counts.items()]
    return jsonify(room_counts)

@socketio.on('disconnect')
@login_required
def handle_disconnect():
    current_user.session_id = None
    db.session.commit()
    for room_id in rooms:
        if current_user.username in rooms[room_id]:
            rooms[room_id].remove(current_user.username)
            room_user_counts[room_id] = max(0, room_user_counts[room_id] - 1)
            emit('user_left', {'username': current_user.username}, room=room_id)
            emit('update_user_count', {'room_id': room_id, 'count': room_user_counts[room_id]}, broadcast=True)
            emit('online_users', rooms[room_id], room=room_id)
            if room_id in voice_chat_peers:
                if current_user.username in voice_chat_peers[room_id]:
                    del voice_chat_peers[room_id][current_user.username]
                    emit('voice_disconnected', {'username': current_user.username}, room=room_id)
                if not voice_chat_peers[room_id]:
                    del voice_chat_peers[room_id]
                else:
                    # If only one user is left, disconnect them
                    if len(voice_chat_peers[room_id]) == 1:
                        remaining_user = next(iter(voice_chat_peers[room_id]))
                        emit('force_voice_disconnect', {'username': remaining_user}, room=room_id)
                        del voice_chat_peers[room_id]

@socketio.on('voice_signal')
@login_required
def handle_voice_signal(data):
    global voice_chat_peers
    room_id = data['room_id']
    signal = data['signal']
    if room_id not in voice_chat_peers:
        voice_chat_peers[room_id] = {}
    voice_chat_peers[room_id][current_user.username] = signal
    emit('voice_signal', {'username': current_user.username, 'signal': signal}, room=room_id, include_self=False)

@socketio.on('voice_disconnected')
@login_required
def handle_voice_disconnected(data):
    global voice_chat_peers
    room_id = data['room_id']
    if room_id in voice_chat_peers and current_user.username in voice_chat_peers[room_id]:
        del voice_chat_peers[room_id][current_user.username]
        emit('voice_disconnected', {'username': current_user.username}, room=room_id)
        
        # If room is empty after removing current user, delete the room entry
        if not voice_chat_peers[room_id]:
            del voice_chat_peers[room_id]
        else:
            # If only one user is left, disconnect them
            if len(voice_chat_peers[room_id]) == 1:
                remaining_user = next(iter(voice_chat_peers[room_id]))
                emit('force_voice_disconnect', {'username': remaining_user}, room=room_id)
                del voice_chat_peers[room_id]

def check_and_initialize_database():
    with app.app_context():
        if not os.path.exists('chat.db'):
            db.create_all()
        add_default_entries()

def add_default_entries():
    with app.app_context():
        try:
            if not User.query.filter_by(username='admin').first():
                default_user = User(username='admin', is_admin=True, is_approved=True)  # Set is_approved to True
                default_user.set_password('password')
                db.session.add(default_user)

            if not ChatRoom.query.filter_by(name='General').first():
                default_room = ChatRoom(name='General')
                db.session.add(default_room)
                
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logging.error(f"Error initializing database: {e}")

if __name__ == '__main__':
    check_and_initialize_database()
    with open("settings.json", "r") as f:
        settings = json.load(f)
    admin.start_flask_app(app, settings['host'], int(settings['port']), settings['debug'], settings['ssl'], settings['cert_file'], settings['key_file'])
    socketio.run(app, host=settings['host'], port=int(settings['port']), debug=settings['debug'])
