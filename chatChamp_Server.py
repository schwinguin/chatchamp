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

db = SQLAlchemy(app)
cache = Cache(app)
socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp3', 'mp4'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_approved = db.Column(db.Boolean, default=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    session_id = db.Column(db.String(128), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    background_image = db.Column(db.String(200), nullable=True)
    password_hash = db.Column(db.String(128), nullable=True)
    messages = db.relationship('Message', backref='room', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, index=True)
    content = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc), index=True)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False, index=True)
    link_preview = db.Column(db.JSON, nullable=True)
    file_path = db.Column(db.String(200), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

	
import smtplib
from email.message import EmailMessage
from email_validator import validate_email, EmailNotValidError

def send_email(to_email, subject, body):
    with open("settings.json", "r") as f:
        settings = json.load(f)

    mail_server = settings.get("mail_server", "")
    mail_port = settings.get("mail_port", 587)
    mail_username = settings.get("mail_username", "")
    mail_password = settings.get("mail_password", "")
    mail_use_tls = settings.get("mail_use_tls", True)
    mail_use_ssl = settings.get("mail_use_ssl", False)
    senders_name = settings.get("senders_name", "Your Name")

    try:
        validate_email(to_email)
    except EmailNotValidError as e:
        return str(e)

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = f"{senders_name} <{mail_username}>"
    msg['To'] = to_email
    msg.set_content(body)

    try:
        if mail_use_ssl:
            server = smtplib.SMTP_SSL(mail_server, mail_port)
        else:
            server = smtplib.SMTP(mail_server, mail_port)
            if mail_use_tls:
                server.starttls()
        server.login(mail_username, mail_password)
        server.send_message(msg)
        server.quit()
        return "Email sent successfully"
    except Exception as e:
        return f"Failed to send email: {e}"


	

@app.route('/admin/send_test_email', methods=['POST'])
@login_required
def send_test_email():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.json
    to_email = data.get('to_email', '')
    subject = data.get('subject', 'Test Email')
    body = data.get('body', 'This is a test email.')

    result = send_email(to_email, subject, body)
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
                    send_notification_email("New User Registration", f"A new user '{username}' has registered and needs approval.")

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
def admin():
    if not current_user.is_admin:
        flash('You are not authorized to view this page.')
        return redirect(url_for('index'))
    return render_template('admin.html')

@app.route('/admin/generate_certificate', methods=['POST'])
@login_required
def admin_generate_certificate():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    cert_file = "selfsigned.crt"
    key_file = "selfsigned.key"
    generate_self_signed_cert(cert_file, key_file)
    return jsonify({'cert_file': cert_file, 'key_file': key_file})

@app.route('/admin/save_settings', methods=['POST'])
@login_required
def admin_save_settings():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.json
    try:
        with open("settings.json", "r") as f:
            settings = json.load(f)
    except FileNotFoundError:
        settings = {}

    settings.update({
        "host": data.get('host', settings.get('host', '0.0.0.0')),
        "port": data.get('port', settings.get('port', '5000')),
        "debug": data.get('debug', settings.get('debug', False)),
        "ssl": data.get('ssl', settings.get('ssl', False)),
        "cert_file": data.get('cert_file', settings.get('cert_file', '')),
        "key_file": data.get('key_file', settings.get('key_file', '')),
        "auto_user_approval": data.get('auto_user_approval', settings.get('auto_user_approval', False))
    })

    with open("settings.json", "w") as f:
        json.dump(settings, f)

    return jsonify({'message': 'Settings saved successfully'})


@app.route('/admin/start_server', methods=['POST'])
@login_required
def admin_start_server():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    host = request.json.get('host', '0.0.0.0')
    port = int(request.json.get('port', 5000))
    debug = request.json.get('debug', False)
    use_ssl = request.json.get('ssl', False)
    cert_file = request.json.get('cert_file', 'selfsigned.crt')
    key_file = request.json.get('key_file', 'selfsigned.key')
    
    flask_thread = threading.Thread(target=start_flask_app, args=(host, port, debug, use_ssl, cert_file, key_file))
    flask_thread.daemon = True
    flask_thread.start()
    return jsonify({'message': 'Server started successfully'})

@app.route('/admin/stop_server', methods=['POST'])
@login_required
def admin_stop_server():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    stop_flask_app()
    return jsonify({'message': 'Server stopped successfully'})

@app.route('/admin/load_settings', methods=['GET'])
@login_required
def admin_load_settings():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        with open("settings.json", "r") as f:
            settings = json.load(f)
            return jsonify(settings)
    except FileNotFoundError:
        return jsonify({
            "host": "0.0.0.0",
            "port": "5000",
            "debug": False,
            "ssl": False,
            "auto_user_approval": False,
            "cert_file": "",
            "key_file": "",
            "mail_server": "",
            "mail_port": 587,
            "mail_username": "",
            "mail_password": "",
            "mail_use_tls": True,
            "mail_use_ssl": False
        })

@app.route('/admin/rooms', methods=['GET', 'POST'])
@login_required
def manage_rooms():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        data = request.json
        room_name = data.get('name')
        room_password = data.get('password')
        if room_name:
            if not ChatRoom.query.filter_by(name=room_name).first():
                room = ChatRoom(name=room_name)
                if room_password:
                    room.set_password(room_password)
                db.session.add(room)
                db.session.commit()
                return jsonify({'message': 'Room created successfully'})
    rooms = ChatRoom.query.all()
    rooms_data = [{'id': room.id, 'name': room.name} for room in rooms]
    return jsonify(rooms_data)

@app.route('/admin/rooms/<int:room_id>', methods=['DELETE'])
@login_required
def delete_room(room_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    room = ChatRoom.query.get(room_id)
    if room and room.name != 'General':  # Prevent deletion of default room
        db.session.delete(room)
        db.session.commit()
        return jsonify({'message': 'Room deleted successfully'})
    return jsonify({'error': 'Room cannot be deleted'}), 400

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        if username and password:
            if not User.query.filter_by(username=username).first():
                user = User(username=username)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                return jsonify({'message': 'User created successfully'})
    users = User.query.all()
    users_data = [{'id': user.id, 'username': user.username, 'is_approved': user.is_approved} for user in users]
    return jsonify(users_data)

@app.route('/admin/users/<int:user_id>', methods=['PUT', 'DELETE'])
@login_required
def update_or_delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    if request.method == 'PUT':
        data = request.json
        if 'approve' in data:
            user.is_approved = data['approve']
        if 'username' in data:
            user.username = data['username']
        if 'password' in data:
            user.set_password(data['password'])
        db.session.commit()
        return jsonify({'message': 'User updated successfully'})

    if request.method == 'DELETE':
        if user.username != 'admin':  # Prevent deletion of default user
            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': 'User deleted successfully'})
        return jsonify({'error': 'User cannot be deleted'}), 400

@app.route('/admin/users/<int:user_id>/update_username', methods=['POST'])
@login_required
def update_username(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.json
    new_username = data.get('username')
    if new_username:
        user.username = new_username
        db.session.commit()
        return jsonify({'message': 'Username updated successfully'})
    return jsonify({'error': 'Invalid username'}), 400

@app.route('/admin/users/<int:user_id>/update_password', methods=['POST'])
@login_required
def update_password(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.json
    new_password = data.get('password')
    if new_password:
        user.set_password(new_password)
        db.session.commit()
        return jsonify({'message': 'Password updated successfully'})
    return jsonify({'error': 'Invalid password'}), 400

@app.route('/admin/files', methods=['GET', 'DELETE'])
@login_required
def manage_files():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    if request.method == 'DELETE':
        message_id = request.json.get('message_id')
        message = Message.query.get(message_id)
        if message and message.file_path:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], message.file_path)
            if os.path.exists(file_path):
                os.remove(file_path)
            db.session.delete(message)
            db.session.commit()
            return jsonify({'message': 'File deleted successfully'})
    
    rooms = ChatRoom.query.all()
    files_data = []
    for room in rooms:
        messages = Message.query.filter_by(room_id=room.id).filter(Message.file_path.isnot(None)).all()
        for message in messages:
            files_data.append({
                'id': message.id,
                'file_path': message.file_path,
                'room_name': room.name,
                'username': message.username,
                'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            })
    return jsonify(files_data)

def send_notification_email(subject, body):
    with open("settings.json", "r") as f:
        settings = json.load(f)

    notification_email = settings.get("notification_email", "")
    if not notification_email:
        return "No notification email address set"

    return send_email(notification_email, subject, body)
	

@app.route('/admin/load_notification_settings', methods=['GET'])
@login_required
def admin_load_notification_settings():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        with open("settings.json", "r") as f:
            settings = json.load(f)
        notification_settings = {
            "notify_on_new_user": settings.get("notify_on_new_user", False),
            "notify_on_new_message": settings.get("notify_on_new_message", False),
            "notify_on_room_creation": settings.get("notify_on_room_creation", False)
        }
        return jsonify(notification_settings)
    except FileNotFoundError:
        return jsonify({
            "notify_on_new_user": False,
            "notify_on_new_message": False,
            "notify_on_room_creation": False
        })

@app.route('/admin/save_notification_settings', methods=['POST'])
@login_required
def admin_save_notification_settings():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.json
    try:
        with open("settings.json", "r") as f:
            settings = json.load(f)
    except FileNotFoundError:
        settings = {}

    settings.update({
        "notify_on_new_user": data.get("notify_on_new_user", settings.get("notify_on_new_user", False)),
        "notify_on_new_message": data.get("notify_on_new_message", settings.get("notify_on_new_message", False)),
        "notify_on_room_creation": data.get("notify_on_room_creation", settings.get("notify_on_room_creation", False))
    })

    with open("settings.json", "w") as f:
        json.dump(settings, f)

    return jsonify({'message': 'Notification settings saved successfully'})



	
@app.route('/admin/load_mail_settings', methods=['GET'])
@login_required
def admin_load_mail_settings():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    try:
        with open("settings.json", "r") as f:
            settings = json.load(f)
        mail_settings = {
            "mail_server": settings.get("mail_server", ""),
            "mail_port": settings.get("mail_port", 587),
            "mail_username": settings.get("mail_username", ""),
            "mail_password": settings.get("mail_password", ""),
            "mail_use_tls": settings.get("mail_use_tls", True),
            "mail_use_ssl": settings.get("mail_use_ssl", False),
            "notification_email": settings.get("notification_email", ""),
            "senders_name": settings.get("senders_name", "Your Name")
        }
        return jsonify(mail_settings)
    except FileNotFoundError:
        return jsonify({
            "mail_server": "",
            "mail_port": 587,
            "mail_username": "",
            "mail_password": "",
            "mail_use_tls": True,
            "mail_use_ssl": False,
            "notification_email": "",
            "senders_name": "Your Name"
        })
		
@app.route('/admin/save_mail_settings', methods=['POST'])
@login_required
def admin_save_mail_settings():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    data = request.json
    try:
        with open("settings.json", "r") as f:
            settings = json.load(f)
    except FileNotFoundError:
        settings = {}

    settings.update({
        "mail_server": data.get("mail_server", settings.get("mail_server", "")),
        "mail_port": data.get("mail_port", settings.get("mail_port", 587)),
        "mail_username": data.get("mail_username", settings.get("mail_username", "")),
        "mail_password": data.get("mail_password", settings.get("mail_password", "")),
        "mail_use_tls": data.get("mail_use_tls", settings.get("mail_use_tls", True)),
        "mail_use_ssl": data.get("mail_use_ssl", settings.get("mail_use_ssl", False)),
        "notification_email": data.get("notification_email", settings.get("notification_email", "")),
        "senders_name": data.get("senders_name", settings.get("senders_name", "Your Name"))
    })

    with open("settings.json", "w") as f:
        json.dump(settings, f)

    return jsonify({'message': 'Mail settings saved successfully'})



rooms = {}  # Dictionary to track users in rooms
room_user_counts = {}  # Dictionary to track user counts in rooms
voice_chat_peers = {}  # Global dictionary to track voice chat participants

@socketio.on('join')
@login_required
def on_join(data):
    room_id = data['room_id']
    join_room(room_id)
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
        db.session.delete(message)
        db.session.commit()
        emit('delete_message', {'id': message_id}, room=room_id)
    else:
        print(f"Message ID: {message_id} not found or user not authorized")

@socketio.on('edit_message')
@login_required
def handle_edit_message(data):
    message_id = data['id']
    print(f"Editing message ID: {message_id}")
    message = Message.query.get(message_id)
    if message and message.username == current_user.username:
        message.content = data['content']
        db.session.commit()
        emit('edit_message', {'id': message_id, 'content': data['content']}, room=message.room_id)
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

    # Clean up empty rooms
    if not voice_chat_peers[room_id]:
        del voice_chat_peers[room_id]
    else:
        # If only one user is left, disconnect them
        if len(voice_chat_peers[room_id]) == 1:
            remaining_user = next(iter(voice_chat_peers[room_id]))
            emit('force_voice_disconnect', {'username': remaining_user}, room=room_id)
            del voice_chat_peers[room_id]

def generate_self_signed_cert(cert_file, key_file):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))

    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption()
        ))

def start_flask_app(host, port, debug, use_ssl, cert_file, key_file):
    with app.app_context():
        check_and_initialize_database()

    eventlet_socket = eventlet.listen((host, port))
    if use_ssl:
        eventlet_socket = eventlet.wrap_ssl(eventlet_socket,
                                            certfile=cert_file,
                                            keyfile=key_file,
                                            server_side=True)

    eventlet.wsgi.server(eventlet_socket, app)

def stop_flask_app():
    os._exit(0)

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
    start_flask_app(settings['host'], int(settings['port']), settings['debug'], settings['ssl'], settings['cert_file'], settings['key_file'])
    socketio.run(app, host=settings['host'], port=int(settings['port']), debug=settings['debug'])