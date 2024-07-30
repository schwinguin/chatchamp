# admin.py
import os
import json
import threading
from datetime import datetime, timezone, timedelta
from flask import Flask, jsonify, request
from flask_login import current_user, login_required
from flask_sqlalchemy import SQLAlchemy
import smtplib
from email.message import EmailMessage
from email_validator import validate_email, EmailNotValidError
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import eventlet
import eventlet.wsgi

# Import models from the models.py file
from models import User, ChatRoom, Message, db

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

@login_required
def admin_generate_certificate():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    cert_file = "selfsigned.crt"
    key_file = "selfsigned.key"
    generate_self_signed_cert(cert_file, key_file)
    return jsonify({'cert_file': cert_file, 'key_file': key_file})

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

@login_required
def admin_start_server(app):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    host = request.json.get('host', '0.0.0.0')
    port = int(request.json.get('port', 5000))
    debug = request.json.get('debug', False)
    use_ssl = request.json.get('ssl', False)
    cert_file = request.json.get('cert_file', 'selfsigned.crt')
    key_file = request.json.get('key_file', 'selfsigned.key')
    
    flask_thread = threading.Thread(target=start_flask_app, args=(app, host, port, debug, use_ssl, cert_file, key_file))
    flask_thread.daemon = True
    flask_thread.start()
    return jsonify({'message': 'Server started successfully'})

@login_required
def admin_stop_server():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403

    stop_flask_app()
    return jsonify({'message': 'Server stopped successfully'})

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
        "mail_port": data.get("mail_port", 587),
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

def generate_self_signed_cert(cert_file, key_file):
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

def start_flask_app(app, host, port, debug, use_ssl, cert_file, key_file):
    eventlet_socket = eventlet.listen((host, port))
    if use_ssl:
        eventlet_socket = eventlet.wrap_ssl(eventlet_socket,
                                            certfile=cert_file,
                                            keyfile=key_file,
                                            server_side=True)

    eventlet.wsgi.server(eventlet_socket, app)

def stop_flask_app():
    os._exit(0)
