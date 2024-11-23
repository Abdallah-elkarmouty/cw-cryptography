import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-new-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file_verification.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'docx'}

# Ensure the uploads and static directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('static', exist_ok=True)

# RSA key pair generation
if not os.path.exists('private_key.pem') or not os.path.exists('public_key.pem'):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    # Save private key
    with open('private_key.pem', 'wb') as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key
    with open('public_key.pem', 'wb') as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Load RSA keys
with open('private_key.pem', 'rb') as private_file:
    private_key = serialization.load_pem_private_key(private_file.read(), password=None, backend=default_backend())

with open('public_key.pem', 'rb') as public_file:
    public_key = serialization.load_pem_public_key(public_file.read(), backend=default_backend())

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    files = db.relationship('File', backref='user', lazy=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False)
    encrypted_aes_key = db.Column(db.LargeBinary, nullable=False)
    file_metadata = db.Column(db.String(200), nullable=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def hash_file(file_path):
    """Generate SHA-256 hash of a file."""
    hasher = sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def generate_aes_key():
    """Generate a random 32-byte AES key."""
    return os.urandom(32)

def encrypt_file(file_path, aes_key):
    """Encrypts the file at file_path using AES encryption."""
    with open(file_path, 'rb') as file:
        data = file.read()

    # Pad data to be a multiple of the block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt data
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(padded_data) + encryptor.finalize()

    # Write the encrypted data back to the file
    with open(file_path, 'wb') as file:
        file.write(encrypted_data)

def decrypt_file(file_path, aes_key):
    """Decrypts the file at file_path using AES decryption."""
    with open(file_path, 'rb') as file:
        data = file.read()

    # Extract the IV and encrypted data
    iv = data[:16]
    encrypted_data = data[16:]

    # Decrypt data
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the data
    unpadder = padding.PKCS7(128).unpadder()
    try:
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    except ValueError as e:
        raise ValueError("Decryption failed due to invalid padding.") from e

    return unpadded_data

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_files = File.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', files=user_files, username=session.get('username'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or file.filename == '':
            flash('No file selected')
            return redirect(url_for('dashboard'))
        if not allowed_file(file.filename):
            flash('Invalid file type')
            return redirect(url_for('dashboard'))
        
        original_filename = secure_filename(file.filename)
        encrypted_filename = f"{original_filename}.encrypted"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], encrypted_filename)
        file.save(file_path)

        # Generate AES key and encrypt the file
        aes_key = generate_aes_key()
        encrypt_file(file_path, aes_key)

        # Encrypt AES key with RSA public key
        encrypted_aes_key = public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Store file metadata, hash, and encrypted AES key
        file_hash = hash_file(file_path)
        file_metadata = f"Size: {os.path.getsize(file_path)} bytes"
        new_file = File(
            filename=encrypted_filename,
            user_id=session['user_id'],
            file_hash=file_hash,
            encrypted_aes_key=encrypted_aes_key,
            file_metadata=file_metadata
        )
        db.session.add(new_file)
        db.session.commit()
        flash('File uploaded and encrypted successfully')
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    file_record = File.query.filter_by(filename=filename, user_id=session['user_id']).first()
    if not file_record:
        flash("File not found in your uploads.")
        return redirect(url_for('dashboard'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        flash("File is missing on the server.")
        return redirect(url_for('dashboard'))

    # Decrypt AES key with RSA private key
    try:
        aes_key = private_key.decrypt(
            file_record.encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        flash(f"Failed to decrypt the AES key: {str(e)}")
        return redirect(url_for('dashboard'))

    # Decrypt the file
    try:
        decrypted_data = decrypt_file(file_path, aes_key)
    except Exception as e:
        flash(f"Failed to decrypt the file: {str(e)}")
        return redirect(url_for('dashboard'))

    decrypted_filename = filename.rsplit('.', 1)[0]
    temp_file_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{decrypted_filename}_decrypted")

    try:
        with open(temp_file_path, 'wb') as temp_file:
            temp_file.write(decrypted_data)

        return send_file(temp_file_path, as_attachment=True, download_name=decrypted_filename)

    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    file = File.query.filter_by(filename=filename, user_id=session['user_id']).first()
    if file:
        db.session.delete(file)
        db.session.commit()
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        flash('File deleted successfully')
    else:
        flash("File not found.")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
