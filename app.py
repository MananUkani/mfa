import sqlite3
from flask import Flask, request, redirect, url_for, render_template, session
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import osfrom flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import pyotp
import qrcode
from io import BytesIO
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key

def get_db_connection():
    conn = sqlite3.connect('mfa.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    qr_code = None

    if request.method == 'POST':
        action = request.form.get('action')
        username = request.form['username']
        password = request.form['password']

        if action == 'register':
            conn = get_db_connection()
            cur = conn.cursor()
            mfa_secret = pyotp.random_base32()
            try:
                cur.execute('INSERT INTO users (username, password, mfa_secret) VALUES (?, ?, ?)',
                            (username, password, mfa_secret))
                conn.commit()
                
                # Generate QR code
                otp_uri = pyotp.TOTP(mfa_secret).provisioning_uri(name=username, issuer_name='YourApp')
                qr = qrcode.make(otp_uri)
                buffered = BytesIO()
                qr.save(buffered, 'PNG')  # Removed format argument
                qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
                qr_code = qr_base64
                
                flash('Registration successful! Scan the QR code to set up MFA.')
            except sqlite3.IntegrityError:
                flash('Username already exists. Please log in instead.')
            finally:
                conn.close()

        elif action == 'login':
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cur.fetchone()
            conn.close()
            
            if user and user['password'] == password:
                # Store MFA secret in session to use it for verification
                session['username'] = username
                session['mfa_secret'] = user['mfa_secret']
                return redirect(url_for('mfa_verification'))
            else:
                flash('Invalid username or password')

    return render_template('index.html', qr_code=qr_code)

@app.route('/mfa_verification', methods=['GET', 'POST'])
def mfa_verification():
    if 'username' not in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        mfa_token = request.form['mfa_token']
        totp = pyotp.TOTP(session['mfa_secret'])
        if totp.verify(mfa_token):
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid MFA token')

    return render_template('mfa_verification.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('mfa_secret', None)
    return redirect(url_for('index'))

@app.route('/delete', methods=['POST'])
def delete():
    if 'username' not in session:
        return redirect(url_for('index'))

    username = session['username']
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()

    session.pop('username', None)
    session.pop('mfa_secret', None)
    flash('Account deleted successfully.')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)


app = Flask(__name__)
app.secret_key = '156abeefdbbaccc7896532486'

def init_db():
    if not os.path.exists('mfa.db'):
        with sqlite3.connect('mfa.db') as conn:
            conn.execute('''CREATE TABLE users
                            (id INTEGER PRIMARY KEY AUTOINCREMENT,
                             username TEXT UNIQUE NOT NULL,
                             password TEXT NOT NULL,
                             mfa_secret TEXT NOT NULL)''')

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('login'))
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('mfa.db')
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        existing_user = cur.fetchone()
        
        if existing_user:
            conn.close()
            return render_template('register.html', message='User already exists. Try a different username.')
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        mfa_secret = pyotp.random_base32()
        conn.execute('INSERT INTO users (username, password, mfa_secret) VALUES (?, ?, ?)',
                     (username, hashed_password, mfa_secret))
        conn.commit()
        conn.close()
        
        # Generate and save QR code
        totp = pyotp.TOTP(mfa_secret)
        uri = totp.provisioning_uri(name=username, issuer_name='YourAppName')
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        img.save('static/qrcode.png')

        return render_template('register.html', message='Registration successful. Please log in.')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        token = request.form['token']
        
        conn = sqlite3.connect('mfa.db')
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cur.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            totp = pyotp.TOTP(user[3])
            if totp.verify(token):
                session['username'] = username
                return redirect(url_for('protected'))
            else:
                return render_template('login.html', message='Invalid MFA token.')
        else:
            return render_template('login.html', message='Invalid username or password.')
    
    return render_template('login.html')

@app.route('/protected')
def protected():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    return 'Welcome to the protected page, {}!'.format(session['username'])

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']
    conn = sqlite3.connect('mfa.db')
    conn.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()
    session.pop('username', None)
    return redirect(url_for('register'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
