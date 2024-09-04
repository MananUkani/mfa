from flask import Flask, request, render_template, redirect, url_for, session, flash
import sqlite3
import pyotp
import qrcode
import io
import base64
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('mfa.db')
    try:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                mfa_secret TEXT NOT NULL
            )
        ''')
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()

init_db()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        action = request.form['action']

        conn = sqlite3.connect('mfa.db')
        cursor = conn.cursor()
        
        if action == 'register':
            mfa_secret = pyotp.random_base32()
            try:
                cursor.execute('INSERT INTO users (username, password, mfa_secret) VALUES (?, ?, ?)',
                               (username, generate_password_hash(password), mfa_secret))
                conn.commit()
                session['username'] = username
                # Generate QR code
                otp = pyotp.TOTP(mfa_secret)
                qr = qrcode.make(otp.provisioning_uri(name=username, issuer_name='MyApp'))
                buffered = io.BytesIO()
                qr.save(buffered, format="PNG")
                qr_code = "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode()
                return render_template('landing.html', qr_code=qr_code)
            except sqlite3.IntegrityError:
                flash('Username already exists. Please login.')
                return redirect(url_for('index'))
            except Exception as e:
                flash(f'Error: {e}')
                return redirect(url_for('index'))
        
        elif action == 'login':
            cursor.execute('SELECT password, mfa_secret FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            if row and check_password_hash(row[0], password):
                session['username'] = username
                session['mfa_secret'] = row[1]  # Save MFA secret in session for verification
                return redirect(url_for('mfa'))
            else:
                flash('Invalid username or password.')
                return redirect(url_for('index'))
        
        conn.close()

    return render_template('landing.html')

@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        token = request.form['token']
        otp = pyotp.TOTP(session.get('mfa_secret'))
        if otp.verify(token):
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid MFA token.')
            return redirect(url_for('mfa'))
    
    return render_template('mfa.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('dashboard.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    session.pop('mfa_secret', None)  # Remove MFA secret from session
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
