import sqlite3
from flask import Flask, request, redirect, url_for, render_template, session
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import os

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
