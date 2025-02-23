from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# Storing user credentials (hashed passwords)
users = {
    'admin': generate_password_hash('password123'),
    'user1': generate_password_hash('mypassword')
}

# Store login attempts
login_history = []

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and check_password_hash(users[username], password):
            session['user'] = username
            login_history.append({
                'username': username,
                'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'Success'
            })
            return redirect(url_for('dashboard'))
        else:
            login_history.append({
                'username': username,
                'time': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'Failed'
            })
            return 'Invalid credentials. Try again!'
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return render_template('dashboard.html', user=session['user'])
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

@app.route('/view-hashes')
def view_hashes():
    if 'user' in session:
        return render_template('hashes.html', password_hashes=users.items())
    return redirect(url_for('login'))

@app.route('/history')
def view_history():
    if 'user' in session:
        return render_template('history.html', history=login_history)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)