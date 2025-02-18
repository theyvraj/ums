#C:\Users\Admin\Documents\devraj_intern\live

from flask import Flask, request, render_template, redirect, url_for, flash, session
import sqlite3
import json
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.urandom(26)

db_file = 'user_data.db'
UPLOAD_FOLDER = 'static/image_uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_db():
    conn = sqlite3.connect(db_file)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as gd:
        gd.execute('''create table if not exists users(
                   id integer primary key autoincrement,
                   username text not null unique,
                   email text not null,
                   password text not null,
                   phone_number text,
                   date_of_birth date,
                   profile_picture text,
                   is_admin boolean not null default 0)''')

        gd.commit()
init_db()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        action = request.form['action']
        if action == 'Signup':
            return redirect(url_for('signup'))
        elif action == 'Login':
            return redirect(url_for('login'))
    return render_template('index.html')


@app.route('/home')
def home():
    if 'username' in session:
        username = session['username']
        with get_db() as gd:
            user_info = gd.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            
            if user_info:
                if user_info['is_admin']:
                    return redirect(url_for('admin_dashboard'))
                else:
                    return render_template('home.html', username=username, user_info=user_info)
            else:
                flash("User not found. Please log in again.")
                session.pop('username', None)
                return redirect(url_for('login'))
    else:
        return redirect(url_for('index'))

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        phone_number = request.form['phone_number']
        date_of_birth = request.form['date_of_birth']
        user_type = request.form['user_type']
        secret_key = request.form['secret_key']
        
        profile_picture_filename = None
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                profile_picture_filename = f"{username}_{secure_filename(file.filename)}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], profile_picture_filename))
            else:
                flash("Invalid file type for profile picture.")
                return redirect(url_for('signup'))

        admin_key = 'sMBoP4x6hsR19INuVkCWn7GZ'
        with get_db() as gd:
            existing_user = gd.execute('select * from users where username = ?', (username,)).fetchone()
            if existing_user:
                flash("User already registered, Please choose a different one or login.")
            else:
                is_admin = False
                if user_type == 'admin':
                    if secret_key == admin_key:
                        is_admin = True
                    else:
                        flash("Invalid secret key")
                        return redirect(url_for('signup'))
                
                gd.execute('insert into users (username, email, password, phone_number, date_of_birth, profile_picture, is_admin) values (?,?,?,?,?,?,?)',
                           (username, email, password, phone_number, date_of_birth, profile_picture_filename, is_admin))

                gd.commit()
                flash("Registration Successful. Please log in.")
                return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        with get_db() as gd:
            user_info = gd.execute('select * from users where username = ?', (username,)).fetchone()
            if user_info and user_info['password'] == password:
                session['username'] = username
                return redirect(url_for('home'))
            else:
                flash("Invaild credentials. Please try again.")
    return render_template('login.html')


@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    if 'username' in session:
        username = session['username']
        with get_db() as gd:
            user_info = gd.execute('select * from users where username = ?', (username,)).fetchone()
            if user_info and user_info['is_admin']:
                users = gd.execute('select * from users').fetchall()
                admin_info = user_info

                return render_template('admin_dashboard.html', users=users, admin_info=admin_info)
            else:
                flash("Access denied. Admins only.")
                return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'username' in session:
        username = session['username']
        with get_db() as gd:
            user_info = gd.execute('select * from users where username = ?', (username,)).fetchone()
            if user_info and user_info['is_admin']:
                if request.method == 'POST':
                    new_username = request.form['username']
                    new_email = request.form['email']
                    new_phone_number = request.form['phone_number']
                    new_date_of_birth = request.form['date_of_birth']
                    gd.execute('update users set username = ?, email = ?, phone_number = ?, date_of_birth = ? where id = ?', (new_username, new_email, new_phone_number, new_date_of_birth, user_id))
                    gd.commit()
                    flash("User updated successfully.")
                    return redirect(url_for('admin_dashboard'))
                user = gd.execute('select * from users where id = ?', (user_id,)).fetchone()
                return render_template('edit_user.html', user=user)
            else:
                flash("Access denied. Admins only.")
                return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if 'username' in session:
        username = session['username']
        with get_db() as gd:
            user_info = gd.execute('select * from users where username = ?', (username,)).fetchone()
            if user_info and user_info['is_admin']:
                if user_id == user_info['id']:
                    flash("You cannot delete your own account.")
                    return redirect(url_for('admin_dashboard'))
                gd.execute('delete from users where id = ?', (user_id,))
                gd.commit()
                alert_message = '<div class="alert alert-success" role="alert">User deleted successfully.</div>'
                return alert_message
            else:
                flash("Access denied. Admins only.")
                return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='192.168.211.5', debug=False, port=8080)
