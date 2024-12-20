import re
import sqlite3
import contextlib
import datetime
from datetime import timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Flask, render_template, 
    request, session, redirect
)

from create_database import setup_database
from utils import login_required, set_session

app = Flask(__name__)

users_connection_string = 'users.db'

app.config['SECRET_KEY'] = 'EXAMPLE_xpSm7p5bgJY8rNoBjGWiz5yjxMNlW6231IBI62OkLc='
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=15)

setup_database(name=users_connection_string)

@app.route('/')
@login_required
def index():
    # Fetch assets with allocated username
    query = '''
    SELECT assets.id, assets.name, assets.description, assets.status, 
           users.username as allocated_to, assets.created_at, assets.updated_at 
    FROM assets 
    LEFT JOIN users ON assets.allocated_to = users.id
    '''
    
    with contextlib.closing(sqlite3.connect(users_connection_string)) as conn:
        with conn:
            assets = conn.execute(query).fetchall()
    
    # Fetch users for allocation dropdown (for admins)
    user_query = 'SELECT id, username FROM users'
    with contextlib.closing(sqlite3.connect(users_connection_string)) as conn:
        with conn:
            users = conn.execute(user_query).fetchall()
    
    return render_template('index.html', 
                           username=session.get('username'), 
                           role=session.get('role'),
                           assets=assets,
                           users=users)

@app.route('/add_asset', methods=['POST'])
@login_required
def add_asset():
    name = request.form.get('name')
    description = request.form.get('description')
    status = request.form.get('status')
    allocated_to = request.form.get('allocated_to')
    
    # Validate inputs
    if not name or not status:
        return jsonify({"error": "Name and status are required"}), 400
    
    query = '''
    INSERT INTO assets (name, description, status, allocated_to, created_at, updated_at) 
    VALUES (:name, :description, :status, :allocated_to, :created_at, :updated_at)
    '''
    
    params = {
        'name': name,
        'description': description or None,
        'status': status,
        'allocated_to': int(allocated_to) if allocated_to else None,
        'created_at': datetime.datetime.now(),
        'updated_at': datetime.datetime.now()
    }
    
    with contextlib.closing(sqlite3.connect(users_connection_string)) as conn:
        with conn:
            conn.execute(query, params)
    
    return redirect('/')

@app.route('/edit_asset/<int:asset_id>', methods=['POST'])
@login_required
def edit_asset(asset_id):
    # Get the current user's information
    current_username = session.get('username')
    current_role = session.get('role')
    
    # First, check if the user has permission to edit this asset
    query = '''
    SELECT assets.*, users.username as allocated_to_username 
    FROM assets 
    LEFT JOIN users ON assets.allocated_to = users.id 
    WHERE assets.id = ?
    '''
    
    with contextlib.closing(sqlite3.connect(users_connection_string)) as conn:
        with conn:
            asset = conn.execute(query, (asset_id,)).fetchone()
    
    if not asset:
        return jsonify({"error": "Asset not found"}), 404
        
    # Check permissions
    if current_role != 'admin':
        # Regular users can only edit unallocated assets or assets allocated to them
        if asset[-1] and asset[-1] != current_username:  # asset[-1] is allocated_to_username
            return jsonify({"error": "Access Denied"}), 403
    
    name = request.form.get('name')
    description = request.form.get('description')
    status = request.form.get('status')
    
    # Only admins can change allocation
    if current_role == 'admin':
        allocated_to = request.form.get('allocated_to')
    else:
        # Regular users maintain the current allocation
        allocated_to = asset[4]  # Keep existing allocation
    
    # Validate inputs
    if not name or not status:
        return jsonify({"error": "Name and status are required"}), 400
    
    query = '''
    UPDATE assets 
    SET name = :name, 
        description = :description, 
        status = :status, 
        allocated_to = :allocated_to, 
        updated_at = :updated_at 
    WHERE id = :asset_id
    '''
    
    params = {
        'asset_id': asset_id,
        'name': name,
        'description': description or None,
        'status': status,
        'allocated_to': int(allocated_to) if allocated_to else None,
        'updated_at': datetime.datetime.now()
    }
    
    with contextlib.closing(sqlite3.connect(users_connection_string)) as conn:
        with conn:
            conn.execute(query, params)
    
    return redirect('/')

@app.route('/delete_asset/<int:asset_id>', methods=['POST'])
@login_required
def delete_asset(asset_id):
    # Only admin can delete assets
    if session.get('role') != 'admin':
        return jsonify({"error": "Access Denied"}), 403
    
    query = 'DELETE FROM assets WHERE id = ?'
    
    with contextlib.closing(sqlite3.connect(users_connection_string)) as conn:
        with conn:
            conn.execute(query, (asset_id,))
    
    return redirect('/')
    
@app.route('/logout')
def logout():
    session.clear()
    session.permanent = False
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    # Set data to variables
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Attempt to query associated user data
    query = 'select username, password, email, role from users where username = :username;'

    with contextlib.closing(sqlite3.connect(users_connection_string)) as conn:
        with conn:
            account = conn.execute(query, {'username': username}).fetchone()

    if not account: 
        return render_template('login.html', error='Username does not exist')

    # Verify password
    try:
        ph = PasswordHasher()
        ph.verify(account[1], password)
    except VerifyMismatchError:
        return render_template('login.html', error='Incorrect password')

    # Check if password hash needs to be updated
    if ph.check_needs_rehash(account[1]):
        query = 'update set password = :password where username = :username;'
        params = {'password': ph.hash(password), 'username': account[0]}

        with contextlib.closing(sqlite3.connect(users_connection_string)) as conn:
            with conn:
                conn.execute(query, params)

    print("Account information:")
    print(account)
    # Set cookie for user session
    set_session(
        username=account[0],
        role=account[3],
        remember_me='remember-me' in request.form
    )
    
    return redirect('/')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    # Store data to variables 
    password = request.form.get('password')
    confirm_password = request.form.get('confirm-password')
    username = request.form.get('username')
    email = request.form.get('email')

    # Verify data
    if len(password) < 8:
        return render_template('register.html', error='Your password must be 8 or more characters')
    if password != confirm_password:
        return render_template('register.html', error='Passwords do not match')
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return render_template('register.html', error='Username must only be letters and numbers')
    if not 3 < len(username) < 26:
        return render_template('register.html', error='Username must be between 4 and 25 characters')

    query = 'SELECT username FROM users WHERE username = :username;'
    with contextlib.closing(sqlite3.connect(users_connection_string)) as conn:
        with conn:
            result = conn.execute(query, {'username': username}).fetchone()
    if result:
        return render_template('register.html', error='Username already exists')

    # Create password hash
    pw = PasswordHasher()
    hashed_password = pw.hash(password)

    # FIXED: Corrected SQL query and parameter names
    query = '''
        INSERT INTO users (username, password, email, role, created_at) 
        VALUES (:username, :password, :email, :role, :created_at);
    '''
    params = {
        'username': username,
        'password': hashed_password,
        'email': email,
        'role': 'user',
        'created_at': datetime.datetime.now()
    }

    with contextlib.closing(sqlite3.connect(users_connection_string)) as conn:
        with conn:
            conn.execute(query, params)

    # We can log the user in right away since no email verification
    set_session(username=username, role='user')
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
