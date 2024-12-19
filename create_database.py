import sqlite3
import contextlib
from pathlib import Path
from argon2 import PasswordHasher
import random
from datetime import datetime

def create_connection(db_file: str) -> None:
    """ Create a database connection to a SQLite database """
    try:
        conn = sqlite3.connect(db_file)
    finally:
        conn.close()

def create_tables(db_file: str) -> None:
    """ Create tables for users and assets """
    users_table_query = '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL, -- 'admin' or 'user'
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    '''

    assets_table_query = '''
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL,
            allocated_to INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (allocated_to) REFERENCES users(id)
        );
    '''

    with contextlib.closing(sqlite3.connect(db_file)) as conn:
        with conn:
            conn.execute(users_table_query)
            conn.execute(assets_table_query)

def create_admin_account(db_file: str) -> None:
    """ Create an admin account with a secure password """
    # Generate a strong, unique admin password
    ph = PasswordHasher()
    admin_password = ph.hash('Admin')
    
    query = '''
        INSERT OR IGNORE INTO users (username, email, password, role) 
        VALUES (?, ?, ?, ?)
    '''
    
    try:
        with contextlib.closing(sqlite3.connect(db_file)) as conn:
            with conn:
                conn.execute(query, ('Admin', 'admin@admin.com', admin_password, 'admin'))
        
        print('\033[92m', 'Admin account created successfully', '\033[0m')
    except sqlite3.IntegrityError:
        print('\033[93m', 'Admin account already exists', '\033[0m')
    except Exception as e:
        print('\033[91m', f'Error creating admin account: {e}', '\033[0m')

def create_sample_assets(db_file: str) -> None:
    """ Generate random assets with predefined names, descriptions, and statuses """
    asset_names = ["Monitor", "Mouse", "Keyboard", "Laptop", "Printer", "Webcam", "Speaker", "Router", "Chair", "Desk"]
    statuses = ["Available", "In Use", "Damaged", "Maintenance"]

    # Generate asset data
    asset_data = [
        (
            name,
            f"A {name.lower()} for office use.",
            random.choice(statuses),
            None  # Initially, assets are not allocated
        )
        for name in asset_names
    ]

    query = '''
        INSERT INTO assets (name, description, status, allocated_to)
        VALUES (?, ?, ?, ?)
    '''
    
    try:
        with contextlib.closing(sqlite3.connect(db_file)) as conn:
            with conn:
                conn.executemany(query, asset_data)
        
        print('\033[92m', 'Sample assets created successfully', '\033[0m')
    except sqlite3.IntegrityError as e:
        print('\033[93m', f'Error inserting sample assets: {e}', '\033[0m')
    except Exception as e:
        print('\033[91m', f'Unexpected error: {e}', '\033[0m')

def create_sample_users(db_file: str) -> None:
    """ Generate 10 sample users with hashed passwords """
    ph = PasswordHasher()
    user_data = [
        (name, f"{name.lower()}@gmail.com", ph.hash(name), "user")
        for name in ["Bob", "Alice", "Charlie", "David", "Eve", "Frank", "Grace", "Hannah", "Isaac", "Julia"]
    ]
    
    query = '''
        INSERT OR IGNORE INTO users (username, email, password, role)
        VALUES (?, ?, ?, ?)
    '''
    
    try:
        with contextlib.closing(sqlite3.connect(db_file)) as conn:
            with conn:
                conn.executemany(query, user_data)
        
        print('\033[92m', 'Sample users created successfully', '\033[0m')
    except sqlite3.IntegrityError as e:
        print('\033[93m', f'Error inserting sample users: {e}', '\033[0m')
    except Exception as e:
        print('\033[91m', f'Unexpected error: {e}', '\033[0m')



def setup_database(name: str) -> None:
    if Path(name).exists():
        return

    create_connection(name)
    create_tables(name)
    create_admin_account(name)

    #Optional sample data
    create_sample_users(name)
    create_sample_assets(name)

    print('\033[92m', f'Successfully created: {name} database!', '\033[0m')
