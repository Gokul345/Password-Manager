import mysql.connector
from flask import Flask, render_template,send_file, request, redirect, url_for,jsonify, session,flash
import base64
from datetime import datetime, timedelta
import logging
from password_strength import PasswordPolicy
import plotly.express as px
import os
import pandas as pd
from typing import Dict
from werkzeug.utils import secure_filename
import io
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas
from matplotlib.figure import Figure
import base64
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import mplcursors  # Import the mplcursors library
import random
import smtplib
from email.mime.text import MIMEText
import re
from email.mime.text import MIMEText
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
import string
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask_session import Session
import json  # Import the json module at the beginning of your script
import csv
app = Flask(__name__)
app.secret_key = 'my_secret_key_1234'  # Replace with your actual secret key
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
app.config['SESSION_TYPE'] = 'filesystem'  # or 'redis', 'memcached', etc.
Session(app)    
# Establish database connection

# Function to establish a database connection
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="12345678",
        auth_plugin="mysql_native_password",
        database="PASSWORD_MANAGER"
    )

# Function to execute a query
def execute_query(query, params=None, fetch=True, commit=False):
    conn = get_db_connection()
    cur = None
    try:
        cur = conn.cursor()
        cur.execute(query, params)
        if commit:
            conn.commit()
        if fetch:
            result = cur.fetchall()
            return result
        else:
            return None
    except mysql.connector.Error as e:
        logger.error(f"An error occurred during query execution: {e}")
        conn.rollback()
        return None
    finally:
        if cur:
            cur.close()
        conn.close()

# Create database and tables
execute_query("CREATE DATABASE IF NOT EXISTS PASSWORD_MANAGER;",fetch=False)
execute_query("USE PASSWORD_MANAGER;",fetch=False)
execute_query('''CREATE TABLE IF NOT EXISTS password(
                pwd_id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(50),
                email VARCHAR(100),
                password VARCHAR(50),
                folder VARCHAR(100),
                category VARCHAR(100),
                url VARCHAR(100))''',fetch=False)

execute_query('''CREATE TABLE IF NOT EXISTS payments(
                pym_id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(50),
                email VARCHAR(100),
                password VARCHAR(50),
                folder VARCHAR(100),
                category VARCHAR(100),
                account_number VARCHAR(50),
                ifsc VARCHAR(50),
                branch VARCHAR(50),
                bank_name VARCHAR(50),
                url VARCHAR(100))''',fetch=False)
execute_query('''CREATE TABLE IF NOT EXISTS category(
                cat_id INT AUTO_INCREMENT PRIMARY KEY,
                category_name VARCHAR(100))''',fetch=False)
execute_query('''
    CREATE TABLE IF NOT EXISTS folder (
        folder_id INT AUTO_INCREMENT PRIMARY KEY,
        folder_name VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''',fetch=False)

execute_query('''CREATE TABLE IF NOT EXISTS user(
            id INT AUTO_INCREMENT PRIMARY KEY   ,
            username VARCHAR(50),
            email VARCHAR(100),
            mobile VARCHAR(100),
            hashed_password VARCHAR(256),
            encrypted_password VARCHAR(256),
            actual_password VARCHAR(256),
            profile_image LONGBLOB,
            address TEXT)''',fetch=False)
execute_query('''CREATE TABLE IF NOT EXISTS delete_items(
            id INT AUTO_INCREMENT PRIMARY KEY   ,
            item_id int ,
            item_name varchar(100) ,
            item_type enum('Folder','Password') ,
            deleted_at timestamp DEFAULT CURRENT_TIMESTAMP,
            created_at timestamp ,
            category varchar(45) ,
            folder varchar(50) ,
            email varchar(45) ,
            url varchar(45) ,
            password varchar(45))''',fetch=False)
policy = PasswordPolicy.from_names(
    length=8,  # Minimum length
    uppercase=1,  # Minimum number of uppercase letters
    numbers=1,  # Minimum number of digits
    special=1  # Minimum number of special characters
)
def generate_strong_password(length=16):
    try:
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password
    except Exception as e:
        print(f"Error in generating password: {e}")
        raise

def encrypt_password_aes(password, aes_key):
    try:
        cipher = AESGCM(aes_key)
        nonce = secrets.token_bytes(12)
        encrypted_password = cipher.encrypt(nonce, password.encode('utf-8'), None)
        return base64.b64encode(nonce + encrypted_password).decode('utf-8')
    except Exception as e:
        print(f"Error in encrypting password: {e}")
        raise

def decrypt_password_aes(encrypted_password, aes_key):
    try:
        encrypted_password_bytes = base64.b64decode(encrypted_password)
        nonce = encrypted_password_bytes[:12]
        encrypted_password_bytes = encrypted_password_bytes[12:]
        cipher = AESGCM(aes_key)
        decrypted_password = cipher.decrypt(nonce, encrypted_password_bytes, None).decode('utf-8')
        return decrypted_password
    except Exception as e:
        print(f"Error in decrypting password: {e}")
        raise

def derive_shared_key(private_key, peer_public_key):
    try:
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        salt = os.urandom(16)
        derived_key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        ).derive(shared_key)
        return derived_key
    except Exception as e:
        print(f"Error in deriving shared key: {e}")
        raise

def generate_ecc_keys():
    try:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key
    except Exception as e:
        print(f"Error in generating ECC keys: {e}")
        raise

# Mock function to check if email exists in database
def check_email_exists(email):
    existing_user=execute_query("SELECT email FROM user WHERE email=%s", (email,),fetch=True)
    return existing_user is not None
# Function to validate password complexity
def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>)."
    return True, None
def calculate_average_strength(passwords):
    """Calculate the average strength of passwords."""
    total_strength = 0
    count = len(passwords)
    
    if count == 0:
        return 0

    for password in passwords:
        try:
            # Check if the password meets the policy
            if policy.test(password):
                strength = 0
            else:
                # Basic scoring mechanism (you can customize this)
                strength = min(len(password) / 8, 1) * 100
            total_strength += strength
        except Exception as e:
            logging.error(f"Error evaluating strength for password '{password}': {e}")
    
    # Calculate average strength as a percentage (0 to 100 scale)
    return total_strength / count if count > 0 else 0
def analyze_password_strength(password: str) -> str:
    """Analyze password strength based on length."""
    if not isinstance(password, str):
        logger.warning(f"Non-string password encountered: {password}")
        return 'Unknown'
    length = len(password)
    if length < 8:
        return 'Weak'
    elif length < 12:
        return 'Moderate'
    else:
        return 'Strong'

def get_password_strength_distribution(df: pd.DataFrame) -> Dict[str, int]:
    """Get distribution of password strengths from a DataFrame."""
    df['password_strength'] = df['password'].apply(analyze_password_strength)
    strength_counts = df['password_strength'].value_counts()
    return strength_counts.to_dict()
def delete_old_items():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        thirty_days_ago = datetime.now().date() - timedelta(days=30)
        query = """
        DELETE FROM delete_items
        WHERE deleted_at <= %s
        """
        cursor.execute(query, (thirty_days_ago,))
        conn.commit()
    except mysql.connector.Error as e:
        print(f"An error occurred: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()
# Base64 filter for encoding binary data
@app.template_filter('b64encode')
def b64encode_filter(data):
    if data:
        return base64.b64encode(data).decode('utf-8')
    return ''
app.jinja_env.filters['b64encode'] = b64encode_filter

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        
        # Example SQL query to check credentials (sanitize inputs to prevent SQL injection)
        user=execute_query("SELECT email, password FROM user WHERE email=%s AND password=%s", (email, password),fetch=True)
        
        if user:
            # Store user email in session
            session['email'] = email
            return redirect(url_for('main'))  # Redirect to home page on successful login
        else:
            error_message = "Invalid email or password."
            return render_template('login1.html', error=error_message)
    
    return render_template('login1.html')  # For GET requests or initial load of the page
@app.route('/generate_password', methods=['POST'])
def generate_password():
    try:
        length = 16
        password = generate_strong_password(length)
        
        # Generate ECC key pairs
        private_key_1, public_key_1 = generate_ecc_keys()
        private_key_2, public_key_2 = generate_ecc_keys()

        # Derive shared AES key using ECDH
        aes_key_1 = derive_shared_key(private_key_1, public_key_2)
        aes_key_2 = derive_shared_key(private_key_2, public_key_1)

        # Encrypt the password
        encrypted_password = encrypt_password_aes(password, aes_key_1)

        # Return results as JSON
        return jsonify({
            'generated_password': password,
            'encrypted_password': encrypted_password
        })
    except Exception as e:
        print(f"Error in /generate_password route: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        user = request.form.get('username')
        em = request.form.get('email')
        mob = request.form.get('mobile')
        pwd = request.form.get('pwd')
        cpwd = request.form.get('re-pwd')
        ph = PasswordHasher()
        hashed_password = ph.hash(pwd)
        
        # Generate an AES key for encryption
        aes_key = os.urandom(16)
        encrypted_password = encrypt_password_aes(pwd, aes_key)
        actual_password = encrypt_password_aes(pwd, aes_key)  # Store actual password encrypted

        # Check if the email already exists in the database
        existing_user = execute_query("SELECT email FROM user WHERE email=%s", (em,), fetch=True)
        
        if existing_user:
            msg = "Email already registered. Please use a different email."
            return render_template('signup1.html', error=msg)
        
        # Validate password
        is_valid, error_message = validate_password(pwd)
        if not is_valid:
            return render_template('signup1.html', error=error_message)
        
        if pwd == cpwd:
            try:
                # Insert new user into the database
                execute_query(
                    "INSERT INTO user (username, email, mobile, hashed_password, encrypted_password, actual_password,password) VALUES (%s, %s, %s, %s, %s, %s,%s)",
                    (user, em, mob, hashed_password, encrypted_password, actual_password,pwd),
                    fetch=False,
                    commit=True  # Ensure the transaction is committed
                )
                return redirect(url_for('login'))  # Redirect to login page after successful signup
            except Exception as e:
                logging.error(f"Error inserting into the database: {e}")
                msg = "There was an error processing your request. Please try again."
                return render_template('signup1.html', error=msg)
        else:
            msg = "Passwords do not match."
            return render_template('signup1.html', error=msg)
    
    # For GET requests or initial load of the page
    return render_template('signup1.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == "POST":
        email = request.form['email']

        # Check if email exists in the database
        if not check_email_exists(email):
            return render_template('forgot.html', error="Email not registered")

        # Generate and send OTP to user's email
        send_otp(email)
        session['email'] = email  # Store email in session for OTP verification
        return redirect(url_for('otp_verification'))

    return render_template('forgot.html')

@app.route('/otp', methods=['GET', 'POST'])
def otp_verification():
    if 'email' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        user_input_otp = request.form['otp']

        # Retrieve the stored OTP from session
        otp = session.get('otp')
        if not otp:
            return render_template('otp.html')
        if user_input_otp !=otp:
             return render_template('otp.html',error="Invalid OTP. Please try again.")
        if user_input_otp == otp:
            # OTP verified successfully, proceed to reset password page
            return redirect(url_for('reset_password',error="OTP verified successfully"))
    # Render the OTP verification form
    return render_template('otp.html')

@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if 'email' not in session:
        return redirect(url_for('login'))

    if request.method == "POST":
        new_password = request.form['pwd']

        # Update password in the database (replace with your actual update query)
        execute_query("UPDATE user SET password=%s WHERE email=%s", (new_password, session['email']),commit=True  # Ensure the transaction is committed
)

        # Clear session after password reset
        session.pop('email', None)

        return redirect(url_for('login'))

    return render_template('reset.html')

def send_otp(email):
    sender_email = 'gokulakrishnan0078@gmail.com'  # Replace with your email
    sender_password = 'rotk vcgm mfjj iosi'  # Replace with your email password

    # Generate OTP
    otp = str(random.randint(100000, 999999))  # Generate a 6-digit OTP
    session['otp'] = otp  # Store OTP in session for verification

    message = MIMEText(f'Your OTP is: {otp}')
    message['Subject'] = 'One-Time Password (OTP)'
    message['From'] = sender_email
    message['To'] = email

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, message.as_string())
        server.quit()

        return "OTP sent successfully"
    except Exception as e:
        return f"Failed to send OTP: {e}"
@app.route('/logout',methods=['GET','POST'])
def logout():
        # Clear the session
    session.pop('user_id', None)
    session.pop('username', None)
    
    # Redirect to the login page
    return redirect(url_for('login'))

@app.route('/main', methods=['GET'])
def main():
    if 'email' not in session:
        return redirect(url_for('login'))

    email = session['email']

    # Fetch user's name and profile image using the email
    user_data = execute_query("SELECT username, profile_image FROM user WHERE email = %s", (email,), fetch=True)

    if user_data and len(user_data) > 0:
        user = user_data[0]  # Access the first (and only) row returned by the query
        name = user[0]
        profile_image = user[1]
    else:
        name = "User"
        profile_image = None    

    # Store user data in session
    session['name'] = name
    session['profile_image'] = profile_image

    return render_template('db1.html', name=name, profile_image=profile_image)
@app.route('/calculate_overall_strength', methods=['GET'])
def calculate_overall_strength():
    """Fetch passwords for the current user and calculate overall strength."""
    try:
        # Ensure the user is logged in
        if 'email' not in session:
            return jsonify({'error': 'User not logged in'}), 401
        
        # Get the current user's email from the session
        user_email = session['email']
        
        # Fetch passwords for the current user from the database
        query = "SELECT password FROM password WHERE user_email=%s"
        passwords_data = execute_query(query, (user_email,))
        
        # Extract passwords as a list
        passwords = [row[0] for row in passwords_data]

        # If no passwords exist for the user, return zero strength
        if not passwords:
            return jsonify({'strength': 0})
        
        # Calculate average strength using your function
        average_strength = calculate_average_strength(passwords)
        
        return jsonify({'strength': average_strength})
    
    except Exception as e:
        logging.error(f"Error fetching or processing passwords: {e}")
        return jsonify({'error': str(e)}), 500
@app.route('/update_profile', methods=['GET', 'POST'])
def update_profile():
    if 'email' not in session:
        return redirect(url_for('login'))

    email = session['email']

    if request.method == 'POST':
        mobile = request.form.get('mobile', '')
        address = request.form.get('address', '')
        profile_image = request.files.get('profile_image')

        # Handle the profile image
        if profile_image and profile_image.filename != '':
            profile_image_data = profile_image.read()
        else:
            profile_image_data = None

        # Prepare the SQL and values depending on whether a profile image is provided
        if profile_image_data:
            sql = '''UPDATE user SET mobile = %s, address = %s, profile_image = %s WHERE email = %s'''
            values = (mobile, address, profile_image_data, email)
        else:
            sql = '''UPDATE user SET mobile = %s, address = %s WHERE email = %s'''
            values = (mobile, address, email)

        # Execute the query to update the database
        execute_query(sql, values, fetch=False, commit=True)

        # Update the session variables
        session['mobile'] = mobile
        session['address'] = address
        if profile_image_data:
            session['profile_image'] = profile_image_data

        flash('Profile updated successfully.', 'success')
        return redirect(url_for('main'))

    # Fetch the user data for displaying on the profile page
    user_data = execute_query("SELECT username, mobile, profile_image, address FROM user WHERE email = %s", (email,), fetch=True)

    # Check if data exists and prepare the user dictionary
    if user_data:
        user_data = user_data[0]  # Get the first row returned
        user = {
            'name': user_data[0],
            'email': email,
            'mobile': user_data[1],
            'profile_image': user_data[2],
            'address': user_data[3]
        }
    else:
        user = {
            'name': '',
            'email': email,
            'mobile': '',
            'profile_image': None,
            'address': ''
        }

    return render_template('profile.html', user=user)

@app.route('/dashboard', methods=['GET'])
def dashboard():
    try:
        # Ensure the user is logged in by checking the session
        if 'email' not in session:
            return redirect(url_for('login'))  # Redirect to login if not logged in
        
        # Retrieve current user's email from session
        user_email = session['email']
        
        # Fetch the number of passwords and folders for the current user
        pwd_count = execute_query("SELECT count(password) FROM password WHERE user_email=%s", (user_email,), fetch=True)
        folder_count = execute_query("SELECT count(folder_name) FROM folder WHERE user_email=%s", (user_email,), fetch=True)
        
        # Set default counts if no results are returned
        pwd_count = pwd_count[0][0] if pwd_count else 0
        folder_count = folder_count[0][0] if folder_count else 0
        # Fetch the counts for strong, moderate, and weak passwords
        strong_count = execute_query("SELECT COUNT(password) FROM password WHERE user_email=%s AND strength='strong'", (user_email,), fetch=True)
        moderate_count = execute_query("SELECT COUNT(password) FROM password WHERE user_email=%s AND strength='moderate'", (user_email,), fetch=True)
        weak_count = execute_query("SELECT COUNT(password) FROM password WHERE user_email=%s AND strength='weak'", (user_email,), fetch=True)
        
        # Set default counts if no results are returned
        strong_count = strong_count[0][0] if strong_count else 0
        moderate_count = moderate_count[0][0] if moderate_count else 0
        weak_count = weak_count[0][0] if weak_count else 0
        
        # Pass the counts and user email to the dashboard template
        return render_template('dashboard.html',
                               pwd_count=pwd_count,
                               folder_count=folder_count,
                               strong_count=strong_count,
                               moderate_count=moderate_count,
                               weak_count=weak_count,
                               user_email=user_email)
        
    
    except Exception as e:
        logger.error(f"Error in the dashboard route: {e}")
        return "An error occurred while processing your request.", 500
@app.route('/dashboard/data', methods=['GET'])
def dashboard_data():
    try:
        # Ensure the user is logged in by checking the session
        if 'email' not in session:
            return jsonify({"error": "User not logged in."}), 401

        # Retrieve current user's email from session
        user_email = session['email']

        # Query to select passwords for the current user
        query = "SELECT password FROM password WHERE user_email=%s"
        df = execute_query(query, (user_email,))  # Pass user_email as a parameter

        # Check if the query returned any data
        if not df:
            return jsonify({"error": "No data found."}), 404

        # Process the result into a DataFrame
        df = pd.DataFrame(df, columns=['password'])

        # Clean the data by dropping NaN values and filtering out non-string entries
        df = df.dropna(subset=['password'])
        df = df[df['password'].apply(lambda x: isinstance(x, str))]

        # Check if the DataFrame is empty after cleaning
        if df.empty:
            return jsonify({"error": "No valid passwords found."}), 404

        # Get the password strength distribution (assuming you have this function)
        strength_counts = get_password_strength_distribution(df)

        # Prepare the labels and values for chart representation
        labels = list(strength_counts.keys())
        values = list(strength_counts.values())

        # Define color mapping for password strength levels
        color_map = {
            'Strong': '#008000',
            'Moderate': '#ffff00',
            'Weak': '#ff0000',
        }
        colors = [color_map.get(label, '#cccccc') for label in labels]

        # Return the data as a JSON response
        return jsonify({
            'labels': labels,
            'values': values,
            'colors': colors
        })

    except Exception as e:
        logger.error(f"Error in the dashboard_data route: {e}")
        return jsonify({"error": "An error occurred while processing your request."}), 500
@app.route('/about')
def about():
        return render_template('about.html')

@app.route('/download_poor_passwords')
def download_poor_passwords():
    """Download a CSV file of passwords deemed 'Very Weak' or 'Weak'."""
    try:
        query = "SELECT password FROM password"
        df = execute_query(query)
        
        df = pd.DataFrame(df, columns=['password'])
        df = df.dropna(subset=['password'])
        df = df[df['password'].apply(lambda x: isinstance(x, str))]
        
        if df.empty:
            logger.warning("No valid passwords found.")
            return "No valid passwords found.", 404

        df['password_strength'] = df['password'].apply(analyze_password_strength)

        poor_passwords_df = df[df['password_strength'].isin(['Very Weak', 'Weak'])]
        
        if poor_passwords_df.empty:
            logger.warning("No poor passwords found.")
            return "No poor passwords found.", 404

        csv_path = secure_filename('poor_passwords.csv')
        poor_passwords_df.to_csv(csv_path, index=False)

        response = send_file(csv_path, as_attachment=True)
        os.remove(csv_path)
        logger.info(f"File {csv_path} sent and removed successfully.")
        return response

    except Exception as e:
        logger.error(f"Error sending poor passwords file: {e}")
        return "An error occurred while processing your request.", 500
@app.route('/passwords', methods=['GET'])
def passwords():
    # Check if user is logged in
    if 'email' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    # Get current user's email from the session
    user_email = session['email']
    
    # Fetch passwords for the current user
    names = execute_query("SELECT name, category, folder, created_at, created_time, strength, url FROM password WHERE user_email=%s", (user_email,))
    
    # Debug: print names to console (can be removed in production)    
    # Table headings
    headings = ['Name', 'Category', 'Folder', 'Created_at', 'Created_time', 'Status','URL','Action']

    # Fetch folder names for the current user
    folders = execute_query("SELECT folder_name FROM folder WHERE user_email=%s", (user_email,))
    if folders is None:
        folders = []
    
    # Render the passwords template with user-specific data
    return render_template('passwords.html', names=names, folder_names=folders, headings=headings)
@app.route('/view', methods=['GET', 'POST'])
def view():
    # Check if user is logged in
    if 'email' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    # Get current user's email from the session
    user_email = session['email']

    # Fetch passwords for the current user
    names = execute_query("SELECT name, category, folder, created_at, created_time, strength FROM password WHERE user_email=%s AND strength='weak'", (user_email,))
    
    if names is None:
        names = []  # Fallback to an empty list if None

    # Table headings
    headings = ['Name', 'Category', 'Folder', 'Created_at', 'Created_time', 'Status', 'Action']

    # Fetch folder names for the current user
    folders = execute_query("SELECT folder_name FROM folder WHERE user_email=%s", (user_email,))
    
    if folders is None:
        folders = []  # Fallback to an empty list if None

    # Render the passwords template with user-specific data
    return render_template('view.html', names=names, folder_names=folders, headings=headings)

@app.route('/pwd/<name>', methods=['GET'])
def pwd(name):
    # Ensure the user is logged in by checking the session
    if 'email' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    # Get the current logged-in user's email from the session
    user_email = session['email']
    
    # Set session variable for the name
    session['name'] = name  
    
    # Query the password entry for the current user based on the name and email
    result = execute_query(
        "SELECT email, password FROM password WHERE name=%s AND user_email=%s", 
        (name, user_email)
    )
    
    if result:
        # Pass the username (email) and password to the form
        form = {'username': result[0][0], 'pwd': result[0][1]}
        return render_template('pwd_form.html', form=form)
    else:
        # If no result, redirect to the passwords page
        return redirect(url_for('passwords'))
@app.route('/folder_form/<folder_name>', methods=['GET'])
def folder_form(folder_name):
    # Ensure the user is logged in
    if 'email' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    user_email = session['email']  # Get the current user's email

    # Fetch passwords based on the category and the current user
    passwords = execute_query(
        "SELECT name,category, url FROM password WHERE folder=%s AND user_email=%s",
        (folder_name, user_email)
    )

    return render_template('folder_form.html', folder_name=folder_name, passwords=passwords)
@app.route('/site', methods=['GET', 'POST'])
def site():
    title = "Add Site"
    user_email = session.get('email')

    if not user_email:
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        folder = request.form['folder']
        username = request.form['username']
        webaddress = request.form['webaddress']
        password = request.form['pwd']
        strength = analyze_password_strength(password)

        query = '''
            INSERT INTO password (name, email, created_at, password, folder, category, url, created_time, user_email,strength)
            VALUES (%s, %s, CURRENT_DATE, %s, %s, %s, %s, CURRENT_TIME, %s,%s)
        '''
        params = (name, user_email, password, folder, category, webaddress, user_email,strength)
        result = execute_query(query, params, commit=True)

        if result is None:
            return "An error occurred during insertion."
        
        return redirect(url_for('main'))

    # Fetch categories and folders for the dropdowns
    categories = execute_query("SELECT category_name FROM category", fetch=True)
    folders = execute_query("SELECT folder_name FROM folder WHERE user_email=%s", (user_email,), fetch=True)

    # Ensure folders is an empty list if None
    if folders is None:
        folders = []

    return render_template('site.html', heading=title, categories=categories, folders=folders, selected_category='Site')

@app.route('/payment', methods=['GET', 'POST'])
def payment():
    title = "Add Payment"
    
    if 'email' not in session:
        return redirect(url_for('login'))
    
    user_email = session['email']
    
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        folder = request.form['folder']
        username = request.form['username']
        acc_no = request.form['acc_no']
        ifsc = request.form['ifsc']
        bank_name = request.form['bank_name']
        branch = request.form['branch']
        webaddress = request.form['webaddress']
        password = request.form['pwd']
        strength = analyze_password_strength(password)

        execute_query('''
            INSERT INTO payments (name, email, password, folder, category, account_number, ifsc, branch, bank_name, url, user_email,strength)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s)
        ''', (name, username, password, folder, category, acc_no, ifsc, branch, bank_name, webaddress, user_email, strength), fetch=False, commit=True)
        
        query = '''
            INSERT INTO password (name, email, created_at, password, folder, category, url, created_time, user_email,strength)
            VALUES (%s, %s, CURRENT_DATE, %s, %s, %s, %s, CURRENT_TIME, %s,%s)
        '''
        params = (name, username, password, folder, category, webaddress, user_email,strength)
        result = execute_query(query, params, commit=True)

        if result is None:
            return "An error occurred during insertion."
        
        return redirect(url_for('main')) 

    categories = execute_query("SELECT category_name FROM category", fetch=True)
    folders = execute_query("SELECT folder_name FROM folder WHERE user_email=%s", (user_email,), fetch=True)
    
    if folders is None:
        folders = []

    return render_template('payment.html', heading=title, categories=categories, folders=folders, selected_category='Payment')

@app.route('/windows', methods=['GET', 'POST'])
def windows():
    title = "Add Windows"
    user_email = session.get('email')

    if not user_email:
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        folder = request.form['folder']
        username = request.form['username']
        webaddress = request.form['webaddress']
        password = request.form['pwd']        
        strength = analyze_password_strength(password)


        query = '''
            INSERT INTO password (name, email, created_at, password, folder, category, url, created_time, user_email,strength)
            VALUES (%s, %s, CURRENT_DATE, %s, %s, %s, %s, CURRENT_TIME, %s,%s)
        '''
        params = (name, username, password, folder, category, webaddress, user_email,strength)
        result = execute_query(query, params, commit=True)

        if result is None:
            return "An error occurred during insertion."
        
        return redirect(url_for('main'))    

    categories = execute_query("SELECT category_name FROM category", fetch=True)
    folders = execute_query("SELECT folder_name FROM folder WHERE user_email=%s", (user_email,), fetch=True)
    
    if folders is None:
        folders = []

    return render_template('site.html', heading=title, categories=categories, folders=folders, selected_category='Windows')
@app.route('/edit_password/<string:name>', methods=['GET', 'POST'])
def edit_password(name):
    user_email = session.get('email')

    # Check if the user is logged in
    if not user_email:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    # Fetch existing data
    if request.method == 'POST':
        # Get form data
        category = request.form.get('category')
        folder = request.form.get('folder')
        email = request.form.get('email')
        password = request.form.get('pwd')
        website = request.form.get('website')
        strength = analyze_password_strength(password)

        query = "SELECT category, folder, email, password, url FROM password WHERE name = %s and user_email=%s"
        existing_data = execute_query(query, (name, user_email), fetch=True)

        if existing_data:
            existing_category, existing_folder, existing_email, existing_password, existing_url = existing_data[0]

            # Compare and only update if necessary
            if (category != existing_category or folder != existing_folder or
                email != existing_email or password != existing_password or website != existing_url):

                # Update the password entry in the database
                query = """
                UPDATE password 
                SET category = %s, folder = %s, email = %s, password = %s, url = %s, strength = %s
                WHERE name = %s and user_email = %s
                """
                data = (category, folder, email, password, website, strength, name, user_email)
                result = execute_query(query, data, fetch=False, commit=True)

                print("Query result:", result)

                # Check if result is None or not
                if result is not None and result > 0:  # Check if rows were affected
                    flash('Password entry updated successfully!', 'success')
                else:
                    flash('Error updating password entry or no changes made.', 'error')
            else:
                flash('No changes detected, nothing to update.', 'info')

        return redirect(url_for('main'))

    # If GET request, fetch the existing password data to pre-fill the form
    query = "SELECT category, folder, email, password, url FROM password WHERE name = %s and user_email=%s"
    existing_data = execute_query(query, (name, user_email), fetch=True)

    if existing_data:
        existing_data = existing_data[0]  # Unpack the first row of results
        existing_data_dict = {
            'name': name,
            'category': existing_data[0],
            'folder': existing_data[1],
            'email': existing_data[2],
            'password': existing_data[3],
            'website': existing_data[4],
        }
    else:
        flash('Password entry not found.', 'error')
        return redirect(url_for('main'))  # Redirect to main if no data is found

    return render_template('edit.html', name=name, edit=existing_data_dict)

@app.route('/import', methods=['GET', 'POST'])
def import_passwords():
    user_email = session.get('email')  # Get the current user's email from the session

    # Check if the user is logged in
    if not user_email:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    if request.method == 'POST':
        file = request.files['file']
        category = request.form['category']
        folder = request.form['folder']

        if file and file.filename.endswith('.csv'):
            try:
                # Read the CSV file
                csv_file = csv.reader(file.stream.read().decode("UTF-8").splitlines())
                next(csv_file)  # Skip header row

                for row in csv_file:
                    if len(row) < 4:  # Ensure there are at least four values
                        logger.warning(f"Skipping row due to insufficient values: {row}")
                        continue
                    
                    name, url, username, password = row[:4]  # Get first four columns
                    note = row[4] if len(row) > 4 else None

                    # Now that password is assigned, analyze its strength
                    strength = analyze_password_strength(password)

                    # Insert into database
                    query = (
                        "INSERT INTO password (name, url, created_at, email, password, created_time, category, folder, user_email, strength) "
                        "VALUES (%s, %s, CURRENT_DATE, %s, %s, CURRENT_TIME, %s, %s, %s, %s)"
                    )
                    execute_query(query, (name, url, username, password, category, folder, user_email, strength), commit=True)

                flash('Passwords imported successfully!', 'success')
                return redirect(url_for('main'))  # Change 'main' to your actual route name

            except Exception as e:
                logger.error(f'Error importing passwords: {e}')
                flash('An error occurred while importing passwords. Please check the format and try again.', 'error')
        
        else:
            flash('Invalid file type. Please upload a CSV file.', 'error')

    # Fetch categories and folders for the dropdowns
    try:    
        categories = execute_query("SELECT category_name FROM category", fetch=True)
        folders = execute_query("SELECT folder_name FROM folder WHERE user_email=%s", (user_email,), fetch=True)
    except Exception as e:
        logger.error(f'Error fetching categories and folders: {e}')
        categories, folders = [], []

    return render_template('import.html', categories=categories, folders=folders)

@app.route('/settings', methods=['GET'])
def settings():
    if 'email' not in session:
        return redirect(url_for('login'))

    email = session['email']

    # Fetch the user data for displaying on the settings page
    user_data = execute_query("SELECT username, mobile, profile_image, address FROM user WHERE email = %s", (email,), fetch=True)

    # Check if data exists and prepare the user dictionary
    if user_data:
        user_data = user_data[0]  # Get the first row returned
        user = {
            'name': user_data[0],
            'email': email,
            'mobile': user_data[1],
            'profile_image': user_data[2],
            'address': user_data[3]
        }
    else:
        user = {
            'name': '',
            'email': email,
            'mobile': '',
            'profile_image': None,
            'address': ''
        }
    return render_template('settings.html',user=user)

@app.route('/change_master_password', methods=['GET'])
def master_password():
    return render_template('master_password.html')

@app.route('/profile', methods=['GET'])
def profile():
    if 'email' not in session:
        return redirect(url_for('login'))

    email = session['email']

    # Fetch the user data for displaying on the settings page
    user_data = execute_query("SELECT username, mobile, profile_image, address FROM user WHERE email = %s", (email,), fetch=True)

    # Check if data exists and prepare the user dictionary
    if user_data:
        user_data = user_data[0]  # Get the first row returned
        user = {
            'name': user_data[0],
            'email': email,
            'mobile': user_data[1],
            'profile_image': user_data[2],
            'address': user_data[3]
        }
    else:
        user = {
            'name': '',
            'email': email,
            'mobile': '',
            'profile_image': None,
            'address': ''
        }
    return render_template('profile_form.html',user=user)

@app.route('/category', methods=['GET'])
def category():
    # Execute the query to get the count
    site_count_result = execute_query("SELECT count(*) FROM password WHERE category='site'")
    payment_count_result = execute_query("SELECT count(*) FROM password WHERE category='payment'")
    window_count_result = execute_query("SELECT count(*) FROM password WHERE category='windows'")
    # Extract the count from the result
    site_count = site_count_result[0][0] if site_count_result else 0  # Default to 0 if no result
    payment_count = payment_count_result[0][0] if payment_count_result else 0  # Default to 0 if no result
    window_count = window_count_result[0][0] if window_count_result else 0  # Default to 0 if no result
    return render_template('category.html', site=site_count,payment=payment_count,window=window_count)

@app.route('/category_form_payment/<category_name>', methods=['GET'])
def category_form_payment(category_name):
    # Ensure the user is logged in
    if 'email' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    user_email = session['email']  # Get the logged-in user's email

    # Fetch passwords based on the category for the current user
    passwords = execute_query(
        "SELECT name, folder, account_number, ifsc, bank_name, branch,url FROM payments WHERE category=%s AND user_email=%s",
        (category_name, user_email)
    )
    
    headings = ['Name', 'Folder', 'Account Number', 'IFSC', 'Bank Name', 'Branch','URL']

    return render_template('category_form_payment.html', category_name=category_name, passwords=passwords, headings=headings)

@app.route('/category_form/<category_name>', methods=['GET'])
def category_form(category_name):
    # Ensure the user is logged in by checking the session
    if 'email' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    user_email = session['email']  # Get the current user's email

    # Fetch passwords based on the category and current user
    headings = ['Name','Folder','URL']
    passwords = execute_query(
        "SELECT name, folder, url FROM password WHERE category=%s AND user_email=%s",
        (category_name, user_email)
    )
    
    return render_template('category_form.html', category_name=category_name, headings=headings, passwords=passwords)

@app.route('/folders', methods=['GET', 'POST'])
def folders():
    # Ensure the user is logged in
    if 'email' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    user_email = session['email']  # Get current user's email

    if request.method == 'POST':
        folder_name = request.form.get('folder_name')
        if folder_name:
            # Insert the folder with the associated user email
            execute_query(
                'INSERT INTO folder (folder_name, created_at, created_time, user_email) VALUES (%s, CURRENT_DATE, CURRENT_TIME, %s)',
                (folder_name, user_email),
                fetch=False,
                commit=True
            )

        # Fetch folders for the current user
        folders = execute_query('SELECT * FROM folder WHERE user_email=%s', (user_email,))
        
        # Generate HTML for the table body
        table_html = ''
        for folder in folders:
            img_url = url_for('static', filename='folder.png')

            table_html += f'''
                <tr>
                    <td>
                        <div class="folder">
                            <img src="{img_url}">
                            <a href="javascript:void(0)" onclick="loadContent('/folder_form/{folder[1]}')">{folder[1]}</a>
                        </div>
                    </td>
                    <td>
                        <div class="dropdown">
                            <a href="javascript:void(0)" class="action_dropbtn">
                                <i class="fas fa-ellipsis-vertical"></i>
                            </a>
                            <div class="dropdown-content">
                                <a href="javascript:void(0)" onclick="showRenameModal('{folder[1]}', this.closest('tr'))">
                                    <i class="fas fa-edit"></i>
                                    <span>Rename</span>
                                </a>
                                <a href="javascript:void(0);" onclick="deleteFolder('/delete_folder/{folder[0]}', this.parentElement.parentElement)" class="delete">
                                    <i class="fas fa-trash"></i>
                                    <span>Delete</span>
                                </a>
                                <a href="javascript:void(0)" onclick="loadContent('/folder_form/{folder[0]}')" title="Created at: {folder[2]} {folder[3]}">
                                    <i class="fas fa-history"></i>
                                    <span>History</span>
                                </a>
                            </div>
                        </div>
                    </td>
                </tr>
            '''
        return table_html

    # Fetch folders for the current user when not in POST method
    folders = execute_query('SELECT * FROM folder WHERE user_email=%s', (user_email,))
    headings = ['Folders', 'Action']

    return render_template('folders.html', folder_names=folders, headings=headings)

@app.route('/rename_folder/<current_folder>', methods=['POST'])
def rename_folder(current_folder):
    new_folder_name = request.form.get('new_folder_name')
    
    # Ensure the user is logged in
    if 'email' not in session:
        return "User not logged in.", 403  # Forbidden response

    user_email = session['email']  # Get current user's email

    if new_folder_name:
        # Update the folder name in the database for the current user only
        update_query = '''
            UPDATE folder 
            SET folder_name = %s 
            WHERE folder_name = %s AND user_email = %s
        '''
        result = execute_query(update_query, (new_folder_name, current_folder, user_email), commit=True)

        if result is not None:
            return 'Folder renamed successfully', 200  # Success response
        else:
            return 'Folder not found or you do not have permission to rename it.', 404  # Not found response

    return 'Folder name is required', 400  # Error response
@app.route('/trash')
def trash():
    # Function to delete old records
    def delete_old_records(user_email):
        now = datetime.now()
        cutoff_date = now - timedelta(days=30)
        cutoff_date_str = cutoff_date.strftime('%Y-%m-%d')

        query = "DELETE FROM delete_items WHERE deleted_at < %s AND user_email=%s"
        try:
            execute_query(query, (cutoff_date_str, user_email), fetch=False, commit=True)
            print(f"Deleted records older than {cutoff_date_str} for user {user_email}")
        except Exception as e:
            print(f"Error deleting old records: {e}")

    # Ensure the user is logged in
    if 'email' not in session:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    # Retrieve current user's email from session
    user_email = session['email']

    # Call the function to delete old records for the current user
    delete_old_records(user_email)

    headings = ['Name', 'Item Type', 'Deleted_at', 'Deleted_time']
    
    # Fetch deleted items for the current user
    passwords = execute_query(
        "SELECT item_name, item_type, deleted_at, deleted_time FROM delete_items WHERE user_email=%s", 
        (user_email,)
    )

    return render_template('trash.html', passwords=passwords, headings=headings)
@app.route('/delete_folder/<string:folder_name>', methods=['POST'])
def delete_folder(folder_name):
    # Ensure the user is logged in
    if 'email' not in session:
        return 'Unauthorized', 401

    user_email = session['email']

    # Fetch folder details for the current user
    folder_query = '''
        SELECT folder_id, folder_name, created_at, created_time 
        FROM folder 
        WHERE folder_name = %s AND user_email = %s
    '''
    folder = execute_query(folder_query, (folder_name, user_email), fetch=True)

    if not folder:
        return 'Folder not found', 404

    folder_id = folder[0][0]
    created_at = folder[0][2]
    created_time = folder[0][3]

    # Get current date and time
    now = datetime.now()
    deletion_date = now.strftime('%Y-%m-%d')
    deletion_time = now.strftime('%H:%M:%S')

    # Get related passwords for the current user
    passwords_query = '''
        SELECT pwd_id, name, created_at, folder, category, email, url, password, created_time 
        FROM password 
        WHERE folder = %s AND user_email = %s
    '''
    passwords = execute_query(passwords_query, (folder_name, user_email), fetch=True)

    for pwd in passwords:
        pwd_id, pwd_name, pwd_created_at, pwd_folder, category, email, url, pwd_password, pwd_created_time = pwd
        strength = analyze_password_strength(pwd_password)

        # Insert password into delete_items
        insert_query = '''
        INSERT INTO delete_items (
            item_id, item_name, item_type, deleted_at, created_at, category, folder, email, url, password, deleted_time, created_time, strength
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s)
        '''
        params = (
            pwd_id, pwd_name, 'Password', deletion_date, pwd_created_at, category, pwd_folder, email, url, pwd_password, deletion_time, pwd_created_time,strength
        )
        try:
            execute_query(insert_query, params, fetch=False, commit=True)
        except Exception as e:
            print(f"Error inserting password into delete_items: {e}")
            return 'Error inserting password into delete_items', 500

    # Delete related passwords
    delete_passwords_query = 'DELETE FROM password WHERE folder = %s AND user_email = %s'
    try:
        execute_query(delete_passwords_query, (folder_name, user_email), fetch=False, commit=True)
    except Exception as e:
        print(f"Error deleting passwords: {e}")
        return 'Error deleting passwords', 500

    # Insert folder into delete_items
    insert_query = '''
    INSERT INTO delete_items (
        item_id, item_name, item_type, deleted_at, created_at, deleted_time, created_time
    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
    '''
    params = (
        folder_id, folder_name, 'Folder', deletion_date, created_at, deletion_time, created_time
    )
    try:
        execute_query(insert_query, params, fetch=False, commit=True)
    except Exception as e:
        print(f"Error inserting folder into delete_items: {e}")
        return 'Error inserting folder into delete_items', 500

    # Delete folder from folder table
    delete_query = 'DELETE FROM folder WHERE folder_name = %s AND user_email = %s'
    try:
        execute_query(delete_query, (folder_name, user_email), fetch=False, commit=True)
    except Exception as e:
        print(f"Error deleting folder: {e}")
        return 'Error deleting folder', 500

    # Return updated folder list
    folders = execute_query('SELECT * FROM folder WHERE user_email = %s', (user_email,))
    table_html = ''
    for folder in folders:
        img_url = url_for('static', filename='folder.png')
        table_html += f'''
            <tr>
                <td>
                    <div class="folder">
                        <img src="{img_url}">
                        <a href="javascript:void(0)" onclick="loadContent('/folder_form/{folder[1]}')">{folder[1]}</a>
                    </div>
                </td>
                <td>
                    <div class="dropdown">
                        <a href="javascript:void(0)" class="action_dropbtn">
                            <i class="fas fa-ellipsis-vertical"></i>
                        </a>
                        <div class="dropdown-content">
                            <a href="javascript:void(0)" onclick="showRenameModal('{folder[1]}', this.closest('tr'))">
                                <i class="fas fa-edit"></i>
                                <span>Rename</span>
                            </a>
                            <a href="javascript:void(0);" onclick="deleteFolder('/delete_folder/{folder[0]}', this.parentElement.parentElement)" class="delete">
                                <i class="fas fa-trash"></i>
                                <span>Delete</span>
                            </a>
                            <a href="javascript:void(0)" onclick="loadContent('/folder_form/{folder[0]}')" title="Created at: {folder[2]} {folder[3]}">
                                <i class="fas fa-history"></i>
                                <span>History</span>
                            </a>
                        </div>
                    </div>
                </td>
            </tr>
        '''

    return table_html

@app.route('/delete_password/<string:password_name>', methods=['POST'])
def delete_password(password_name):
    # Check if user is logged in
    if 'email' not in session:
        return 'Unauthorized', 403  # Return unauthorized if no user is logged in
    
    user_email = session['email']  # Get the current user's email from the session

    # Fetch password details for the current user
    password_query = '''
        SELECT pwd_id, name, folder, category, email, password, url, created_at, created_time 
        FROM password 
        WHERE name = %s AND user_email = %s
    '''
    password = execute_query(password_query, (password_name, user_email), fetch=True)

    if not password:
        return 'Password not found or does not belong to the current user', 404
    
    # Extract details
    password_id = password[0][0]
    item_name = password[0][1]
    folder = password[0][2] or ''
    category = password[0][3] or ''
    email = password[0][4] or ''
    password_value = password[0][5] or ''
    url = password[0][6] or ''
    created_at = password[0][7]
    created_time = password[0][8]
    strength = analyze_password_strength(password_value)

    # Get current date and time for deletion
    now = datetime.now()
    deletion_date = now.strftime('%Y-%m-%d')  # Date only
    deletion_time = now.strftime('%H:%M:%S')  # Time only

    # Debugging output
    print(f"Inserting into delete_items: {password_id}, {item_name}, 'Password', {deletion_date}, {created_at}, {folder}, {category}, {email}, {url}, {password_value}, {deletion_time}, {created_time},{user_email}")

    # Insert into delete_items table
    insert_query = '''
        INSERT INTO delete_items 
        (item_id, item_name, item_type, deleted_at, created_at, folder, category, email, url, password, deleted_time, created_time,user_email,strength) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s,%s)
    '''
    try:
        # Execute the insert query
        print(f"Executing query: {insert_query}")
        execute_query(insert_query, 
                      (password_id, item_name, 'Password', deletion_date, created_at, folder, category, email, url, password_value, deletion_time, created_time,user_email,strength), 
                      fetch=False, 
                      commit=True)
    except Exception as e:
        print(f"Error inserting into delete_items: {e}")
        return 'Error inserting into delete_items', 500

    # Delete from password table
    delete_query = 'DELETE FROM password WHERE pwd_id = %s AND user_email = %s'
    try:
        # Execute the delete query
        print(f"Executing query: {delete_query}")
        execute_query(delete_query, (password_id, user_email), fetch=False, commit=True)
    except Exception as e:
        print(f"Error deleting from password table: {e}")
        return 'Error deleting from password table', 500

    return 'Password deleted successfully', 200
@app.route('/restore_all', methods=['POST'])
def restore_all():
    # Ensure the user is logged in by checking the session
    if 'email' not in session:
        flash('You need to log in to restore items.')
        return redirect(url_for('login'))  # Redirect to login if not logged in
    
    user_email = session['email']
    
    # Fetch deleted items for the current user
    deleted_items = execute_query(
        "SELECT item_id, item_name, item_type, folder, category, email, url, created_at, password, created_time, user_email "
        "FROM delete_items WHERE user_email=%s",
        (user_email,), fetch=True
    )

    if not deleted_items:
        flash('No items found to restore.')
        return redirect(url_for('trash'))

    for item in deleted_items:
        if len(item) != 11:  # Check if we have the correct number of fields
            print(f"Unexpected item length: {len(item)}. Item data: {item}")
            continue  # Skip this item or handle it as needed
        
        item_id, item_name, item_type, folder, category, email, url, created_at, password, created_time, user_email = item
        
        if item_type == 'Folder':
            execute_query(
                "INSERT INTO folder (folder_id, folder_name, created_at, created_time, user_email) VALUES (%s, %s, %s, %s, %s)",
                (item_id, item_name, created_at, created_time, user_email), fetch=False, commit=True
            )
        elif item_type == 'Password':
            execute_query(
                "INSERT INTO password (pwd_id, name, created_at, email, password, folder, category, url, created_time, user_email) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (item_id, item_name, created_at, email or '', password or '', folder or '', category or '', url or '', created_time, user_email), fetch=False, commit=True
            )

    # Clear the delete_items table for the current user
    execute_query("DELETE FROM delete_items WHERE user_email=%s", (user_email,), fetch=False, commit=True)
    flash('All items restored successfully.')
    return redirect(url_for('trash'))

@app.route('/restore_selected', methods=['POST'])
def restore_selected():
    try:
        data = request.get_json()
        item_names = data.get('item_ids', [])  # Assuming the payload is item names

        if not item_names:
            flash('No items selected for restoration.')
            return redirect(url_for('trash'))

        # Get the current user's email from the session
        user_email = session.get('email')
        if not user_email:
            flash('User is not logged in.')
            return redirect(url_for('login'))  # Redirect if user is not logged in

        for item_name in item_names:
            print(f"Attempting to restore item with name: {item_name}")

            # Fetch the item to restore based on item_name and user_email
            item = execute_query(
                "SELECT item_id, item_name, item_type, folder, category, email, url, created_at, password, created_time, user_email FROM delete_items WHERE item_name = %s AND user_email = %s", 
                (item_name, user_email), 
                fetch=True
            )

            if item:
                if len(item[0]) == 11:  # Ensure the correct number of values returned
                    item_id, item_name, item_type, folder, category, email, url, created_at, password, created_time, user_email = item[0]
                    print(f"Fetched item: {item}")

                    if item_type == 'Folder':
                        print(f"Inserting folder with ID: {item_id}")
                        result = execute_query(
                            "INSERT INTO folder (folder_id, folder_name, created_at, created_time, user_email) VALUES (%s, %s, %s, %s, %s)",
                            (item_id, item_name, created_at, created_time, user_email), fetch=False, commit=True
                        )
                        print(f"Insert result: {result}")
                    elif item_type == 'Password':
                        print(f"Inserting password with ID: {item_id}")
                        result = execute_query(
                            "INSERT INTO password (pwd_id, name, created_at, email, password, folder, category, url, created_time, user_email) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                            (item_id, item_name, created_at, email or '', password or '', folder or '', category or '', url or '', created_time, user_email), fetch=False, commit=True
                        )
                        print(f"Insert result: {result}")

                    # Delete the restored item from the delete_items table
                    print(f"Deleting item with ID: {item_id} from delete_items")
                    delete_result = execute_query(
                        "DELETE FROM delete_items WHERE item_id = %s and user_email=%s", 
                        (item_id, user_email), 
                        fetch=False, 
                        commit=True
                    )
                    print(f"Deletion result: {delete_result}")
                else:
                    print(f"Unexpected number of values returned: {len(item[0])}")
            else:
                print(f"No item found with name: {item_name} for user: {user_email}")

        flash('Selected items restored successfully.')
    except Exception as e:
        print(f"An error occurred in restore_selected: {e}")  # Log any exceptions
        flash(f'An error occurred: {str(e)}')

    return redirect(url_for('trash'))

@app.route('/delete_selected', methods=['POST'])
def delete_selected():
    try:
        data = request.get_json()
        item_names = data.get('item_ids', [])  # Assuming the payload is item names

        if not item_names:
            flash('No items selected for deletion.')
            return redirect(url_for('trash'))

        # Get current user's email from session
        user_email = session.get('email')
        
        if not user_email:
            flash('User not logged in.')
            return redirect(url_for('login'))

        for item_name in item_names:
            print(f"Attempting to delete item with name: {item_name}")

            # Delete the item from the delete_items table for the current user
            delete_result = execute_query(
                "DELETE FROM delete_items WHERE item_name = %s AND user_email = %s", 
                (item_name, user_email), 
                fetch=False, 
                commit=True
            )
            print(f"Deletion result: {delete_result}")

        flash('Selected items deleted successfully.')
    except Exception as e:
        print(f"An error occurred in delete_selected: {e}")  # Log any exceptions
        flash(f'An error occurred: {str(e)}')

    return redirect(url_for('trash'))

@app.route('/delete_all', methods=['POST'])
def delete_all():
    try:
        # Get current user's email from session
        user_email = session.get('email')

        if not user_email:
            flash('User not logged in.')
            return redirect(url_for('login'))

        # Delete all items for the current user from the delete_items table
        result = execute_query(
            "DELETE FROM delete_items WHERE user_email = %s", 
            (user_email,), 
            fetch=False, 
            commit=True
        )

        if result is None:
            flash('An error occurred during deletion.')
        else:
            flash('All items deleted successfully.')
    except Exception as e:
        print(f"An error occurred in delete_all: {e}")  # Log any exceptions
        flash(f'An error occurred: {str(e)}')

    return redirect(url_for('trash'))

if __name__ == '__main__':
    app.run(debug=True, port=5001)
