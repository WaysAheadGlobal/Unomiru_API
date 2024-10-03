from flask import Flask, request, jsonify
from functools import wraps
import pyodbc
import random
import hashlib
import jwt
import datetime
import http.client
from codecs import encode
import os
import re
import pytesseract
from PIL import Image
import tempfile
import cv2
import uuid
import numpy as np
import os
from werkzeug.utils import secure_filename


from flask_cors import CORS 

# Initialize the Flask application
app = Flask(__name__)
CORS(app)

# Secret key for JWT encoding/decoding
SECRET_KEY = 'your_secret_key'

# Define the upload folder and allowed extensions
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))  # Gets the current directory
UPLOAD_FOLDER = os.path.join(CURRENT_DIR, 'uploads')  # Base upload directory
SELFIE_FOLDER = os.path.join(UPLOAD_FOLDER, 'users')  # Subfolder for selfies
PROPERTY_FOLDER = os.path.join(UPLOAD_FOLDER, 'property')  # Subfolder for property images
VISITING_CARD_FOLDER = os.path.join(UPLOAD_FOLDER, 'visitingcards')  # Subfolder for visiting cards
REVIEWS_FOLDER = os.path.join(UPLOAD_FOLDER, 'reviews')  # Subfolder for reviews images
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure all folders exist
os.makedirs(SELFIE_FOLDER, exist_ok=True)
os.makedirs(PROPERTY_FOLDER, exist_ok=True)
os.makedirs(VISITING_CARD_FOLDER, exist_ok=True)
os.makedirs(REVIEWS_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to save the file if it exists and has an allowed extension
def save_file(file, folder):
    if file and allowed_file(file.filename):
        # Create a secure and unique filename
        unique_filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        filepath = os.path.join(folder, unique_filename)
        file.save(filepath)
        return filepath  # Return the path for DB storage
    return None

# Your additional code here...

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')

        # Check if token exists
        if not token:
            return jsonify({'status': 401, 'message': 'Token is missing'}), 401

        try:
            # Strip the "Bearer " prefix if it exists
            if token.startswith('Bearer '):
                token = token[7:]

            # Decode the token and extract payload
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

            # Extract user_id and add it to the request context
            user_id = payload.get('user_id')

            if not user_id:
                return jsonify({'status': 401, 'message': 'User ID missing in token'}), 401

            # Set user_id in the request or pass it to the wrapped function
            request.user_id = user_id  # Optional: if needed globally in request context

        except jwt.ExpiredSignatureError:
            return jsonify({'status': 401, 'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'status': 401, 'message': 'Invalid token'}), 401

        # Pass the user_id to the wrapped function as an argument
        return f(user_id, *args, **kwargs)

    return decorator

# Database connection string
db_connection_string = (
    "Driver={ODBC Driver 17 for SQL Server};"
    "Server=103.239.89.99,21433;"
    "Database=UnomiruAppDB;"
    "UID=UnoMiruDBUsr01;"
    "PWD=UnoMiru*8520!;"
)

# Function to get a database connection
def get_db_connection():
    try:
        connection = pyodbc.connect(db_connection_string)
        return connection
    except Exception as e:
        print(f"Database connection failed: {e}")
        return None

# Helper function to validate email format
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

# Hash OTP
def hash_otp(otp):
    return hashlib.sha256(otp.encode()).hexdigest()

# Generate OTP
def generate_otp():
    return str(random.randint(100000, 999999))

# Generate JWT token
def generate_jwt(user_id, expires_delta=datetime.timedelta(days=20)):
    payload = {
        'user_id': user_id,  # Ensure user_id is used, not email
        'exp': datetime.datetime.now() + expires_delta
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Helper function to split name
def split_name(name):
    parts = name.split(' ', 1)
    if len(parts) == 1:
        return parts[0], ''
    return parts[0], parts[1]

# Send email function
def send_email(recipient, subject, body):
    conn = http.client.HTTPSConnection("api.waysdatalabs.com")
    boundary = 'wL36Yn8afVp8Ag7AmP8qZ0SA4n1v9T'
    dataList = []

    dataList.append(encode('--' + boundary))
    dataList.append(encode('Content-Disposition: form-data; name=Recipient;'))
    dataList.append(encode('Content-Type: {}'.format('text/plain')))
    dataList.append(encode(''))
    dataList.append(encode(recipient))

    dataList.append(encode('--' + boundary))
    dataList.append(encode('Content-Disposition: form-data; name=Subject;'))
    dataList.append(encode('Content-Type: {}'.format('text/plain')))
    dataList.append(encode(''))
    dataList.append(encode(subject))

    dataList.append(encode('--' + boundary))
    dataList.append(encode('Content-Disposition: form-data; name=Body;'))
    dataList.append(encode('Content-Type: {}'.format('text/plain')))
    dataList.append(encode(''))
    dataList.append(encode(body))

    dataList.append(encode('--' + boundary))
    dataList.append(encode('Content-Disposition: form-data; name=ApiKey;'))
    dataList.append(encode('Content-Type: {}'.format('text/plain')))
    dataList.append(encode(''))
    dataList.append(encode("6A7339A3-E70B-4A8D-AA23-0264125F4959"))

    dataList.append(encode('--'+boundary+'--'))
    dataList.append(encode(''))

    body = b'\r\n'.join(dataList)
    payload = body
    headers = {
       'Content-type': 'multipart/form-data; boundary={}'.format(boundary) 
    }
    conn.request("POST", "/api/EmailSender/SendMail", payload, headers)
    res = conn.getresponse()
    data = res.read()
    print(data.decode("utf-8"))

# REGISTER API
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    
    if not data:
        return jsonify({'status': 400, 'message': 'No data provided'}), 400

    user_name = data.get('user_name', '').strip()
    phone_number = str(data.get('phone_number', '')).strip()  # Ensure phone_number is a string
    email = data.get('email', '').strip()
    country_code = data.get('country_code', '').strip()
    device_name = data.get('device_name', '').strip()
    
    # Get dynamic UserTypeId from request, default to 4 if not provided
    user_type_id = data.get('user_type_id', 4)

    # Validate mandatory fields
    if not phone_number:
        return jsonify({'status': 400, 'message': 'Phone number is mandatory'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 500, 'message': 'Database connection error'}), 500

    try:
        cursor = conn.cursor()

        # Check if user already exists
        cursor.execute("SELECT UserId, IsActive FROM tbgl_User WHERE Mobile = ? OR Email = ?", (phone_number, email))
        user_record = cursor.fetchone()
        
        if user_record:
            user_id, is_active = user_record
            if is_active == 0:
                # User exists but is not verified, resend OTP
                first_name, last_name = split_name(user_name)
                otp = generate_otp()
                hashed_otp = hash_otp(otp)
                token = generate_jwt(user_id)  # Generate token here

                # Update CreatedDate and send OTP
                cursor.execute("""
                    UPDATE tbgl_User 
                    SET CreatedDate = GETDATE()
                    WHERE UserId = ?
                """, (user_id,))
                
                cursor.execute("""
                    INSERT INTO tbgl_OTP_Login (UserId, OTP, app, Created_at, Updated_at, OtpVerified_at, JwtToken, TokenExpires_at, TokenIssued_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (user_id, hashed_otp, device_name, datetime.datetime.now(), datetime.datetime.now(), datetime.datetime.now() + datetime.timedelta(minutes=3), token, datetime.datetime.now() + datetime.timedelta(hours=1), datetime.datetime.now()))

                conn.commit()

                # Send OTP via email
                email_subject = "Your OTP Code"
                email_body = f"Dear {first_name},\n\nYour OTP code is {otp}. It is valid for 3 minutes.\n\nBest regards,\nUnoMiru"
                send_email(email, email_subject, email_body)

                return jsonify({'status': 200, 'message': 'Account exists but is not verified. OTP resent to email.', 'otp_sent_to': email, 'token': token, 'user_id': user_id})

            return jsonify({'status': 409, 'message': 'Phone number or email already exists'}), 409

        # Split user_name into FirstName and LastName
        first_name, last_name = split_name(user_name)
        
        # Generate OTP and temporary token
        otp = generate_otp()
        hashed_otp = hash_otp(otp)

        # Insert user into tbgl_User table and retrieve the UserId, using the dynamic UserTypeId
        cursor.execute("""
            INSERT INTO tbgl_User (FirstName, LastName, Email, Mobile, UserTypeId, CountryCode, CreatedDate)
            OUTPUT INSERTED.UserId
            VALUES (?, ?, ?, ?, ?, ?, GETDATE())
        """, (first_name, last_name, email, phone_number, user_type_id, country_code))

        user_id = cursor.fetchone()[0]  # Fetch the UserId directly from the OUTPUT clause

        if not user_id:
            raise Exception("Failed to retrieve UserId")

        # Use local machine time for consistency
        created_at = datetime.datetime.now()
        otp_verified_at = created_at + datetime.timedelta(minutes=3)
        token = generate_jwt(user_id)  # Correcting this to use user_id later

        # Insert OTP into tbgl_OTP_Login table using the retrieved UserId and include device_name and JWT token details
        cursor.execute("""
            INSERT INTO tbgl_OTP_Login (UserId, OTP, app, Created_at, Updated_at, OtpVerified_at, JwtToken, TokenExpires_at, TokenIssued_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, hashed_otp, device_name, created_at, created_at, otp_verified_at, token, created_at + datetime.timedelta(hours=1), created_at))

        conn.commit()  # Commit the transaction

        # Send OTP via email
        email_subject = "Your OTP Code"
        email_body = f"Dear {first_name},\n\nYour OTP code is {otp}. It is valid for 3 minutes.\n\nBest regards,\nUnoMiru"
        send_email(email, email_subject, email_body)

        # Return response with UserId
        return jsonify({
            'status': 200,
            'message': 'Signup successful. OTP sent to email.',
            'otp_sent_to': email,
            'token': token,
            'user_id': user_id  # Return the UserId
        })

    except Exception as e:
        print(f"Error during database operation: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        conn.close()

@app.route('/api/verify-signup-otp', methods=['POST'])
def verify_signup_otp():
    data = request.json
    
    if not data:
        return jsonify({'status': 400, 'message': 'No data provided'}), 400

    token = data.get('token')
    otp = data.get('otp')

    if not token or not otp:
        return jsonify({'status': 400, 'message': 'Token and OTP are mandatory'}), 400

    hashed_otp = hash_otp(otp)
    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 500, 'message': 'Database connection error'}), 500

    try:
        cursor = conn.cursor()

        # Verify JWT token
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_id = int(payload.get('user_id'))  # Ensure this is an integer
        except jwt.ExpiredSignatureError:
            return jsonify({'status': 401, 'message': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'status': 401, 'message': 'Invalid token'}), 401

        if not user_id:
            return jsonify({'status': 401, 'message': 'Invalid token'}), 401

        # Check OTP validity
        cursor.execute("""
            SELECT OTP, OtpVerified_at
            FROM tbgl_OTP_Login
            WHERE UserId = ? AND OTP = ?
        """, (user_id, hashed_otp))
    
        otp_record = cursor.fetchone()  # Fetch the result
        
        if not otp_record:
            return jsonify({'status': 401, 'message': 'Invalid OTP'}), 401
        
        otp_db_hash, otp_verified_at = otp_record

        # Check if OTP has expired
        if datetime.datetime.now() > otp_verified_at:
            return jsonify({'status': 401, 'message': 'OTP expired'}), 401

        # Mark OTP as verified in tbgl_OTP_Login table
        cursor.execute("""
            UPDATE tbgl_OTP_Login
            SET OtpVerified_at = ?
            WHERE UserId = ? AND OTP = ?
        """, (datetime.datetime.now(), user_id, hashed_otp))

        # Update IsActive and ModifiedDate in tbgl_User table
        rows_affected = cursor.execute("""
            UPDATE tbgl_User
            SET IsActive = 1, ModifiedDate = ?
            WHERE UserId = ?
        """, (datetime.datetime.now(), user_id))

        # Check if the update was successful
        if cursor.rowcount == 0:
            return jsonify({'status': 500, 'message': 'Failed to update user status'}), 500

        conn.commit()  # Commit the transaction

        return jsonify({'status': 200, 'message': 'OTP verified successfully and user is now active'})

    except Exception as e:
        print(f"Error during OTP verification: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    
    if not data:
        return jsonify({'status': 400, 'message': 'No data provided'}), 400

    email = data.get('email', '').strip()

    if not email:
        return jsonify({'status': 400, 'message': 'Email is mandatory'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 500, 'message': 'Database connection error'}), 500

    try:
        cursor = conn.cursor()

        # Check if user exists by email and is active
        cursor.execute("""
            SELECT UserId, Email, IsActive 
            FROM tbgl_User 
            WHERE Email = ?
        """, (email,))
        
        user = cursor.fetchone()

        if not user:
            return jsonify({'status': 404, 'message': 'Email does not exist'}), 404

        user_id, email, is_active = user

        # Check if the user's account is active
        if is_active == 0:
            return jsonify({'status': 403, 'message': 'Account is not active. Please verify your email.'}), 403

        # Generate OTP and temporary token
        otp = generate_otp()
        hashed_otp = hash_otp(otp)
        token = generate_jwt(user_id)

        # Use local machine time for consistency
        created_at = datetime.datetime.now()
        otp_verified_at = created_at + datetime.timedelta(minutes=3)

        # Insert OTP into tbgl_OTP_Login table using the retrieved UserId
        cursor.execute("""
            INSERT INTO tbgl_OTP_Login (UserId, OTP, Created_at, Updated_at, OtpVerified_at, JwtToken, TokenExpires_at, TokenIssued_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, hashed_otp, created_at, created_at, otp_verified_at, token, created_at + datetime.timedelta(hours=1), created_at))

        conn.commit()  # Commit the transaction

        # Send OTP via email
        email_subject = "Your OTP Code"
        email_body = f"Dear User,\n\nYour OTP code is {otp}. It is valid for 3 minutes.\n\nBest regards,\nUnoMiru"
        send_email(email, email_subject, email_body)

        # Return response
        return jsonify({
            'status': 200,
            'message': 'Login successful. OTP sent.',
            'otp_sent_to': email,
            'token': token
        })

    except Exception as e:
        print(f"Error during login: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        conn.close()

@app.route('/api/verify-login-otp', methods=['POST'])
def verify_login_otp():
    data = request.json
    
    if not data:
        return jsonify({'status': 400, 'message': 'No data provided'}), 400

    token = data.get('token')
    otp = data.get('otp')

    if not token or not otp:
        return jsonify({'status': 400, 'message': 'Token and OTP are mandatory'}), 400

    hashed_otp = hash_otp(otp)
    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 500, 'message': 'Database connection error'}), 500

    try:
        cursor = conn.cursor()

        # Verify JWT token
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('user_id')
        except jwt.ExpiredSignatureError:
            return jsonify({'status': 401, 'message': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'status': 401, 'message': 'Invalid token'}), 401

        if not user_id:
            return jsonify({'status': 401, 'message': 'Invalid token'}), 401

        # Check OTP validity in tbgl_OTP_Login
        cursor.execute("""
            SELECT OTP, OtpVerified_at 
            FROM tbgl_OTP_Login 
            WHERE UserId = ? AND OTP = ?
        """, (user_id, hashed_otp))

        otp_record = cursor.fetchone()

        if not otp_record:
            return jsonify({'status': 401, 'message': 'Invalid OTP'}), 401

        otp_db_hash, otp_verified_at = otp_record

        # Check if OTP has expired
        if datetime.datetime.now() > otp_verified_at:
            return jsonify({'status': 401, 'message': 'OTP expired'}), 401

        # Mark OTP as verified
        cursor.execute("""
            UPDATE tbgl_OTP_Login
            SET OtpVerified_at = ?
            WHERE UserId = ? AND OTP = ?
        """, (datetime.datetime.now(), user_id, hashed_otp))
        conn.commit()

        # Fetch the UserId and UserTypeId from tbgl_User table
        cursor.execute("SELECT UserId, UserTypeId FROM tbgl_User WHERE UserId = ?", (user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'status': 500, 'message': 'User not found after verification'}), 500

        uid, user_type_id = user  # Get both UserId and UserTypeId from the result

        return jsonify({
            'status': 200,
            'message': 'OTP verified successfully',
            'uid': uid,
            'user_type_id': user_type_id  # Include UserTypeId in the response
        })

    except Exception as e:
        print(f"Error during OTP verification: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        conn.close()

@app.route('/api/all-discover', methods=['GET'])
@token_required
def get_tags(user_id):  # Accept the user_id parameter
    try:
        # Get the 'all' query parameter to determine if all tags should be shown
        show_all = request.args.get('all', 'false').lower() == 'true'

        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Get all user-selected tags
        cursor.execute("""
            SELECT TagIds
            FROM tbDS_User_Tags
            WHERE UserId = ? AND IsActive = 1 AND IsDeleted = 0
        """, (user_id,))
        user_selected_tags = {row[0] for row in cursor.fetchall()}  # Use a set for quick lookup

        # Adjust the SQL query for SQL Server based on 'show_all' flag
        if show_all:
            cursor.execute("""
                SELECT TagId, TagName, Title, IconUrl, ImageURL, PageBGImageURL
                FROM tbDS_Tags
                WHERE IsActive = 1 AND IsDeleted = 0
                ORDER BY SortOrder ASC
            """)
        else:
            cursor.execute("""
                SELECT TOP 9 TagId, TagName, Title, IconUrl, ImageURL, PageBGImageURL
                FROM tbDS_Tags
                WHERE IsActive = 1 AND IsDeleted = 0
                ORDER BY SortOrder ASC
            """)

        tags = cursor.fetchall()
        if not tags:
            return jsonify({'status': 404, 'message': 'No tags found'}), 404

        # Extract tag details from the fetched results and check if they are selected by the user
        tag_list = [
            {
                'TagId': tag[0],
                'TagName': tag[1],
                'Title': tag[2],
                'IconUrl': tag[3],
                'ImageURL': tag[4],
                'PageBGImageURL': tag[5],
                'Selected': tag[0] in user_selected_tags  # Mark as selected if in user's tags
            }
            for tag in tags
        ]

        return jsonify({
            'status': 200,
            'tags': tag_list,
            'totalTags': len(tag_list),
            'message': 'All tags retrieved' if show_all else 'First 9 tags retrieved'
        })

    except Exception as e:
        print(f"Error retrieving tags: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/customize-discover', methods=['POST'])
@token_required
def customize_discover(user_id):
    try:
        # Get the user_id from the request (set by token_required decorator)
        user_id = request.user_id

        # Parse the JSON body to get the tag IDs
        data = request.json
        if not data or 'tags' not in data:
            return jsonify({'status': 400, 'message': 'Tags data is missing'}), 400

        tag_ids = data['tags']  # Expecting a list of tag IDs
        if not isinstance(tag_ids, list):
            return jsonify({'status': 400, 'message': 'Tags should be a list of tag IDs'}), 400

        # Convert the list of tag IDs to a comma-separated string
        tag_ids_str = ','.join(map(str, tag_ids))

        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Check if the user already has tags selected
        cursor.execute("""
            SELECT UserTagId, TagIds
            FROM tbDS_User_Tags
            WHERE UserId = ? AND IsActive = 1 AND IsDeleted = 0
        """, (user_id,))
        existing_tags = cursor.fetchone()

        if existing_tags:
            # If user exists, update the TagIds and ModifiedDate
            cursor.execute("""
                UPDATE tbDS_User_Tags
                SET TagIds = ?, ModifiedDate = ?, IsActive = 1, IsDeleted = 0
                WHERE UserId = ?
            """, (tag_ids_str, datetime.datetime.now(), user_id))
        else:
            # If no existing tags, insert new row
            cursor.execute("""
                INSERT INTO tbDS_User_Tags (UserId, TagIds, IsActive, IsDeleted, CreatedDate)
                VALUES (?, ?, 1, 0, ?)
            """, (user_id, tag_ids_str, datetime.datetime.now()))

        conn.commit()  # Commit the transaction

        # Return the newly selected tags for the user
        cursor.execute("""
            SELECT TagId, TagName, Title, IconUrl, ImageURL, PageBGImageURL
            FROM tbDS_Tags
            WHERE TagId IN ({}) AND IsActive = 1 AND IsDeleted = 0
        """.format(','.join(['?'] * len(tag_ids))), tag_ids)
        selected_tags = cursor.fetchall()

        # Prepare the response list with selected tags
        tag_list = [
            {
                'TagId': tag[0],
                'TagName': tag[1],
                'Title': tag[2],
                'IconUrl': tag[3],
                'ImageURL': tag[4],
                'PageBGImageURL': tag[5]
            }
            for tag in selected_tags
        ]

        return jsonify({
            'status': 200,
            'message': 'User tags updated successfully',
            'selectedTags': tag_list
        })

    except Exception as e:
        print(f"Error during add or update user tags: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()

# API route to get VR Discover Listing
@app.route('/api/vr-discover-listing', methods=['GET'])
@token_required  # Apply token validation to this route as well
def vr_discover_listing(user_id):
    try:
        # Get the 'all' query parameter to determine if all properties should be shown
        show_all = request.args.get('all', 'false').lower() == 'true'

        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Adjust the SQL query based on the show_all flag
        if show_all:
            cursor.execute("""
                SELECT [VR360ID], [CategoryID], [SubCategoryID], [Country], [State], 
                       [City], [PropertyName], [PropertyDescription], [PropertyImageURL], 
                       [CategoryTitle], [AvgPropertyRating], [ButtonTitle], [ButtonURL], 
                       [PartofPackage], [SortOrder], [IsActive], [IsDeleted], 
                       [CreatedDate], [ModifiedDate]
                FROM [dbo].[tbDS_VR360]
                WHERE IsActive = 1 AND IsDeleted = 0
                ORDER BY SortOrder ASC
            """)
        else:
            cursor.execute("""
                SELECT TOP 10 [VR360ID], [CategoryID], [SubCategoryID], [Country], [State], 
                              [City], [PropertyName], [PropertyDescription], [PropertyImageURL], 
                              [CategoryTitle], [AvgPropertyRating], [ButtonTitle], [ButtonURL], 
                              [PartofPackage], [SortOrder], [IsActive], [IsDeleted], 
                              [CreatedDate], [ModifiedDate]
                FROM [dbo].[tbDS_VR360]
                WHERE IsActive = 1 AND IsDeleted = 0
                ORDER BY SortOrder ASC
            """)

        properties = cursor.fetchall()
        if not properties:
            return jsonify({'status': 404, 'message': 'No properties found'}), 404

        # Extract property details from the fetched results
        property_list = [
            {
                'VR360ID': prop[0],
                'CategoryID': prop[1],
                'SubCategoryID': prop[2],
                'Country': prop[3],
                'State': prop[4],
                'City': prop[5],
                'PropertyName': prop[6],
                'PropertyDescription': prop[7],
                'PropertyImageURL': prop[8],
                'CategoryTitle': prop[9],
                'AvgPropertyRating': prop[10],
                'ButtonTitle': prop[11],
                'ButtonURL': prop[12],
                'PartofPackage': prop[13],
                'SortOrder': prop[14],
                'IsActive': prop[15],
                'IsDeleted': prop[16],
                'CreatedDate': prop[17],
                'ModifiedDate': prop[18]
            }
            for prop in properties
        ]

        return jsonify({
            'status': 200,
            'properties': property_list,
            'totalProperties': len(property_list),
            'message': 'All properties retrieved' if show_all else 'First 10 properties retrieved'
        })

    except Exception as e:
        print(f"Error retrieving properties: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()

# API route to get an individual VR360 listing by ID
@app.route('/api/vr-discover-listing/<int:vr360_id>', methods=['GET'])
@token_required  # Apply token validation to this route as well
def get_vr360_listing(user_id, vr360_id):
    try:
        # Establish the database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # SQL query to fetch the VR360 details by ID with country name join
        cursor.execute("""
            SELECT vr.[VR360ID], vr.[CategoryID], vr.[SubCategoryID], vr.[Country], vr.[State], 
                   vr.[City], vr.[PropertyName], vr.[PropertyDescription], vr.[PropertyImageURL], 
                   vr.[CategoryTitle], vr.[AvgPropertyRating], vr.[ButtonTitle], vr.[ButtonURL], 
                   vr.[PartofPackage], vr.[SortOrder], vr.[IsActive], vr.[IsDeleted], 
                   vr.[CreatedDate], vr.[ModifiedDate],
                   vr.[PropertyFeatures], vr.[FeaturesHeading], vr.[CityName], 
                   cn.[Name]  -- Fetch country name from tbMS_Country
            FROM [dbo].[tbDS_VR360] vr
            LEFT JOIN [dbo].[tbMS_Country] cn ON vr.[Country] = cn.[CountryID]  -- Join with tbMS_Country table
            WHERE vr.[VR360ID] = ? AND vr.[IsActive] = 1 AND vr.[IsDeleted] = 0
        """, (vr360_id,))

        property = cursor.fetchone()
        if not property:
            return jsonify({'status': 404, 'message': f'Property with VR360ID {vr360_id} not found'}), 404

        # Extract property details from the fetched result
        property_data = {
            'VR360ID': property[0],
            'CategoryID': property[1],
            'SubCategoryID': property[2],
            'Country': property[22],  # CountryName instead of CountryID
            'State': property[4],
            'City': property[5],
            'PropertyName': property[6],
            'PropertyDescription': property[7],
            'PropertyImageURL': property[8],
            'CategoryTitle': property[9],
            'AvgPropertyRating': property[10],
            'ButtonTitle': property[11],
            'ButtonURL': property[12],
            'PartofPackage': property[13],
            'SortOrder': property[14],
            'IsActive': property[15],
            'IsDeleted': property[16],
            'CreatedDate': property[17],
            'ModifiedDate': property[18],
            'PropertyFeatures': property[19],
            'FeaturesHeading': property[20],
            'CityName': property[21]
        }

        return jsonify({
            'status': 200,
            'property': property_data,
            'message': f'Property with VR360ID {vr360_id} retrieved successfully'
        })

    except Exception as e:
        print(f"Error retrieving property with VR360ID {vr360_id}: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()

# Search API for VR360 using single search input for multiple columns
@app.route('/api/vr360/search', methods=['POST'])
@token_required
def search_vr360(user_id):
    try:
        # Parse the JSON request body
        data = request.get_json()

        # Extract search input from the JSON body
        search_input = data.get('search_input', None)

        if not search_input:
            return jsonify({'status': 400, 'message': 'Search input is required'}), 400

        # Build the SQL query to search across multiple columns
        query = """
            SELECT [VR360ID], [CategoryID], [SubCategoryID], [Country], [State], [City], 
                   [PropertyName], [PropertyDescription], [PropertyImageURL], [CategoryTitle],
                   [AvgPropertyRating], [ButtonTitle], [ButtonURL], [PartofPackage], 
                   [SortOrder], [IsActive], [IsDeleted], [CreatedDate], [ModifiedDate]
            FROM [dbo].[tbDS_VR360]
            WHERE IsActive = 1 AND IsDeleted = 0
            AND (
                [Country] LIKE ? OR
                [State] LIKE ? OR
                [City] LIKE ? OR
                [PropertyName] LIKE ? OR
                [CategoryTitle] LIKE ?
            )
            ORDER BY SortOrder ASC
        """

        # Wildcard the search input for partial matches
        search_pattern = f'%{search_input}%'

        # Connect to the database
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Execute the query with the search input used for multiple columns
        cursor.execute(query, (search_pattern, search_pattern, search_pattern, search_pattern, search_pattern))
        properties = cursor.fetchall()

        if not properties:
            return jsonify({'status': 404, 'message': 'No properties found'}), 404

        # Convert the result to a list of dictionaries
        property_list = [
            {
                'VR360ID': prop[0],
                'CategoryID': prop[1],
                'SubCategoryID': prop[2],
                'Country': prop[3],
                'State': prop[4],
                'City': prop[5],
                'PropertyName': prop[6],
                'PropertyDescription': prop[7],
                'PropertyImageURL': prop[8],
                'CategoryTitle': prop[9],
                'AvgPropertyRating': prop[10],
                'ButtonTitle': prop[11],
                'ButtonURL': prop[12],
                'PartofPackage': prop[13],
                'SortOrder': prop[14],
                'IsActive': prop[15],
                'IsDeleted': prop[16],
                'CreatedDate': prop[17],
                'ModifiedDate': prop[18]
            }
            for prop in properties
        ]

        return jsonify({
            'status': 200,
            'properties': property_list,
            'totalProperties': len(property_list),
            'message': f"{len(property_list)} properties found"
        })

    except Exception as e:
        print(f"Error during property search: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()

import os
import uuid
from werkzeug.utils import secure_filename
from flask import request, jsonify

# Define the folder where uploaded images will be stored
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))  # Gets the current directory
UPLOAD_FOLDER = os.path.join(CURRENT_DIR, 'uploads', 'reviews')  # Path to 'uploads/reviews' folder
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to generate a unique filename
def generate_unique_filename(filename):
    extension = filename.rsplit('.', 1)[1].lower()  # Get the file extension
    unique_filename = f"{uuid.uuid4()}.{extension}"  # Create unique filename using UUID
    return unique_filename

import os
import uuid
from werkzeug.utils import secure_filename
from flask import Flask, request, jsonify
from flask_cors import CORS

# Initialize the Flask application
app = Flask(__name__)
CORS(app)

# Secret key for JWT encoding/decoding
SECRET_KEY = 'your_secret_key'

# Define the upload folders and allowed extensions
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))  # Gets the current directory
UPLOAD_FOLDER = os.path.join(CURRENT_DIR, 'uploads')  # Base upload directory
REVIEWS_FOLDER = os.path.join(UPLOAD_FOLDER, 'reviews')  # Subfolder for reviews
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure the reviews folder exists
os.makedirs(REVIEWS_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to save files in the specified folder
def save_file(file, folder):
    if file and allowed_file(file.filename):
        # Create a secure and unique filename
        unique_filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
        filepath = os.path.join(folder, unique_filename)
        file.save(filepath)
        return filepath  # Return the path for DB storage
    return None

@app.route('/api/vr-review/<int:vr360_id>', methods=['POST'])
@token_required
def submit_review_comment(user_id, vr360_id):
    try:
        # Parse form data and get the image (optional)
        data = request.form  # Use form to get both file and JSON data
        image = request.files.get('ReviewImage')  # Get the image file from the request

        # Ensure required fields are provided
        rating = data.get('Rating')
        review_text = data.get('ReviewText')

        if rating is None or not review_text:
            return jsonify({'status': 400, 'message': 'Rating and ReviewText are required'}), 400

        # Save the review image (if provided and valid)
        review_image_path = save_file(image, REVIEWS_FOLDER)

        # Generate a URL for the saved image
        review_image_url = None
        if review_image_path:
            review_image_url = f"{request.host_url}uploads/reviews/{os.path.basename(review_image_path)}"

        # Establish the database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Check if the user already submitted a review for this VR360ID
        cursor.execute("""
            SELECT ReviewID 
            FROM [UnomiruAppDB].[dbo].[tbDS_RatingsReviews]
            WHERE VR360ID = ? AND UserID = ? AND IsActive = 1 AND IsDeleted = 0
        """, (vr360_id, user_id))
        
        existing_review = cursor.fetchone()

        if existing_review:
            return jsonify({
                'status': 400,
                'message': 'User has already submitted an active review for this VR360ID'
            }), 400

        # Insert the new review into the tbDS_RatingsReviews table, including the image URL if provided
        cursor.execute("""
            INSERT INTO [UnomiruAppDB].[dbo].[tbDS_RatingsReviews] 
            (VR360ID, UserID, Rating, ReviewText, ReviewsImageUrl, IsActive, IsDeleted, CreatedDate)
            VALUES (?, ?, ?, ?, ?, 1, 0, GETDATE())
        """, (vr360_id, user_id, rating, review_text, review_image_url))

        conn.commit()

        return jsonify({
            'status': 201,
            'message': f'Review successfully submitted for VR360ID {vr360_id}',
            'image_url': review_image_url
        }), 201

    except Exception as e:
        print(f"Error submitting review for VR360ID {vr360_id}: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()

           
@app.route('/api/vr-reviews/<int:vr360_id>', methods=['GET'])
@token_required  # Assuming you are using the same token-based authentication
def get_reviews(user_id, vr360_id):
    try:
        # Establish the database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Query to get all reviews for the specified VR360, including user first and last names, and review image URL
        cursor.execute("""
            SELECT 
                r.ReviewText, 
                r.Rating, 
                r.CreatedDate, 
                u.FirstName, 
                u.LastName,
                r.ReviewsImageUrl  -- Fetch the review image URL
            FROM [UnomiruAppDB].[dbo].[tbDS_RatingsReviews] AS r
            JOIN [UnomiruAppDB].[dbo].[tbgl_User] AS u ON r.UserID = u.UserId
            WHERE r.VR360ID = ? AND r.IsActive = 1 AND r.IsDeleted = 0
        """, (vr360_id,))

        reviews = cursor.fetchall()

        # Query to calculate the average rating for the VR360ID
        cursor.execute("""
            SELECT AVG(CAST(Rating AS FLOAT))
            FROM [UnomiruAppDB].[dbo].[tbDS_RatingsReviews]
            WHERE VR360ID = ? AND IsActive = 1 AND IsDeleted = 0
        """, (vr360_id,))
        
        avg_rating = cursor.fetchone()[0]  # Fetch the average rating
        
        # Handle no reviews case
        if not reviews:
            return jsonify({
                'status': 404,
                'message': f'No reviews found for VR360ID {vr360_id}'
            }), 404

        # If avg_rating is None (no reviews), set to 0
        if avg_rating is None:
            avg_rating = 0.0

        # Prepare the response data for each review
        review_list = []
        for review in reviews:
            review_list.append({
                'ReviewText': review[0],  # ReviewText
                'Rating': review[1],      # Rating
                'CreatedDate': review[2].strftime("%Y-%m-%d %H:%M:%S"),  # Format the CreatedDate
                'FirstName': review[3],   # FirstName
                'LastName': review[4],    # LastName
                'ReviewsImageUrl': review[5]  # Review Image URL (can be null)
            })

        # Respond with the list of reviews, average rating, and total reviews
        return jsonify({
            'status': 200,
            'VR360ID': vr360_id,
            'Reviews': review_list,
            'AverageRating': round(float(avg_rating), 2),  # Round to 2 decimal places
            'TotalReviews': len(review_list)  # Total number of reviews
        }), 200

    except Exception as e:
        print(f"Error retrieving reviews for VR360ID {vr360_id}: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()  # Ensure the connection is closed

# Add route for managing wishlist
@app.route('/api/wishlist/<int:vr360_id>', methods=['POST'])
@token_required
def toggle_wishlist(user_id, vr360_id):
    try:
        # Establish the database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Check if a wishlist entry exists for the user and VR360ID
        cursor.execute("""
            SELECT WishlistID, IsDeleted 
            FROM [UnomiruAppDB].[dbo].[tbDS_Wishlist] 
            WHERE UserID = ? AND VR360ID = ?
        """, (user_id, vr360_id))
        
        wishlist_entry = cursor.fetchone()

        if wishlist_entry:
            # Toggle the IsDeleted value: If 0, set to 1, and vice versa
            new_is_deleted = 1 if wishlist_entry[1] == 0 else 0

            # Update the existing wishlist entry
            cursor.execute("""
                UPDATE [UnomiruAppDB].[dbo].[tbDS_Wishlist]
                SET IsDeleted = ?, CreatedDate = GETDATE()
                WHERE WishlistID = ?
            """, (new_is_deleted, wishlist_entry[0]))

            message = "Removed from wishlist" if new_is_deleted == 1 else "Added to wishlist"
        else:
            # Insert a new wishlist entry
            cursor.execute("""
                INSERT INTO [UnomiruAppDB].[dbo].[tbDS_Wishlist] 
                (UserID, VR360ID, CreatedDate, IsDeleted)
                VALUES (?, ?, GETDATE(), 0)
            """, (user_id, vr360_id))
            message = "Added to wishlist"

        conn.commit()

        return jsonify({
            'status': 200,
            'message': message
        }), 200

    except Exception as e:
        print(f"Error toggling wishlist for VR360ID {vr360_id}: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()
      
# API route to get VR Discover Listing for guest access
@app.route('/api/guest-vr-discover-listing', methods=['GET'])
def guest_vr_discover_listing():
    try:
        # Get the 'all' query parameter to determine if all properties should be shown
        show_all = request.args.get('all', 'false').lower() == 'true'

        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Adjust the SQL query based on the show_all flag
        if show_all:
            cursor.execute("""
                SELECT [VR360ID], [CategoryID], [SubCategoryID], [Country], [State], 
                       [City], [PropertyName], [PropertyDescription], [PropertyImageURL], 
                       [CategoryTitle], [AvgPropertyRating], [ButtonTitle], [ButtonURL], 
                       [PartofPackage], [SortOrder], [IsActive], [IsDeleted], 
                       [IsPermission], [CreatedDate], [ModifiedDate]
                FROM [dbo].[tbDS_VR360]
                WHERE IsActive = 1 AND IsDeleted = 0
                ORDER BY SortOrder ASC
            """)
        else:
            cursor.execute("""
                SELECT TOP 10 [VR360ID], [CategoryID], [SubCategoryID], [Country], [State], 
                              [City], [PropertyName], [PropertyDescription], [PropertyImageURL], 
                              [CategoryTitle], [AvgPropertyRating], [ButtonTitle], [ButtonURL], 
                              [PartofPackage], [SortOrder], [IsActive], [IsDeleted], 
                              [IsPermission], [CreatedDate], [ModifiedDate]
                FROM [dbo].[tbDS_VR360]
                WHERE IsActive = 1 AND IsDeleted = 0
                ORDER BY SortOrder ASC
            """)

        properties = cursor.fetchall()
        if not properties:
            return jsonify({'status': 404, 'message': 'No properties found'}), 404

        # Extract property details from the fetched results
        property_list = [
            {
                'VR360ID': prop[0],
                'CategoryID': prop[1],
                'SubCategoryID': prop[2],
                'Country': prop[3],
                'State': prop[4],
                'City': prop[5],
                'PropertyName': prop[6],
                'PropertyDescription': prop[7],
                'PropertyImageURL': prop[8],
                'CategoryTitle': prop[9],
                'AvgPropertyRating': prop[10],
                'ButtonTitle': prop[11],
                'ButtonURL': prop[12],
                'PartofPackage': prop[13],
                'SortOrder': prop[14],
                'IsActive': prop[15],
                'IsDeleted': prop[16],
                'IsPermission': prop[17],  # Determines if the 360 video is allowed
                'CanView360': prop[17] == 1,  # True if permission is granted
                'CreatedDate': prop[18],
                'ModifiedDate': prop[19]
            }
            for prop in properties
        ]

        return jsonify({
            'status': 200,
            'properties': property_list,
            'totalProperties': len(property_list),
            'message': 'All properties retrieved' if show_all else 'First 10 properties retrieved'
        })

    except Exception as e:
        print(f"Error retrieving properties: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()

#Opportunity API Part starts here
def extract_info_from_card(image_path):
    try:
        pytesseract.pytesseract.tesseract_cmd = r'/usr/bin/tesseract'

        img = Image.open(image_path)

        # Use pytesseract to extract text from the image
        text = pytesseract.image_to_string(img)

        # Patterns for detecting relevant information from the text
        name_pattern = r'\b[A-Z][a-z]*\s[A-Z][a-z]+(?:\s[A-Z][a-z]+)?\b'
        email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
        phone_pattern = r'(\+?\d{1,3}[-.\s]?)?(\(?\d{1,4}?\)?[-.\s]?)?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}'
        company_pattern = r'\b[A-Z][a-zA-Z]+(?:\s[A-Za-z]+)?(?:\s(?:Corporation|Inc|Ltd|LLC|Group|Technologies|Solutions|Corp|Pvt|Company|Co|Pvt. Ltd.))?\b'
        designation_pattern = r'\b(CEO|CTO|Manager|Director|Engineer|Consultant|Developer|Founder|President|Partner|Sales|Marketing|Chief Technology Officer|Business Head|Head|HR Executive|Marketing Head)\b'
        address_pattern = r'\d{1,5}\s[A-Za-z0-9.,\s]+(?:\b[A-Za-z]+\b[,.\s]+)+(?:[A-Za-z]{2,},?\s?\d{5,6}|PO Box\s?\d{1,6}|[A-Za-z]+\s[A-Za-z]+,\s?[A-Za-z]+)'
        # Extracting using regex
        name = re.search(name_pattern, text)
        email = re.search(email_pattern, text)
        phone = re.search(phone_pattern, text)
        company = re.search(company_pattern, text)
        designation = re.search(designation_pattern, text, re.IGNORECASE)
        address = re.search(address_pattern, text)

        # Build the result dictionary with defaults if not found
        result = {
            'name': name.group(0) if name else 'Not Found',
            'email': email.group(0) if email else 'Not Found',
            'phone': phone.group(0) if phone else 'Not Found',
            'company': company.group(0) if company else 'Not Found',
            'designation': designation.group(0) if designation else 'Not Found',
            'address': address.group(0) if address else 'Not Found'
        }

        return result

    except Exception as e:
        return {"error": str(e)}

@app.route('/api/extract', methods=['POST'])
@token_required  # Require token for this route
def extract(user_id):
    if 'image' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    image = request.files['image']
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as temp_image:
        image_path = temp_image.name
        image.save(image_path)
    
    result = extract_info_from_card(image_path)
    os.remove(image_path)
    
    return jsonify(result)

@app.route('/api/property', methods=['POST'])
@token_required
def save_or_update_property(user_id):
    try:
        # Get form data
        data = request.form

        # Extract values from the form data
        pname = data.get('PName')
        address = data.get('Address')
        latitude = data.get('Latitude')
        longitude = data.get('Longitude')
        designation = data.get('Designation')
        company_name = data.get('CompanyName')
        mobile_number = data.get('MobileNumber')

        # Handle file uploads (images) if sent
        selfie = request.files.get('SelfieWithPropertyURL')
        property_image = request.files.get('PropertyImageURL')
        visiting_card = request.files.get('VisitingCardURL')

        # Save each file (if provided and valid)
        selfie_path = save_file(selfie, SELFIE_FOLDER)
        property_image_path = save_file(property_image, PROPERTY_FOLDER)
        visiting_card_path = save_file(visiting_card, VISITING_CARD_FOLDER)

        # Connect to the database
        connection = get_db_connection()
        if not connection:
            return jsonify({'status': 500, 'message': 'Database connection failed'}), 500

        cursor = connection.cursor()

        # Check if the property already exists (e.g., by PName and UserID or Address)
        check_query = """
            SELECT PropertyID FROM [dbo].[tbOPT_Property] 
            WHERE UserID = ? AND (PName = ? OR Address = ?)
        """
        cursor.execute(check_query, (user_id, pname, address))
        result = cursor.fetchone()

        if result:
            # Property exists, so update it
            property_id = result[0]
            update_query = """
                UPDATE [dbo].[tbOPT_Property]
                SET PName = ?, Address = ?, Latitude = ?, Longitude = ?, Designation = ?, 
                    CompanyName = ?, MobileNumber = ?, SelfieWithPropertyURL = ?, 
                    PropertyImageURL = ?, VisitingCardURL = ?, ModifiedBy = ?, ModifiedAt = GETDATE()
                WHERE PropertyID = ?
            """
            cursor.execute(update_query, (pname, address, latitude, longitude, designation, company_name, 
                                          mobile_number, selfie_path, property_image_path, visiting_card_path, 
                                          user_id, property_id))
            message = 'Property updated successfully'
        else:
            # Property does not exist, so insert a new one
            insert_query = """
                INSERT INTO [dbo].[tbOPT_Property] 
                (UserID, PName, Address, Latitude, Longitude, Designation, CompanyName, MobileNumber, 
                 SelfieWithPropertyURL, PropertyImageURL, VisitingCardURL, IsActive, IsDeleted, IsPermission, CreatedAt, ModifiedBy, ModifiedAt)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 0, GETDATE(), ?, GETDATE())
            """
            cursor.execute(insert_query, (user_id, pname, address, latitude, longitude, designation, 
                                          company_name, mobile_number, selfie_path, property_image_path, 
                                          visiting_card_path, user_id))
            message = 'Property saved successfully'

        connection.commit()
        cursor.close()

        return jsonify({'status': 200, 'message': message}), 200

    except Exception as e:
        print(f"Error saving or updating property: {e}")
        return jsonify({'status': 500, 'message': 'An error occurred while saving or updating the property'}), 500

@app.route('/api/user/properties', methods=['GET'])
@token_required
def get_user_properties(user_id):
    try:
        connection = get_db_connection()
        if not connection:
            return jsonify({'status': 500, 'message': 'Database connection failed'}), 500
        
        cursor = connection.cursor()

        # Query to get all properties for the authenticated user
        query = """
            SELECT PropertyID, PName, Address, Latitude, Longitude, Designation, 
                   CompanyName, MobileNumber, CreatedAt 
            FROM [dbo].[tbOPT_Property] 
            WHERE UserID = ? AND IsDeleted = 0
        """
        cursor.execute(query, (user_id,))  # Use user_id from the token to get only this user's properties
        properties = cursor.fetchall()

        if properties:
            property_list = []
            for property in properties:
                property_list.append({
                    'PropertyID': property[0],
                    'PName': property[1],
                    'Address': property[2],
                    'Latitude': property[3],
                    'Longitude': property[4],
                    'Designation': property[5],
                    'CompanyName': property[6],
                    'MobileNumber': property[7],
                    'CreatedAt': property[8].isoformat()
                })
            cursor.close()
            return jsonify({'status': 200, 'properties': property_list}), 200
        else:
            cursor.close()
            return jsonify({'status': 404, 'message': 'No properties found for this user'}), 404

    except Exception as e:
        print(f"Error retrieving properties: {e}")
        return jsonify({'status': 500, 'message': 'An error occurred while retrieving properties'}), 500


# Route to get all properties
@app.route('/api/properties', methods=['GET'])
@token_required
def get_all_properties(user_id):
    try:
        connection = get_db_connection()
        if not connection:
            return jsonify({'status': 500, 'message': 'Database connection failed'}), 500
        
        cursor = connection.cursor()
        query = "SELECT PropertyID, UserID, PName, Address, Latitude, Longitude, Designation, CompanyName, MobileNumber, CreatedAt FROM [dbo].[tbOPT_Property] WHERE IsDeleted = 0"
        cursor.execute(query)
        properties = cursor.fetchall()

        # Convert properties to a list of dictionaries
        properties_list = []
        for property in properties:
            properties_list.append({
                'PropertyID': property[0],
                'UserID': property[1],
                'PName': property[2],
                'Address': property[3],
                'Latitude': property[4],
                'Longitude': property[5],
                'Designation': property[6],
                'CompanyName': property[7],
                'MobileNumber': property[8],
                'CreatedAt': property[9].isoformat()
            })

        cursor.close()
        return jsonify({'status': 200, 'properties': properties_list}), 200

    except Exception as e:
        print(f"Error retrieving properties: {e}")
        return jsonify({'status': 500, 'message': 'An error occurred while retrieving properties'}), 500


@app.route('/api/property/search', methods=['POST'])
@token_required
def search_property(user_id):
    try:
        # Parse the JSON request body
        data = request.get_json()

        # Extract search input from the JSON body
        search_input = data.get('search_input', None)

        if not search_input:
            return jsonify({'status': 400, 'message': 'Search input is required'}), 400

        # Build the SQL query to search across multiple columns
        query = """
            SELECT PropertyID, UserID, PName, Address, Latitude, Longitude, Designation, 
                   CompanyName, MobileNumber, CreatedAt
            FROM [dbo].[tbOPT_Property]
            WHERE IsDeleted = 0
            AND (
                PName LIKE ? OR
                CompanyName LIKE ? OR
                Address LIKE ? OR
                Designation LIKE ?
            )
            ORDER BY CreatedAt DESC
        """

        # Wildcard the search input for partial matches
        search_pattern = f'%{search_input}%'

        # Connect to the database
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Execute the query with the search input used for multiple columns
        cursor.execute(query, (search_pattern, search_pattern, search_pattern, search_pattern))
        properties = cursor.fetchall()

        if not properties:
            return jsonify({'status': 404, 'message': 'No properties found'}), 404

        # Convert the result to a list of dictionaries
        property_list = [
            {
                'PropertyID': prop[0],
                'UserID': prop[1],
                'PName': prop[2],
                'Address': prop[3],
                'Latitude': prop[4],
                'Longitude': prop[5],
                'Designation': prop[6],
                'CompanyName': prop[7],
                'MobileNumber': prop[8],
                'CreatedAt': prop[9].isoformat() if prop[9] else None
            }
            for prop in properties
        ]

        return jsonify({
            'status': 200,
            'properties': property_list,
            'totalProperties': len(property_list),
            'message': f"{len(property_list)} properties found"
        })

    except Exception as e:
        print(f"Error during property search: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500

    finally:
        if conn:
            conn.close()

# Route to get a specific property by PropertyID
@app.route('/api/property/<int:property_id>', methods=['GET'])
@token_required
def get_property_by_id(user_id, property_id):
    try:
        connection = get_db_connection()
        if not connection:
            return jsonify({'status': 500, 'message': 'Database connection failed'}), 500
        
        cursor = connection.cursor()
        query = "SELECT PropertyID, UserID, PName, Address, Latitude, Longitude, Designation, CompanyName, MobileNumber, CreatedAt FROM [dbo].[tbOPT_Property] WHERE PropertyID = ? AND IsDeleted = 0"
        cursor.execute(query, (property_id,))
        property = cursor.fetchone()

        if property:
            property_data = {
                'PropertyID': property[0],
                'UserID': property[1],
                'PName': property[2],
                'Address': property[3],
                'Latitude': property[4],
                'Longitude': property[5],
                'Designation': property[6],
                'CompanyName': property[7],
                'MobileNumber': property[8],
                'CreatedAt': property[9].isoformat()
            }
            cursor.close()
            return jsonify({'status': 200, 'property': property_data}), 200
        else:
            cursor.close()
            return jsonify({'status': 404, 'message': 'Property not found'}), 404

    except Exception as e:
        print(f"Error retrieving property: {e}")
        return jsonify({'status': 500, 'message': 'An error occurred while retrieving the property'}), 500
# Route to submit a review and rating
@app.route('/api/property/review/<int:property_id>', methods=['POST'])
@token_required
def submit_review(user_id, property_id):
    try:
        data = request.get_json()

        # Ensure required fields are provided
        rating = data.get('Rating')
        review_text = data.get('ReviewText')

        if rating is None or not review_text:
            return jsonify({'status': 400, 'message': 'Rating and ReviewText are required'}), 400

        # Establish the database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Check if the user already submitted a review for this PropertyID
        cursor.execute("""
            SELECT ReviewOptID 
            FROM [UnomiruAppDB].[dbo].[tbOPT_RatingsReviews]
            WHERE PropertyID = ? AND UserID = ? AND IsActive = 1 AND IsDeleted = 0
        """, (property_id, user_id))
        
        existing_review = cursor.fetchone()

        if existing_review:
            return jsonify({
                'status': 400,
                'message': 'User has already submitted an active review for this PropertyID'
            }), 400

        # Insert the new review into the tbOPT_RatingsReviews table
        cursor.execute("""
            INSERT INTO [UnomiruAppDB].[dbo].[tbOPT_RatingsReviews] 
            (PropertyID, UserID, Rating, ReviewText, IsActive, IsDeleted, CreatedDate)
            VALUES (?, ?, ?, ?, 1, 0, GETDATE())
        """, (property_id, user_id, rating, review_text))

        conn.commit()

        return jsonify({
            'status': 201,
            'message': f'Review successfully submitted for PropertyID {property_id}'
        }), 201

    except Exception as e:
        print(f"Error submitting review for PropertyID {property_id}: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()
# Route to get review count and average rating
@app.route('/api/property/reviews/<int:property_id>', methods=['GET'])
@token_required
def get_property_reviews(user_id, property_id):
    try:
        # Establish the database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Query to get all reviews for the specified property, including user first and last names
        cursor.execute("""
            SELECT 
                r.ReviewText, 
                r.Rating, 
                r.CreatedDate, 
                u.FirstName, 
                u.LastName
            FROM [UnomiruAppDB].[dbo].[tbOPT_RatingsReviews] AS r
            JOIN [UnomiruAppDB].[dbo].[tbgl_User] AS u ON r.UserID = u.UserId
            WHERE r.PropertyID = ? AND r.IsActive = 1 AND r.IsDeleted = 0
        """, (property_id,))

        reviews = cursor.fetchall()

        # Query to calculate the precise average rating for the property
        cursor.execute("""
            SELECT AVG(CAST(Rating AS FLOAT))
            FROM [UnomiruAppDB].[dbo].[tbOPT_RatingsReviews]
            WHERE PropertyID = ? AND IsActive = 1 AND IsDeleted = 0
        """, (property_id,))
        
        avg_rating = cursor.fetchone()[0]  # Fetch the average rating
        
        if avg_rating is None:
            avg_rating = 0  # Set to 0 if there are no reviews

        # Format the result
        review_list = []
        for review in reviews:
            review_list.append({
                'ReviewText': review[0],   # ReviewText
                'Rating': review[1],       # Rating
                'CreatedDate': review[2].strftime("%Y-%m-%d %H:%M:%S"),  # Format the date
                'FirstName': review[3],    # FirstName
                'LastName': review[4]      # LastName
            })

        if review_list:
            return jsonify({
                'status': 200,
                'PropertyID': property_id,
                'Reviews': review_list,
                'AverageRating': round(float(avg_rating), 2),  # Round average rating to 2 decimal places
                'TotalReviews': len(review_list)  # Total number of reviews
            }), 200
        else:
            return jsonify({
                'status': 404,
                'message': 'No reviews found for this property'
            }), 404

    except Exception as e:
        print(f"Error retrieving reviews for PropertyID {property_id}: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/wishlist/property/<int:property_id>', methods=['POST'])
@token_required
def toggle_property_wishlist(user_id, property_id):
    try:
        # Establish the database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Check if a wishlist entry exists for the user and PropertyID
        cursor.execute("""
            SELECT WishlistOptID, IsDeleted 
            FROM [UnomiruAppDB].[dbo].[tbOPT_Wishlist] 
            WHERE UserID = ? AND PropertyID = ?
        """, (user_id, property_id))
        
        wishlist_entry = cursor.fetchone()

        if wishlist_entry:
            # Toggle the IsDeleted value: If 0, set to 1 (removes from wishlist), and vice versa
            new_is_deleted = 1 if wishlist_entry[1] == 0 else 0

            # Update the existing wishlist entry
            cursor.execute("""
                UPDATE [UnomiruAppDB].[dbo].[tbOPT_Wishlist]
                SET IsDeleted = ?, CreatedDate = GETDATE()
                WHERE WishlistOptID = ?
            """, (new_is_deleted, wishlist_entry[0]))

            message = "Removed from wishlist" if new_is_deleted == 1 else "Added to wishlist"
        else:
            # Insert a new wishlist entry
            cursor.execute("""
                INSERT INTO [UnomiruAppDB].[dbo].[tbOPT_Wishlist] 
                (UserID, PropertyID, CreatedDate, IsDeleted)
                VALUES (?, ?, GETDATE(), 0)
            """, (user_id, property_id))
            message = "Added to wishlist"

        conn.commit()

        return jsonify({
            'status': 200,
            'message': message
        }), 200

    except Exception as e:
        print(f"Error toggling wishlist for PropertyID {property_id}: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()


#==================================================================== Web Page API ===============================================================


# API route to submit an enquiry
@app.route('/api/enquiries', methods=['POST'])
def submit_enquiry():
    conn = None  # Initialize conn to None
    try:
        data = request.get_json()

        # Validate input fields
        name = data.get('Name')
        email = data.get('Email')
        phone = data.get('Phone')
        course_name = data.get('CourseName')
        enquiry_message = data.get('EnquiryMessage')

        if not email or not phone:
            return jsonify({'status': 400, 'message': 'Email and Phone are required fields'}), 400

        # Establish database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Insert the new enquiry into the database
        cursor.execute("""
            INSERT INTO [dbo].[tbgl_V360courseEnquiries] 
            ([Name], [Email], [Phone], [CourseName], [EnquiryMessage], [EnquiryDate], [Status], [IsDeleted]) 
            VALUES (?, ?, ?, ?, ?, GETDATE(), 'Pending', 0)
        """, (name, email, phone, course_name, enquiry_message))

        conn.commit()

        return jsonify({
            'status': 201,
            'message': 'Enquiry submitted successfully'
        }), 201

    except Exception as e:
        print(f"Error submitting enquiry: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()  # Ensure conn is closed only if it was successfully established

    try:
        data = request.get_json()

        # Validate input fields
        name = data.get('Name')
        email = data.get('Email')
        phone = data.get('Phone')
        course_name = data.get('CourseName')
       # enquiry_message = data.get('EnquiryMessage')

        if not email or not phone:
            return jsonify({'status': 400, 'message': 'Email and Phone are required fields'}), 400

        # Establish database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Insert the new enquiry into the database
        cursor.execute("""
            INSERT INTO [dbo].[tbgl_V360courseEnquiries] 
            ([Name], [Email], [Phone], [CourseName], [EnquiryMessage], [EnquiryDate], [Status], [IsDeleted]) 
            VALUES (?, ?, ?, ?, ?, GETDATE(), 'Pending', 0)
        """, (name, email, phone, course_name, enquiry_message))

        conn.commit()

        return jsonify({
            'status': 201,
            'message': 'Enquiry submitted successfully'
        }), 201

    except Exception as e:
        print(f"Error submitting enquiry: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()

# API route to retrieve all enquiries (protected by token)
@app.route('/api/enquiries', methods=['GET'])
@token_required
def get_all_enquiries():
    try:
        # Establish database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Fetch all non-deleted enquiries from the database
        cursor.execute("""
            SELECT [EnquiryID], [Name], [Email], [Phone], [CourseName], [EnquiryMessage], 
                   [EnquiryDate], [Status] 
            FROM [dbo].[tbgl_V360courseEnquiries]
            WHERE [IsDeleted] = 0
            ORDER BY [EnquiryDate] DESC
        """)

        enquiries = cursor.fetchall()

        # Format the response data
        enquiry_list = []
        for enquiry in enquiries:
            enquiry_list.append({
                'EnquiryID': enquiry[0],
                'Name': enquiry[1],
                'Email': enquiry[2],
                'Phone': enquiry[3],
                'CourseName': enquiry[4],
                'EnquiryMessage': enquiry[5],
                'EnquiryDate': enquiry[6],
                'Status': enquiry[7]
            })

        return jsonify({
            'status': 200,
            'enquiries': enquiry_list,
            'message': 'Enquiries retrieved successfully'
        })

    except Exception as e:
        print(f"Error retrieving enquiries: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()

# API route to retrieve an individual enquiry by ID
@app.route('/api/enquiries/<int:enquiry_id>', methods=['GET'])
@token_required
def get_enquiry(enquiry_id):
    try:
        # Establish database connection
        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Fetch the specific enquiry by ID
        cursor.execute("""
            SELECT [EnquiryID], [Name], [Email], [Phone], [CourseName], [EnquiryMessage], 
                   [EnquiryDate], [Status]
            FROM [dbo].[tbgl_V360courseEnquiries]
            WHERE [EnquiryID] = ? AND [IsDeleted] = 0
        """, (enquiry_id,))

        enquiry = cursor.fetchone()

        if not enquiry:
            return jsonify({'status': 404, 'message': f'Enquiry with ID {enquiry_id} not found'}), 404

        # Format the response
        enquiry_data = {
            'EnquiryID': enquiry[0],
            'Name': enquiry[1],
            'Email': enquiry[2],
            'Phone': enquiry[3],
            'CourseName': enquiry[4],
            'EnquiryMessage': enquiry[5],
            'EnquiryDate': enquiry[6],
            'Status': enquiry[7]
        }

        return jsonify({
            'status': 200,
            'enquiry': enquiry_data,
            'message': f'Enquiry with ID {enquiry_id} retrieved successfully'
        })

    except Exception as e:
        print(f"Error retrieving enquiry with ID {enquiry_id}: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/newsletter/subscribe', methods=['POST'])
def subscribe_newsletter():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')

    if not name or not email:
        return jsonify({'status': 400, 'message': 'Name and Email are required'}), 400

    # Establish the database connection
    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 500, 'message': 'Database connection error'}), 500

    try:
        cursor = conn.cursor()
        
        # Insert the new subscriber into the newsletter table
        cursor.execute("""
            INSERT INTO [UnomiruAppDB].[dbo].[tbgl_NewsletterSignUp] 
            (Name, Email) VALUES (?, ?)
        """, (name, email))

        conn.commit()

        # Send confirmation email
        subject = "Welcome to Our Newsletter"
        body = f"Hello {name},\n\nThank you for subscribing to our newsletter!\n\nBest Regards,\nYour Company"
        send_email(email, subject, body)

        return jsonify({'status': 201, 'message': 'Subscription successful and email sent!'}), 201

    except Exception as e:
        print(f"Error during subscription: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500

    finally:
        if conn:
            conn.close()


if __name__ == '__main__':
    app.run(debug=True)

