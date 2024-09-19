from flask import Flask, request, jsonify
from functools import wraps
import pyodbc
import random
import hashlib
import jwt
import datetime
import http.client
from codecs import encode
from flask_cors import CORS 

app = Flask(__name__)
CORS(app)
# Secret key for JWT encoding/decoding
SECRET_KEY = 'your_secret_key'

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'status': 401, 'message': 'Token is missing'}), 401

        try:
            # Remove "Bearer " prefix if it exists
            if token.startswith('Bearer '):
                token = token[7:]

            # Decode the token
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.user_id = payload.get('user_id')  # Set user ID in the request
        except jwt.ExpiredSignatureError:
            return jsonify({'status': 401, 'message': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'status': 401, 'message': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
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
def get_tags():
    try:
        # Get the user_id from the request (set by token_required decorator)
        user_id = request.user_id

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

        # Adjust the SQL query for SQL Server
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
def customize_discover():
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

        conn = get_db_connection()
        if not conn:
            return jsonify({'status': 500, 'message': 'Database connection error'}), 500

        cursor = conn.cursor()

        # Check if the user already has tags selected
        cursor.execute("""
            SELECT TagId
            FROM tbDS_User_Tags
            WHERE UserId = ? AND IsActive = 1 AND IsDeleted = 0
        """, (user_id,))
        existing_tags = cursor.fetchall()

        if existing_tags:
            # If user exists, update the tags and ModifiedDate
            cursor.execute("""
                UPDATE tbDS_User_Tags
                SET IsActive = 0, IsDeleted = 1, ModifiedDate = ?
                WHERE UserId = ?
            """, (datetime.datetime.now(), user_id))
        
        # Insert new tags into the tbDS_User_Tags table
        for tag_id in tag_ids:
            cursor.execute("""
                INSERT INTO tbDS_User_Tags (UserId, TagId, IsActive, IsDeleted, CreatedDate)
                VALUES (?, ?, 1, 0, ?)
            """, (user_id, tag_id, datetime.datetime.now()))

        conn.commit()  # Commit the transaction

        # Return the newly selected tags for the user
        cursor.execute("""
            SELECT TagId, TagName, Title, IconUrl, ImageURL, PageBGImageURL
            FROM tbDS_Tags
            WHERE TagId IN (?) AND IsActive = 1 AND IsDeleted = 0
        """, (",".join(map(str, tag_ids)),))
        selected_tags = cursor.fetchall()

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
def vr_discover_listing():
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


# Search API for VR360 using single search input for multiple columns
@app.route('/api/vr360/search', methods=['POST'])
@token_required
def search_vr360():
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

if __name__ == '__main__':
    app.run(debug=True)

