from flask import Flask, request, jsonify
import pyodbc
import random
import hashlib
import jwt
import datetime
import http.client
from codecs import encode

app = Flask(__name__)

# Secret key for JWT encoding/decoding
SECRET_KEY = 'your_secret_key'

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
def generate_jwt(user_id, expires_delta=datetime.timedelta(hours=1)):
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

    # Validate mandatory fields
    if not phone_number:
        return jsonify({'status': 400, 'message': 'Phone number is mandatory'}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({'status': 500, 'message': 'Database connection error'}), 500

    try:
        cursor = conn.cursor()

        # Check if user already exists
        cursor.execute("SELECT COUNT(1) FROM tbgl_User WHERE Mobile = ? OR Email = ?", (phone_number, email))
        if cursor.fetchone()[0] > 0:
            return jsonify({'status': 409, 'message': 'Phone number or email already exists'}), 409
        
        # Split user_name into FirstName and LastName
        first_name, last_name = split_name(user_name)
        
        # Generate OTP and temporary token
        otp = generate_otp()
        hashed_otp = hash_otp(otp)

        # Insert user into tbgl_User table and retrieve the UserId
        cursor.execute("""
            INSERT INTO tbgl_User (FirstName, LastName, Email, Mobile, UserTypeId, CountryCode, CreatedDate)
            OUTPUT INSERTED.UserId
            VALUES (?, ?, ?, ?, ?, ?, GETDATE())
        """, (first_name, last_name, email, phone_number, 4, country_code))

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

        # Mark OTP as verified
        cursor.execute("""
            UPDATE tbgl_OTP_Login
            SET OtpVerified_at = ?
            WHERE UserId = ? AND OTP = ?
        """, (datetime.datetime.now(), user_id, hashed_otp))
        conn.commit()

        return jsonify({'status': 200, 'message': 'OTP verified successfully'})

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

        # Check if user exists by email
        cursor.execute("""
            SELECT UserId, Email 
            FROM tbgl_User 
            WHERE Email = ?
        """, (email,))
        
        user = cursor.fetchone()

        if not user:
            return jsonify({'status': 404, 'message': 'Email does not exist'}), 404

        user_id, email = user

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
            'otp_sent_to': 'email',
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

        # Fetch the permanent UID
        cursor.execute("SELECT UserId FROM tbgl_User WHERE UserId = ?", (user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'status': 500, 'message': 'User not found after verification'}), 500

        uid = user[0]

        return jsonify({
            'status': 200,
            'message': 'OTP verified successfully',
            'uid': uid
        })

    except Exception as e:
        print(f"Error during OTP verification: {e}")
        return jsonify({'status': 500, 'message': 'Internal Server Error'}), 500
    finally:
        conn.close()


if __name__ == '__main__':
    app.run(debug=True)
