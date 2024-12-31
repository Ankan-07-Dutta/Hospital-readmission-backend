from flask import Flask, request, jsonify, make_response
from flask_pymongo import PyMongo
import bcrypt  # Import bcrypt for password hashing
from datetime import datetime, timedelta
from schemas import user_schema, users_schema  # Import schema
import jwt
from bson import ObjectId

app = Flask(__name__)

# Replace with your actual MongoDB URI
app.config['MONGO_URI'] = 'mongodb://localhost:27017/readmission-db'
app.config['SECRET_KEY'] = 'asdoaisdnqwdnoba'

# Initialize PyMongo for MongoDB
mongo = PyMongo(app)
users_collection = mongo.db.users  # Collection to store users

# Route for user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Validate input data with the schema
    errors = user_schema.validate(data)
    if errors:
        return jsonify({"errors": errors}), 400

    # Check if user already exists by email
    if users_collection.find_one({'email': data['email']}):
        return jsonify({"message": "Email already registered!"}), 400

    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

    # Create a new user document (replace password with hashed password)
    new_user = {
        'name': data['name'],
        'email': data['email'],
        'phone': data['phone'],
        'password': hashed_password.decode('utf-8')  # Store as string in MongoDB
    }

    # Insert the new user into MongoDB
    try:
        result = users_collection.insert_one(new_user)
        if result.inserted_id:
            # Generate a JWT token for the new user
            token = jwt.encode({
                'user_id': str(result.inserted_id),  # MongoDB ObjectId needs to be converted to string
                'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
            }, app.config['SECRET_KEY'], algorithm="HS256")

            # Return the token along with a success message
            response = jsonify({"message": "User registered successfully!", "token": token})
            response.set_cookie('readmission-token', token, httponly=True, expires=datetime.utcnow() + timedelta(hours=1))
            return response, 201
        else:
            return jsonify({"message": "User could not be registered."}), 500
    except Exception as e:
        return jsonify({"message": "User could not be registered", "error": str(e)}), 500

# Route for user login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    # Validate input data with the schema (email and password required)
    if 'email' not in data or 'password' not in data:
        return jsonify({"message": "Email and password are required!"}), 400

    # Find user by email in MongoDB
    user = users_collection.find_one({'email': data['email']})

    if not user or not bcrypt.checkpw(data['password'].encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({"message": "Login failed! Check email and password"}), 401

    # Generate a JWT token for session
    token = jwt.encode({
        'user_id': str(user['_id']),  # MongoDB ObjectId needs to be converted to string
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    # Create response with token cookie (expires in 1 hour)
    response = make_response(jsonify({"message": "Logged in successfully!"}))
    response.set_cookie('readmission-token', token, httponly=True, expires=datetime.utcnow() + timedelta(hours=1))
    return response

# Route for user logout
@app.route('/logout', methods=['POST'])
def logout():
    response = make_response(jsonify({"message": "Logged out successfully!"}))
    response.set_cookie('readmission-token', '', expires=0)  # Remove token cookie
    return response

# Middleware to protect routes
def token_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('readmission-token')
        
        if not token:
            return jsonify({"message": "Token is missing!"}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_collection.find_one({'_id': ObjectId(data['user_id'])})
            if not current_user:
                raise Exception("User not found")
        except Exception as e:
            return jsonify({"message": "Token is invalid!", "error": str(e)}), 401

        return f(current_user, *args, **kwargs)
    
    return decorated

# Protected route example
@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        "name": current_user['name'],
        "email": current_user['email'],
        "phone": current_user['phone']
    })

if __name__ == '__main__':
    app.run(debug=True)
