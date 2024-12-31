from flask import Flask, jsonify, request, make_response
from flask_cors import CORS, cross_origin
from predictions import prediction
from flask_pymongo import PyMongo
from schemas import user_schema, users_schema, ma
import bcrypt
import jwt
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from dotenv import load_dotenv
load_dotenv()
import os

app = Flask(__name__)

client_url = os.getenv("CLIENT_URL")
# Enable CORS for all routes with a specific origin (React app in this case)
CORS(app, resources={r"/*": {"origins": client_url}}, supports_credentials=True)  # Replace with your actual React app origin if needed

# Database connection
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config['SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")  # Set your secret key here
mongo = PyMongo(app)

# Initialize Marshmallow with the Flask app
ma.init_app(app)

# MongoDB collection
collection = mongo.db.users

@app.route('/')
def home():
    return jsonify({"message": "Welcome to Flask API"})

# Route for user registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    # Validate input data with the schema
    errors = user_schema.validate(data)
    if errors:
        return jsonify({"errors": errors}), 400

    # Check if user already exists by email
    if collection.find_one({'email': data['email']}):
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
        result = collection.insert_one(new_user)
        if result.inserted_id:
            # Generate a JWT token for the new user
            token = jwt.encode({
                'user_id': str(result.inserted_id),  # MongoDB ObjectId needs to be converted to string
                'exp': datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
            }, app.config['SECRET_KEY'], algorithm="HS256")

            # Return the token along with a success message
            response = jsonify({"message": "User registered successfully!", "token": token})
            response.set_cookie(
                'readmission-token',
                token,
                max_age=24 * 60 * 60,  # Cookie expiration time set to 15 days
                samesite='None',  # For cross-origin requests
                httponly=True,  # Prevents JavaScript access to the cookie
                secure=True  # Requires HTTPS
            )
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
    user = collection.find_one({'email': data['email']})

    if not user or not bcrypt.checkpw(data['password'].encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({"message": "Login failed! Check email and password"}), 401

    # Generate a JWT token for session
    token = jwt.encode({
        'user_id': str(user['_id']),  # MongoDB ObjectId needs to be converted to string
        'exp': datetime.utcnow() + timedelta(hours=1)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    # Create response with token cookie (expires in 1 hour)
    response = make_response(jsonify({"message": "Logged in successfully!"}))
    response.set_cookie(
        'readmission-token',
        token,
        max_age=24 * 60 * 60,  # Cookie expiration time set to 15 days
        samesite='None',  # For cross-origin requests
        httponly=True,  # Prevents JavaScript access to the cookie
        secure=True  # Requires HTTPS
    )
    return response

# Route for user logout
@app.route('/logout', methods=['GET'])
def logout():
    response = make_response(jsonify({
        "success": True,
        "message": "Logged out successfully"
    }))
    
    # Remove the 'readmission-token' cookie by expiring it
    response.set_cookie(
        'readmission-token',
        '',  # Set to empty string
        max_age=0,  # Expire the cookie immediately
        samesite='None',  # Ensure cross-origin compatibility if required
        httponly=True,  # Ensure the cookie is HttpOnly
        secure=True  # Requires HTTPS
    )
    
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
            current_user = collection.find_one({'_id': ObjectId(data['user_id'])})
            if not current_user:
                raise Exception("User not found")
        except Exception as e:
            return jsonify({"message": "Token is invalid!", "error": str(e)}), 401

        return f(current_user, *args, **kwargs)
    
    return decorated

# Protected route
@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    return jsonify({
        "name": current_user['name'],
        "email": current_user['email'],
        "phone": current_user['phone']
    })

# readmission prediction route
@app.route('/predict', methods=['POST'])
def handle_data():
    print("I am inside handelr data function")
    if request.method == 'POST':
        form_data = request.json
        sorted_keys = sorted(form_data.keys())
        data_store = []

        sorted_data = [form_data[key] for key in sorted_keys]

        data_store.append(sorted_data)
        output = prediction(data_store[0])[0]  # Call to the prediction function
        output = int(output)
        message = ""
        if output:
            message = "Based on the analysis, you may require readmission."
        else:
            message = "Based on the analysis, readmission may not be necessary."
            
        response_data = {
            "message": "Data received and processed successfully.",
            "success": True,
            "data": message
        }
        return jsonify(response_data)

    # If it's a GET request, send some sample data back
    sample_data = {
        "id": 1,
        "name": "Flask-React Integration",
        "description": "This is sample data from Flask to React."
    }
    return jsonify(sample_data)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
