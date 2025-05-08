from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity, set_access_cookies, unset_jwt_cookies
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from datetime import timedelta

app = Flask(__name__)

# ✅ Correct CORS setup with supports_credentials + allowed origin
CORS(app, supports_credentials=True, resources={r"/*": {"origins": ["http://ayaj.infy.uk"]}})

# ✅ JWT Configuration for cookies
app.config['JWT_SECRET_KEY'] = 'your_secret_key'
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_COOKIE_NAME"] = "access_token_cookie"
app.config["JWT_COOKIE_SAMESITE"] = "Lax"  # Important for cross-origin
app.config["JWT_COOKIE_SECURE"] = False     # Set True when using HTTPS
app.config["JWT_COOKIE_DOMAIN"] = "ayaj.infy.uk"  # ⚠️ No leading dot
app.config["JWT_COOKIE_CSRF_PROTECT"] = False     # Can keep False for testing

jwt = JWTManager(app)

# Dummy in-memory user store
users = {}

@app.route('/', methods=['GET'])
def home():
    return jsonify({"msg": "Home Page Access"})

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')

    if username in users:
        return jsonify({"msg": "User already exists"}), 400

    users[username] = generate_password_hash(password)
    return jsonify({"msg": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if username not in users or not check_password_hash(users[username], password):
        return jsonify({"msg": "Invalid credentials"}), 401

    access_token = create_access_token(identity=username)
    response = jsonify({"msg": "Login successful"})
    set_access_cookies(response, access_token)
    return response, 200

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(message="This is a protected route", user=current_user), 200

@app.route('/logout', methods=['POST'])
def logout():
    response = jsonify({"msg": "Logout successful"})
    unset_jwt_cookies(response)
    return response, 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002)
