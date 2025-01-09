from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import bcrypt
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Secret key for JWT
SECRET_KEY = "your-secret-key"

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100))
    region = db.Column(db.String(100))
    expertise = db.Column(db.String(100))
    work_region = db.Column(db.String(100))
    role = db.Column(db.String(50), default='user')

# Request model
class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    area = db.Column(db.Integer, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    bedrooms = db.Column(db.Integer)
    style = db.Column(db.String(100))
    budget = db.Column(db.Integer)
    payment = db.Column(db.String(100))
    description = db.Column(db.String(500))
    status = db.Column(db.String(50), default='pending')

# Create database tables
with app.app_context():
    db.create_all()

# Helper function to generate JWT token
def generate_token(user_id, role):
    payload = {
        'id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

# Helper function to verify JWT token
def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Register a new user
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    full_name = data.get('fullName')
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    city = data.get('city')
    region = data.get('region')
    expertise = data.get('expertise')
    work_region = data.get('workRegion')
    role = data.get('role', 'user')

    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'User already exists.'}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Create new user
    new_user = User(
        full_name=full_name,
        email=email,
        username=username,
        password=hashed_password.decode('utf-8'),
        city=city,
        region=region,
        expertise=expertise,
        work_region=work_region,
        role=role
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully.'}), 201

# Login user
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Find user by email
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found.'}), 404

    # Check password
    if not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({'message': 'Invalid password.'}), 401

    # Generate JWT token
    token = generate_token(user.id, user.role)
    return jsonify({'token': token}), 200

# Get user profile (protected route)
@app.route('/api/user/profile', methods=['GET'])
def get_profile():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'No token provided.'}), 403

    payload = verify_token(token)
    if not payload:
        return jsonify({'message': 'Invalid or expired token.'}), 401

    user = User.query.get(payload['id'])
    if not user:
        return jsonify({'message': 'User not found.'}), 404

    return jsonify({
        'id': user.id,
        'fullName': user.full_name,
        'email': user.email,
        'username': user.username,
        'city': user.city,
        'region': user.region,
        'role': user.role
    }), 200

# Create a new property request (protected route)
@app.route('/api/requests', methods=['POST'])
def create_request():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'No token provided.'}), 403

    payload = verify_token(token)
    if not payload:
        return jsonify({'message': 'Invalid or expired token.'}), 401

    data = request.get_json()
    new_request = Request(
        user_id=payload['id'],
        type=data.get('type'),
        area=data.get('area'),
        location=data.get('location'),
        bedrooms=data.get('bedrooms'),
        style=data.get('style'),
        budget=data.get('budget'),
        payment=data.get('payment'),
        description=data.get('description')
    )
    db.session.add(new_request)
    db.session.commit()

    return jsonify({'message': 'Request created successfully.'}), 201

# Get all requests for a user (protected route)
@app.route('/api/requests', methods=['GET'])
def get_requests():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'message': 'No token provided.'}), 403

    payload = verify_token(token)
    if not payload:
        return jsonify({'message': 'Invalid or expired token.'}), 401

    requests = Request.query.filter_by(user_id=payload['id']).all()
    requests_data = [{
        'id': req.id,
        'type': req.type,
        'area': req.area,
        'location': req.location,
        'bedrooms': req.bedrooms,
        'style': req.style,
        'budget': req.budget,
        'payment': req.payment,
        'description': req.description,
        'status': req.status
    } for req in requests]

    return jsonify(requests_data), 200

# Run the server
if __name__ == '__main__':
    app.run(debug=True)