import os  # For reading environment variables
from flask import Flask, request, jsonify  # Flask framework essentials
from flask_sqlalchemy import SQLAlchemy  # ORM for database operations
from datetime import datetime  # For managing timestamps
from twilio.rest import Client  # Twilio API client for sending SMS
from flask_jwt_extended import (  # JWT extension for authentication
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from passlib.hash import pbkdf2_sha256  # For secure password hashing

app = Flask(__name__)

# Configure database URI, prioritize environment variable (e.g., from cloud)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///crashalerts.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable to save resources

# Load sensitive configuration variables securely from environment
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')  # Twilio Account SID
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')  # Twilio Auth Token
TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER')  # Your Twilio phone number
# JWT secret key used to sign and verify tokens; keep this secret in production
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-secret-key')

# Initialize SQLAlchemy ORM
db = SQLAlchemy(app)
# Initialize JWT manager for handling tokens
jwt = JWTManager(app)
# Initialize Twilio client for SMS API access
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# User database model stores username, email, and hashed password
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Primary key unique identifier
    username = db.Column(db.String(80), unique=True, nullable=False)  # User login name
    email = db.Column(db.String(120), unique=True, nullable=False)  # User email
    password_hash = db.Column(db.String(128), nullable=False)  # Hashed password

    # Hash password for secure storage
    def set_password(self, password):
        self.password_hash = pbkdf2_sha256.hash(password)

    # Confirm plaintext password against stored hash
    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password_hash)

# CrashAlert model records crash data linked to a user
class CrashAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique crash alert ID
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)  # Foreign key to User
    lat = db.Column(db.Float, nullable=False)  # Latitude coordinate
    lon = db.Column(db.Float, nullable=False)  # Longitude coordinate
    timestamp = db.Column(db.DateTime, nullable=False)  # Crash timestamp

    # Serializes the crash alert object to a JSON-serializable dict
    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "location": {"lat": self.lat, "lon": self.lon},
            "timestamp": self.timestamp.isoformat()
        }

# EmergencyContact model stores contacts for a user
class EmergencyContact(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique contact ID
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)  # Foreign key to User
    name = db.Column(db.String(100), nullable=False)  # Contact's name
    phone = db.Column(db.String(20), nullable=False)  # Contact phone number

    # Convert contact to dictionary for JSON response
    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "phone": self.phone
        }

# Create database tables if they don't exist on first request
@app.before_first_request
def create_tables():
    db.create_all()

# Endpoint to register new users (no auth required)
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()  # Parse incoming JSON payload
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    # Check for missing registration fields
    if not username or not email or not password:
        return jsonify({"error": "Missing required fields"}), 400

    # Prevent duplicate usernames or emails
    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"error": "User already exists"}), 409

    # Create new user and hash password for storage
    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# Endpoint for user login that issues JWT token on valid credentials
@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Validate login fields presence
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    user = User.query.filter_by(username=username).first()

    # Verify user and password correctness
    if not user or not user.check_password(password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Create access JWT token representing user identity
    access_token = create_access_token(identity=user.id)
    return jsonify({"access_token": access_token}), 200

# Endpoint to add emergency contact; requires valid JWT auth token
@app.route("/api/emergency-contact", methods=["POST"])
@jwt_required()
def add_emergency_contact():
    user_id = get_jwt_identity()  # Extract user ID from token
    data = request.get_json()
    name = data.get("name")
    phone = data.get("phone")

    # Ensure required contact fields are present
    if not name or not phone:
        return jsonify({"error": "Missing required fields"}), 400

    # Create and save new contact in DB
    contact = EmergencyContact(user_id=user_id, name=name, phone=phone)
    db.session.add(contact)
    db.session.commit()
    return jsonify({"message": "Emergency contact added", "contact": contact.to_dict()}), 200

# Endpoint to retrieve emergency contacts for logged-in user (JWT protected)
@app.route("/api/emergency-contacts", methods=["GET"])
@jwt_required()
def get_emergency_contacts():
    user_id = get_jwt_identity()
    contacts = EmergencyContact.query.filter_by(user_id=user_id).all()
    return jsonify([contact.to_dict() for contact in contacts]), 200

# Endpoint to submit crash alert, save it, and notify contacts via SMS (JWT protected)
@app.route("/api/crash-alert", methods=["POST"])
@jwt_required()
def crash_alert():
    user_id = get_jwt_identity()
    data = request.get_json()
    location = data.get("location")
    timestamp_str = data.get("timestamp")

    # Validate needed fields
    if not location or not timestamp_str:
        return jsonify({"error": "Missing required fields"}), 400

    # Parse timestamp string; report error if invalid format
    try:
        timestamp = datetime.fromisoformat(timestamp_str)
    except ValueError:
        return jsonify({"error": "Invalid timestamp format"}), 400

    # Store the crash alert in database
    alert = CrashAlert(user_id=user_id, lat=location.get("lat"), lon=location.get("lon"), timestamp=timestamp)
    db.session.add(alert)
    db.session.commit()

    # Retrieve user's emergency contacts
    contacts = EmergencyContact.query.filter_by(user_id=user_id).all()

    notification_messages = []
    # Loop over contacts and send SMS via Twilio
    for contact in contacts:
        message_body = (
            f"Emergency Alert!\n"
            f"Crash detected for user ID {user_id} at {timestamp_str}.\n"
            f"Location: Lat {alert.lat}, Lon {alert.lon}.\n"
            f"Please assist immediately."
        )
        try:
            message = twilio_client.messages.create(
                to=contact.phone,
                from_=TWILIO_PHONE_NUMBER,
                body=message_body
            )
            notification_messages.append(f"Sent SMS to {contact.name} ({contact.phone}), SID: {message.sid}")
        except Exception as e:
            notification_messages.append(f"Failed to send SMS to {contact.name} ({contact.phone}): {str(e)}")

    # Return success response with crash alert and SMS status
    return jsonify({
        "message": "Crash alert saved and notifications sent",
        "alert": alert.to_dict(),
        "notifications": notification_messages
    }), 200

# Run the Flask app on the port defined by environment (e.g., Heroku) or default 5000
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
