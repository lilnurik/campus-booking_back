from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from flask_restx import Api, Resource, fields
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import random
import os
from datetime import datetime, timedelta
from external_api import sync_class_schedules
from datetime import datetime, timedelta
import pytz

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///booking_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Change in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
# Fix for JWT token subject type issue
app.config['JWT_JSON_KEY'] = 'result'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ======== CORS CONFIGURATION ========
# Apply a single, consistent CORS configuration
CORS(app,
     resources={r"/*": {
         "origins": ["http://localhost:8081", "http://localhost:3000", "http://localhost:8080"],
         "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         "allow_headers": ["Content-Type", "Authorization", "Accept"]
     }},
     supports_credentials=True
     )


# Helper function to get current time
def get_current_time():
    # Using your provided timestamp (2025-04-01 08:34:52)
    return datetime(2025, 4, 1, 8, 34, 52, tzinfo=pytz.UTC)


# Helper function to check if a time slot conflicts with any scheduled class or booking
def is_time_slot_available(room_id, from_date, until_date):
    # Check class schedules
    conflicting_schedule = Schedule.query.filter_by(room_id=room_id).filter(
        ((Schedule.from_date <= from_date) & (Schedule.until_date >= from_date)) |
        ((Schedule.from_date <= until_date) & (Schedule.until_date >= until_date)) |
        ((Schedule.from_date >= from_date) & (Schedule.until_date <= until_date))
    ).first()

    if conflicting_schedule:
        return False

    # Check existing bookings
    conflicting_booking = Booking.query.filter_by(room_id=room_id).filter(
        Booking.status.in_(['pending', 'approved', 'given'])
    ).filter(
        ((Booking.from_date <= from_date) & (Booking.until_date >= from_date)) |
        ((Booking.from_date <= until_date) & (Booking.until_date >= until_date)) |
        ((Booking.from_date >= from_date) & (Booking.until_date <= until_date))
    ).first()

    if conflicting_booking:
        return False

    return True

# Add this class to your models (after the existing Booking class):
class BookingPurpose(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))




# ======== SINGLE AFTER_REQUEST HANDLER ========
@app.after_request
def after_request(response):
    origin = request.headers.get('Origin', '')

    # Allow requests from listed origins
    if origin in ['http://localhost:8081', 'http://localhost:3000', 'http://localhost:8080']:
        # Only add headers if they don't exist already to avoid duplicates
        if 'Access-Control-Allow-Origin' not in response.headers:
            response.headers.add('Access-Control-Allow-Origin', origin)
            response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,Accept')
            response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
            response.headers.add('Access-Control-Allow-Credentials', 'true')

    # Log request info for debugging
    print(f"Request: {request.method} {request.path} | Response Status: {response.status_code}")

    return response


# ======== OPTIONS REQUEST HANDLER ========
@app.route('/<path:path>', methods=['OPTIONS'])
@app.route('/api/<path:path>', methods=['OPTIONS'])
def options_handler(path):
    # Return a 200 OK with CORS headers for OPTIONS requests
    response = jsonify({'status': 'ok'})
    # Headers will be added by the after_request handler
    return response


# Setup Swagger documentation
authorizations = {
    'Bearer Auth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Type in the *'Value'* input box below: **'Bearer &lt;JWT&gt;'**, where JWT is the token"
    },
}

api = Api(app, version='1.0', title='Room Booking API',
          description='API for university room booking system',
          authorizations=authorizations, security='Bearer Auth',
          doc='/swagger/', prefix='/api')

# Define namespaces
ns_auth = api.namespace('auth', description='Authentication operations')
ns_rooms = api.namespace('rooms', description='Room operations')
ns_bookings = api.namespace('bookings', description='Booking operations')
ns_security = api.namespace('security', description='Security operations')
ns_admin = api.namespace('admin', description='Admin operations')


# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)  # Student ID
    password_hash = db.Column(db.String(256), nullable=True)
    full_name = db.Column(db.String(100))
    role = db.Column(db.String(20), default='student')  # student, security, admin
    email = db.Column(db.String(100))
    group = db.Column(db.String(50))
    course = db.Column(db.Integer)
    status = db.Column(db.String(20), default='active')
    faculty = db.Column(db.String(100))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50))
    capacity = db.Column(db.Integer)
    status = db.Column(db.String(20), default='available')  # available, maintenance


class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    from_date = db.Column(db.DateTime, nullable=False)
    until_date = db.Column(db.DateTime, nullable=False)
    type = db.Column(db.String(20))  # class, booking

    room = db.relationship('Room', backref=db.backref('schedules', lazy=True))


# Modify the Booking class to add purpose and attendees
class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    from_date = db.Column(db.DateTime, nullable=False)
    until_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected, given, taken, cancelled
    secret_code = db.Column(db.String(5), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    purpose = db.Column(db.String(255), nullable=True)  # New field
    attendees = db.Column(db.Integer, default=1)  # New field
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)  # New field

    room = db.relationship('Room', backref=db.backref('bookings', lazy=True))
    user = db.relationship('User', backref=db.backref('bookings', lazy=True))


# JWT callbacks for proper identity handling
@jwt.user_identity_loader
def user_identity_lookup(identity):
    """Convert user identity to string format"""
    return str(identity)


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    """Convert JWT subject back to integer for database lookups"""
    identity = jwt_data["sub"]
    try:
        # Try to convert back to integer for DB lookups
        return User.query.filter_by(id=int(identity)).one_or_none()
    except (ValueError, TypeError):
        # If it fails, try using it as is
        return User.query.filter_by(id=identity).one_or_none()


# Helper function to load student data from Excel
def load_student_data(student_id):
    """
    Load student data from Excel file with improved error handling
    and data type flexibility.
    """
    try:
        # Print debugging information
        print(f"Searching for student ID: '{student_id}' (type: {type(student_id).__name__})")
        excel_file = 'students.xlsx'

        # Check if file exists
        if not os.path.exists(excel_file):
            print(f"ERROR: Excel file '{excel_file}' not found in {os.getcwd()}")
            return None

        print(f"Reading Excel file: {excel_file}")
        df = pd.read_excel(excel_file)

        # Print columns to debug
        print(f"Excel columns: {df.columns.tolist()}")

        # Check if 'id' column exists
        if 'id' not in df.columns:
            print(f"ERROR: 'id' column not found in Excel. Available columns: {df.columns.tolist()}")
            return None

        # Print first few rows for debugging
        print(f"First 5 rows of Excel file:\n{df.head()}")

        # Try multiple approaches to match the ID
        # 1. Direct match
        student = df[df['id'] == student_id].to_dict('records')

        # 2. Try with string conversion if numeric
        if not student and isinstance(student_id, str) and student_id.isdigit():
            student = df[df['id'] == int(student_id)].to_dict('records')

        # 3. Try with string conversion if the Excel has numbers
        if not student:
            # Convert all IDs to strings for comparison
            df['id_str'] = df['id'].astype(str)
            student = df[df['id_str'] == str(student_id)].to_dict('records')

        if student:
            print(f"Student found: {student[0]}")
            return student[0]
        else:
            print(f"No student found with ID: {student_id}")
            print(f"Available IDs in Excel: {df['id'].tolist()[:10]}...")
            return None
    except Exception as e:
        print(f"Error loading student data: {e}")
        import traceback
        traceback.print_exc()
        return None


# Generate secret code for booking
def generate_secret_code():
    return ''.join(random.choices('0123456789', k=5))


# API Models for request and response
user_register_model = api.model('UserRegister', {
    'username': fields.String(required=True, description='Student ID'),
    'password': fields.String(required=True, description='Password')
})

user_login_model = api.model('UserLogin', {
    'username': fields.String(required=True, description='Student ID'),
    'password': fields.String(required=True, description='Password')
})

# Updated model for booking creation
booking_model = api.model('Booking', {
    'room_id': fields.Integer(required=True, description='Room ID'),
    'start_time': fields.String(required=True, description='Start time (ISO format)'),
    'end_time': fields.String(required=True, description='End time (ISO format)'),
    'purpose': fields.String(required=True, description='Purpose of booking'),
    'attendees': fields.Integer(required=True, description='Number of attendees')
})

key_handover_model = api.model('KeyHandover', {
    'username': fields.String(required=True, description='Student username'),
    'name': fields.String(required=True, description='Room name'),
    'secret_code_to_security': fields.String(required=True, description='Secret code')
})

key_return_model = api.model('KeyReturn', {
    'username': fields.String(required=True, description='Student username'),
    'name': fields.String(required=True, description='Room name')
})

# Authentication endpoints
# For step 1: Student ID validation
student_id_check_model = api.model('StudentIdCheck', {
    'username': fields.String(required=True, description='Student ID')
})

complete_registration_model = api.model('CompleteRegistration', {
    'username': fields.String(required=True, description='Student ID'),
    'password': fields.String(required=True, description='Password')
})


# Replace the current registration endpoint with these two endpoints
@ns_auth.route('/check-student-id')
class CheckStudentId(Resource):
    @ns_auth.expect(student_id_check_model)
    def post(self):
        data = request.json
        student_id = data.get('username')

        # First check if this student already has an account
        existing_user = User.query.filter_by(username=student_id).first()
        if existing_user and existing_user.password_hash:
            return {
                "message": "Student already registered. Please login instead.",
                "status": "registered"
            }, 200

        # Then check if student ID exists in Excel file
        print(f"Checking if student ID {student_id} exists in Excel file...")
        student_data = load_student_data(student_id)

        if not student_data:
            print(f"Student ID {student_id} not found in Excel file")
            return {
                "message": "Student ID not found in university records.",
                "status": "not_found"
            }, 404

        # Student exists in Excel but hasn't registered yet
        print(f"Student ID {student_id} found in Excel file: {student_data}")
        return {
            "message": "Student ID verified. Please set your password to complete registration.",
            "status": "verified",
            "student_info": {
                "full_name": student_data.get('full_name'),
                "email": student_data.get('email'),
                "group": student_data.get('group'),
                # "faculty": student_data.get('faculty')
            }
        }, 200


# Add this endpoint to get room availability by date
@ns_rooms.route('/<int:room_id>/availability')
class RoomAvailability(Resource):
    @jwt_required()
    def get(self, room_id):
        date_str = request.args.get('date')
        if not date_str:
            return {"error": "Date parameter is required (YYYY-MM-DD)"}, 400

        room = Room.query.get(room_id)
        if not room:
            return {"error": "Room not found"}, 404

        try:
            # Parse the date
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            day_start = datetime.combine(date, datetime.min.time())
            day_end = datetime.combine(date, datetime.max.time())

            # Standard time slots (9:00 to 18:00 with 1.5 hour intervals)
            time_slots = []
            start_times = ['09:00', '10:30', '12:00', '13:30', '15:00', '16:30']

            # Get schedules for this day
            schedules = Schedule.query.filter_by(room_id=room_id).filter(
                ((Schedule.from_date >= day_start) & (Schedule.from_date <= day_end)) |
                ((Schedule.until_date >= day_start) & (Schedule.until_date <= day_end)) |
                ((Schedule.from_date <= day_start) & (Schedule.until_date >= day_end))
            ).all()

            # Get bookings for this day
            bookings = Booking.query.filter_by(room_id=room_id).filter(
                Booking.status.in_(['pending', 'approved', 'given'])
            ).filter(
                ((Booking.from_date >= day_start) & (Booking.from_date <= day_end)) |
                ((Booking.until_date >= day_start) & (Booking.until_date <= day_end)) |
                ((Booking.from_date <= day_start) & (Booking.until_date >= day_end))
            ).all()

            # Generate all time slots
            for index, start_time in enumerate(start_times):
                hour, minute = map(int, start_time.split(':'))
                slot_start = datetime.combine(date, datetime.min.time().replace(hour=hour, minute=minute))
                slot_end = slot_start + timedelta(hours=1, minutes=30)

                # Check if this slot is available
                is_available = True

                # Check against schedules
                for schedule in schedules:
                    if (slot_start >= schedule.from_date and slot_start < schedule.until_date) or \
                            (slot_end > schedule.from_date and slot_end <= schedule.until_date) or \
                            (slot_start <= schedule.from_date and slot_end >= schedule.until_date):
                        is_available = False
                        break

                # Check against bookings if still available
                if is_available:
                    for booking in bookings:
                        if (slot_start >= booking.from_date and slot_start < booking.until_date) or \
                                (slot_end > booking.from_date and slot_end <= booking.until_date) or \
                                (slot_start <= booking.from_date and slot_end >= booking.until_date):
                            is_available = False
                            break

                # Add time slot to response
                time_slots.append({
                    "id": f"{room_id}-{date_str}-{index}",
                    "start": slot_start.isoformat(),
                    "end": slot_end.isoformat(),
                    "isAvailable": is_available
                })

            return {
                "roomId": room_id,
                "date": date_str,
                "timeSlots": time_slots
            }, 200

        except ValueError:
            return {"error": "Invalid date format. Use YYYY-MM-DD"}, 400
        except Exception as e:
            return {"error": f"Server error: {str(e)}"}, 500


@ns_auth.route('/complete-registration')
class CompleteRegistration(Resource):
    @ns_auth.expect(complete_registration_model)
    def post(self):
        data = request.json
        student_id = data.get('username')
        password = data.get('password')

        # Check if the student already has a password
        existing_user = User.query.filter_by(username=student_id).first()
        if existing_user and existing_user.password_hash:
            return {"message": "Student already registered. Please login instead."}, 400

        # Verify student_id against Excel file again
        student_data = load_student_data(student_id)
        if not student_data:
            return {"message": "Student ID not found in university records."}, 404

        # Create or update user
        if existing_user:
            user = existing_user
        else:
            # Create new user from Excel data
            user = User(
                username=student_id,
                full_name=student_data.get('full_name'),
                email=student_data.get('email'),
                group=student_data.get('group'),
                course=student_data.get('course', 1),
                faculty=student_data.get('faculty'),
                status='active',
                role='student'
            )
            db.session.add(user)

        # Set password
        user.set_password(password)
        db.session.commit()

        return {"message": "Registration successful. You can now login with your student ID and password."}, 201


# Keep the original registration endpoint for backward compatibility
@ns_auth.route('/register')
class Register(Resource):
    @ns_auth.expect(user_register_model)
    def post(self):
        data = request.json
        # Redirect to the complete-registration endpoint
        return CompleteRegistration().post()


@ns_auth.route('/login')
class Login(Resource):
    @ns_auth.expect(user_login_model)
    def post(self):
        data = request.json
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if not user or not user.check_password(password):
            return {"message": "Invalid credentials"}, 401

        # Create token - using the user identity as a string
        access_token = create_access_token(identity=str(user.id))

        # Get user bookings
        user_bookings = []
        for booking in user.bookings:
            room = Room.query.get(booking.room_id)
            user_bookings.append({
                'id': booking.id,
                'room_id': booking.room_id,
                'name': room.name,
                'category': room.category,
                'capacity': room.capacity,
                'status': booking.status,
                'from_date': booking.from_date.isoformat(),
                'until_date': booking.until_date.isoformat(),
                'secret_code': booking.secret_code
            })

        return {
            'token': access_token,
            'full_name': user.full_name,
            'role': user.role,
            'email': user.email,
            'group': user.group,
            'course': user.course,
            'status': user.status,
            'faculty': user.faculty,
            'bookings': user_bookings
        }, 200


# Room endpoints
@ns_rooms.route('/')
class RoomList(Resource):
    @jwt_required()
    def get(self):
        rooms = Room.query.all()
        result = []

        for room in rooms:
            # Get all schedules for the room (including both class schedules and bookings)
            schedules = Schedule.query.filter_by(room_id=room.id).all()

            # Also get approved bookings
            bookings = Booking.query.filter_by(room_id=room.id, status='approved').all()

            # Combine schedules and bookings
            all_time_slots = []

            # Add class schedules
            for schedule in schedules:
                all_time_slots.append({
                    'from_date': schedule.from_date.isoformat(),
                    'until_date': schedule.until_date.isoformat(),
                    'type': schedule.type
                })

            # Add approved bookings
            for booking in bookings:
                all_time_slots.append({
                    'from_date': booking.from_date.isoformat(),
                    'until_date': booking.until_date.isoformat(),
                    'type': 'booking',
                    'booking_id': booking.id
                })

            result.append({
                'id': room.id,
                'name': room.name,
                'category': room.category,
                'capacity': room.capacity,
                'status': room.status,
                'schedule': all_time_slots
            })

        return result, 200


@ns_auth.route('/me/profile')
class UserProfileResource(Resource):
    @jwt_required()
    def get(self):
        """Get current user profile data"""
        # Get user ID from JWT token
        current_user_id = get_jwt_identity()

        try:
            # Query the user
            user = User.query.get(int(current_user_id))

            if not user:
                return {"error": "User not found"}, 404

            # Get current time for timestamps
            current_time = datetime.utcnow().isoformat()

            # Return user profile with correct attribute names
            return {
                "studentId": user.username,
                "username": user.username,
                "fullName": user.username,  # Since there's no name attribute
                "email": getattr(user, 'email', f"{user.username}@example.com"),
                "faculty": getattr(user, 'faculty', 'Информатики и вычислительной техники'),
                "group": getattr(user, 'group', 'ИВТ-301'),
                "course": getattr(user, 'course', 3),
                "academicYear": getattr(user, 'academic_year', '2024-2025'),
                "status": getattr(user, 'status', 'Активный студент'),
                "role": getattr(user, 'role', 'student'),
                "createdAt": current_time,
                "lastLogin": "2025-03-27T11:30:44"  # Using the time you provided
            }, 200

        except Exception as e:
            print(f"Error in profile endpoint: {str(e)}")
            return {"error": f"Failed to retrieve profile: {str(e)}"}, 500


@ns_auth.route('/change-password')
class ChangePasswordResource(Resource):
    @jwt_required()
    @ns_auth.expect(ns_auth.model('ChangePasswordInput', {
        'old_password': fields.String(required=True, description='Current password'),
        'new_password': fields.String(required=True, description='New password')
    }))
    def post(self):
        """Change user password"""
        # Get the current user
        current_user_id = get_jwt_identity()
        user = User.query.get(int(current_user_id))

        if not user:
            return {"error": "User not found"}, 404

        # Get old and new passwords from request
        data = request.get_json()
        old_password = data.get('old_password')
        new_password = data.get('new_password')

        if not old_password or not new_password:
            return {"error": "Both old and new passwords are required"}, 400

        # Verify old password
        if not check_password_hash(user.password_hash, old_password):
            return {"error": "Current password is incorrect"}, 401

        # Set new password
        user.password_hash = generate_password_hash(new_password)

        # Update password_changed_at if this field exists in your model
        if hasattr(user, 'password_changed_at'):
            user.password_changed_at = datetime.datetime.utcnow()

        db.session.commit()

        return {"message": "Password changed successfully"}, 200


# Booking endpoints
# Update the BookingResource to handle new booking format and return more details
@ns_bookings.route('/')
class BookingResource(Resource):
    @jwt_required()
    def get(self):
        """Get all bookings"""
        user_id = get_jwt_identity()
        user = User.query.get(int(user_id))

        # Only admin can see all bookings
        if user.role != 'admin':
            return {"message": "Access denied"}, 403

        bookings = Booking.query.all()
        result = []

        for booking in bookings:
            room = Room.query.get(booking.room_id)
            booking_user = User.query.get(booking.user_id)
            result.append({
                'id': booking.id,
                'room_id': booking.room_id,
                'room_name': room.name,
                'room_category': room.category,
                'room_capacity': room.capacity,
                'username': booking_user.username,
                'full_name': booking_user.full_name,
                'from_date': booking.from_date.isoformat(),
                'until_date': booking.until_date.isoformat(),
                'purpose': booking.purpose,
                'attendees': booking.attendees,
                'status': booking.status,
                'secret_code': booking.secret_code,
                'created_at': booking.created_at.isoformat(),
                'remaining_capacity': room.capacity - booking.attendees if booking.attendees else room.capacity
            })

        return result, 200

    @jwt_required()
    @ns_bookings.expect(booking_model)
    def post(self):
        """Create a new booking with purpose and attendees"""
        user_id = get_jwt_identity()
        data = request.json

        room_id = data.get('room_id')
        purpose = data.get('purpose')
        attendees = data.get('attendees')

        # Parse dates from ISO format
        try:
            from_date = datetime.fromisoformat(data.get('start_time').replace('Z', '+00:00'))
            until_date = datetime.fromisoformat(data.get('end_time').replace('Z', '+00:00'))
        except ValueError:
            return {"error": "Invalid date format. Use ISO format"}, 400

        # Validate all required fields
        if not all([room_id, from_date, until_date, purpose, attendees]):
            return {"error": "All fields are required"}, 400

        # Check if room exists
        room = Room.query.get(room_id)
        if not room:
            return {"error": "Room not found"}, 404

        # Check if attendees count is valid
        if attendees <= 0 or attendees > room.capacity:
            return {"error": f"Attendees count must be between 1 and {room.capacity}"}, 400

        # Check if the time slot is available
        if not is_time_slot_available(room_id, from_date, until_date):
            return {"error": "This time slot is not available for booking"}, 400

        # Create booking with new fields
        booking = Booking(
            room_id=room_id,
            user_id=int(user_id),
            from_date=from_date,
            until_date=until_date,
            purpose=purpose,
            attendees=attendees,
            status='pending'  # Always start as pending for admin approval
        )

        db.session.add(booking)
        db.session.commit()

        return {
            "id": booking.id,
            "status": booking.status,
            "message": "Booking created successfully and is pending admin approval",
            "room_name": room.name,
            "room_capacity": room.capacity,
            "remaining_capacity": room.capacity - attendees,
            "from_date": from_date.isoformat(),
            "until_date": until_date.isoformat()
        }, 201


# Add booking cancellation endpoint
@ns_bookings.route('/<int:booking_id>/cancel')
class CancelBooking(Resource):
    @jwt_required()
    def post(self, booking_id):
        """Cancel a booking"""
        user_id = get_jwt_identity()

        # Find the booking
        booking = Booking.query.get(booking_id)
        if not booking:
            return {"error": "Booking not found"}, 404

        # Check if the booking belongs to the user
        if str(booking.user_id) != user_id and User.query.get(int(user_id)).role != 'admin':
            return {"error": "You do not have permission to cancel this booking"}, 403

        # Check if the booking can be cancelled
        if booking.status not in ['pending', 'approved']:
            return {"error": f"Cannot cancel a booking with status: {booking.status}"}, 400

        # Cancel the booking
        booking.status = 'cancelled'
        booking.updated_at = datetime.utcnow()
        db.session.commit()

        return {"message": "Booking cancelled successfully"}, 200


# Add endpoint to get a specific booking by ID
@ns_bookings.route('/<int:booking_id>')
class BookingDetail(Resource):
    @jwt_required()
    def get(self, booking_id):
        """Get booking details by ID"""
        user_id = get_jwt_identity()

        booking = Booking.query.get(booking_id)
        if not booking:
            return {"error": "Booking not found"}, 404

        # Check if user has permission (own booking or admin)
        if str(booking.user_id) != user_id and User.query.get(int(user_id)).role != 'admin':
            return {"error": "You do not have permission to view this booking"}, 403

        room = Room.query.get(booking.room_id)
        user = User.query.get(booking.user_id)

        return {
            'id': booking.id,
            'room_id': booking.room_id,
            'room_name': room.name,
            'room_category': room.category,
            'room_capacity': room.capacity,
            'username': user.username,
            'full_name': user.full_name,
            'from_date': booking.from_date.isoformat(),
            'until_date': booking.until_date.isoformat(),
            'purpose': booking.purpose,
            'attendees': booking.attendees,
            'status': booking.status,
            'secret_code': booking.secret_code if user.id == int(user_id) or User.query.get(int(user_id)).role in [
                'admin', 'security'] else None,
            'created_at': booking.created_at.isoformat(),
            'remaining_capacity': room.capacity - booking.attendees if booking.attendees else room.capacity
        }, 200


# Security endpoints
@ns_security.route('/give_keys')
class GiveKeys(Resource):
    @jwt_required()
    @ns_security.expect(key_handover_model)
    def post(self):
        user_id = get_jwt_identity()
        security = User.query.get(int(user_id))

        if security.role != 'security':
            return {"message": "Access denied"}, 403

        data = request.json
        username = data.get('username')
        room_name = data.get('name')
        secret_code = data.get('secret_code_to_security')

        user = User.query.filter_by(username=username).first()
        if not user:
            return {"message": "User not found"}, 404

        room = Room.query.filter_by(name=room_name).first()
        if not room:
            return {"message": "Room not found"}, 404

        # Find booking
        booking = Booking.query.filter_by(
            user_id=user.id,
            room_id=room.id,
            status='approved',
            secret_code=secret_code
        ).first()

        if not booking:
            return {"message": "Invalid booking or secret code"}, 400

        booking.status = 'given'
        db.session.commit()

        return {"message": "Keys given successfully", "status": booking.status}, 200


@ns_security.route('/key_taked')
class KeyTaken(Resource):
    @jwt_required()
    @ns_security.expect(key_return_model)
    def post(self):
        user_id = get_jwt_identity()
        security = User.query.get(int(user_id))

        if security.role != 'security':
            return {"message": "Access denied"}, 403

        data = request.json
        username = data.get('username')
        room_name = data.get('name')

        user = User.query.filter_by(username=username).first()
        if not user:
            return {"message": "User not found"}, 404

        room = Room.query.filter_by(name=room_name).first()
        if not room:
            return {"message": "Room not found"}, 404

        # Find booking
        booking = Booking.query.filter_by(
            user_id=user.id,
            room_id=room.id,
            status='given'
        ).first()

        if not booking:
            return {"message": "No active key handover found"}, 400

        booking.status = 'taken'
        db.session.commit()

        return {"message": "Keys returned successfully", "status": booking.status}, 200


@ns_security.route('/bookings')
class SecurityBookings(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        security = User.query.get(int(user_id))

        if security.role != 'security':
            return {"message": "Access denied"}, 403

        bookings = Booking.query.filter(Booking.status.in_(['approved', 'given'])).all()
        result = []

        for booking in bookings:
            user = User.query.get(booking.user_id)
            room = Room.query.get(booking.room_id)

            result.append({
                'id': booking.id,
                'name': room.name,
                'username': user.username,
                'full_name': user.full_name,
                'status': booking.status,
                'from_date': booking.from_date.isoformat(),
                'until_date': booking.until_date.isoformat(),
                'secret_code': booking.secret_code
            })

        return result, 200


# Admin endpoints
@ns_admin.route('/users')
class AdminUsers(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        admin = User.query.get(int(user_id))

        if admin.role != 'admin':
            return {"message": "Access denied"}, 403

        users = User.query.all()
        result = []

        for user in users:
            result.append({
                'id': user.id,
                'username': user.username,
                'full_name': user.full_name,
                'role': user.role,
                'email': user.email,
                'group': user.group,
                'course': user.course,
                'status': user.status,
                'faculty': user.faculty
            })

        return result, 200


# Enhance the user bookings endpoint to include more details and filtering
@ns_bookings.route('/user')
class UserBookings(Resource):
    @jwt_required()
    def get(self):
        """Get bookings for the current authenticated user"""
        user_id = get_jwt_identity()
        status = request.args.get('status')  # Optional status filter

        # Build query
        query = Booking.query.filter_by(user_id=int(user_id))

        # Apply status filter if provided
        if status:
            query = query.filter_by(status=status)

        # Execute the query
        user_bookings = query.order_by(Booking.from_date.desc()).all()
        result = []

        for booking in user_bookings:
            room = Room.query.get(booking.room_id)
            result.append({
                'id': booking.id,
                'room_id': booking.room_id,
                'room_name': room.name,
                'room_category': room.category,
                'room_capacity': room.capacity,
                'from_date': booking.from_date.isoformat(),
                'until_date': booking.until_date.isoformat(),
                'purpose': booking.purpose,
                'attendees': booking.attendees,
                'status': booking.status,
                'secret_code': booking.secret_code,
                'created_at': booking.created_at.isoformat(),
                'remaining_capacity': room.capacity - booking.attendees if booking.attendees else room.capacity
            })

        return result, 200


# Add a function to init_db to create bookings for class schedules
def create_bookings_for_classes():
    """Create bookings for all scheduled classes"""
    print("Creating bookings for scheduled classes...")

    # Get admin user for booking creation
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        print("Admin user not found. Cannot create class bookings.")
        return

    # Get all class schedules
    schedules = Schedule.query.filter_by(type='class').all()
    bookings_created = 0

    for schedule in schedules:
        # Check if booking already exists for this schedule
        existing_booking = Booking.query.filter_by(
            room_id=schedule.room_id,
            from_date=schedule.from_date,
            until_date=schedule.until_date
        ).first()

        if not existing_booking:
            # Create a new booking for this class
            class_booking = Booking(
                room_id=schedule.room_id,
                user_id=admin.id,
                from_date=schedule.from_date,
                until_date=schedule.until_date,
                purpose="Scheduled Class",
                attendees=0,  # Special value for classes
                status='approved'  # Classes are automatically approved
            )
            db.session.add(class_booking)
            bookings_created += 1

    db.session.commit()
    print(f"Created {bookings_created} bookings for scheduled classes")


@ns_admin.route('/user/<int:user_id>')
class AdminUserUpdate(Resource):
    @jwt_required()
    def put(self, user_id):
        admin_id = get_jwt_identity()
        admin = User.query.get(int(admin_id))

        if admin.role != 'admin':
            return {"message": "Access denied"}, 403

        user = User.query.get(user_id)
        if not user:
            return {"message": "User not found"}, 404

        data = request.json

        # Update user fields
        if 'full_name' in data:
            user.full_name = data['full_name']
        if 'role' in data:
            user.role = data['role']
        if 'email' in data:
            user.email = data['email']
        if 'group' in data:
            user.group = data['group']
        if 'course' in data:
            user.course = data['course']
        if 'status' in data:
            user.status = data['status']
        if 'faculty' in data:
            user.faculty = data['faculty']
        if 'password' in data:
            user.set_password(data['password'])

        db.session.commit()

        return {"message": "User updated successfully"}, 200


@ns_admin.route('/rooms')
class AdminRooms(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        admin = User.query.get(int(user_id))

        if admin.role != 'admin':
            return {"message": "Access denied"}, 403

        rooms = Room.query.all()
        result = []

        for room in rooms:
            result.append({
                'id': room.id,
                'name': room.name,
                'category': room.category,
                'capacity': room.capacity,
                'status': room.status
            })

        return result, 200

    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()
        admin = User.query.get(int(user_id))

        if admin.role != 'admin':
            return {"message": "Access denied"}, 403

        data = request.json

        room = Room(
            name=data.get('name'),
            category=data.get('category'),
            capacity=data.get('capacity'),
            status=data.get('status', 'available')
        )

        db.session.add(room)
        db.session.commit()

        return {"message": "Room created successfully", "id": room.id}, 201


@ns_admin.route('/room/<int:room_id>')
class AdminRoomUpdate(Resource):
    @jwt_required()
    def put(self, room_id):
        user_id = get_jwt_identity()
        admin = User.query.get(int(user_id))

        if admin.role != 'admin':
            return {"message": "Access denied"}, 403

        room = Room.query.get(room_id)
        if not room:
            return {"message": "Room not found"}, 404

        data = request.json

        # Update room fields
        if 'name' in data:
            room.name = data['name']
        if 'category' in data:
            room.category = data['category']
        if 'capacity' in data:
            room.capacity = data['capacity']
        if 'status' in data:
            room.status = data['status']

        db.session.commit()

        return {"message": "Room updated successfully"}, 200


@ns_admin.route('/bookings')
class AdminBookings(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        admin = User.query.get(int(user_id))

        if admin.role != 'admin':
            return {"message": "Access denied"}, 403

        bookings = Booking.query.all()
        result = []

        for booking in bookings:
            user = User.query.get(booking.user_id)
            room = Room.query.get(booking.room_id)

            result.append({
                'id': booking.id,
                'room_name': room.name,
                'username': user.username,
                'full_name': user.full_name,
                'from_date': booking.from_date.isoformat(),
                'until_date': booking.until_date.isoformat(),
                'status': booking.status,
                'created_at': booking.created_at.isoformat()
            })

        return result, 200


@ns_admin.route('/booking/<int:booking_id>/approve')
class AdminBookingApprove(Resource):
    @jwt_required()
    def post(self, booking_id):
        user_id = get_jwt_identity()
        admin = User.query.get(int(user_id))

        if admin.role != 'admin':
            return {"message": "Access denied"}, 403

        booking = Booking.query.get(booking_id)
        if not booking:
            return {"message": "Booking not found"}, 404

        booking.status = 'approved'
        booking.secret_code = generate_secret_code()

        # Add to schedule
        schedule = Schedule(
            room_id=booking.room_id,
            from_date=booking.from_date,
            until_date=booking.until_date,
            type='booking'
        )
        db.session.add(schedule)
        db.session.commit()

        return {
            "message": "Booking approved",
            "status": booking.status,
            "secret_code_to_security": booking.secret_code
        }, 200


@ns_admin.route('/booking/<int:booking_id>/reject')
class AdminBookingReject(Resource):
    @jwt_required()
    def post(self, booking_id):
        user_id = get_jwt_identity()
        admin = User.query.get(int(user_id))

        if admin.role != 'admin':
            return {"message": "Access denied"}, 403

        booking = Booking.query.get(booking_id)
        if not booking:
            return {"message": "Booking not found"}, 404

        booking.status = 'rejected'
        db.session.commit()

        return {"message": "Booking rejected", "status": booking.status}, 200

    @ns_admin.route('/verify-password')
    class VerifyPassword(Resource):
        @jwt_required()
        def post(self):
            user_id = get_jwt_identity()
            admin = User.query.get(int(user_id))

            # Verify the user is an admin
            if admin.role != 'admin':
                return {"message": "Access denied"}, 403

            # Get password from request
            data = request.json
            password = data.get('password')

            if not password:
                return {"message": "Password is required"}, 400

            # Check if the password is correct
            if admin.check_password(password):  # Assuming User model has a check_password method
                return {"success": True, "message": "Password verified"}, 200
            else:
                return {"success": False, "message": "Invalid password"}, 401


@ns_admin.route('/sync-class-schedules')
class SyncClassSchedules(Resource):
    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()
        admin = User.query.get(int(user_id))

        if admin.role != 'admin':
            return {"message": "Access denied"}, 403

        # Verify password again for extra security
        data = request.json
        password = data.get('password')

        if not password or not admin.check_password(password):
            return {"message": "Invalid password"}, 401

        try:
            sync_class_schedules(app, db, Room, Schedule)
            return {"message": "Class schedules synchronized successfully"}, 200
        except Exception as e:
            return {"message": f"Error syncing class schedules: {str(e)}"}, 500


# Initialize function - Flask 3.x compatible
# Update the init_db function to call our new function
def init_db():
    with app.app_context():
        db.create_all()

        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                full_name='Administrator',
                role='admin',
                email='admin@university.edu',
                status='active'
            )
            admin.set_password('admin')  # Change in production
            db.session.add(admin)

        # Create security user if it doesn't exist
        security = User.query.filter_by(username='security').first()
        if not security:
            security = User(
                username='security',
                full_name='Security Officer',
                role='security',
                email='security@university.edu',
                status='active'
            )
            security.set_password('security')  # Change in production
            db.session.add(security)

        db.session.commit()

        # Create bookings for all scheduled classes
        create_bookings_for_classes()

        print("Database initialized successfully!")


if __name__ == '__main__':
    # Initialize database before running app
    init_db()
    app.run(debug=True)