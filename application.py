from flask import Flask, render_template, redirect, url_for, flash, request, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import uuid
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import logging
import firebase_admin
from firebase_admin import credentials, auth
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Initialize Flask app
application = Flask(__name__)

# AWS Configuration
application.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-goes-here')
application.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///complaints.db')
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
application.config['UPLOAD_FOLDER'] = 'uploads'
application.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max-limit

# S3 Configuration
application.config['S3_BUCKET'] = os.getenv('S3_BUCKET')
application.config['S3_REGION'] = os.getenv('S3_REGION', 'us-east-1')
application.config['S3_ACCESS_KEY'] = os.getenv('AWS_ACCESS_KEY_ID')
application.config['S3_SECRET_KEY'] = os.getenv('AWS_SECRET_ACCESS_KEY')

# Initialize S3 client if in production
if os.getenv('FLASK_ENV') == 'production':
    try:
        logger.info(f"Initializing S3 client with bucket: {application.config['S3_BUCKET']}, region: {application.config['S3_REGION']}")
        s3_client = boto3.client(
            's3',
            aws_access_key_id=application.config['S3_ACCESS_KEY'],
            aws_secret_access_key=application.config['S3_SECRET_KEY'],
            region_name=application.config['S3_REGION']
        )
        # Test S3 connection
        s3_client.list_buckets()
        logger.info("S3 client initialized and connection tested successfully")
    except Exception as e:
        logger.error(f"Failed to initialize S3 client: {str(e)}")
        logger.error(f"S3 Configuration - Bucket: {application.config['S3_BUCKET']}, Region: {application.config['S3_REGION']}, Access Key: {'Present' if application.config['S3_ACCESS_KEY'] else 'Missing'}, Secret Key: {'Present' if application.config['S3_SECRET_KEY'] else 'Missing'}")
        raise
else:
    logger.warning("Not in production mode - S3 uploads will not be available")

# Initialize Firebase Admin SDK
try:
    # Get Firebase credentials from environment variable
    firebase_credentials = os.getenv('FIREBASE_CREDENTIALS')
    if firebase_credentials:
        cred_dict = json.loads(firebase_credentials)
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
        logger.info("Firebase Admin SDK initialized successfully")
    else:
        logger.warning("FIREBASE_CREDENTIALS not found in environment variables")
except Exception as e:
    logger.error(f"Failed to initialize Firebase Admin SDK: {str(e)}")
    raise

# Ensure upload directory exists locally (for development)
if not os.getenv('FLASK_ENV') == 'production':
    os.makedirs(application.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize database
db = SQLAlchemy(application)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = 'login'

# Define database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Changed back to not nullable
    is_admin = db.Column(db.Boolean, default=False)
    date_joined = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    complaints = db.relationship('Complaint', backref='user', lazy=True)
    hostel_id = db.Column(db.Integer, db.ForeignKey('hostel.id'), nullable=True)
    room_number = db.Column(db.String(20), nullable=True)
    
    # Add session-based property for Firebase UID
    _firebase_uid = None
    
    @property
    def firebase_uid(self):
        return self._firebase_uid
        
    @firebase_uid.setter
    def firebase_uid(self, value):
        self._firebase_uid = value
    
    @property
    def complaint_count(self):
        return len(self.complaints)
    
    def get_id(self):
        return str(self.id)
    
    def is_authenticated(self):
        return True
    
    def is_active(self):
        return True
    
    def is_anonymous(self):
        return False

class Hostel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text, nullable=True)
    users = db.relationship('User', backref='hostel', lazy=True)
    complaints = db.relationship('Complaint', backref='hostel', lazy=True)

class StatusUpdate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(20), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)

class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)  # Original filename displayed to user
    original_filename = db.Column(db.String(100), nullable=False)  # Required field from database schema
    file_path = db.Column(db.String(200), nullable=False)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='Pending')
    priority = db.Column(db.String(20), nullable=False, default='Low')
    category = db.Column(db.String(50), nullable=True)
    complaint_type = db.Column(db.String(50), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    hostel_id = db.Column(db.Integer, db.ForeignKey('hostel.id'), nullable=True)
    location = db.Column(db.String(100), nullable=True)  # Specific location within the hostel
    responses = db.relationship('Response', backref='complaint', lazy=True)
    status_updates = db.relationship('StatusUpdate', backref='complaint', lazy=True, order_by="StatusUpdate.date")
    attachments = db.relationship('Attachment', backref='complaint', lazy=True)

class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='responses')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Hostel complaint categories
COMPLAINT_CATEGORIES = [
    'Room & Furniture',
    'Plumbing & Water Supply',
    'Electrical & Lighting',
    'Housekeeping & Cleanliness',
    'Internet & Connectivity',
    'Pest Control',
    'Staff & Management',
    'Roommate & Social',
    'Other / General Suggestions'
]

# Helper functions
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def upload_file_to_s3(file, bucket_name, acl="public-read"):
    try:
        logger.info(f"Attempting to upload file {file.filename} to bucket {bucket_name}")
        # Generate a unique filename to prevent collisions
        file_extension = os.path.splitext(file.filename)[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        
        logger.info(f"Generated unique filename: {unique_filename}")
        
        # Upload without ACL
        s3_client.upload_fileobj(
            file,
            bucket_name,
            unique_filename,
            ExtraArgs={
                "ContentType": file.content_type
            }
        )
        
        # Construct S3 URL based on region
        region = application.config['S3_REGION']
        if region == 'us-east-1':
            url = f"https://{bucket_name}.s3.amazonaws.com/{unique_filename}"
        else:
            url = f"https://{bucket_name}.s3.{region}.amazonaws.com/{unique_filename}"
            
        logger.info(f"File uploaded successfully. URL: {url}")
        return url
    except Exception as e:
        logger.error(f"Failed to upload file to S3: {str(e)}")
        logger.error(f"File details - Name: {file.filename}, Content Type: {file.content_type}")
        raise

# Firebase Authentication Middleware
def verify_firebase_token(id_token):
    try:
        decoded_token = auth.verify_id_token(id_token)
        return decoded_token
    except Exception as e:
        logger.error(f"Error verifying Firebase token: {str(e)}")
        return None

# Routes
@application.route('/')
def home():
    return render_template('home.html')

@application.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get the Firebase ID token from the request
        id_token = request.json.get('idToken')
        if not id_token:
            return jsonify({'error': 'No ID token provided'}), 400
            
        # Verify the Firebase token
        decoded_token = verify_firebase_token(id_token)
        if not decoded_token:
            return jsonify({'error': 'Invalid token'}), 401
            
        # Get user details from the token
        email = decoded_token['email']
        username = request.json.get('username', email.split('@')[0])
        hostel_id = request.json.get('hostel_id')
        room_number = request.json.get('room_number')
        
        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        if user:
            return jsonify({'error': 'Email already exists'}), 400
        
        user = User.query.filter_by(username=username).first()
        if user:
            return jsonify({'error': 'Username already exists'}), 400
        
        # Generate a random password for Firebase users
        random_pass = os.urandom(24).hex()
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(random_pass),
            hostel_id=hostel_id if hostel_id else None,
            room_number=room_number
        )
        db.session.add(new_user)
        db.session.commit()
        
        # Store Firebase UID in session
        new_user.firebase_uid = decoded_token['uid']
        
        return jsonify({'message': 'Account created successfully'})
    
    # GET request - render the registration page
    hostels = Hostel.query.all()
    return render_template('register.html', hostels=hostels)

@application.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Get the Firebase ID token from the request
        id_token = request.json.get('idToken')
        if not id_token:
            return jsonify({'error': 'No ID token provided'}), 400
            
        # Verify the Firebase token
        decoded_token = verify_firebase_token(id_token)
        if not decoded_token:
            return jsonify({'error': 'Invalid token'}), 401
            
        # Get or create user
        user = User.query.filter_by(email=decoded_token['email']).first()
        if not user:
            # Create new user from Firebase
            user = User(
                username=decoded_token.get('name', decoded_token['email'].split('@')[0]),
                email=decoded_token['email'],
                password=generate_password_hash(request.json.get('password'), method='pbkdf2:sha256')
            )
            db.session.add(user)
            db.session.commit()
            
        login_user(user)
        return jsonify({'message': 'Login successful'})
    
    # GET request - render the login page
    return render_template('login.html')

@application.route('/firebase/login', methods=['POST'])
def firebase_login():
    try:
        id_token = request.json.get('idToken')
        if not id_token:
            return jsonify({'error': 'No ID token provided'}), 400
            
        decoded_token = verify_firebase_token(id_token)
        if not decoded_token:
            return jsonify({'error': 'Invalid token'}), 401
            
        # Get or create user using email
        user = User.query.filter_by(email=decoded_token['email']).first()
        
        # Only check email verification for new users
        if not user and not decoded_token.get('email_verified', False):
            return jsonify({'error': 'Email not verified'}), 403
            
        if not user:
            # Create new user from Firebase
            random_pass = os.urandom(24).hex()  # Generate random password
            
            # Make the first user an admin
            is_first_user = User.query.count() == 0
            
            user = User(
                username=decoded_token.get('name', decoded_token['email'].split('@')[0]),
                email=decoded_token['email'],
                password=generate_password_hash(random_pass),
                is_admin=is_first_user  # First user becomes admin
            )
            db.session.add(user)
            db.session.commit()
            
        # Store Firebase UID in session
        user.firebase_uid = decoded_token['uid']
            
        login_user(user)
        return jsonify({'message': 'Login successful'})
    except Exception as e:
        logger.error(f"Error in Firebase login: {str(e)}")
        return jsonify({'error': str(e)}), 500

@application.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@application.route('/dashboard')
@login_required
def dashboard():
    # Get filter parameters
    hostel_id = request.args.get('hostel_id', type=int)
    category = request.args.get('category')
    
    if current_user.is_admin:
        # Base query
        query = Complaint.query
        
        # Apply filters if provided
        if hostel_id:
            query = query.filter_by(hostel_id=hostel_id)
        if category:
            query = query.filter_by(category=category)
            
        # Get filtered complaints
        complaints = query.order_by(Complaint.date_posted.desc()).all()
    else:
        # Regular users see only their complaints
        complaints = Complaint.query.filter_by(user_id=current_user.id).order_by(Complaint.date_posted.desc()).all()
    
    # Get all hostels for the filter dropdown
    hostels = Hostel.query.all()
    
    return render_template('dashboard.html', complaints=complaints, User=User, hostels=hostels, categories=COMPLAINT_CATEGORIES)

@application.route('/complaint/new', methods=['GET', 'POST'])
@login_required
def new_complaint():
    if request.method == 'POST':
        try:
            title = request.form.get('title')
            content = request.form.get('content')
            category = request.form.get('category')
            complaint_type = request.form.get('complaint_type')
            priority = request.form.get('priority')
            location = request.form.get('location')
            
            if not title or not content:
                flash('Title and content are required', 'error')
                return redirect(url_for('new_complaint'))
            
            complaint = Complaint(
                title=title,
                content=content,
                category=category,
                complaint_type=complaint_type,
                priority=priority,
                location=location,
                user_id=current_user.id,
                hostel_id=request.form.get('hostel_id', type=int)
            )
            
            db.session.add(complaint)
            db.session.commit()
            
            # Handle file uploads
            if 'attachments' in request.files:
                files = request.files.getlist('attachments')
                for file in files:
                    if file and allowed_file(file.filename):
                        try:
                            if os.getenv('FLASK_ENV') == 'production':
                                # Upload to S3 in production
                                file_url = upload_file_to_s3(file, application.config['S3_BUCKET'])
                                attachment = Attachment(
                                    filename=file.filename,
                                    original_filename=file.filename,
                                    file_path=file_url,
                                    complaint_id=complaint.id
                                )
                            else:
                                # Local storage for development
                                filename = secure_filename(file.filename)
                                file_path = os.path.join(application.config['UPLOAD_FOLDER'], filename)
                                file.save(file_path)
                                attachment = Attachment(
                                    filename=filename,
                                    original_filename=filename,
                                    file_path=url_for('uploaded_file', filename=filename, _external=True),
                                    complaint_id=complaint.id
                                )
                            db.session.add(attachment)
                        except Exception as e:
                            logger.error(f"Failed to process attachment: {str(e)}")
                            flash('Error processing attachment', 'error')
                            continue
                
                db.session.commit()
            
            flash('Complaint submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            logger.error(f"Error creating complaint: {str(e)}")
            db.session.rollback()
            flash('An error occurred while submitting your complaint', 'error')
            return redirect(url_for('new_complaint'))
    
    # Get all hostels and categories for the form
    hostels = Hostel.query.all()
    return render_template('new_complaint.html', hostels=hostels, categories=COMPLAINT_CATEGORIES)

@application.route('/complaint/<int:complaint_id>')
@login_required
def view_complaint(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    
    # Check if user is authorized to view this complaint
    if not current_user.is_admin and complaint.user_id != current_user.id:
        flash('You are not authorized to view this complaint')
        return redirect(url_for('dashboard'))
    
    responses = Response.query.filter_by(complaint_id=complaint_id).order_by(Response.date_posted).all()
    
    # Get hostel information if associated with a hostel
    hostel = None
    if complaint.hostel_id:
        hostel = Hostel.query.get(complaint.hostel_id)
    
    return render_template('view_complaint.html', complaint=complaint, responses=responses, hostel=hostel, categories=COMPLAINT_CATEGORIES)

@application.route('/complaint/<int:complaint_id>/add_response', methods=['POST'])
@login_required
def add_response(complaint_id):
    complaint = Complaint.query.get_or_404(complaint_id)
    
    # Only admins or the complaint owner can respond
    if not current_user.is_admin and complaint.user_id != current_user.id:
        flash('You are not authorized to respond to this complaint')
        return redirect(url_for('dashboard'))
    
    content = request.form.get('content')
    
    response = Response(content=content, complaint_id=complaint_id, user_id=current_user.id)
    db.session.add(response)
    db.session.commit()
    
    flash('Response added successfully')
    return redirect(url_for('view_complaint', complaint_id=complaint_id))

@application.route('/complaint/<int:complaint_id>/update_status', methods=['POST'])
@login_required
def update_status(complaint_id):
    if not current_user.is_admin:
        flash('You do not have permission to update status')
        return redirect(url_for('dashboard'))
    
    complaint = Complaint.query.get_or_404(complaint_id)
    new_status = request.form.get('status')
    
    if complaint.status != new_status:
        # Create status update entry
        status_update = StatusUpdate(status=new_status, complaint_id=complaint.id)
        db.session.add(status_update)
        
        # Update complaint status
        complaint.status = new_status
        db.session.commit()
        
        flash(f'Complaint status updated to {new_status}')
    
    return redirect(url_for('view_complaint', complaint_id=complaint_id))

@application.route('/attachment/<int:attachment_id>')
@login_required
def attachment(attachment_id):
    try:
        attachment = Attachment.query.get_or_404(attachment_id)
        complaint = Complaint.query.get(attachment.complaint_id)
        
        # Check if user is authorized to view this attachment
        if not current_user.is_admin and complaint.user_id != current_user.id:
            flash('You are not authorized to view this attachment', 'error')
            return redirect(url_for('dashboard'))
        
        if os.getenv('FLASK_ENV') == 'production':
            # For S3 files, redirect to the S3 URL
            return redirect(attachment.file_path)
        else:
            # For local files, serve directly
            return send_file(attachment.file_path, as_attachment=True, download_name=attachment.filename)
    except Exception as e:
        logger.error(f"Error accessing attachment: {str(e)}")
        flash('Error accessing attachment', 'error')
        return redirect(url_for('dashboard'))

@application.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('You do not have permission to access this page')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@application.route('/admin/hostels')
@login_required
def admin_hostels():
    if not current_user.is_admin:
        flash('You do not have permission to access this page')
        return redirect(url_for('dashboard'))
    
    hostels = Hostel.query.all()
    return render_template('admin_hostels.html', hostels=hostels)

@application.route('/admin/hostel/new', methods=['GET', 'POST'])
@login_required
def new_hostel():
    if not current_user.is_admin:
        flash('You do not have permission to access this page')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        capacity = request.form.get('capacity')
        description = request.form.get('description')
        
        hostel = Hostel(name=name, capacity=capacity, description=description)
        db.session.add(hostel)
        db.session.commit()
        
        flash('Hostel added successfully')
        return redirect(url_for('admin_hostels'))
    
    return render_template('new_hostel.html')

@application.route('/admin/hostel/<int:hostel_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_hostel(hostel_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page')
        return redirect(url_for('dashboard'))
    
    hostel = Hostel.query.get_or_404(hostel_id)
    
    if request.method == 'POST':
        hostel.name = request.form.get('name')
        hostel.capacity = request.form.get('capacity')
        hostel.description = request.form.get('description')
        
        db.session.commit()
        flash('Hostel updated successfully')
        return redirect(url_for('admin_hostels'))
    
    return render_template('edit_hostel.html', hostel=hostel)

@application.route('/admin/hostel/<int:hostel_id>/delete', methods=['POST'])
@login_required
def delete_hostel(hostel_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page')
        return redirect(url_for('dashboard'))
    
    hostel = Hostel.query.get_or_404(hostel_id)
    
    # Check if there are any users or complaints associated with this hostel
    if hostel.users or hostel.complaints:
        flash('Cannot delete hostel with associated users or complaints')
        return redirect(url_for('admin_hostels'))
    
    db.session.delete(hostel)
    db.session.commit()
    flash('Hostel deleted successfully')
    return redirect(url_for('admin_hostels'))

@application.route('/admin/reports')
@login_required
def admin_reports():
    if not current_user.is_admin:
        flash('You do not have permission to access this page')
        return redirect(url_for('dashboard'))
    
    # Get statistics per hostel
    hostels = Hostel.query.all()
    hostel_stats = []
    
    for hostel in hostels:
        total_complaints = len(hostel.complaints)
        pending_complaints = Complaint.query.filter_by(hostel_id=hostel.id, status='Pending').count()
        resolved_complaints = Complaint.query.filter_by(hostel_id=hostel.id, status='Resolved').count()
        
        # Calculate category breakdowns
        category_counts = {}
        for category in COMPLAINT_CATEGORIES:
            count = Complaint.query.filter_by(hostel_id=hostel.id, category=category).count()
            category_counts[category] = count
        
        hostel_stats.append({
            'hostel': hostel,
            'total': total_complaints,
            'pending': pending_complaints,
            'resolved': resolved_complaints,
            'category_counts': category_counts
        })
    
    return render_template('admin_reports.html', hostel_stats=hostel_stats)

@application.route('/uploads/<path:filename>')
def uploaded_file(filename):
    if os.getenv('FLASK_ENV') == 'production':
        return redirect(url_for('dashboard'))
    return send_file(os.path.join(application.config['UPLOAD_FOLDER'], filename))

# Initialize database tables
def init_db():
    with application.app_context():
        try:
            logger.info("Attempting to create database tables...")
            logger.info(f"Database URL: {application.config['SQLALCHEMY_DATABASE_URI']}")
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Verify tables were created
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            logger.info(f"Created tables: {tables}")
            
        except Exception as e:
            logger.error(f"Error creating database tables: {str(e)}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error(f"Error details: {e.__dict__ if hasattr(e, '__dict__') else 'No details available'}")
            raise

# Initialize the database when the application starts
init_db()

# Create admin user and initialize hostels if not exists
with application.app_context():
    # Create admin user if not exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        hashed_password = generate_password_hash('admin123', method='pbkdf2:sha256')
        admin = User(username='admin', email='admin@example.com', password=hashed_password, is_admin=True)
        db.session.add(admin)
        db.session.commit()
    
    # Create default hostels if none exist
    if Hostel.query.count() == 0:
        hostels_data = [
            {'name': 'Hostel 1', 'capacity': 200, 'description': 'Boys hostel with single and double rooms'},
            {'name': 'Hostel 2', 'capacity': 180, 'description': 'Boys hostel with double rooms'},
            {'name': 'Hostel 3', 'capacity': 220, 'description': 'Boys hostel with single and double rooms'},
            {'name': 'Hostel 4', 'capacity': 250, 'description': 'Girls hostel with double and triple rooms'},
            {'name': 'Hostel 5', 'capacity': 200, 'description': 'Girls hostel with single and double rooms'},
            {'name': 'Hostel 6', 'capacity': 180, 'description': 'Girls hostel with double rooms'},
            {'name': 'Hostel 7', 'capacity': 150, 'description': 'International students hostel with single rooms'},
            {'name': 'Hostel 8', 'capacity': 220, 'description': 'Mixed hostel with single rooms'},
            {'name': 'Hostel 9', 'capacity': 240, 'description': 'Boys hostel with single and double rooms'},
            {'name': 'Hostel 10', 'capacity': 180, 'description': 'Girls hostel with single and double rooms'},
            {'name': 'Hostel 11', 'capacity': 160, 'description': 'Postgraduate hostel with single rooms'},
            {'name': 'Hostel 12', 'capacity': 200, 'description': 'Research scholars hostel with single rooms'}
        ]
        
        for hostel_data in hostels_data:
            hostel = Hostel(**hostel_data)
            db.session.add(hostel)
        
        db.session.commit()

if __name__ == '__main__':
    application.run(debug=os.getenv('FLASK_ENV') != 'production') 