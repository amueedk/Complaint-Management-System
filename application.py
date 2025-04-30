from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import uuid

# Initialize Flask app
application = Flask(__name__)
application.config['SECRET_KEY'] = 'your-secret-key-goes-here'
application.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///complaints.db'
application.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
application.config['UPLOAD_FOLDER'] = 'uploads'
application.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max-limit

# Ensure upload directory exists
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
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    date_joined = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    complaints = db.relationship('Complaint', backref='user', lazy=True)
    hostel_id = db.Column(db.Integer, db.ForeignKey('hostel.id'), nullable=True)
    room_number = db.Column(db.String(20), nullable=True)
    
    @property
    def complaint_count(self):
        return len(self.complaints)

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

# Routes
@application.route('/')
def home():
    return render_template('home.html')

@application.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hostel_id = request.form.get('hostel_id')
        room_number = request.form.get('room_number')
        
        # Check if user already exists
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists')
            return redirect(url_for('register'))
        
        email_exists = User.query.filter_by(email=email).first()
        if email_exists:
            flash('Email already exists')
            return redirect(url_for('register'))
        
        # Create new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(
            username=username, 
            email=email, 
            password=hashed_password,
            hostel_id=hostel_id if hostel_id else None,
            room_number=room_number
        )
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created successfully')
        return redirect(url_for('login'))
    
    hostels = Hostel.query.all()
    return render_template('register.html', hostels=hostels)

@application.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
            
    return render_template('login.html')

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
        title = request.form.get('title')
        content = request.form.get('content')
        priority = request.form.get('priority', 'Low')
        category = request.form.get('category')
        hostel_id = request.form.get('hostel_id')
        location = request.form.get('location')
        
        # Use user's hostel if not specified and user has a hostel
        if not hostel_id and current_user.hostel_id:
            hostel_id = current_user.hostel_id
        
        complaint = Complaint(
            title=title, 
            content=content, 
            user_id=current_user.id, 
            priority=priority,
            category=category,
            complaint_type=category,
            hostel_id=hostel_id,
            location=location
        )
        
        db.session.add(complaint)
        db.session.commit()
        
        # Handle file attachments
        if 'attachments' in request.files:
            files = request.files.getlist('attachments')
            for file in files:
                if file and file.filename and allowed_file(file.filename):
                    # Create unique filename to prevent collisions
                    file_extension = os.path.splitext(file.filename)[1]
                    unique_filename = secure_filename(f"{uuid.uuid4()}{file_extension}")
                    
                    # Create relative path for storage
                    relative_path = os.path.join(application.config['UPLOAD_FOLDER'], unique_filename)
                    
                    # Save the file
                    file.save(relative_path)
                    
                    attachment = Attachment(
                        filename=file.filename,  # Store original filename for display
                        original_filename=file.filename,  # Required field in the database
                        file_path=relative_path,  # Store relative path
                        complaint_id=complaint.id
                    )
                    db.session.add(attachment)
            
            db.session.commit()
        
        flash('Complaint submitted successfully')
        return redirect(url_for('dashboard'))
    
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
    attachment = Attachment.query.get_or_404(attachment_id)
    complaint = Complaint.query.get(attachment.complaint_id)
    
    # Check if user is authorized to view this attachment
    if not current_user.is_admin and complaint.user_id != current_user.id:
        flash('You are not authorized to view this attachment')
        return redirect(url_for('dashboard'))
    
    # Use original_filename for display, but serve from file_path
    return send_file(attachment.file_path, as_attachment=True, download_name=attachment.filename)

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

# Create database tables
with application.app_context():
    db.create_all()

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
    application.run(debug=True) 