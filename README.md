# Complaint Management System

A web-based application built with Flask for managing hostel complaints. The system allows students to submit complaints, track their status, and receive responses from administrators. The application is fully cloud-deployed with AWS services and Firebase Authentication.

## Features

- User registration and authentication with Firebase
- Submit complaints with titles, descriptions, categories, and file attachments
- Track complaint status (pending, in progress, resolved, rejected)
- Dashboard for viewing all complaints
- Admin interface for managing complaints, users, and hostels
- Response system for communication between users and admins
- File attachment support with S3 storage
- Multi-hostel support

## Tech Stack

- **Backend**: Flask, SQLAlchemy
- **Frontend**: HTML, CSS, JavaScript, Bootstrap
- **Database**: PostgreSQL (RDS)
- **Authentication**: Firebase Authentication
- **File Storage**: AWS S3
- **Deployment**: AWS Elastic Beanstalk
- **Environment**: Python 3.11

## Cloud Architecture

The application is deployed using the following AWS services:

### AWS Elastic Beanstalk
- Provides automated deployment and scaling
- Load balancing for high availability
- Health monitoring and auto-recovery
- Python 3.8 platform

### AWS RDS (PostgreSQL)
- Managed database service
- Automated backups
- High availability with Multi-AZ deployment
- Scalable storage and performance

### AWS S3
- Object storage for complaint attachments
- Secure file upload and retrieval
- Versioning support
- CORS enabled for web access

### Firebase Authentication
- User registration and login
- Email/password authentication
- Google sign-in integration
- Email verification
- Secure token-based authentication

## Installation and Setup

### Local Development

1. Clone the repository from GitHub and navigate to the project directory.

2. Create and activate a virtual environment:
```
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```
pip install -r requirements.txt
```

4. Set up environment variables:
```
# Create a .env file with the following variables
FLASK_ENV=development
SECRET_KEY=your-secret-key
DATABASE_URL=sqlite:///complaints.db
```

5. Run the application:
```
python application.py
```

6. Access the application at http://localhost:5000

### Cloud Deployment

1. Create AWS resources:
   - RDS PostgreSQL database
   - S3 bucket for file storage
   - Elastic Beanstalk environment with Python 3.11 platform

2. Set up Firebase project:
   - Enable Authentication
   - Configure email/password sign-in
   - Set up Google sign-in (optional)

3. Configure environment variables in Elastic Beanstalk:
```
FLASK_ENV=production
SECRET_KEY=your-secure-secret-key
DATABASE_URL=postgresql://username:password@your-rds-instance.region.rds.amazonaws.com:5432/database
S3_BUCKET=your-bucket-name
S3_REGION=your-region
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
FIREBASE_CREDENTIALS=your-firebase-credentials-json
```

4. Deploy to Elastic Beanstalk:
```
eb init -p python-3.8 complaint-system
eb create complaint-system-env
eb deploy
```

## Default Admin Account

- Username: admin
- Password: admin123

## Project Structure

```
complaint-management-system/
├── application.py           # Main application file
├── requirements.txt         # Python dependencies
├── Procfile                 # For Elastic Beanstalk deployment
├── templates/               # HTML templates
│   ├── admin_users.html     # Admin user management
│   ├── admin_hostels.html   # Admin hostel management
│   ├── admin_reports.html   # Admin reporting dashboard
│   ├── dashboard.html       # Main user dashboard
│   ├── home.html            # Landing page
│   ├── layout.html          # Base layout template
│   ├── login.html           # Login page with Firebase auth
│   ├── new_complaint.html   # Complaint submission form
│   ├── new_hostel.html      # Hostel creation form
│   ├── register.html        # User registration with Firebase
│   ├── view_complaint.html  # Complaint details view
│   └── edit_hostel.html     # Hostel editing form
├── images/                  # Application screenshots
│   ├── dashboard.PNG        # Dashboard view
│   ├── complaint.PNG        # Complaint form
│   ├── statuschange.PNG     # Status update interface
│   └── loginpage.PNG        # Login interface
└── .git/                    # Git repository
```

## Application Screenshots

### Login Page
![Login Page](images/loginpage.PNG)

### Dashboard
![Dashboard](images/dashboard.PNG)

### Complaint Form
![Complaint Form](images/complaint.PNG)

### Status Management
![Status Management](images/statuschange.PNG)

## Configuration

### AWS S3 Configuration
The application is configured to use S3 for file storage in production:

```python
# S3 Configuration
application.config['S3_BUCKET'] = os.getenv('S3_BUCKET')
application.config['S3_REGION'] = os.getenv('S3_REGION', 'us-east-1')
application.config['S3_ACCESS_KEY'] = os.getenv('AWS_ACCESS_KEY_ID')
application.config['S3_SECRET_KEY'] = os.getenv('AWS_SECRET_ACCESS_KEY')
```

### Firebase Configuration
Firebase authentication is initialized with credentials from environment variables:

```python
# Initialize Firebase Admin SDK
firebase_credentials = os.getenv('FIREBASE_CREDENTIALS')
if firebase_credentials:
    cred_dict = json.loads(firebase_credentials)
    cred = credentials.Certificate(cred_dict)
    firebase_admin.initialize_app(cred)
```

### Database Configuration
The application supports both SQLite (development) and PostgreSQL (production):

```python
application.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///complaints.db')
```
