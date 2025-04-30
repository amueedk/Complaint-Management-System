# Complaint Management System

A web-based application built with Flask for managing complaints. The system allows users to submit complaints, track their status, and receive responses from administrators.

## Features

- User registration and authentication
- Submit complaints with title and detailed description
- Track complaint status (pending, in progress, resolved, rejected)
- Dashboard for viewing all complaints
- Admin interface for managing complaints and users
- Response system for communication between users and admins

## Tech Stack

- **Backend**: Flask, SQLAlchemy
- **Frontend**: HTML, CSS, JavaScript, Bootstrap
- **Database**: SQLite
- **Authentication**: Flask-Login

## Installation and Setup

1. Clone the repository:
```
git clone https://github.com/yourusername/complaint-management-system.git
cd complaint-management-system
```

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

4. Run the application:
```
python app.py
```

5. Access the application at http://localhost:5000

## Default Admin Account

- Username: admin
- Password: admin123

## Project Structure

```

## CI/CD Pipeline

This project uses GitHub Actions for continuous integration and deployment. The pipeline includes:
- Automated testing
- Code quality checks
- Coverage reporting
- Automated deployment (configured in the workflow file)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 