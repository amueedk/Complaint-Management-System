import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from app import app, db, User, Complaint
from flask_login import login_user

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()

def test_home_page(client):
    response = client.get('/')
    assert response.status_code == 200

def test_login_page(client):
    response = client.get('/login')
    assert response.status_code == 200

def test_register_page(client):
    response = client.get('/register')
    assert response.status_code == 200

def test_dashboard_requires_login(client):
    response = client.get('/dashboard', follow_redirects=True)
    assert b'Please log in to access this page' in response.data

def test_user_registration(client):
    response = client.post('/register', data={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'testpass123',
        'confirm_password': 'testpass123'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Registration successful' in response.data

def test_complaint_creation(client):
    # First create a test user
    user = User(username='testuser', email='test@example.com', password='testpass123')
    db.session.add(user)
    db.session.commit()
    
    # Login the user
    with client:
        login_user(user)
        response = client.post('/complaint/new', data={
            'title': 'Test Complaint',
            'content': 'This is a test complaint',
            'category': 'Room & Furniture',
            'priority': 'Low'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'Complaint created successfully' in response.data 