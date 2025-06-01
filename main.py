from flask import Flask, render_template, jsonify, request, redirect, url_for, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from flask_wtf.csrf import CSRFProtect, generate_csrf
from functools import wraps
import atexit
from flask import abort
import os
import json
import random

app = Flask(__name__, static_folder='static')
csrf = CSRFProtect(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///restaurant.db'
app.config['SECRET_KEY'] = 'd3f4ult_s3cr3t_k3y_!23#CHANGEME!456'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login_page'

# Initialize database migration
migrate = Migrate(app, db)

# Models (unchanged from your original code)
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='staff')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    active = db.Column(db.Boolean, default=True)
    image_url = db.Column(db.String(255), default='/static/images/placeholder.png')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.Text)
    permissions = db.Column(db.Text)  # JSON string of permissions
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Store(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.Text)
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    image = db.Column(db.String(255))
    opening_hours = db.Column(db.Text)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Table(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    store_id = db.Column(db.Integer, db.ForeignKey('store.id'), nullable=False)
    table_number = db.Column(db.String(20), nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='available')  # available, occupied, reserved, cleaning
    reservation_time = db.Column(db.DateTime)  # Add this field to track when reservation starts
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    store = db.relationship('Store', backref='tables')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    image = db.Column(db.String(255))
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    cost = db.Column(db.Float)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    image = db.Column(db.String(255))
    available = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    category = db.relationship('Category', backref='products')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    status = db.Column(db.String(20), default='pending')  # pending, processing, completed, cancelled
    total_amount = db.Column(db.Float)
    payment_method = db.Column(db.String(50))
    payment_status = db.Column(db.String(20), default='unpaid')  # unpaid, paid, refunded
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    
    table = db.relationship('Table', backref='orders')
    user = db.relationship('User', backref='orders')
    items = db.relationship('OrderItem', backref='order', lazy='dynamic')

# Add Reservation model
class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    store_id = db.Column(db.Integer, db.ForeignKey('store.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.String(10), nullable=False)  # Store as string like "18:30"
    party_size = db.Column(db.Integer, nullable=False)
    table_id = db.Column(db.Integer, db.ForeignKey('table.id'))
    status = db.Column(db.String(20), default='pending')  # pending, confirmed, cancelled, completed
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='reservations')
    store = db.relationship('Store', backref='reservations')
    table = db.relationship('Table', backref='reservations')

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    notes = db.Column(db.Text)
    
    product = db.relationship('Product')

# Add this with the other models
class Waitlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    phone = db.Column(db.String(20))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    seated_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='waiting')  # waiting, seated, cancelled

# Online Order Models
class OnlineOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    order_number = db.Column(db.String(20), unique=True, nullable=False)
    items = db.Column(db.Text)  # JSON string of items
    subtotal = db.Column(db.Float, nullable=False)
    tax = db.Column(db.Float, nullable=False)
    delivery_fee = db.Column(db.Float, default=0.0)
    discount = db.Column(db.Float, default=0.0)
    total = db.Column(db.Float, nullable=False)
    delivery_address = db.Column(db.Text)
    payment_method = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, processing, completed, cancelled
    payment_status = db.Column(db.String(20), default='unpaid')  # Add this line
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='online_orders')

class Coupon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(50), unique=True, nullable=False)
    discount_type = db.Column(db.String(20), nullable=False)  # 'percent' or 'fixed'
    discount_value = db.Column(db.Float, nullable=False)
    min_order = db.Column(db.Float, default=0.0)
    valid_from = db.Column(db.DateTime, nullable=False)
    valid_to = db.Column(db.DateTime, nullable=False)
    max_uses = db.Column(db.Integer, default=1)
    times_used = db.Column(db.Integer, default=0)
    active = db.Column(db.Boolean, default=True)
    max_discount = db.Column(db.Float)  # Optional for percent discounts

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions (add a new one for access key validation)
def validate_email(email):
    return '@' in email

def validate_password(password):
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    return True

def validate_access_key(role, access_key):
    if role in ['admin', 'staff']:
        return access_key == '123456789'
    return True

# Page Routes (add signup route)
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_page'))
    return redirect(url_for('login_page'))

@app.route('/login')
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_page'))
    return render_template('login.html')

@app.route('/signup')
def signup_page():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard_page'))
    return render_template('signup.html')

@app.route('/api/csrf_token')
def get_csrf_token():
    return jsonify({'csrf_token': generate_csrf()})

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/api/login', methods=['POST'])
def api_login():
    # Get CSRF token from headers
    csrf_token = request.headers.get('X-CSRFToken')
    
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Missing JSON in request'}), 400
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required'}), 400
    
    user = User.query.filter_by(username=username).first()
    
    if not user:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    if not user.check_password(password):
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    
    if not user.active:
        return jsonify({'success': False, 'message': 'Account is disabled'}), 403
    
    user.last_login = datetime.utcnow()
    db.session.commit()
    login_user(user)
    
    # Redirect based on role
    if user.role == 'admin':
        redirect_url = url_for('dashboard_page')
    elif user.role == 'staff':
        redirect_url = url_for('staff_dashboard_page')
    else:
        redirect_url = url_for('guest_dashboard_page')
    
    return jsonify({
        'success': True, 
        'redirect': redirect_url,
        'csrf_token': generate_csrf()
    })

# Add these new routes for different user types
@app.route('/admin/dashboard')
@login_required
def admin_dashboard_page():
    if current_user.role != 'admin':
        return redirect(url_for('login_page'))
    return render_template('index.html')

@app.route('/staff/dashboard')
@login_required
def staff_dashboard_page():
    if current_user.role != 'staff':
        return redirect(url_for('login_page'))
    return render_template('staff.html')
    
# API Routes (add signup endpoint)
@app.route('/api/signup', methods=['POST'])
def api_signup():
    # Get CSRF token from headers
    csrf_token = request.headers.get('X-CSRFToken')
    
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Missing JSON in request'}), 400
    
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'guest')
    access_key = data.get('access_key', '')
    
    # Validation
    if not username or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400
    
    if not validate_email(email):
        return jsonify({'success': False, 'message': 'Invalid email format'}), 400
    
    if not validate_password(password):
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters with uppercase, lowercase, and number'}), 400
    
    if not validate_access_key(role, access_key):
        return jsonify({'success': False, 'message': 'Invalid access key for selected role'}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'Username already exists'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'Email already exists'}), 400
    
    # Create user
    user = User(
        username=username,
        email=email,
        role=role,
        active=True
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    
    # Log the user in
    login_user(user)
    
    # Determine redirect URL based on role
    if role == 'admin':
        redirect_url = url_for('admin_dashboard_page')
    elif role == 'staff':
        redirect_url = url_for('staff_dashboard_page')
    else:  # guest or any other role
        redirect_url = url_for('guest_dashboard_page')
    
    return jsonify({
        'success': True, 
        'redirect': redirect_url,
        'csrf_token': generate_csrf(),
        'message': 'Account created successfully'
    })

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'admin':  # Using your role field
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

def staff_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if current_user.role != 'staff':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def staff_or_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role not in ['admin', 'staff']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@login_required
@admin_required
def admin_page():
    return render_template('index.html')

# Admin-only routes
@app.route('/admin/dashboard')
@login_required
@admin_required
def dashboard_page():
    return render_template('index.html')

@app.route('/admin/users')
@login_required
@admin_required
def users_page():
    return render_template('index.html')

@app.route('/admin/groups')
@login_required
@admin_required
def groups_page():
    return render_template('index.html')

@app.route('/admin/stores')
@login_required
@admin_required
def stores_page():
    return render_template('index.html')

@app.route('/admin/tables')
@login_required
@admin_required
def tables_page():
    return render_template('index.html')

@app.route('/admin/category')
@login_required
@admin_required
def category_page():
    return render_template('index.html')

@app.route('/admin/products')
@login_required
@admin_required
def products_page():
    return render_template('index.html')

@app.route('/admin/orders')
@login_required
@admin_required
def orders_page():
    return render_template('index.html')

@app.route('/admin/online-orders')
@login_required
@admin_required
def online_orders_page():
    return render_template('index.html')

@app.route('/admin/reports')
@login_required
@admin_required
def reports_page():
    return render_template('index.html')

@app.route('/admin/company-info')
@login_required
@admin_required
def company_info_page():
    return render_template('index.html')

@app.route('/admin/setting')
@login_required
@admin_required
def setting_page():
    return render_template('index.html')

# Staff routes (accessible to both admin and staff)
@app.route('/staff')
@login_required
@staff_or_admin_required
def staff_page():
    return render_template('staff.html')

@app.route('/staff/tables')
@login_required
@staff_or_admin_required
def staff_tables_page():
    return render_template('staff.html')

@app.route('/staff/orders')
@login_required
@staff_or_admin_required
def staff_orders_page():
    return render_template('staff.html')

@app.route('/staff/reservations')
@login_required
@staff_or_admin_required
def staff_reservations_page():
    return render_template('staff.html')

@app.route('/staff/waitlist')
@login_required
@staff_or_admin_required
def staff_waitlist_page():
    return render_template('staff.html')

@app.route('/staff/online-orders')
@login_required
@staff_or_admin_required
def staff_online_orders_page():
    return render_template('staff.html')

@app.route('/staff/menu')
@login_required
@staff_or_admin_required
def staff_menu_page():
    return render_template('staff.html')

@app.route('/profile')
@login_required
@admin_required
def admin_profile_page():
    return render_template('index.html')

@app.route('/staff/profile')
@login_required
@staff_required
def staff_profile_page():
    return render_template('staff.html')

@app.route('/guest/dashboard')
def guest_dashboard_page():
    return render_template('guest.html')

@app.route('/guest/dashboard/reservations')
def guest_reservations_page():
    return render_template('guest.html')

@app.route('/guest/dashboard/orders')
def guest_orders_page():
    return render_template('guest.html')

@app.route('/guest/dashboard/checkout')
@login_required
def guest_checkout():
    return render_template('guest.html')

# API Endpoints for Dashboard
@app.route('/api/dashboard')
@login_required
def dashboard_data():
    # Common statistics for both roles
    today = datetime.today().date()
    
    # Get base statistics
    revenue_today = db.session.query(db.func.sum(Order.total_amount)).filter(
        db.func.date(Order.created_at) == today,
        Order.payment_status == 'paid'
    ).scalar() or 0
    
    available_tables = Table.query.filter_by(status='available').count()
    occupied_tables = Table.query.filter_by(status='occupied').count()
    active_orders = Order.query.filter(
        Order.status.in_(['pending', 'processing'])
    ).count()
    waitlist_count = Waitlist.query.filter_by(status='waiting').count()
    
    # Initialize response with common data
    response = {
        'revenue_today': float(revenue_today),
        'available_tables': available_tables,
        'occupied_tables': occupied_tables,
        'active_orders': active_orders,
        'waitlist_count': waitlist_count,
    }
    
    # Add admin-specific statistics
    if current_user.role == 'admin':
        # Product statistics
        response['total_products'] = Product.query.filter_by(available=True).count()
        
        # Order statistics
        response['paid_orders'] = Order.query.filter_by(payment_status='paid').count()
        response['unpaid_orders'] = Order.query.filter_by(payment_status='unpaid').count()
        
        # Store statistics
        response['total_stores'] = Store.query.filter_by(active=True).count()
        
        # User statistics
        response['total_users'] = User.query.filter_by(active=True).count()
        
        # Financial statistics
        response['total_revenue'] = float(db.session.query(
            db.func.sum(Order.total_amount)
        ).filter(
            Order.payment_status == 'paid'
        ).scalar() or 0)
    
    # Recent orders (last 5) - for both roles but might display differently
    recent_orders = Order.query.order_by(Order.created_at.desc()).limit(5).all()
    response['recent_orders'] = [{
        'id': order.id,
        'table_number': order.table.table_number if order.table else None,
        'status': order.status,
        'payment_status': order.payment_status,
        'total_amount': float(order.total_amount) if order.total_amount else 0,
        'created_at': order.created_at.isoformat()
    } for order in recent_orders]
    
    return jsonify(response)

# Updated login route
@app.route('/login', methods=['GET', 'POST'])
def login_route():
    if request.method == 'POST':
        try:
            if not request.is_json:
                return jsonify({'success': False, 'message': 'Missing JSON in request'}), 400
            
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            if not username or not password:
                return jsonify({'success': False, 'message': 'Username and password are required'}), 400
            
            user = User.query.filter_by(username=username).first()
            
            if not user:
                print(f"Login failed: User {username} not found")
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            
            if not user.check_password(password):
                print(f"Login failed: Incorrect password for user {username}")
                return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
            
            if not user.active:
                print(f"Login failed: User {username} is inactive")
                return jsonify({'success': False, 'message': 'Account is disabled'}), 403
            
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            
            print(f"User {username} logged in successfully")
            return jsonify({
                'success': True, 
                'redirect': url_for('dashboard_page'),
                'csrf_token': generate_csrf()
            })
        except Exception as e:
            print(f"Login error: {str(e)}")
            return jsonify({'success': False, 'message': 'An error occurred during login'}), 500
    
    # For GET request, return CSRF token
    return jsonify({'csrf_token': generate_csrf()})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    # Return a response that works for both AJAX and normal requests
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True, 
            'redirect': url_for('guest_dashboard_page'),
            'csrf_token': generate_csrf()
        })
    return redirect(url_for('guest_dashboard_page'))

@login_manager.unauthorized_handler
def unauthorized():
    # For API requests, return JSON
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    # For page requests, redirect to login
    return redirect(url_for('login_page'))

@app.route('/api/check_auth')
def check_auth():
    return jsonify({'authenticated': current_user.is_authenticated})

# User Management
@app.route('/api/users', methods=['GET', 'POST'])
@login_required
def users_data():
    if request.method == 'GET':
        users = User.query.all()
        return jsonify([{
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'active': user.active,
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'created_at': user.created_at.isoformat()
        } for user in users])
    
    elif request.method == 'POST':
        data = request.get_json()  # This is correct for POST
        
        # Validation
        if not data.get('username') or not data.get('email') or not data.get('password'):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        if User.query.filter_by(username=data['username']).first():
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'success': False, 'message': 'Email already exists'}), 400
        
        if not validate_email(data['email']):
            return jsonify({'success': False, 'message': 'Invalid email format'}), 400
        
        if not validate_password(data['password']):
            return jsonify({'success': False, 'message': 'Password must be at least 8 characters with uppercase, lowercase, and number'}), 400
        
        # Create user
        user = User(
            username=data['username'],
            email=data['email'],
            role=data.get('role', 'staff')
        )
        user.set_password(data['password'])
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'User created successfully'}), 201

@app.route('/api/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'GET':
        return jsonify({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'active': user.active,
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'created_at': user.created_at.isoformat()
        })
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        # Update fields
        if 'username' in data and data['username'] != user.username:
            if User.query.filter_by(username=data['username']).first():
                return jsonify({'success': False, 'message': 'Username already exists'}), 400
            user.username = data['username']
        
        if 'email' in data and data['email'] != user.email:
            if User.query.filter_by(email=data['email']).first():
                return jsonify({'success': False, 'message': 'Email already exists'}), 400
            if not validate_email(data['email']):
                return jsonify({'success': False, 'message': 'Invalid email format'}), 400
            user.email = data['email']
        
        if 'role' in data:
            user.role = data['role']
        
        if 'active' in data:
            user.active = data['active']
        
        if 'password' in data and data['password']:
            if not validate_password(data['password']):
                return jsonify({'success': False, 'message': 'Password must be at least 8 characters with uppercase, lowercase, and number'}), 400
            user.set_password(data['password'])
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'User updated successfully'})
    
    elif request.method == 'DELETE':
        # Prevent deleting yourself
        if user.id == current_user.id:
            return jsonify({'success': False, 'message': 'Cannot delete your own account'}), 400
        
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'User deleted successfully'})

# Group Management
@app.route('/api/groups', methods=['GET', 'POST'])
@login_required
def groups_data():
    if request.method == 'GET':
        groups = Group.query.all()
        return jsonify([{
            'id': group.id,
            'name': group.name,
            'description': group.description,
            'permissions': group.permissions,
            'created_at': group.created_at.isoformat()
        } for group in groups])
    
    elif request.method == 'POST':
        data = request.get_json()
        
        if not data.get('name'):
            return jsonify({'success': False, 'message': 'Group name is required'}), 400
        
        if Group.query.filter_by(name=data['name']).first():
            return jsonify({'success': False, 'message': 'Group name already exists'}), 400
        
        group = Group(
            name=data['name'],
            description=data.get('description', ''),
            permissions=data.get('permissions', '{}')
        )
        db.session.add(group)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Group created successfully'}), 201

@app.route('/api/groups/<int:group_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def group_detail(group_id):
    group = Group.query.get_or_404(group_id)
    
    if request.method == 'GET':
        return jsonify({
            'id': group.id,
            'name': group.name,
            'description': group.description,
            'permissions': group.permissions,
            'created_at': group.created_at.isoformat()
        })
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        if 'name' in data and data['name'] != group.name:
            if Group.query.filter_by(name=data['name']).first():
                return jsonify({'success': False, 'message': 'Group name already exists'}), 400
            group.name = data['name']
        
        if 'description' in data:
            group.description = data['description']
        
        if 'permissions' in data:
            group.permissions = data['permissions']
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Group updated successfully'})
    
    elif request.method == 'DELETE':
        db.session.delete(group)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Group deleted successfully'})

# Store Management
@app.route('/api/stores', methods=['GET', 'POST'])
@login_required
def stores_data():
    if request.method == 'GET':
        stores = Store.query.all()
        return jsonify([{
            'id': store.id,
            'name': store.name,
            'address': store.address,
            'phone': store.phone,
            'email': store.email,
            'image': store.image,  # Include image URL in response
            'opening_hours': store.opening_hours,
            'active': store.active,
            'created_at': store.created_at.isoformat()
        } for store in stores])
    
    elif request.method == 'POST':
        data = request.get_json()
        
        if not data.get('name'):
            return jsonify({'success': False, 'message': 'Store name is required'}), 400
        
        store = Store(
            name=data['name'],
            address=data.get('address', ''),
            phone=data.get('phone', ''),
            email=data.get('email', ''),
            image=data.get('image', ''),  # Add image URL
            opening_hours=data.get('opening_hours', ''),
            active=data.get('active', True)
        )
        db.session.add(store)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Store created successfully'}), 201

@app.route('/api/stores/<int:store_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def store_detail(store_id):
    store = Store.query.get_or_404(store_id)
    
    if request.method == 'GET':
        return jsonify({
            'id': store.id,
            'name': store.name,
            'address': store.address,
            'phone': store.phone,
            'email': store.email,
            'image': store.image,  # Include image URL in response
            'opening_hours': store.opening_hours,
            'active': store.active,
            'created_at': store.created_at.isoformat()
        })
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        if 'name' in data:
            store.name = data['name']
        
        if 'address' in data:
            store.address = data['address']
        
        if 'phone' in data:
            store.phone = data['phone']
        
        if 'email' in data:
            store.email = data['email']
        
        if 'image' in data:  # Handle image URL updates
            store.image = data['image']
        
        if 'opening_hours' in data:
            store.opening_hours = data['opening_hours']
        
        if 'active' in data:
            store.active = data['active']
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Store updated successfully'})
    
    elif request.method == 'DELETE':
        db.session.delete(store)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Store deleted successfully'})

# Table Management
@app.route('/api/tables', methods=['GET', 'POST'])
@login_required
def tables_data():
    if request.method == 'GET':
        tables = Table.query.all()
        return jsonify([{
            'id': table.id,
            'store_id': table.store_id,
            'store_name': table.store.name if table.store else '',
            'table_number': table.table_number,
            'capacity': table.capacity,
            'status': table.status,
            'created_at': table.created_at.isoformat()
        } for table in tables])
    
    elif request.method == 'POST':
        data = request.get_json()
        
        if not data.get('store_id') or not data.get('table_number') or not data.get('capacity'):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        store = Store.query.get(data['store_id'])
        if not store:
            return jsonify({'success': False, 'message': 'Store not found'}), 404
        
        if Table.query.filter_by(store_id=data['store_id'], table_number=data['table_number']).first():
            return jsonify({'success': False, 'message': 'Table number already exists in this store'}), 400
        
        table = Table(
            store_id=data['store_id'],
            table_number=data['table_number'],
            capacity=data['capacity'],
            status=data.get('status', 'available')
        )
        db.session.add(table)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Table created successfully'}), 201

@app.route('/api/tables/<int:table_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def table_detail(table_id):
    table = Table.query.get_or_404(table_id)
    
    if request.method == 'GET':
        return jsonify({
            'id': table.id,
            'store_id': table.store_id,
            'store_name': table.store.name if table.store else '',
            'table_number': table.table_number,
            'capacity': table.capacity,
            'status': table.status,
            'created_at': table.created_at.isoformat()
        })
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        # Check if store_id is being updated
        if 'store_id' in data and data['store_id'] != table.store_id:
            # Verify the new store exists
            if not Store.query.get(data['store_id']):
                return jsonify({'success': False, 'message': 'Store not found'}), 404
            table.store_id = data['store_id']
        
        if 'table_number' in data:
            # Check if table number already exists in the (possibly new) store
            if Table.query.filter_by(store_id=table.store_id, table_number=data['table_number']).filter(Table.id != table.id).first():
                return jsonify({'success': False, 'message': 'Table number already exists in this store'}), 400
            table.table_number = data['table_number']
        
        if 'capacity' in data:
            table.capacity = data['capacity']
        
        if 'status' in data:
            table.status = data['status']
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Table updated successfully'})
        
def get_table_reservation(table_id):
    table = Table.query.get_or_404(table_id)
    
    if not table.reservation_time:
        return jsonify({'success': False, 'message': 'No reservation for this table'}), 404
    
    reservation = Reservation.query.filter_by(table_id=table_id).order_by(Reservation.date.desc()).first()
    
    if not reservation:
        return jsonify({'success': False, 'message': 'Reservation not found'}), 404
    
    return jsonify({
        'success': True,
        'reservation': {
            'id': reservation.id,
            'name': reservation.name,
            'party_size': reservation.party_size,
            'time': reservation.time,
            'date': reservation.date.isoformat(),
            'notes': reservation.notes,
            'time_until': (table.reservation_time - datetime.utcnow()).total_seconds() / 60  # minutes
        }
    })

def update_table(table_id):
    table = Table.query.get_or_404(table_id)
    data = request.get_json()
    
    if 'status' in data:
        table.status = data['status']
    
    if 'reservation_time' in data:
        table.reservation_time = datetime.strptime(data['reservation_time'], '%Y-%m-%d %H:%M:%S') if data['reservation_time'] else None
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Table updated successfully'
    })

# Category Management
@app.route('/api/categories', methods=['GET', 'POST'])
@login_required
def categories_data():
    if request.method == 'GET':
        categories = Category.query.all()
        return jsonify([{
            'id': category.id,
            'name': category.name,
            'description': category.description,
            'image': category.image,
            'active': category.active,
            'created_at': category.created_at.isoformat()
        } for category in categories])
    
    elif request.method == 'POST':
        data = request.get_json()
        
        if not data.get('name'):
            return jsonify({'success': False, 'message': 'Category name is required'}), 400
        
        if Category.query.filter_by(name=data['name']).first():
            return jsonify({'success': False, 'message': 'Category name already exists'}), 400
        
        category = Category(
            name=data['name'],
            description=data.get('description', ''),
            image=data.get('image', ''),
            active=data.get('active', True)
        )
        db.session.add(category)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Category created successfully'}), 201

@app.route('/api/categories/<int:category_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def category_detail(category_id):
    category = Category.query.get_or_404(category_id)
    
    if request.method == 'GET':
        return jsonify({
            'id': category.id,
            'name': category.name,
            'description': category.description,
            'image': category.image,
            'active': category.active,
            'created_at': category.created_at.isoformat()
        })
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        if 'name' in data and data['name'] != category.name:
            if Category.query.filter_by(name=data['name']).first():
                return jsonify({'success': False, 'message': 'Category name already exists'}), 400
            category.name = data['name']
        
        if 'description' in data:
            category.description = data['description']
        
        if 'image' in data:
            category.image = data['image']
        
        if 'active' in data:
            category.active = data['active']
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Category updated successfully'})
    
    elif request.method == 'DELETE':
        # Check if category has products
        if category.products.count() > 0:
            return jsonify({'success': False, 'message': 'Cannot delete category with products'}), 400
        
        db.session.delete(category)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Category deleted successfully'})

# Product Management
@app.route('/api/products', methods=['GET', 'POST'])
def products_data():
    if request.method == 'GET':
        # For admin users, show all products
        if current_user.is_authenticated and current_user.role == 'admin':
            products = Product.query.all()
        else:
            # Public access shows only available products
            products = Product.query.filter_by(available=True).all()
        
        return jsonify([{
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': product.price,
            'category_id': product.category_id,
            'category_name': product.category.name if product.category else '',
            'image': product.image,
            'available': product.available,  # Make sure this is included
            'created_at': product.created_at.isoformat()
        } for product in products])
    
    elif request.method == 'POST':
        # Still require login for POST (admin operations)
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
            
        data = request.get_json()
        
        if not data.get('name') or not data.get('price'):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        if Product.query.filter_by(name=data['name']).first():
            return jsonify({'success': False, 'message': 'Product name already exists'}), 400
        
        product = Product(
            name=data['name'],
            description=data.get('description', ''),
            price=data['price'],
            cost=data.get('cost'),
            category_id=data.get('category_id'),
            image=data.get('image', ''),
            available=data.get('available', True)
        )
        db.session.add(product)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Product created successfully'}), 201

def public_endpoint(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/products/<int:product_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    
    if request.method == 'GET':
        return jsonify({
            'id': product.id,
            'name': product.name,
            'description': product.description,
            'price': product.price,
            'cost': product.cost,
            'category_id': product.category_id,
            'category_name': product.category.name if product.category else '',
            'image': product.image,
            'available': product.available,
            'created_at': product.created_at.isoformat()
        })

    elif request.method == 'PUT':
        data = request.get_json()
        
        if 'name' in data and data['name'] != product.name:
            if Product.query.filter_by(name=data['name']).first():
                return jsonify({'success': False, 'message': 'Product name already exists'}), 400
            product.name = data['name']
        
        if 'description' in data:
            product.description = data['description']
        
        if 'price' in data:
            product.price = data['price']
        
        if 'cost' in data:
            product.cost = data['cost']
        
        if 'category_id' in data:
            product.category_id = data['category_id']
        
        if 'image' in data:
            product.image = data['image']
        
        # Make sure this handles the available field
        if 'available' in data:
            product.available = bool(data['available'])
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Product updated successfully'})
    
    elif request.method == 'DELETE':
        db.session.delete(product)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Product deleted successfully'})

# Order Management
@app.route('/api/orders', methods=['GET', 'POST'])
@login_required
def orders_data():
    if request.method == 'GET':
        # Get query parameters
        table_id = request.args.get('table_id')
        status = request.args.get('status')

        # Base query
        query = Order.query

        # Apply filters
        if table_id:
            query = query.filter_by(table_id=table_id)
        if status:
            query = query.filter_by(status=status)

        orders = query.order_by(Order.created_at.desc()).all()

        return jsonify([{
            'id': order.id,
            'table_id': order.table_id,
            'table_number': order.table.table_number if order.table else '',
            'user_id': order.user_id,
            'username': order.user.username if order.user else '',
            'status': order.status,
            'total_amount': order.total_amount,
            'payment_method': order.payment_method,
            'payment_status': order.payment_status,
            'notes': order.notes,
            'created_at': order.created_at.isoformat(),
            'updated_at': order.updated_at.isoformat() if order.updated_at else None,
            'items': [{
                'product_id': item.product_id,
                'product_name': item.product.name if item.product else '',
                'quantity': item.quantity,
                'price': item.price,
                'notes': item.notes
            } for item in order.items]
        } for order in orders])
    
    elif request.method == 'POST':
        data = request.get_json()
        
        if not data.get('table_id') or not data.get('items') or len(data['items']) == 0:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        table = Table.query.get(data['table_id'])
        if not table:
            return jsonify({'success': False, 'message': 'Table not found'}), 404
        
        # Check if table is reserved
        if table.status == 'reserved':
            return jsonify({
                'success': False, 
                'message': 'Table is reserved for an upcoming reservation'
            }), 400
        
        # Check if table already has an active order
        existing_order = Order.query.filter_by(
            table_id=data['table_id']
        ).filter(
            Order.status.in_(['pending', 'processing'])
        ).first()
        
        if existing_order:
            return jsonify({
                'success': False, 
                'message': 'Table already has an active order',
                'order_id': existing_order.id
            }), 400
        
        # Calculate total amount
        total_amount = 0
        items = []
        for item_data in data['items']:
            product = Product.query.get(item_data['product_id'])
            if not product:
                return jsonify({'success': False, 'message': f'Product {item_data["product_id"]} not found'}), 404
            
            if not product.available:
                return jsonify({'success': False, 'message': f'Product {product.name} is not available'}), 400
            
            quantity = item_data.get('quantity', 1)
            if quantity <= 0:
                return jsonify({'success': False, 'message': 'Quantity must be positive'}), 400
            
            total_amount += product.price * quantity
            items.append({
                'product_id': product.id,
                'quantity': quantity,
                'price': product.price,
                'notes': item_data.get('notes', '')
            })
        
        # Create order
        order = Order(
            table_id=data['table_id'],
            user_id=current_user.id,
            status=data.get('status', 'pending'),
            total_amount=total_amount,
            payment_method=data.get('payment_method', ''),
            payment_status=data.get('payment_status', 'unpaid'),
            notes=data.get('notes', '')
        )
        db.session.add(order)
        db.session.commit()
        
        # Add order items
        for item_data in items:
            order_item = OrderItem(
                order_id=order.id,
                product_id=item_data['product_id'],
                quantity=item_data['quantity'],
                price=item_data['price'],
                notes=item_data['notes']
            )
            db.session.add(order_item)
        
        # Update table status
        table.status = 'occupied'
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Order created successfully', 
            'order_id': order.id
        }), 201

@app.route('/api/orders/<int:order_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def order_detail(order_id):
    order = Order.query.get_or_404(order_id)
    
    if request.method == 'GET':
        return jsonify({
            'id': order.id,
            'table_id': order.table_id,
            'table_number': order.table.table_number if order.table else '',
            'user_id': order.user_id,
            'username': order.user.username if order.user else '',
            'status': order.status,
            'total_amount': order.total_amount,
            'payment_method': order.payment_method,
            'payment_status': order.payment_status,
            'notes': order.notes,
            'created_at': order.created_at.isoformat(),
            'updated_at': order.updated_at.isoformat() if order.updated_at else None,
            'items': [{
                'id': item.id,
                'product_id': item.product_id,
                'product_name': item.product.name if item.product else '',
                'quantity': item.quantity,
                'price': item.price,
                'notes': item.notes
            } for item in order.items]
        })
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        if 'status' in data:
            order.status = data['status']
            # Update table status when order is completed
            if data['status'] == 'completed' and order.table:
                order.table.status = 'available'
        
        if 'payment_method' in data:
            order.payment_method = data['payment_method']
        
        if 'payment_status' in data:
            order.payment_status = data['payment_status']
        
        if 'notes' in data:
            order.notes = data['notes']

        # Handle items update
        if 'items' in data:
            # Clear existing items
            OrderItem.query.filter_by(order_id=order.id).delete()
            
            # Add new items
            total_amount = 0
            for item_data in data['items']:
                product = Product.query.get(item_data['product_id'])
                if product and product.available:
                    item = OrderItem(
                        order_id=order.id,
                        product_id=product.id,
                        quantity=item_data['quantity'],
                        price=product.price,
                        notes=item_data.get('notes', '')
                    )
                    db.session.add(item)
                    total_amount += product.price * item_data['quantity']
            
            order.total_amount = total_amount
        
        order.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True, 
            'message': 'Order updated successfully',
            'total_amount': order.total_amount
        })

    elif request.method == 'DELETE':
        # Update table status if order is deleted
        if order.table:
            order.table.status = 'available'
        
        db.session.delete(order)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Order deleted successfully'})

# Reservation API
@app.route('/api/reservations', methods=['GET', 'POST'])
# @login_required  # Remove this decorator if you want to allow unauthenticated access
def reservations():
    if request.method == 'GET':
        query = Reservation.query

        # For staff/admin, allow filtering
        if current_user.is_authenticated and current_user.role in ['admin', 'staff']:
            date = request.args.get('date')
            status = request.args.get('status')
            
            if date:
                query = query.filter(Reservation.date == date)
            if status:
                query = query.filter(Reservation.status == status)
        # For guests, only their reservations
        elif current_user.is_authenticated:
            query = query.filter_by(user_id=current_user.id)
        else:
            return jsonify([])
        
        reservations = query.order_by(Reservation.date.desc()).all()
        return jsonify([{
            'id': r.id,
            'user_id': r.user_id,
            'name': r.name,  # Make sure to include the name
            'email': r.email,
            'phone': r.phone,
            'date': r.date.isoformat(),
            'time': r.time,
            'party_size': r.party_size,
            'table_id': r.table_id,
            'table_number': r.table.table_number if r.table else None,
            'store_name': r.store.name if r.store else None,
            'status': r.status,
            'notes': r.notes,
            'created_at': r.created_at.isoformat()
        } for r in reservations])
    
    elif request.method == 'POST':
        data = request.get_json()

        # Validate time is in 30-minute increments
        try:
            time_parts = data['time'].split(':')
            hour = int(time_parts[0])
            minute = int(time_parts[1])

            if minute % 30 != 0:
                return jsonify({
                    'success': False, 
                    'message': 'Reservations must be in 30-minute intervals (e.g., 7:00, 7:30, etc.)'
                }), 400
        except (ValueError, IndexError):
            return jsonify({'success': False, 'message': 'Invalid time format'}), 400
        
        # Required fields validation
        required_fields = ['name', 'email', 'phone', 'party_size', 'store_id', 'date', 'time']
        if not all(field in data for field in required_fields):
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        try:
            # Parse date and validate
            reservation_date = datetime.strptime(data['date'], '%Y-%m-%d').date()
            if reservation_date < datetime.utcnow().date():
                return jsonify({'success': False, 'message': 'Cannot book for past dates'}), 400

            # Find or assign a table
            table = None
            if data.get('table_id'):
                table = Table.query.get(data['table_id'])
                if not table or table.store_id != data['store_id']:
                    return jsonify({'success': False, 'message': 'Invalid table selection'}), 400
            else:
                # Auto-assign a table
                table = Table.query.filter(
                    Table.store_id == data['store_id'],
                    Table.capacity >= data['party_size'],
                    Table.status == 'available'
                ).first()
                
                if not table:
                    return jsonify({'success': False, 'message': 'No available tables for the selected party size'}), 400

            # Create reservation
            reservation = Reservation(
                user_id=current_user.id if current_user.is_authenticated else None,
                name=data['name'],
                email=data['email'],
                phone=data['phone'],
                date=reservation_date,
                time=data['time'],
                party_size=data['party_size'],
                table_id=table.id if table else None,
                store_id=data['store_id'],
                status='confirmed',
                notes=data.get('notes', '')
            )
            db.session.add(reservation)
            
            # Update table status and set reservation time
            if table:
                # Calculate the exact reservation time
                reservation_datetime = datetime.combine(reservation_date, 
                                                    datetime.strptime(data['time'], '%H:%M').time())
                table.reservation_time = reservation_datetime
                # Only mark as reserved if within 30 minutes
                if (reservation_datetime - datetime.utcnow()).total_seconds() <= 1800:  # 30 minutes
                    table.status = 'reserved'
                else:
                    table.status = 'available'  # Will be updated by the periodic check
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Reservation created successfully',
                'reservation_id': reservation.id,
                'table_number': table.table_number if table else 'Auto-assigned',
                'store_name': table.store.name if table and table.store else None
            }), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500
        
@app.route('/api/reservations/<int:reservation_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def handle_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    
    if request.method == 'GET':
        # GET - Return reservation details
        return jsonify({
            'id': reservation.id,
            'user_id': reservation.user_id,
            'name': reservation.name,
            'email': reservation.email,
            'phone': reservation.phone,
            'date': reservation.date.isoformat(),
            'time': reservation.time,
            'party_size': reservation.party_size,
            'table_id': reservation.table_id,
            'table_number': reservation.table.table_number if reservation.table else None,
            'store_name': reservation.store.name if reservation.store else None,
            'status': reservation.status,
            'notes': reservation.notes,
            'created_at': reservation.created_at.isoformat()
        })
    
    elif request.method == 'PUT':
        # PUT - Update reservation
        data = request.get_json()

        # Validate time is in 30-minute increments
        try:
            time_parts = data['time'].split(':')
            hour = int(time_parts[0])
            minute = int(time_parts[1])

            if minute % 30 != 0:
                return jsonify({
                    'success': False, 
                    'message': 'Reservations must be in 30-minute intervals (e.g., 7:00, 7:30, etc.)'
                }), 400
        except (ValueError, IndexError):
            return jsonify({'success': False, 'message': 'Invalid time format'}), 400
        
        # Update fields
        if 'name' in data:
            reservation.name = data['name']
        if 'phone' in data:
            reservation.phone = data['phone']
        if 'party_size' in data:
            reservation.party_size = data['party_size']
        if 'date' in data:
            reservation.date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        if 'time' in data:
            reservation.time = data['time']
        if 'status' in data:
            reservation.status = data['status']
        if 'notes' in data:
            reservation.notes = data['notes']
        
        # Handle table assignment
        if 'table_id' in data:
            new_table_id = data['table_id']
            
            # If table is being unassigned
            if not new_table_id:
                if reservation.table:
                    reservation.table.status = 'available'
                    reservation.table.reservation_time = None
                reservation.table_id = None
            else:
                # If table is being changed
                new_table = Table.query.get(new_table_id)
                if not new_table:
                    return jsonify({'success': False, 'message': 'Table not found'}), 404
                
                # If table was previously assigned, free it up
                if reservation.table and reservation.table.id != new_table.id:
                    reservation.table.status = 'available'
                    reservation.table.reservation_time = None
                
                # Assign new table
                reservation.table_id = new_table.id
                new_table.reservation_time = datetime.combine(
                    reservation.date, 
                    datetime.strptime(reservation.time, '%H:%M').time()
                )
                # Only mark as reserved if within 30 minutes
                if (new_table.reservation_time - datetime.utcnow()).total_seconds() <= 1800:
                    new_table.status = 'reserved'
                else:
                    new_table.status = 'available'
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Reservation updated successfully'
        })
    
    elif request.method == 'DELETE':
        # DELETE - Cancel reservation
        # Update table status if assigned
        if reservation.table:
            reservation.table.status = 'available'
            reservation.table.reservation_time = None
        
        # Delete reservation
        db.session.delete(reservation)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Reservation cancelled successfully'})

# Table Availability Check
@app.route('/api/tables/available', methods=['POST'])
def check_table_availability():
    data = request.get_json()

    # Validate time is in 30-minute increments
    try:
        time_parts = data['time'].split(':')
        hour = int(time_parts[0])
        minute = int(time_parts[1])

        if minute % 30 != 0:
            return jsonify({
                'success': False, 
                'message': 'Time must be in 30-minute intervals'
            }), 400
    except (ValueError, IndexError):
        return jsonify({'success': False, 'message': 'Invalid time format'}), 400
    
    required_fields = ['party_size', 'date', 'time']
    if not all(field in data for field in required_fields):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    try:
        # Parse date and time
        reservation_date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        reservation_time = data['time']
        
        # Get all reservations for this date/time
        reservations = Reservation.query.filter(
            Reservation.date == reservation_date,
            Reservation.time == reservation_time,
            Reservation.status == 'confirmed'
        ).all()
        
        # Get tables that are already reserved
        reserved_table_ids = [r.table_id for r in reservations if r.table_id]
        
        # Base query for available tables
        query = Table.query.filter(
            Table.capacity >= int(data['party_size']),
            Table.status == 'available',
            Table.id.notin_(reserved_table_ids)
        )
        
        # Filter by store if provided
        if 'store_id' in data:
            query = query.filter_by(store_id=data['store_id'])
        
        available_tables = query.all()
        
        return jsonify({
            'success': True,
            'available_tables': [{
                'id': t.id,
                'table_number': t.table_number,
                'capacity': t.capacity,
                'store_name': t.store.name if t.store else None
            } for t in available_tables]
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# Reports
@app.route('/api/reports/sales', methods=['GET'])
@login_required
def sales_report():
    # Get parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    period = request.args.get('period', 'daily')
    payment_status = request.args.get('payment_status')
    report_type = request.args.get('type', 'all')  # all, restaurant, online
    
    # Validate dates
    try:
        if start_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            # Include the entire end date
            end_date_plus_1 = end_date + timedelta(days=1)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid date format (YYYY-MM-DD)'}), 400
    
    # Base query for restaurant orders
    query = Order.query
    
    # Apply payment status filter if provided
    if payment_status:
        query = query.filter(Order.payment_status == payment_status)
    
    # Apply date filters
    if start_date:
        query = query.filter(Order.created_at >= start_date)
    if end_date:
        query = query.filter(Order.created_at < end_date_plus_1)
    
    # Get orders
    orders = query.order_by(Order.created_at).all()
    
    # Calculate report data
    total_sales = sum(order.total_amount for order in orders) if orders else 0
    total_orders = len(orders)
    
    # Group data based on period
    chart_data = []
    if period == 'daily':
        sales_by_day = {}
        for order in orders:
            day = order.created_at.date()
            sales_by_day[day] = sales_by_day.get(day, 0) + order.total_amount
        # Sort by date and format for chart
        for day in sorted(sales_by_day.keys()):
            chart_data.append({
                'date': day.strftime('%b %d, %Y'),
                'sales': sales_by_day[day]
            })
    
    elif period == 'weekly':
        sales_by_week = {}
        for order in orders:
            year = order.created_at.isocalendar()[0]
            week = order.created_at.isocalendar()[1]
            key = (year, week)
            sales_by_week[key] = sales_by_week.get(key, 0) + order.total_amount
        # Sort by year and week number
        for (year, week) in sorted(sales_by_week.keys()):
            chart_data.append({
                'date': f"Week {week}, {year}",
                'sales': sales_by_week[(year, week)]
            })
    
    elif period == 'monthly':
        sales_by_month = {}
        for order in orders:
            key = (order.created_at.year, order.created_at.month)
            sales_by_month[key] = sales_by_month.get(key, 0) + order.total_amount
        # Sort by year and month
        for (year, month) in sorted(sales_by_month.keys()):
            chart_data.append({
                'date': datetime(year, month, 1).strftime('%b %Y'),
                'sales': sales_by_month[(year, month)]
            })
    
    elif period == 'yearly':
        sales_by_year = {}
        for order in orders:
            key = order.created_at.year
            sales_by_year[key] = sales_by_year.get(key, 0) + order.total_amount
        # Sort by year
        for year in sorted(sales_by_year.keys()):
            chart_data.append({
                'date': str(year),
                'sales': sales_by_year[year]
            })
    
    # Top products
    product_sales = {}
    for order in orders:
        for item in order.items:
            product_sales[item.product_id] = product_sales.get(item.product_id, {
                'name': item.product.name if item.product else 'Unknown',
                'quantity': 0,
                'revenue': 0
            })
            product_sales[item.product_id]['quantity'] += item.quantity
            product_sales[item.product_id]['revenue'] += item.price * item.quantity
    
    top_products = sorted(product_sales.values(), key=lambda x: x['revenue'], reverse=True)[:5]
    
    return jsonify({
        'success': True,
        'total_sales': float(total_sales),
        'total_orders': total_orders,
        'chart_data': chart_data,
        'top_products': top_products,
        'period': period
    })

# Profile Management
@app.route('/api/profile', methods=['GET', 'PUT'])
@login_required
def profile():
    if request.method == 'GET':
        return jsonify({
            'id': current_user.id,
            'username': current_user.username,
            'email': current_user.email,
            'role': current_user.role,
            'image_url': current_user.image_url,
            'last_login': current_user.last_login.isoformat() if current_user.last_login else None,
            'created_at': current_user.created_at.isoformat()
        })
    
    elif request.method == 'PUT':
        data = request.get_json()

        if 'email' in data and data['email'] != current_user.email:
            if User.query.filter_by(email=data['email']).first():
                return jsonify({'success': False, 'message': 'Email already exists'}), 400
            if not validate_email(data['email']):
                return jsonify({'success': False, 'message': 'Invalid email format'}), 400
            current_user.email = data['email']

        if 'image_url' in data:
            current_user.image_url = data['image_url']

        if 'password' in data and data['password']:
            if not validate_password(data['password']):
                return jsonify({'success': False, 'message': 'Password must be at least 8 characters with uppercase, lowercase, and number'}), 400
            current_user.set_password(data['password'])

        db.session.commit()
        return jsonify({'success': True, 'message': 'Profile updated successfully'})

# Settings
@app.route('/api/settings', methods=['GET', 'PUT'])
@login_required
def settings():
    if request.method == 'GET':
        # In a real app, you would get these from a settings table or config file
        return jsonify({
            'company_name': 'Restaurant System',
            'currency': '$',
            'tax_rate': 0.1,
            'timezone': 'UTC',
            'date_format': 'YYYY-MM-DD'
        })
    
    elif request.method == 'PUT':
        # In a real app, you would save these to a settings table
        data = request.get_json()
        return jsonify({'success': True, 'message': 'Settings updated successfully'})

# Waitlist Management
@app.route('/api/waitlist', methods=['GET', 'POST'])
@login_required
def waitlist_data():
    if request.method == 'GET':
        waitlist = Waitlist.query.filter_by(status='waiting').all()
        return jsonify([{
            'id': party.id,
            'name': party.name,
            'size': party.size,
            'phone': party.phone,
            'notes': party.notes,
            'wait_time': (datetime.utcnow() - party.created_at).seconds // 60,  # minutes
            'created_at': party.created_at.isoformat()
        } for party in waitlist])
    
    elif request.method == 'POST':
        data = request.get_json()
        
        if not data.get('name') or not data.get('size'):
            return jsonify({'success': False, 'message': 'Name and party size are required'}), 400
        
        party = Waitlist(
            name=data['name'],
            size=data['size'],
            phone=data.get('phone', ''),
            notes=data.get('notes', ''),
            status='waiting'
        )
        db.session.add(party)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Party added to waitlist', 'party_id': party.id}), 201

@app.route('/api/waitlist/<int:party_id>', methods=['GET', 'PUT', 'DELETE'])
@login_required
def waitlist_party(party_id):
    party = Waitlist.query.get_or_404(party_id)
    
    if request.method == 'GET':
        return jsonify({
            'id': party.id,
            'name': party.name,
            'size': party.size,
            'phone': party.phone,
            'notes': party.notes,
            'wait_time': (datetime.utcnow() - party.created_at).seconds // 60,
            'created_at': party.created_at.isoformat(),
            'status': party.status
        })
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        if 'status' in data:
            party.status = data['status']
            if data['status'] == 'seated':
                party.seated_at = datetime.utcnow()
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Waitlist party updated successfully'})
    
    elif request.method == 'DELETE':
        party.status = 'cancelled'
        db.session.commit()
        return jsonify({'success': True, 'message': 'Waitlist party removed successfully'})

@app.route('/api/waitlist/seat', methods=['POST'])
@login_required
def seat_party():
    data = request.get_json()
    
    # Validate input
    if not data.get('party_id') or not data.get('table_id'):
        return jsonify({'success': False, 'message': 'Party ID and Table ID are required'}), 400
    
    # Get party and table
    party = Waitlist.query.get(data['party_id'])
    table = Table.query.get(data['table_id'])
    
    if not party or not table:
        return jsonify({'success': False, 'message': 'Party or table not found'}), 404
    
    # Update statuses
    party.status = 'seated'
    party.seated_at = datetime.utcnow()
    table.status = 'occupied'
    
    # Create order with initial items if provided
    order = Order(
        table_id=table.id,
        user_id=current_user.id,
        status='pending',
        total_amount=0,  # Will be calculated from items
        payment_status='unpaid',
        notes=f"Party: {party.name} ({party.size} people)"
    )
    db.session.add(order)
    db.session.commit()
    
    # Add initial items if provided
    if data.get('initial_items'):
        for item_data in data['initial_items']:
            product = Product.query.get(item_data['product_id'])
            if product and product.available:
                order_item = OrderItem(
                    order_id=order.id,
                    product_id=product.id,
                    quantity=item_data.get('quantity', 1),
                    price=product.price,
                    notes=item_data.get('notes', '')
                )
                db.session.add(order_item)
        
        # Recalculate total
        order.total_amount = sum(item.price * item.quantity for item in order.items)
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Party seated successfully',
        'order_id': order.id,
        'total_amount': order.total_amount
    })

# Initialize database
@app.before_first_request
def create_tables():
    try:
        db.create_all()
        
        # Create admin user if none exists
        if not User.query.filter_by(role='admin').first():
            admin = User(
                username='admin',
                email='admin@restaurant.com',
                role='admin',
                active=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            print("Created admin user with username: admin, password: admin123")

        # Create sample reservations if none exist
        if Reservation.query.count() == 0 and User.query.count() > 0 and Table.query.count() > 0:
            reservations = [
                Reservation(
                    user_id=User.query.first().id,
                    name='John Doe',
                    email='john@example.com',
                    phone='555-1234',
                    date=datetime.utcnow().date() + timedelta(days=1),
                    time='19:00',
                    party_size=4,
                    table_id=Table.query.first().id,
                    status='confirmed',
                    notes='Window seat preferred'
                )
            ]
            db.session.bulk_save_objects(reservations)

        # Add to the create_tables function
        if Coupon.query.count() == 0:
            coupons = [
                Coupon(
                    code='WELCOME10',
                    discount_type='percent',
                    discount_value=10,
                    min_order=20,
                    valid_from=datetime.utcnow(),
                    valid_to=datetime.utcnow() + timedelta(days=30),
                ),
                Coupon(
                    code='FREESHIP',
                    discount_type='fixed',
                    discount_value=5,
                    min_order=25,
                    valid_from=datetime.utcnow(),
                    valid_to=datetime.utcnow() + timedelta(days=15)),
                Coupon(
                    code='SAVE20',
                    discount_type='percent',
                    discount_value=20,
                    min_order=50,
                    valid_from=datetime.utcnow(),
                    valid_to=datetime.utcnow() + timedelta(days=7))
            ]
            db.session.bulk_save_objects(coupons)
        
        # Create sample data if none exists
        if Group.query.count() == 0:
            groups = [
                Group(name='Managers', description='Store managers', permissions='{"all": true}'),
                Group(name='Staff', description='Regular staff members', permissions='{"orders": true}'),
                Group(name='Chefs', description='Kitchen staff', permissions='{"kitchen": true}')
            ]
            db.session.bulk_save_objects(groups)
        
        if Store.query.count() == 0:
            stores = [
                Store(name='Main Restaurant', address='123 Main St', phone='555-1234', email='main@restaurant.com', opening_hours='9AM-10PM'),
                Store(name='Downtown Branch', address='456 Downtown Ave', phone='555-5678', email='downtown@restaurant.com', opening_hours='10AM-11PM')
            ]
            db.session.bulk_save_objects(stores)
        
        if Table.query.count() == 0:
            tables = [
                Table(store_id=1, table_number='1', capacity=4, status='available'),
                Table(store_id=1, table_number='2', capacity=6, status='available'),
                Table(store_id=2, table_number='1', capacity=2, status='available'),
                Table(store_id=2, table_number='2', capacity=4, status='available')
            ]
            db.session.bulk_save_objects(tables)
        
        if Category.query.count() == 0:
            categories = [
                Category(name='Appetizers', description='Starters and small plates', active=True),
                Category(name='Main Courses', description='Main dishes', active=True),
                Category(name='Desserts', description='Sweet treats', active=True),
                Category(name='Drinks', description='Beverages', active=True)
            ]
            db.session.bulk_save_objects(categories)
        
        if Product.query.count() == 0:
            products = [
                Product(name='Bruschetta', description='Toasted bread with tomatoes', price=8.99, cost=3.50, category_id=1, available=True),
                Product(name='Caesar Salad', description='Romaine lettuce with dressing', price=10.99, cost=4.00, category_id=1, available=True),
                Product(name='Spaghetti Carbonara', description='Pasta with creamy sauce', price=14.99, cost=5.50, category_id=2, available=True),
                Product(name='Grilled Salmon', description='Fresh salmon with vegetables', price=18.99, cost=7.00, category_id=2, available=True),
                Product(name='Tiramisu', description='Italian dessert', price=7.99, cost=2.50, category_id=3, available=True),
                Product(name='Soda', description='Carbonated beverage', price=2.99, cost=0.50, category_id=4, available=True)
            ]
            db.session.bulk_save_objects(products)
        
        # Add this to the create_tables function
        if Waitlist.query.count() == 0:
            waitlist = [
                Waitlist(name='Anna Gutiérrez', size=4, phone='555-1234', notes='High chair needed'),
                Waitlist(name='Dorinel Atchison', size=2, phone='555-5678')
            ]
            db.session.bulk_save_objects(waitlist)
            db.session.commit()
        
        db.session.commit()
        print("Database initialized successfully")
    except Exception as e:
        db.session.rollback()
        print(f"Error initializing database: {str(e)}")

# Online Order API Endpoints
@app.route('/api/online/checkout', methods=['POST'])
def online_checkout():
    if not request.is_json:
        return jsonify({'success': False, 'message': 'Missing JSON in request'}), 400
    
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['items', 'subtotal', 'tax', 'total', 'payment_method']
    if not all(field in data for field in required_fields):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    
    # Validate items
    if not isinstance(data['items'], list) or len(data['items']) == 0:
        return jsonify({'success': False, 'message': 'Invalid items'}), 400
    
    # Generate order number
    order_number = f"ONL-{datetime.utcnow().strftime('%Y%m%d')}-{random.randint(1000, 9999)}"
    
    # Create order
    order = OnlineOrder(
        user_id=current_user.id if current_user.is_authenticated else None,
        order_number=order_number,
        items=json.dumps(data['items']),
        subtotal=data['subtotal'],
        tax=data['tax'],
        delivery_fee=data.get('delivery_fee', 0.0),
        discount=data.get('discount', 0.0),
        total=data['total'],
        delivery_address=data.get('delivery_address'),
        payment_method=data['payment_method'],
        status='pending',
        notes=data.get('notes', '')
    )
    
    db.session.add(order)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'order_id': order.id,
        'order_number': order.order_number,
        'message': 'Order placed successfully'
    }), 201

@app.route('/api/online/coupons/validate', methods=['POST'])
def validate_coupon():
    try:
        if not request.is_json:
            return jsonify({'success': False, 'message': 'Missing JSON in request'}), 400
        
        data = request.get_json()
        code = data.get('code', '').strip().upper()
        subtotal = float(data.get('subtotal', 0.0))
        
        coupon = Coupon.query.filter_by(code=code, active=True).first()
        
        if not coupon:
            return jsonify({'success': False, 'message': 'Invalid coupon code'}), 404
        
        # Validate coupon dates and usage
        now = datetime.utcnow()
        if now < coupon.valid_from or now > coupon.valid_to:
            return jsonify({'success': False, 'message': 'Coupon is not valid'}), 400
        
        if coupon.times_used >= coupon.max_uses:
            return jsonify({'success': False, 'message': 'Coupon has reached maximum uses'}), 400
        
        if subtotal < coupon.min_order:
            return jsonify({
                'success': False, 
                'message': f'Minimum order amount of ${coupon.min_order:.2f} required'
            }), 400
        
        # Calculate discount (always return positive value)
        if coupon.discount_type == 'percent':
            discount = subtotal * (coupon.discount_value / 100)
            if hasattr(coupon, 'max_discount') and coupon.max_discount:
                discount = min(discount, coupon.max_discount)
        else:
            discount = coupon.discount_value
        
        discount = round(discount, 2)
        
        return jsonify({
            'success': True,
            'discount': discount,  # Return positive value
            'discount_type': coupon.discount_type,
            'discount_value': coupon.discount_value,
            'message': 'Coupon applied successfully'
        })
        
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid subtotal value'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': 'An error occurred'}), 500

@app.route('/api/online/orders', methods=['GET'])
@login_required
def get_all_online_orders():
    try:
        # Get query parameters
        status = request.args.get('status')
        date = request.args.get('date')
        search = request.args.get('search')
        user_id = request.args.get('user_id')
        
        # Build query
        query = OnlineOrder.query
        
        # Filter by user if user_id parameter is provided
        if user_id:
            query = query.filter_by(user_id=user_id)
            
        if status:
            query = query.filter_by(status=status)
            
        if date:
            query = query.filter(
                db.func.date(OnlineOrder.created_at) == date
            )
            
        if search:
            search = f"%{search}%"
            query = query.filter(
                db.or_(
                    OnlineOrder.order_number.like(search),
                    OnlineOrder.delivery_address.like(search),
                    OnlineOrder.notes.like(search)
                )
            )
            
        orders = query.order_by(OnlineOrder.created_at.desc()).all()
        
        return jsonify([{
            'id': order.id,
            'order_number': order.order_number,
            'customer_name': order.user.username if order.user else 'Guest',
            'items': json.loads(order.items),
            'subtotal': order.subtotal,
            'tax': order.tax,
            'delivery_fee': order.delivery_fee,
            'discount': order.discount,
            'total': order.total,
            'payment_method': order.payment_method,
            'payment_status': order.payment_status if order.payment_status else 'unpaid',
            'status': order.status,
            'created_at': order.created_at.isoformat(),
            'delivery_address': order.delivery_address,
            'notes': order.notes
        } for order in orders])
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route('/api/online/orders/<int:order_id>', methods=['GET'])
@login_required
def get_online_order(order_id):
    order = OnlineOrder.query.get_or_404(order_id)
    
    return jsonify({
        'id': order.id,
        'order_number': order.order_number,
        'customer_name': order.user.username if order.user else 'Guest',
        'items': json.loads(order.items),
        'subtotal': order.subtotal,
        'tax': order.tax,
        'delivery_fee': order.delivery_fee,
        'discount': order.discount,
        'total': order.total,
        'payment_method': order.payment_method,
        'status': order.status,
        'created_at': order.created_at.isoformat(),
        'delivery_address': order.delivery_address,
        'notes': order.notes
    })

@app.route('/api/online/orders/<int:order_id>', methods=['PUT'])
@login_required
def update_online_order(order_id):
    order = OnlineOrder.query.get_or_404(order_id)
    
    data = request.get_json()
    
    # Validate status
    valid_statuses = ['pending', 'processing', 'completed', 'cancelled']
    if 'status' in data and data['status'] not in valid_statuses:
        return jsonify({'success': False, 'message': 'Invalid status'}), 400
    
    # Update fields
    if 'status' in data:
        order.status = data['status']
        # Update payment status based on order status
        if data['status'] == 'completed':
            order.payment_status = 'paid'
        elif data['status'] in ['pending', 'processing']:
            order.payment_status = 'unpaid'
        # For cancelled, leave as is (will be filtered out in reports)
            
    if 'notes' in data:
        order.notes = data['notes']
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Order updated successfully'
    })

@app.route('/api/online/orders/<int:order_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_online_order(order_id):
    order = OnlineOrder.query.get_or_404(order_id)
    
    try:
        db.session.delete(order)
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Order deleted successfully'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'Failed to delete order: {str(e)}'
        }), 500

@app.route('/api/reports/online-orders', methods=['GET'])
@login_required
def online_orders_report():
    # Get parameters
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    period = request.args.get('period', 'daily')
    status = request.args.get('status')
    payment_status = request.args.get('payment_status')
    
    # Validate dates
    try:
        if start_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            # Include the entire end date
            end_date_plus_1 = end_date + timedelta(days=1)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid date format (YYYY-MM-DD)'}), 400
    
    # Base query for online orders
    query = OnlineOrder.query
    
    # Apply status filter if provided
    if status:
        query = query.filter(OnlineOrder.status == status)
    
    # Apply payment status filter
    if payment_status:
        if payment_status == 'paid':
            # Consider completed orders as paid
            query = query.filter(
                (OnlineOrder.payment_status == 'paid') | 
                ((OnlineOrder.payment_status == None) & (OnlineOrder.status == 'completed'))
            )
        elif payment_status == 'unpaid':
            # Consider non-completed orders as unpaid
            query = query.filter(
                (OnlineOrder.payment_status == 'unpaid') | 
                ((OnlineOrder.payment_status == None) & (OnlineOrder.status != 'completed'))
            )
    
    # Apply date filters
    if start_date:
        query = query.filter(OnlineOrder.created_at >= start_date)
    if end_date:
        query = query.filter(OnlineOrder.created_at < end_date_plus_1)
    
    # Get orders
    orders = query.order_by(OnlineOrder.created_at).all()
    
    # Calculate report data
    total_sales = sum(order.total for order in orders) if orders else 0
    total_orders = len(orders)
    
    # Group data based on period
    chart_data = []
    if period == 'daily':
        sales_by_day = {}
        for order in orders:
            day = order.created_at.date()
            sales_by_day[day] = sales_by_day.get(day, 0) + order.total
        # Sort by date and format for chart
        for day in sorted(sales_by_day.keys()):
            chart_data.append({
                'date': day.strftime('%b %d, %Y'),
                'sales': sales_by_day[day]
            })
    
    elif period == 'weekly':
        sales_by_week = {}
        for order in orders:
            year = order.created_at.isocalendar()[0]
            week = order.created_at.isocalendar()[1]
            key = (year, week)
            sales_by_week[key] = sales_by_week.get(key, 0) + order.total
        # Sort by year and week number
        for (year, week) in sorted(sales_by_week.keys()):
            chart_data.append({
                'date': f"Week {week}, {year}",
                'sales': sales_by_week[(year, week)]
            })
    
    elif period == 'monthly':
        sales_by_month = {}
        for order in orders:
            key = (order.created_at.year, order.created_at.month)
            sales_by_month[key] = sales_by_month.get(key, 0) + order.total
        # Sort by year and month
        for (year, month) in sorted(sales_by_month.keys()):
            chart_data.append({
                'date': datetime(year, month, 1).strftime('%b %Y'),
                'sales': sales_by_month[(year, month)]
            })
    
    elif period == 'yearly':
        sales_by_year = {}
        for order in orders:
            key = order.created_at.year
            sales_by_year[key] = sales_by_year.get(key, 0) + order.total
        # Sort by year
        for year in sorted(sales_by_year.keys()):
            chart_data.append({
                'date': str(year),
                'sales': sales_by_year[year]
            })
    
    # Top products from online orders
    product_sales = {}
    for order in orders:
        items = json.loads(order.items)
        for item in items:
            product_id = item.get('product_id', 0)
            product_name = item.get('name', 'Unknown')
            quantity = item.get('quantity', 0)
            price = item.get('price', 0)
            
            product_sales[product_id] = product_sales.get(product_id, {
                'name': product_name,
                'quantity': 0,
                'revenue': 0
            })
            product_sales[product_id]['quantity'] += quantity
            product_sales[product_id]['revenue'] += price * quantity
    
    top_products = sorted(product_sales.values(), key=lambda x: x['revenue'], reverse=True)[:5]
    
    return jsonify({
        'success': True,
        'total_sales': float(total_sales),
        'total_orders': total_orders,
        'chart_data': chart_data,
        'top_products': top_products,
        'period': period
    })

# Error Handlers
@app.errorhandler(400)
def bad_request(error):
    if request.path.startswith('/api/'):
        return jsonify({
            'success': False, 
            'message': str(error.description) if error.description else 'Bad request',
            'errors': request.get_json()  # Include the received data
        }), 400
    return render_template('index.html')

@app.errorhandler(404)
def not_found(error):
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Resource not found'}), 404
    return render_template('index.html')

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Internal server error'}), 500
    return render_template('index.html')

def check_reservation_times():
    with app.app_context():
        now = datetime.utcnow()
        # Get tables with upcoming reservations
        tables = Table.query.filter(
            Table.reservation_time != None,
            Table.status.in_(['available', 'reserved'])
        ).all()
        
        for table in tables:
            time_until_reservation = (table.reservation_time - now).total_seconds()
            
            if time_until_reservation <= 1800:  # 30 minutes or less
                if table.status != 'reserved':
                    table.status = 'reserved'
            else:
                if table.status == 'reserved':
                    table.status = 'available'
            
            # If reservation time has passed (with 15 minute grace period)
            if time_until_reservation < -900:  # 15 minutes after reservation time
                table.status = 'available'
                table.reservation_time = None
        
        db.session.commit()

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=check_reservation_times, trigger="interval", minutes=5)
scheduler.start()

# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    app.run(debug=True)