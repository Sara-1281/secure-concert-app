from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///concert.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Initialize Flask-Talisman for security headers including clickjacking protection
Talisman(app, 
         force_https=False,  # Set to True in production
         frame_options='DENY',  # Prevents clickjacking
         frame_options_allow_from=None,
         strict_transport_security=True,
         strict_transport_security_preload=True,
         strict_transport_security_max_age=31536000,
         content_security_policy={
             'default-src': "'self'",
             'script-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com"],
             'style-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "fonts.googleapis.com"],
             'font-src': ["'self'", "fonts.gstatic.com"],
             'img-src': ["'self'", "data:", "https:"],
         })

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    tickets = db.relationship('Ticket', backref='user', lazy=True)

class Concert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    artist = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    venue = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Float, nullable=False)
    available_tickets = db.Column(db.Integer, nullable=False)
    tickets = db.relationship('Ticket', backref='concert', lazy=True)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    concert_id = db.Column(db.Integer, db.ForeignKey('concert.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    purchase_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    quantity = db.Column(db.Integer, nullable=False, default=1)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    concerts = Concert.query.all()
    return render_template('index.html', concerts=concerts)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit for login attempts
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            login_user(user)
            flash('Logged in successfully!')
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("3 per minute")  # Rate limit for signup attempts
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Password validation
        if not any(c.isupper() for c in password):
            flash('Password must contain at least one uppercase letter')
            return redirect(url_for('signup'))
        if not any(c.islower() for c in password):
            flash('Password must contain at least one lowercase letter')
            return redirect(url_for('signup'))
        if not any(c.isdigit() for c in password):
            flash('Password must contain at least one number')
            return redirect(url_for('signup'))
        if not any(c in '@$!%*?&' for c in password):
            flash('Password must contain at least one special character (@$!%*?&)')
            return redirect(url_for('signup'))
        if len(password) < 8:
            flash('Password must be at least 8 characters long')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('signup'))
            
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=False
        )
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! Please login.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    concerts = Concert.query.all()
    return render_template('admin.html', concerts=concerts)

@app.route('/add_concert', methods=['POST'])
@login_required
def add_concert():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    concert = Concert(
        title=request.form.get('title'),
        artist=request.form.get('artist'),
        date=datetime.strptime(request.form.get('date'), '%Y-%m-%dT%H:%M'),
        venue=request.form.get('venue'),
        price=float(request.form.get('price')),
        available_tickets=int(request.form.get('available_tickets', 100))
    )
    db.session.add(concert)
    db.session.commit()
    flash('Concert added successfully!')
    return redirect(url_for('admin'))

@app.route('/edit_concert/<int:id>', methods=['POST'])
@login_required
def edit_concert(id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    concert = Concert.query.get_or_404(id)
    concert.title = request.form.get('title')
    concert.artist = request.form.get('artist')
    concert.date = datetime.strptime(request.form.get('date'), '%Y-%m-%dT%H:%M')
    concert.venue = request.form.get('venue')
    concert.price = float(request.form.get('price'))
    concert.available_tickets = int(request.form.get('available_tickets'))
    
    db.session.commit()
    flash('Concert updated successfully!')
    return redirect(url_for('admin'))

@app.route('/delete_concert/<int:id>', methods=['POST'])
@login_required
def delete_concert(id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    
    concert = Concert.query.get_or_404(id)
    db.session.delete(concert)
    db.session.commit()
    flash('Concert deleted successfully!')
    return redirect(url_for('admin'))

@app.route('/book_ticket/<int:concert_id>', methods=['POST'])
@login_required
def book_ticket(concert_id):
    concert = Concert.query.get_or_404(concert_id)
    quantity = int(request.form.get('quantity', 1))
    
    if concert.available_tickets < quantity:
        flash('Not enough tickets available!')
        return redirect(url_for('index'))
    
    ticket = Ticket(
        concert_id=concert_id,
        user_id=current_user.id,
        quantity=quantity
    )
    concert.available_tickets -= quantity
    
    db.session.add(ticket)
    db.session.commit()
    flash('Ticket booked successfully!')
    return redirect(url_for('my_tickets'))

@app.route('/my_tickets')
@login_required
def my_tickets():
    tickets = Ticket.query.filter_by(user_id=current_user.id).all()
    return render_template('my_tickets.html', tickets=tickets)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # In a real application, you would:
            # 1. Generate a secure reset token
            # 2. Send a password reset email to the user
            # 3. Create a reset password page
            # For now, we'll just show a success message
            flash('If an account exists with this email, you will receive password reset instructions.')
        else:
            # We show the same message even if the email doesn't exist
            # This prevents email enumeration attacks
            flash('If an account exists with this email, you will receive password reset instructions.')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.drop_all()  # This will clear any existing tables
        db.create_all()  # This will create all the tables
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully!")
            print("Username: admin")
            print("Password: admin123")
    
    app.run(debug=True)
