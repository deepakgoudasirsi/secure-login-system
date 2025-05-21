from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
import bcrypt
import pyotp
import os
from datetime import datetime, timedelta
from captcha.image import ImageCaptcha
import random
import string
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASSWORD')

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    otp_secret = db.Column(db.String(32))
    is_verified = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    captcha = StringField('Captcha', validators=[DataRequired()])
    submit = SubmitField('Login')

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
        otp_secret = pyotp.random_base32()
        
        user = User(
            email=form.email.data,
            password=hashed_password.decode('utf-8'),
            otp_secret=otp_secret
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Send verification email
        send_verification_email(user)
        
        flash('Registration successful! Please check your email for verification.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.password.encode('utf-8')):
            if not user.is_verified:
                flash('Please verify your email first.', 'warning')
                return redirect(url_for('login'))
            
            if form.captcha.data != session.get('captcha'):
                flash('Invalid CAPTCHA. Please try again.', 'error')
                return redirect(url_for('login'))
            
            # Check for too many failed attempts
            if user.failed_login_attempts >= 3:
                if user.last_failed_login and datetime.utcnow() - user.last_failed_login < timedelta(minutes=15):
                    flash('Too many failed attempts. Please try again in 15 minutes.', 'error')
                    return redirect(url_for('login'))
                else:
                    user.failed_login_attempts = 0
            
            # Generate and send OTP
            otp = pyotp.TOTP(user.otp_secret).now()
            send_otp_email(user.email, otp)
            
            session['temp_user_id'] = user.id
            return redirect(url_for('verify_otp'))
        
        if user:
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.utcnow()
            db.session.commit()
        
        flash('Invalid email or password.', 'error')
    
    # Generate new CAPTCHA
    captcha_text = generate_captcha()
    session['captcha'] = captcha_text
    
    return render_template('login.html', form=form, captcha_text=captcha_text)

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp = request.form.get('otp')
        user = User.query.get(session['temp_user_id'])
        
        if pyotp.TOTP(user.otp_secret).verify(otp):
            login_user(user)
            user.failed_login_attempts = 0
            db.session.commit()
            session.pop('temp_user_id', None)
            return redirect(url_for('dashboard'))
        
        flash('Invalid OTP. Please try again.', 'error')
    
    return render_template('verify_otp.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    user = User.query.filter_by(email=token).first()
    if user:
        user.is_verified = True
        db.session.commit()
        flash('Email verified successfully! You can now login.', 'success')
    else:
        flash('Invalid verification link.', 'error')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Helper functions
def send_verification_email(user):
    msg = Message('Verify Your Email',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[user.email])
    msg.body = f'Please click the following link to verify your email: {url_for("verify_email", token=user.email, _external=True)}'
    mail.send(msg)

def send_otp_email(email, otp):
    msg = Message('Your OTP Code',
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])
    msg.body = f'Your OTP code is: {otp}'
    mail.send(msg)

def generate_captcha():
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(6))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 