# Secure Login System

A secure authentication system built with Python, Flask, and SQL that implements multiple layers of security including password hashing, CAPTCHA, OTP, and email verification.

## Features

- Secure password hashing using bcrypt
- Email verification for new accounts
- CAPTCHA protection against automated attacks
- OTP (One-Time Password) authentication
- Protection against brute force attacks
- SQLite database for user management
- Modern and responsive UI using Bootstrap

## Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd secure-login-system
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file in the root directory with the following content:
```
SECRET_KEY=your-secret-key-here
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-specific-password
```

Note: For Gmail, you'll need to use an App Password. You can generate one by:
1. Going to your Google Account settings
2. Enabling 2-Step Verification if not already enabled
3. Going to Security → App passwords
4. Generating a new app password for "Mail"

## Running the Application

1. Make sure your virtual environment is activated
2. Run the Flask application:
```bash
python app.py
```

3. Open your web browser and navigate to `http://localhost:5000`

## Security Features

1. **Password Security**
   - Passwords are hashed using bcrypt
   - Minimum password length requirement
   - Password confirmation during registration

2. **Email Verification**
   - New accounts require email verification
   - Verification links are sent via email
   - Accounts remain unverified until email is confirmed

3. **CAPTCHA Protection**
   - Prevents automated login attempts
   - Simple text-based CAPTCHA implementation

4. **OTP Authentication**
   - Two-factor authentication using TOTP
   - OTP codes are sent via email
   - Time-based OTP validation

5. **Brute Force Protection**
   - Account lockout after 3 failed attempts
   - 15-minute cooldown period
   - Failed attempt tracking

## Project Structure

```
secure-login-system/
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── .env               # Environment variables (create from .env.example)
├── templates/         # HTML templates
│   ├── base.html
│   ├── home.html
│   ├── login.html
│   ├── register.html
│   ├── verify_otp.html
│   └── dashboard.html
└── instance/         # Database files (created automatically)
    └── users.db
```

## Contributing

Feel free to submit issues and enhancement requests! 