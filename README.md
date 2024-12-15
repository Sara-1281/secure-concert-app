# Concert Management System

A web-based concert management system built with Flask that allows users to book concert tickets and administrators to manage concerts.

## Features

- User Authentication (Login/Signup)
- Password Recovery
- Role-based Access Control (Admin/User)
- Concert Management (Create, Edit, Delete)
- Ticket Booking System
- Security Features:
  - Password Policy
  - Rate Limiting
  - Clickjacking Protection
  - Content Security Policy

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/concert-management.git
cd concert-management
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Default Admin Account
- Username: admin
- Password: admin123

## Technologies Used

- Flask
- SQLAlchemy
- Flask-Login
- Flask-WTF
- Flask-Limiter
- Flask-Talisman
- Bootstrap 5
- SQLite

## Security Features

- Strong password policy enforcement
- Rate limiting on login and signup attempts
- Protection against clickjacking attacks
- Content Security Policy implementation
- CSRF protection
- Secure password hashing

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)
