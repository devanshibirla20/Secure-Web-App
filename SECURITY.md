Security Design Explanation

This project is designed with multiple layers of security to protect user data and prevent common web attacks.

Authentication & Authorization
- Secure login and registration system
- Role-based access (Admin/User)
- Password hashing using Werkzeug

Input Security
- Input validation using Flask-WTF
- XSS sanitization using Bleach
- SQL Injection prevention via SQLAlchemy ORM

Session Security
- Secure cookies (HttpOnly, Secure, SameSite)
- Auto session timeout
- Session clearing on logout

Threat Protection
- CSRF protection
- Rate limiting to prevent brute-force attacks
- HTTPS enforcement

This layered approach ensures secure handling of user data and protects against common web vulnerabilities.
