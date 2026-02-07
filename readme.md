Secure Web Application & Threat Hardening

A Flask-based secure web application built to demonstrate cybersecurity best practices including secure authentication, authorization, session protection, and threat mitigation.

This project showcases practical implementation of secure web development concepts and is ideal for cybersecurity learning and portfolio demonstration.

-------------------------------------

Features

Authentication & Authorization
• User registration and login system  
• Role-based access control (Admin/User)  
• Secure password hashing using Werkzeug  
• Strong password policy enforcement  

Security Protections
• CSRF protection using Flask-WTF  
• Rate limiting to prevent brute-force attacks  
• Input validation and XSS sanitization  
• SQL injection prevention via SQLAlchemy ORM  
• Secure session cookies (HttpOnly, Secure, SameSite)  
• Automatic session timeout (inactivity logout)  
• HTTPS redirection support  

Database
• SQLite database  
• Parameterized queries via ORM  
• Unique constraints on username and email  
