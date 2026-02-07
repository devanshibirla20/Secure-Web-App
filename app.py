import os
import bleach
import logging
from datetime import timedelta

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, Regexp

from werkzeug.security import generate_password_hash, check_password_hash

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


#APP SETUP

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

app.config.update(
    SECRET_KEY="super-secret-key-change-this",  # fixed key
    SQLALCHEMY_DATABASE_URI="sqlite:///database.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,

    SESSION_COOKIE_SECURE=False,  # local dev ke liye False
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",

    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

#Security headers
Talisman(app, content_security_policy=None)

#Logging
logging.basicConfig(level=logging.INFO)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200/day", "50/hour"]
)

#MODEL

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)

    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="user")

    failed_logins = db.Column(db.Integer, default=0)
    locked = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

#FORMS 

class RegistrationForm(FlaskForm):
    username = StringField("Username",
        validators=[DataRequired(), Length(min=3, max=150)])

    email = StringField("Email",
        validators=[DataRequired(), Email()])

    password = PasswordField("Password",
        validators=[
            DataRequired(),
            Length(min=8),
            Regexp(
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).+$',
                message="Weak password"
            )
        ])

    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    email = StringField("Email",
        validators=[DataRequired(), Email()])
    password = PasswordField("Password",
        validators=[DataRequired()])
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")


with app.app_context():
    db.drop_all() 
    db.create_all()


def sanitize_input(text):
    return bleach.clean(text.strip(), strip=True)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Login required", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        email = sanitize_input(form.email.data).lower()
        password = form.password.data

        existing = User.query.filter(
            (User.email == email) | (User.username == username)
        ).first()

        if existing:
            flash("User exists", "danger")
            return redirect(url_for("register"))

        user = User(username=username, email=email)
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        flash("Registration successful", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = sanitize_input(form.email.data).lower()
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if user and user.locked:
            flash("Account locked", "danger")
            return redirect(url_for("login"))

        if user and user.check_password(password):
            user.failed_logins = 0
            db.session.commit()

            session.clear()
            session["user_id"] = user.id
            session["role"] = user.role

            if form.remember.data:
                session.permanent = True

            flash("Login successful", "success")
            return redirect(url_for("dashboard"))

        if user:
            user.failed_logins += 1
            if user.failed_logins >= 5:
                user.locked = True
            db.session.commit()

        flash("Invalid credentials", "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = db.session.get(User, session["user_id"])

    if not user:
        session.clear()
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        user=user,
        is_admin=session.get("role") == "admin"
    )


@app.errorhandler(429)
def ratelimit_error(e):
    return "Too many requests", 429


if __name__ == "__main__":
    app.run(debug=True)
