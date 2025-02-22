from flask import Blueprint, render_template, redirect, url_for, flash, request
from app import db, login_manager, bcrypt
from flask_login import login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email
from app.models import User

# Create Blueprint
auth_bp = Blueprint('auth', __name__)

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Registration Form
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    submit = SubmitField('Register')

# Login Form
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

# Home Route
@auth_bp.route("/")
def home():
    return render_template("index.html")

# Register Route
@auth_bp.route("/register", methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account Created! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    return render_template("register.html", form=form)

# Login Route
@auth_bp.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('auth.home'))
        else:
            flash('Invalid Credentials', 'danger')
    return render_template("login.html", form=form)

# Logout Route
@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.home'))
