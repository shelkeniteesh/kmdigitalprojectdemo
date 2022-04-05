# Reference :: https://www.digitalocean.com/community/tutorials/how-to-add-authentication-to-your-app-with-flask-login

from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user
from . import db
from .models import User
auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login'))
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))
@auth.route('/signup')
def signup():
    return render_template('signup.html')

@auth.route('/signup', methods=['POST'])
def signup_post():
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    user = User.query.filter_by(email=email).first()

    from .validation import emailValidation, nameValidation, passwordValidation
    validEmail = emailValidation(email)
    validName  = nameValidation(name)
    validPassword = passwordValidation(password)
    if user:
        flash('This email is already registered!') 
        return redirect(url_for('auth.signup'))
    elif not (validEmail and validName and validPassword):
        if not validEmail:
            flash('Invalid email!')
        if not validName:
            flash('Username should consist of alphabets only!')
        if not validPassword:
            flash('Password should be at least 8 characters long!\nShould contain at least { 1 numeric[0-9], 1 uppercase[A-Z], 1 lowercase[a-z], 1 special character[!,@,#,$,%,^,&,*] }.')
        return redirect(url_for('auth.signup'))
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))