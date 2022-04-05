from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin

from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user

from flask import Blueprint, render_template
from flask_login import login_required, current_user

from re import fullmatch, search

db = SQLAlchemy()
app = Flask(__name__)

app.config['SECRET_KEY'] = '\xe9b\xf3-\x81\xc7)9(\x02pG\x9b\x98\x0ed'

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://tbfqkeix:UFgWc4ZFb5pX1iO_8OWvVt6fbRCii7sS@ruby.db.elephantsql.com/tbfqkeix"

db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)

from flask_login import UserMixin
from app import db

def emailValidation(email):
    regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return fullmatch(regex, email)

def nameValidation(name):
    regex = r'[A-Za-z]{2,25}( [A-Za-z]{2,25})?'
    return len(name) <= 30 and fullmatch(regex, name)

def passwordValidation(password):
    regex = r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$'
    return fullmatch(regex, password)

class User(UserMixin, db.Model):
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

main = Blueprint('main', __name__)


@main.route('/')
def index():
    return render_template('index.html')


@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.name)

app.register_blueprint(auth)
app.register_blueprint(main)

if __name__ == '__main__':
    app.run(debug=True)
