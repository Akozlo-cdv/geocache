import flask_login
import uuid
from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
import requests
import simplejson as json
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'admin'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(20), nullable=False)


class Cache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    creator = db.Column(db.String(20), nullable=False)
    X_Cord = db.Column(db.Float, nullable=False)
    Y_Cord = db.Column(db.Float, nullable=False)
    Comment = db.Column(db.String(500), nullable=True)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"Placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"Placeholder": "Password"})
    submit = SubmitField("Register")

    def check_if_user_exists(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError("User already exists")


class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"Placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"Placeholder": "Password"})
    submit = SubmitField("Login")


class CacheForm(FlaskForm):
    X_Cord = StringField(validators=[InputRequired()], render_kw={"Placeholder": "X:"})
    Y_Cord = StringField(validators=[InputRequired()], render_kw={"Placeholder": "Y:"})
    Comment = StringField(validators=[InputRequired(), Length(min=0, max=300)], render_kw={"Placeholder": "Comment:"})
    submit = SubmitField("Add Cache")


class FindCacheFormByUser(FlaskForm):
    username = StringField(validators=[InputRequired()], render_kw={"Placeholder": "ID: "})
    submit = SubmitField("Find Cache")


@app.route('/home')
def main():
    return render_template('main.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('main'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/add_cache', methods=['GET', 'POST'])
@login_required
def addCache():
    form = CacheForm()
    if form.validate_on_submit():

        new_cache = Cache(X_Cord=form.X_Cord.data, Y_Cord=form.Y_Cord.data,
                          Comment=form.Comment.data, creator=flask_login.current_user.username)
        db.session.add(new_cache)
        db.session.commit()
        return redirect(url_for('addCache'))

    return render_template('addCache.html', form=form)

@app.route('/find_cache', methods=['GET', 'POST'])
@login_required
def findCache():
    form = CacheForm()
    if form.validate_on_submit():
        db.session.commit()

    return render_template('addCache.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        password_hashed = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=password_hashed)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# new_cache = Cache(creator=flask_login.current_user, X_Cord=form.X_Cord.data, Y_Cord=form.Y_Cord.data,
#                  Comment=form.Comment.data)
