import os

from flask import Flask, session, render_template, request, redirect, url_for
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from hashlib import sha224
from wtforms import Form, StringField, PasswordField, TextAreaField, validators, BooleanField
from wtforms.validators import InputRequired, Email, Length, AnyOf

app = Flask(__name__)

# Check for environment variable
if not os.getenv("DATABASE_URL"):
	raise RuntimeError("DATABASE_URL is not set")

# Configure session to use filesystem
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Set up database
engine = create_engine(os.getenv("DATABASE_URL"))
# engine = create_engine("postgresql://postgres:8696@localhost:5432/bookdb")
db = scoped_session(sessionmaker(bind=engine))


class RegistrationForm(Form):
	username = StringField('Username', [validators.Length(min=3, max=25)])
	email = StringField('Email Address', [validators.Length(min=4, max=35)])
	password = PasswordField('New Password', [
		validators.DataRequired(),
		validators.EqualTo('confirm', message='Passwords must match')
	])
	confirm = PasswordField('Repeat Password')


def get_hash(pw):
	return sha224(pw.encode("utf-8")).hexdigest()


def get_login(username: str, password: str) -> str:
	hashpassword = get_hash(password)
	print("password = :password", {"password": password})
	print("hash = :hash", {"hash": hash})
	try:
		user_login_results = db.execute(
			"SELECT id FROM user_login where username = :username AND userpassword = :password",
			{"username": username, "password": hashpassword})
		print("ROOOW")

	except Exception as e:
		return None
	row = user_login_results.fetchone()
	if not row:
		print(f"No id returned, user {username} not present in the DB")
		return None
	print(f"Id from user login = {row[0]}")
	return row[0]


def get_username():
	username = session.get("username")
	if username is None:
		return None
	return username


def clean_user():
	session.pop("username", None)


def create_user(username, password, email):
	# not needed to check if the user exists in the DB because it's checked in "register" service.
	hashpassword = get_hash(password)

	print(f"CREATE_USER: creating {email} in the DB")
	db.execute("INSERT INTO user_login (username, userpassword, email) VALUES (:username, :userpassword, :email)" ,
			   {"username":username, "userpassword":hashpassword, "email":email})
	db.commit()
	return


@app.route("/")
def index():
	username = session.get("username")
	print("Username = :username", {"username": username})
	# if username:
	return render_template("index.html", username=username)


@app.route("/login", methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		username = request.form.get("username")
		password = request.form.get("password")
		user_login = get_login(username, password)
		if not user_login:
			error = "User not found in DB. Please check name and password, or Register first."

			return render_template("login.html", username=username, error=error)
		else:
			session["username"] = username
			print(f"User {username} successfully logged in")
			return redirect(url_for("index"))
	else:
		return render_template("login.html")


@app.route("/logout")
def logout():
	clean_user()
	return redirect(url_for("index"))


@app.route("/register", methods=['GET', 'POST'])
def register():
	form = RegistrationForm(request.form)
	if request.method == 'POST' and form.validate():
		username = request.form.get("username")
		password = request.form.get("password")

		email = request.form.get("email")
		user_login = get_login(username, password)
		if not user_login:
			create_user(username, password, email)
		else:
			error = "eeerrrooorr"
			print(f"REGISTER: user {username} already exists in the DB. Login instead")
			form.errors[0]="The user already exists. Login instead"
			print(form.errors)
			render_template("register.html", form=form)

	return render_template("register.html", form=form)
