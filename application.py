import os

from flask import Flask, session, render_template, request, redirect, url_for
from flask_session import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from hashlib import sha224
# from flask_login import LoginManager
# from flask_login import current_user

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

def get_hash(pw):
    return sha224(pw.encode("utf-8")).hexdigest()

def get_login(username, password):
	hash = get_hash(password)
	print ("password = :password", {"password":password})
	print ("hash = :hash", {"hash":hash})
	try:
		# user_login_results = db.execute("SELECT id FROM user_login where username = :username AND userpassword = :passwordhash", {"username": username, "passwordhash":hash})
		user_login_results = db.execute("SELECT id FROM user_login where username = :username AND userpassword = :password", {"username": username, "password":password})
		print ("ROOOW")
		
	except Exception as e:
		return None
	row = user_login_results.fetchone()
	if not row:
		print ("No id returned, user :user not present in the DB", {"user":username})
		return None
	print ("Id from user login = :row", {"row":row[0]})
	return row[0]

def get_username():
	username = session.get("username")
	if username is None:
		return None
	return username

def clean_user():
	session.pop("username", None)
	
@app.route("/a")
def a():
	flights = db.execute("SELECT * FROM user_login").fetchall()
	print(flights)
	return render_template("index.html", username=username)

	
@app.route("/")
def index():
	username = session.get("username")
	print("Username = :username", {"username":username})
	# if username:
	return render_template("index.html", username=username)
	# else:
		# return render_template("index.html")

	
@app.route("/login", methods = ['GET', 'POST'])
def login():
	error = None
	
	if request.method == 'POST':
		username = request.form.get("username")
		password = request.form.get("password")
		user_login = get_login(username, password)
		if not user_login:
			error = "User not found in DB. Please check name and password, or Register first."
			
			return render_template("login.html", username=username, error=error)
		else:
			session["username"] = username
			return redirect(url_for("index"))
	else:
		return render_template("login.html")

@app.route("/logout")
def logout():
	clean_user()
	return redirect(url_for("index"))
	
@app.route("/register")
def register():
	return render_template("register.html")
