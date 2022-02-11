from cs50 import SQL
from flask import *
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from firebase import firebase

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# connecting firebase
firebase = firebase.FirebaseApplication('https://social-fitness-86ac8-default-rtdb.firebaseio.com/', None)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///fitness.db")


@app.route("/login", methods=["GET", "POST"])
def login():

    # Forget any user_id
    session.clear()

    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)
        
        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)
        
        # Ensure password matches confirmation
        elif not confirmation:
            return apology("must confirm password", 403)
        
        # Query database for username, should only yield one row
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        # Ensure that username does not match another
        if rows:
            return apology("username already exists", 403)
        
        # Ensure that password equals confirmation
        if password != confirmation:
            return apology("passwords do not match", 403)

        password_hash = generate_password_hash(password)

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, password_hash)
        return render_template("login.html")
    
    # Pedantic/unnecessary but for clarity
    elif request.method == "GET":
        return render_template("register.html")

@app.route("/")
@login_required
def index():
    user_id = firebase.get('/user_id', None)
    return render_template("index.html", users = user_id)

@app.route("/groups")
@login_required
def groups():
    return render_template("groups.html")

@app.route("/join")
@login_required
def join():
    return render_template("join.html")

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)