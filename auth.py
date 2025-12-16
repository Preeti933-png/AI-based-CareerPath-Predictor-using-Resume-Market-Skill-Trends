from flask import Blueprint, request, render_template, redirect, url_for, session, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash

# Setup MongoDB connection
client = MongoClient("mongodb://localhost:27017/")
db = client["career_path_db"]
users_collection = db["users"]
admins_collection = db["admins"]

# Blueprint for auth routes
auth_bp = Blueprint('auth', __name__)

# flash("Login successful!", "success")
# flash("Invalid credentials", "danger")


from functools import wraps
from flask import abort

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function


# Show login page
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient

auth_bp = Blueprint('auth', __name__)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["career_path_db"]
users_collection = db["users"]
admins_collection = db["admins"]

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if user exists
        user = users_collection.find_one({"email": email, "password": password})
        admin = admins_collection.find_one({"email": email, "password": password})

        if user:
            session['username'] = user['username']
            session['role'] = 'user'
            flash("Login successful!", "success")
            return redirect(url_for('index'))

        elif admin:
            session['username'] = admin['username']
            session['role'] = 'admin'
            flash("Admin login successful!", "success")
            return redirect(url_for('index'))

        else:
            flash("Invalid credentials!", "danger")
            return redirect(url_for('auth.login'))

    return render_template('login.html')


# Show registration page
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = generate_password_hash(request.form.get("password"))
        role = request.form.get("role")

        collection = users_collection if role == "user" else admins_collection

        if collection.find_one({"email": email}):
            flash("Email already exists", "warning")
            return redirect(url_for("auth.register"))

        collection.insert_one({
            "username": username,
            "email": email,
            "password": password,
            "role": role
        })
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("auth.login"))
    return render_template("register.html")

@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out!", "info")
    return redirect(url_for("auth.login"))
