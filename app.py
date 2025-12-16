from flask import Flask, render_template, request, redirect, url_for, session, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
import os
import fitz  # PyMuPDF for PDF
import docx
import spacy
import pandas as pd
from datetime import datetime

import pandas as pd




df = pd.read_csv("templates/static/data/skills_job_roles.csv", encoding='utf-8-sig')
print(df.columns)



# ----------------------------------------------------------------------
# Flask Setup
# ----------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = "your_secret_key"

# ----------------------------------------------------------------------
# MongoDB Setup
# ----------------------------------------------------------------------
client = MongoClient("mongodb://localhost:27017/")
db = client["career_predictor"]
users_collection = db["users"]
logs_collection = db["analysis_logs"]

# ----------------------------------------------------------------------
# File Upload Setup
# ----------------------------------------------------------------------
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {"pdf", "docx", "png", "jpg", "jpeg"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ----------------------------------------------------------------------
# spaCy Model + Skills CSV Load
# ----------------------------------------------------------------------
nlp = spacy.load("en_core_web_sm")

job_data = pd.read_csv("templates/static/data/skills_job_roles.csv", encoding='utf-8-sig')

valid_skills = set()
for _, row in job_data.iterrows():
    skills = row.get("Skills", "")
    if isinstance(skills, str):
        for skill in skills.split(","):
            valid_skills.add(skill.strip().lower())

# ----------------------------------------------------------------------
# Helper Functions
# ----------------------------------------------------------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def extract_text_from_pdf(filepath):
    text = ""
    pdf = fitz.open(filepath)
    for page in pdf:
        text += page.get_text()
    return text


def extract_text_from_docx(filepath):
    doc = docx.Document(filepath)
    return "\n".join([p.text for p in doc.paragraphs])


def extract_text_from_image(filepath):
    return " "   # Placeholder – Add OCR later


# ----------------------------------------------------------------------
# spaCy Skill Extraction
# ----------------------------------------------------------------------
def extract_skills_from_text(text):
    doc = nlp(text.lower())
    extracted = set()

    # Single-word skills
    for token in doc:
        if token.is_stop or token.is_punct:
            continue
        lemma = token.lemma_.strip()
        if lemma in valid_skills:
            extracted.add(lemma.capitalize())

    # Multi-word skills
    for chunk in doc.noun_chunks:
        phrase = chunk.text.lower().strip()
        if phrase in valid_skills:
            extracted.add(phrase.capitalize())

    return sorted(extracted)


def analyze_gap(resume_skills, job_skills):
    resume_set = {s.lower() for s in resume_skills}
    required_set = {s.strip().lower() for s in job_skills.split(",")}

    matched = list(resume_set & required_set)
    missing = list(required_set - resume_set)

    return matched, missing


def suggest_roles(resume_skills):
    resume_set = {s.lower() for s in resume_skills}
    scores = []

    for _, row in job_data.iterrows():  # job_data is your DataFrame
        job_role = str(row["Role"]).strip()   # use exact column name
        skills = row["Skills"]

        if pd.isna(skills):
            continue  # skip empty skills

        required = {s.strip().lower() for s in skills.split(",")}
        score = len(resume_set & required)
        scores.append((job_role, score))

    top = sorted(scores, key=lambda x: x[1], reverse=True)[:3]
    return [r for r, s in top]



# ----------------------------------------------------------------------
# ROUTES
# ----------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")


# ----------------------------------------------------------------------
# LOGIN (email + hashed password)
# ----------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        pwd = request.form.get("password")

        if not email or not pwd:
            return "Email or Password missing!"

        user = users_collection.find_one({"email": email})

        if user and check_password_hash(user["password"], pwd):
            session["username"] = user["username"]
            session["email"] = user["email"]
            session["role"] = user.get("role", "user")

            if session["role"] == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("dashboard"))

        return "Invalid email or password!"

    return render_template("login.html")


# ----------------------------------------------------------------------
# REGISTER (username + email + hashed password)
# ----------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        uname = request.form.get("username")
        email = request.form.get("email")
        pwd = request.form.get("password")

        if users_collection.find_one({"email": email}):
            return "Email already registered!"

        hashed_pw = generate_password_hash(pwd)

        users_collection.insert_one({
            "username": uname,
            "email": email,
            "password": hashed_pw,
            "role": "user"
        })

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("user_dashboard.html", username=session["username"])


@app.route("/admin_dashboard")
def admin_dashboard():
    return render_template("admin_dashboard.html")


# ----------------------------------------------------------------------
# ANALYZE ROUTE
# ----------------------------------------------------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    if "username" not in session:
        return redirect(url_for("login"))

    if "resume" not in request.files:
        return "No file uploaded!"

    file = request.files["resume"]

    if file.filename == "":
        return "File not selected!"

    if not allowed_file(file.filename):
        return "Invalid file type!"

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    ext = filename.rsplit(".", 1)[1].lower()

    if ext == "pdf":
        text = extract_text_from_pdf(filepath)
    elif ext == "docx":
        text = extract_text_from_docx(filepath)
    else:
        text = extract_text_from_image(filepath)

    extracted_skills = extract_skills_from_text(text)

    dream_job = request.form.get("dream_job", "")
    job_row = job_data[job_data["Role"] == dream_job]

    if job_row.empty:
        matched = []
        missing = []
    else:
        job_skills = job_row.iloc[0]["Skills"]
        matched, missing = analyze_gap(extracted_skills, job_skills)

    suggested_roles = suggest_roles(extracted_skills)

    logs_collection.insert_one({
        "username": session["username"],
        "dream_job": dream_job,
        "skills": extracted_skills,
        "matched": matched,
        "missing": missing,
        "timestamp": datetime.now()
    })

    return render_template(
        "analyze.html",
        filename=filename,
        extracted_skills=extracted_skills,
        matched=matched,
        missing=missing,
        suggested_roles=suggested_roles,
        dream_job=dream_job
    )
    
def suggest_roles(extracted_skills):
    roles = []

    for _, row in job_roles_df.iterrows():
        job_role = str(row["Job Role"]).strip()

        skills = row["Skills"]

        if isinstance(skills, float) or skills is None:
            continue  # skip bad/empty rows

        required_skills = {s.strip().lower() for s in skills.split(",") if s.strip()}

        matched = required_skills.intersection({s.lower() for s in extracted_skills})

        match_percentage = (len(matched) / len(required_skills)) * 100 if required_skills else 0

        roles.append({
            "job_role": job_role,
            "match_percentage": round(match_percentage, 2),
            "matched_skills": list(matched),
            "missing_skills": list(required_skills - set(matched))
        })

    # Sort by highest match %
    roles = sorted(roles, key=lambda x: x["match_percentage"], reverse=True)
    return roles

@app.route('/admin/add-skills', methods=['POST'])
def add_skills():
    if session.get('role') != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    file = request.files.get('csv_file')

    if not file or not file.filename.endswith('.csv'):
        flash("Please upload a valid CSV file.", "danger")
        return redirect(url_for('manage_skills'))

    try:
        # Read uploaded CSV
        df = pd.read_csv(file)

        # Validate required columns
        if 'Role' not in df.columns or 'Skills' not in df.columns:
            flash("CSV must contain 'Role' and 'Skills' columns.", "danger")
            return redirect(url_for('manage_skills'))

        # Save dataset (overwrite or update)
        df.to_csv(
            "templates/static/data/skills_job_roles.csv",
            index=False,
            encoding='utf-8-sig'
        )

        flash("Skill dataset uploaded and updated successfully!", "success")

    except Exception as e:
        flash(f"Error processing file: {str(e)}", "danger")

    return redirect(url_for('admin_dashboard'))




# ----------------------------------------------------------------------
# LOGOUT
# ----------------------------------------------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/about")
def about():
    return render_template("about.html")


# ----------------------------------------------------------------------
# RUN APP
# ----------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
