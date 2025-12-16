import spacy
import pandas as pd

# Load spaCy English model
nlp = spacy.load("en_core_web_sm")

# Load valid skills from CSV
job_data = pd.read_csv("templates/static/data/skills_job_roles.csv", encoding='utf-8-sig')

# Build valid skill list
valid_skills = set()

for _, row in job_data.iterrows():
    skills = row.get("Skills", "")

    # Skip NaN or non-string values
    if not isinstance(skills, str):
        continue

    # Add each skill after splitting
    for skill in skills.split(","):
        skill = skill.strip().lower()
        if skill:
            valid_skills.add(skill)


# -------------------------------------------------------------------
# 1️⃣ Extract skills using spaCy
# -------------------------------------------------------------------
def extract_skills_from_text(text):
    doc = nlp(text.lower())
    extracted = set()

    # Single-word skill match
    for token in doc:
        if token.is_stop or token.is_punct or len(token.text) < 2:
            continue
        lemma = token.lemma_.strip()
        if lemma in valid_skills:
            extracted.add(lemma.capitalize())

    # Multi-word skill match
    for chunk in doc.noun_chunks:
        phrase = chunk.text.lower().strip()
        if phrase in valid_skills:
            extracted.add(phrase.capitalize())

    return sorted(extracted)


# -------------------------------------------------------------------
# 2️⃣ Analyze skill gap
# -------------------------------------------------------------------
def analyze_gap(resume_skills, job_skills):
    resume_set = {skill.lower() for skill in resume_skills}
    required_set = {s.strip().lower() for s in job_skills.split(",")}

    matched = list(resume_set & required_set)
    missing = list(required_set - resume_set)

    return matched, missing


# -------------------------------------------------------------------
# 3️⃣ Suggest top 3 roles based on skill match
# -------------------------------------------------------------------
def suggest_roles(resume_skills):
    resume_set = {skill.lower() for skill in resume_skills}
    role_scores = []

    for _, row in job_data.iterrows():
        role = row.get("Role", "")
        skills = row.get("Skills", "")

        if not isinstance(skills, str):
            continue

        required_set = {s.strip().lower() for s in skills.split(",")}

        matched_count = len(resume_set & required_set)

        role_scores.append((role, matched_count))

    # Sort based on matched skills
    top_roles = sorted(role_scores, key=lambda x: x[1], reverse=True)[:3]

    return [role for role, score in top_roles]
