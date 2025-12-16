from werkzeug.security import generate_password_hash
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["career_path_db"]
users = db["users"]

# Remove existing admin (optional)
users.delete_many({"email": "admin01@example.com"})

# Generate hashed password
hashed_password = generate_password_hash("admin123")

# Insert new admin
users.insert_one({
    "name": "Admin01",
    "email": "admin01@example.com",
    "password": hashed_password,
    "role": "admin"
})

print("✅ Admin user created successfully!")
