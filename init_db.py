from pymongo import MongoClient

# Connect to local MongoDB
client = MongoClient("mongodb://localhost:27017/")

# Create or connect to the database
db = client["career_path_db"]

# Create collections and insert sample documents
users_collection = db["users"]
admins_collection = db["admins"]

# Insert sample user
users_collection.insert_one({
    "username": "student01",
    "email": "student01@example.com",
    "password": "hashed_password_here",
    "role": "user"
})

# Insert sample admin
admins_collection.insert_one({
    "username": "admin01",
    "email": "admin01@example.com",
    "password": "hashed_password_here",
    "role": "admin"
})

print("Database, users, and admins collections created successfully!")
