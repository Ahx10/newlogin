import os
import sqlite3
import shutil
import uuid

import bcrypt
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from pathlib import Path

app = FastAPI()

# Create SQLite database connection and cursor
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Create users table if it doesn't exist
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_name TEXT,
        email TEXT,
        phone_number TEXT,
        password TEXT
    )
    """
)

# Create user_photos table if it doesn't exist
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS user_photos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        file_name TEXT,
        file_path TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """
)

# Create blood_bank table if it doesn't exist
cursor.execute(
    """
    CREATE TABLE IF NOT EXISTS blood_bank (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        donor_name TEXT,
        address TEXT,
        phone_number TEXT,
        blood_type TEXT
    )
    """
)

conn.commit()

# Create a directory to store the uploaded photos
photo_directory = "user_photos"
Path(photo_directory).mkdir(parents=True, exist_ok=True)


class UserSignUp(BaseModel):
    user_name: str
    email: str = ""
    phone_number: str = ""
    password: str


class UserLogin(BaseModel):
    email: str
    password: str


class ResetPassword(BaseModel):
    email: str
    new_password: str


class DonorInfo(BaseModel):
    donor_name: str
    address: str
    phone_number: str
    blood_type: str


class PhotoUploadResponse(BaseModel):
    message: str
    file_name: str
    file_path: str


@app.get("/")
async def root():
    return {
        "message": "Hello, This is a FastAPI for user login, add /docs to the URL to see the documentation"
    }


@app.post("/register")
async def signup(user: UserSignUp):
    cursor.execute(
        "SELECT * FROM users WHERE email = ? OR phone_number = ?",
        (user.email, user.phone_number),
    )
    existing_user = cursor.fetchone()
    if existing_user:
        return JSONResponse(status_code=400, content={"message": "User already exists"})

    hashed_password = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt())

    cursor.execute(
        "INSERT INTO users (user_name, email, phone_number, password) VALUES (?, ?, ?, ?)",
        (user.user_name, user.email, user.phone_number, hashed_password.decode()),
    )
    conn.commit()
    return {"message": "User created successfully"}


@app.post("/login")
async def login(user: UserLogin):
    cursor.execute(
        "SELECT id, user_name, password FROM users WHERE email = ?",
        (user.email,),
    )
    existing_user = cursor.fetchone()
    if existing_user:
        hashed_password = existing_user[2]

        if bcrypt.checkpw(user.password.encode(), hashed_password.encode()):
            return {"message": "Login successful", "user_id": existing_user[0]}

    return JSONResponse(status_code=401, content={"message": "Invalid email or password"})


@app.post("/reset-password")
async def reset_password(reset_data: ResetPassword):
    cursor.execute("SELECT id, password FROM users WHERE email = ?", (reset_data.email,))
    user = cursor.fetchone()
    if user:
        hashed_password = bcrypt.hashpw(reset_data.new_password.encode(), bcrypt.gensalt())
        cursor.execute(
            "UPDATE users SET password = ? WHERE id = ?", (hashed_password.decode(), user[0])
        )
        conn.commit()
        return {"message": "Password reset successfully"}
    else:
        return JSONResponse(status_code=404, content={"message": "User not found"})


@app.post("/upload-photo/{user_id}")
async def upload_photo(user_id: int, file: UploadFile = File(...)):
    # Generate a unique file name
    file_extension = os.path.splitext(file.filename)[1]
    file_name = f"{user_id}_{uuid.uuid4().hex}{file_extension}"
    file_path = os.path.join(photo_directory, file_name)

    # Save the file to disk
    with open(file_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    # Store the file details in the database
    cursor.execute(
        "INSERT INTO user_photos (user_id, file_name, file_path) VALUES (?, ?, ?)",
        (user_id, file_name, file_path),
    )
    conn.commit()

    return PhotoUploadResponse(
        message="Photo uploaded successfully",
        file_name=file_name,
        file_path=file_path,
    )


@app.post("/add-donor")
async def add_donor(donor: DonorInfo):
    cursor.execute(
        "INSERT INTO blood_bank (donor_name, address, phone_number, blood_type) VALUES (?, ?, ?, ?)",
        (donor.donor_name, donor.address, donor.phone_number, donor.blood_type),
    )
    conn.commit()
    return {"message": "Donor information added successfully"}
