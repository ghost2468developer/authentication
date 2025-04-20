from fastapi import FastAPI, HTTPException, status, Depends, Header
import json
from pathlib import Path
from auth import hash_password, verify_password, create_token, decode_token
from schemas import UserCreate, UserLogin, UpdatePassword

app = FastAPI()

USER_FILE_PATH = Path("users.json")

# Read and write user data to the JSON file
def read_users():
    with open(USER_FILE_PATH, "r") as file:
        data = json.load(file)
    return data["users"]

def write_users(users):
    with open(USER_FILE_PATH, "w") as file:
        json.dump({"users": users}, file, indent=4)

@app.post("/register")
def register(user: UserCreate):
    users = read_users()

    # Check if user already exists
    if any(existing_user["username"] == user.username for existing_user in users):
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create new user
    hashed_password = hash_password(user.password)
    new_user = {"username": user.username, "hashed_password": hashed_password}
    users.append(new_user)
    
    # Save users to the file
    write_users(users)
    
    return {"msg": "User created successfully"}

@app.post("/login")
def login(user: UserLogin):
    users = read_users()

    # Find user and verify password
    db_user = next((u for u in users if u["username"] == user.username), None)
    if not db_user or not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate JWT token
    token = create_token({"sub": db_user["username"]})
    return {"access_token": token}

@app.get("/profile")
def profile(Authorization: str = Header(...)):
    try:
        token = Authorization.split(" ")[1]
        payload = decode_token(token)
        username = payload.get("sub")
        
        users = read_users()
        user = next((u for u in users if u["username"] == username), None)
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {"username": user["username"]}
    
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# New route to list all users
@app.get("/users")
def get_users(Authorization: str = Header(...)):
    try:
        token = Authorization.split(" ")[1]
        decode_token(token)  # Just verifying the token, no need to extract the username

        users = read_users()
        return {"users": users}
    
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# New route to delete a user by username
@app.delete("/users/{username}")
def delete_user(username: str, Authorization: str = Header(...)):
    try:
        token = Authorization.split(" ")[1]
        payload = decode_token(token)
        logged_in_username = payload.get("sub")

        # Only the user who is logged in or an admin can delete the user
        if logged_in_username != username:
            raise HTTPException(status_code=403, detail="Forbidden: You can only delete your own account")

        users = read_users()
        user_to_delete = next((u for u in users if u["username"] == username), None)
        if not user_to_delete:
            raise HTTPException(status_code=404, detail="User not found")
        
        users.remove(user_to_delete)
        write_users(users)
        return {"msg": f"User '{username}' deleted successfully"}
    
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# New route to update a user's password
@app.put("/users/{username}/password")
def update_password(username: str, password_data: UpdatePassword, Authorization: str = Header(...)):
    try:
        token = Authorization.split(" ")[1]
        payload = decode_token(token)
        logged_in_username = payload.get("sub")

        # Only the user who is logged in can update their password
        if logged_in_username != username:
            raise HTTPException(status_code=403, detail="Forbidden: You can only update your own password")

        users = read_users()
        user_to_update = next((u for u in users if u["username"] == username), None)
        if not user_to_update:
            raise HTTPException(status_code=404, detail="User not found")

        if not verify_password(password_data.old_password, user_to_update["hashed_password"]):
            raise HTTPException(status_code=400, detail="Old password is incorrect")
        
        # Update password
        user_to_update["hashed_password"] = hash_password(password_data.new_password)
        write_users(users)
        return {"msg": "Password updated successfully"}
    
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
