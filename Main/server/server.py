#!/usr/bin/env python3
import socket
import threading
import re
import keygeneration.server_main as server_main
import sqlite3
import base64
import os

# host = '127.0.0.1'
host = '0.0.0.0'
port = 9999

# Get absolute paths
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.abspath(os.path.join(ROOT_DIR, '..', '..', 'database.db'))
VIDEOS_DIR = os.path.join(ROOT_DIR, 'videos')

# Ensure directories exist
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(VIDEOS_DIR, exist_ok=True)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
print(f"Server is listening on {host}:{port}")
print(f"Database path: {DB_PATH}")
server.listen()

clients = ["test"]
emails = ["test@gmail.com"]

def get_encrypted_video(choice, email):
    video_path = os.path.join(VIDEOS_DIR, f"{choice}.mp4")
    if not os.path.exists(video_path):
        raise FileNotFoundError(f"Video file not found: {video_path}")
    
    enc_video, iv = server_main.main_encrypt(video_path, email, DB_PATH)
    return enc_video, iv

def handle(client):
    email = None  # Initialize email to handle disconnection message
    try:
        # Database connection
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Create table if it doesn't exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS user
                         (email TEXT PRIMARY KEY, password TEXT)''')
        conn.commit()

        creds = client.recv(1024).decode("ascii")
        if not creds or "," not in creds:
            raise ValueError("Invalid credentials format")

        email, password_b64 = creds.split(",")
        if email:
            print(f"Email of the client is {email}")
            emails.append(email)
            clients.append(client)

        password = base64.b64decode(password_b64).decode("ascii")

        cursor.execute("SELECT * FROM user WHERE email = ? AND password = ?", (email, password))
        row = cursor.fetchone()

        if row is None:
            client.send("Login failed..".encode("ascii"))
            return

        print(f"{email} login success")
        client.send("Login Success..".encode("ascii"))

        playlist = """
-------------------------------------------------
Playlist : 
    1. What is cryptography
    2. Learn about RSA
    3. Digital Signatures
    4. AES security
    0. Exit
Choose any one video from the playlist(1/2/3/4) : """

        client.send(playlist.encode("ascii"))
        choice = client.recv(2).decode("ascii")
        if not choice:
            raise ValueError("No choice received")

        print(f'{email} chose {choice}')

        video, iv = get_encrypted_video(choice, email)

        client.send("Receiving video chunks...".encode("ascii"))
        client.send(iv)

        # Sending encrypted raw video data
        chunk_size = 1024
        offset = 0
        while offset < len(video):
            chunk = video[offset:offset+chunk_size]
            client.send(chunk)
            offset += len(chunk)
        client.send("DONE".encode("ascii"))

    except sqlite3.OperationalError as e:
        print(f"Database error: {e}")
        client.send("Server error: Database connection failed".encode("ascii"))
    except FileNotFoundError as e:
        print(f"File error: {e}")
        client.send("Server error: Video file not found".encode("ascii"))
    except Exception as e:
        print(f"Error: {e}")
        client.send("Server error occurred".encode("ascii"))
    finally:
        if 'conn' in locals():
            conn.close()
        if client:
            client.close()
        if email:
            print(f'{email} disconnected..')

def receive():
    while True:
        client, address = server.accept()
        print(f"Connected with {str(address)}")
        client.send("Connected to the server!".encode("ascii"))

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()

if __name__ == "__main__":
    receive()