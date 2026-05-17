import sqlite3
import os
import pickle
import subprocess

# SQL Injection vulnerability
def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

# Command Injection vulnerability
def ping_host(host):
    os.system("ping " + host)

# Insecure Deserialization
def load_data(data):
    return pickle.loads(data)

# Path Traversal
def read_file(filename):
    with open("/var/www/" + filename, "r") as f:
        return f.read()

# Subprocess Injection
def run_command(cmd):
    subprocess.call(cmd, shell=True)