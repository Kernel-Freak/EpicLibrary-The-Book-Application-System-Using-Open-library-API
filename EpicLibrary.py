import bcrypt
import maskpass
import time
from datetime import datetime, timedelta
import logging
import re
import os
import random
import requests

# Set up logging
logging.basicConfig(filename='user_activity.log', level=logging.INFO,
                    format='[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Constants variables
USER_DATA_FILE = 'user_data.csv'  
BLOCK_DURATION = timedelta(hours=6) 
FAILED_ATTEMPT_LIMIT = 3  
CAPTCHA_ATTEMPTS = 3  
OPEN_LIBRARY_URL = "https://openlibrary.org/search.json"  

# Function to load user data from the CSV file
def load_user_data():
    user_data = {}
    if not os.path.exists(USER_DATA_FILE):
        return user_data
    
    try:
        with open(USER_DATA_FILE, 'r') as file:
            for line in file:
                # Splitting each line by comma to get email, name, and password
                email, name, password = line.strip().split(',')
                user_data[email] = {'name': name, 'password': password}
    except Exception as e:
        logging.error(f"Error loading user data: {e}")
    
    return user_data

# Function to save user data to the CSV file
def save_user_data(user_data):
    try:

        with open(USER_DATA_FILE, 'w') as file:
            for email, data in user_data.items():
                # Write each user's email, name, and password in a comma-separated line
                file.write(f'{email},{data["name"]},{data["password"]}\n')
    except Exception as e:
        logging.error(f"Error saving user data: {e}")

# Function to hash the password using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

# Function to verify login password with the stored hashed password
def verify_password(stored_password, input_password):
    return bcrypt.checkpw(input_password.encode('utf-8'), stored_password.encode('utf-8'))

# Function to check the input email is valid
def is_valid_email(email):
    return re.match(r'[^@]+@[^@]+\.[^@][^0-9]+', email)

# Function to check if the password is strong enough
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[@#$%^&+=_]", password):
        return False
    return True

# CAPTCHA function to prevent brute force attacks during password reset
def captcha():
    num1, num2 = random.randint(0, 99), random.randint(0, 99)
    correct_answer = num1 + num2
    for _ in range(CAPTCHA_ATTEMPTS):
        try:
            answer = int(input(f"Solve this CAPTCHA: {num1} + {num2} = "))
            if answer == correct_answer:
                return True
            print("Incorrect CAPTCHA. Try again.")
        except ValueError:
            print("Invalid input. Enter numbers only.")
    return False

# Function to log failed login attempts
def log_failed_attempt(email, failed_attempts):
    logging.warning(f'Failed login attempt for {email}. Attempt {failed_attempts} of {FAILED_ATTEMPT_LIMIT}')

# Function to log when a user is blocked
def log_user_block(email, block_until_time):
    logging.error(f'User {email} blocked until {block_until_time}')

# Function to search for books using OpenLibrary API
def search_books():
    while True:
        print("\nSearch Menu")
        print("1. Search by Title")
        print("2. Search by Author")
        print("3. Search by ISBN")
        print("4. Exit to Main Menu")
        choice = input("Enter your choice: ")

        if choice == '1':
            query = input("Enter book title: ")
            search_open_library(query, "title")
        elif choice == '2':
            query = input("Enter author name: ")
            search_open_library(query, "author")
        elif choice == '3':
            query = input("Enter ISBN: ")
            search_open_library(query, "isbn")
        elif choice == '4':
            break
        else:
            print("Invalid option. Please try again.")

# Function to call OpenLibrary API and search for books
def search_open_library(query, search_type):
    params = {search_type: query}
    try:
        response = requests.get(OPEN_LIBRARY_URL, params=params)

        if response.status_code == 200:
            results = response.json()
            books = results.get('docs', [])
            if books:
                for book in books[:5]:  # Show top 5 results
                    print("\nBook Found:")
                    print(f"Title: {book.get('title', 'N/A')}")
                    print(f"Author: {', '.join(book.get('author_name', ['N/A']))}")
                    print(f"First Published: {book.get('first_publish_year', 'N/A')}")
                    print(f"ISBN: {', '.join(book.get('isbn', ['N/A'])[:1])}")
            else:
                print("No books found.")
        else:
            print(f"Error {response.status_code}: Failed to fetch data from OpenLibrary.")
    except requests.ConnectionError:
        print("Network error: Please check your internet connection.")
        logging.error("Network error while trying to fetch data from OpenLibrary.")
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"Error occurred while searching OpenLibrary: {e}")

# Function to register a new user
def register_user():
    user_data = load_user_data()
    
    name = input("Enter your name: ")
    email = input("Enter email: ").lower()

    if email in user_data:
        print("Email is already registered.")
        return
    
    if not is_valid_email(email):
        print("Invalid email format.")
        return

    password = maskpass.askpass(prompt="Enter a password (at least 8 characters, with upper, lower, digit, and special char):", mask="#")

    if not is_strong_password(password):
        print("Password is too weak.")
        return

    hashed_password = hash_password(password)
    user_data[email] = {
        'name': name,
        'password': hashed_password,
    }
    save_user_data(user_data)
    logging.info(f'User {name} registered with email: {email}')
    print("User registered successfully!")

# Function for user login
def login_user():
    user_data = load_user_data()
    email = input("Enter email: ").lower()

    if email not in user_data:
        print("User not found.")
        return

    user = user_data[email]

    failed_attempts = 0
    blocked_until = None

    while failed_attempts < FAILED_ATTEMPT_LIMIT:
        if blocked_until and datetime.now() < blocked_until:
            print(f"Account is blocked. Try again after {blocked_until}.")
            return
        password = maskpass.askpass(prompt="Enter Password:", mask="#")
        if verify_password(user['password'], password):
            logging.info(f'User {email} logged in successfully')
            print("Login successful!")
            search_books()
            logging.info(f'User {email} logged out successfully')
            return
        else:
            failed_attempts += 1
            log_failed_attempt(email, failed_attempts)
            print(f"Invalid password. {FAILED_ATTEMPT_LIMIT - failed_attempts} attempt(s) remaining.")
        
    blocked_until = datetime.now() + BLOCK_DURATION
    log_user_block(email, blocked_until)
    print(f"Too many failed attempts. You are blocked until {blocked_until.strftime('%Y-%m-%d %H:%M:%S')}.")

# Function to reset password
def reset_password():
    user_data = load_user_data()
    email = input("Enter your registered email: ").lower()

    if email not in user_data:
        print("Email not found.")
        return

    if captcha():
        new_password = maskpass.askpass(prompt="Enter New Password:", mask="#")

        if not is_strong_password(new_password):
            print("Password is too weak.")
            return

        user_data[email]['password'] = hash_password(new_password)
        save_user_data(user_data)
        logging.info(f'Password reset for email: {email}')
        print("Password reset successful!")
    else:
        print("Failed CAPTCHA attempts. Try again later.")
        logging.info(f'Password reset failed for email: {email}')

# Main menu to navigate the system
def main_menu():
    while True:
        print("\nMain Menu")
        print("1. Register")
        print("2. Login")
        print("3. Reset Password")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            register_user()
        elif choice == '2':
            login_user()
        elif choice == '3':
            reset_password()
        elif choice == '4':
            print("Exiting program...")
            break
        else:
            print("Invalid option. Please try again.")

# Run the application
if __name__ == '__main__':
    main_menu()
