# EpicLibrary-The-Book-Searching-Application-Using-Open-library-API
# User Authentication and Book Search System

This project is a Python-based console application that provides user registration, login, password reset functionalities, and a book search feature using the OpenLibrary API. The system ensures secure user management with hashed passwords, CAPTCHA for security, and logging for tracking user activities.

---
## Features
- **User Registration:** Secure registration with email validation and password strength requirements.
- **User Login:** Password-based login with account lockout after multiple failed attempts.
- **Password Reset:** CAPTCHA-based security for resetting passwords.
- **Book Search:** Search for books by title, author, or ISBN using the OpenLibrary API.
- **Secure Password Management:** Passwords are hashed using bcrypt.
- **Logging:** Activity logs maintained for user registration, login attempts, and book search.

---
## Technologies Used
- **Python 3**
- **bcrypt:** For secure password hashing.
- **maskpass:** For secure password input.
- **requests:** To interact with the OpenLibrary API.
- **logging:** For activity tracking.

---
## Setup Instructions

### Prerequisites
- Python 3.x installed on your system.
- `pip` package manager installed.

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/user-auth-book-search.git
   cd user-auth-book-search
   ```
2. Install required dependencies:
   ```bash
   pip install bcrypt maskpass requests
   ```

### Running the Application
Execute the following command in your terminal:
```bash
python EpicLibrary.py
```

---
## How to Use

### Main Menu
1. **Register:** Create a new user account.
2. **Login:** Login with your registered email and password.
3. **Reset Password:** Reset your password after completing a CAPTCHA challenge.
4. **Exit:** Exit the program.

### Book Search
Once logged in, you can search for books by:
- Title
- Author
- ISBN

The system will display up to 5 book results for each search query.

---
## File Structure
```
user-auth-book-search/
├── main.py            # Main application script
├── user_data.csv       # Stores user information
└── user_activity.log   # Activity logs for the application
```

---
## Security Measures
- **Password Hashing:** User passwords are securely hashed using bcrypt.
- **CAPTCHA:** CAPTCHA verification to prevent brute force attacks during password reset.
- **Account Lockout:** Users are blocked for 6 hours after 3 consecutive failed login attempts.
- **Logging:** Detailed activity logging for monitoring user actions.

---
## Important Notes
- Ensure that you have a stable internet connection to use the book search feature.
- The `user_data.csv` file should be kept secure, and access should be restricted.

---
## Contributions
Contributions are welcome! Feel free to fork this repository and submit a pull request.

---
## License
This project is licensed under the MIT License. See the LICENSE file for details.

---
## Contact
For any queries or issues, please contact [your-email@example.com].

