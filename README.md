# User Authentication System

A simple command-line user authentication system built in Java that provides secure user registration, login, and password reset functionality with SHA-256 password hashing.

## Features

- **User Registration**: Create new user accounts with unique usernames
- **User Authentication**: Secure login system with password verification
- **Password Reset**: Reset passwords for existing users
- **Password Security**: SHA-256 hashing for secure password storage
- **Persistent Storage**: User data stored in local file system
- **Interactive CLI**: Easy-to-use command-line interface

## Prerequisites

- Java Development Kit (JDK) 8 or higher
- Command line access

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ehte-s/java-based-user-authentication-system.git
cd java-based-user-authentication-system
```

2. Compile the Java file:
```bash
javac UserAuthenticationSystem.java
```

3. Run the application:
```bash
java UserAuthenticationSystem.UserAuthenticationSystem
```

## Usage

Upon running the application, you'll see a menu with the following options:

### 1. Register New User
- Select option `1`
- Enter a unique username
- Enter a password (will be hashed and stored securely)

### 2. Login
- Select option `2`
- Enter your username and password
- System will verify credentials and confirm successful login

### 3. Reset Password
- Select option `3`
- Enter your existing username
- Enter your new password

### 4. Exit
- Select option `4` to close the application

### Example Usage
```
1. Register
2. Login
3. Reset Password
4. Exit
Choose an option: 1
Enter username: john_doe
Enter password: mySecurePassword123
User registered successfully.
```

## File Structure

```
├── UserAuthenticationSystem.java  # Main application file
├── users.txt                     # User data storage (auto-generated)
└── README.md                     # This file
```

## Security Features

- **Password Hashing**: All passwords are hashed using SHA-256 before storage
- **No Plain Text Storage**: Passwords are never stored in plain text
- **File-based Persistence**: User data persists between application sessions

## Technical Details

- **Language**: Java
- **Storage**: File-based (users.txt)
- **Hashing Algorithm**: SHA-256
- **Architecture**: Single-class application with modular methods
- **Input/Output**: Scanner for user input, BufferedReader/Writer for file operations

## Data Format

User data is stored in `users.txt` in the following format:
```
username:hashedpassword
```

## Limitations

- Single-user session (no concurrent users)
- File-based storage (not suitable for production environments)
- No password strength validation
- No account lockout mechanisms
- No user role management

## Future Enhancements

- [ ] Database integration (MySQL/PostgreSQL)
- [ ] Password strength validation
- [ ] Account lockout after failed attempts
- [ ] User roles and permissions
- [ ] GUI interface
- [ ] Session management
- [ ] Two-factor authentication
- [ ] Password recovery via email

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

## Error Handling

The system includes error handling for:
- File I/O operations
- Invalid user input
- Duplicate username registration
- Non-existent user authentication
- Password hashing failures

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Created as a demonstration of basic authentication principles in Java.

## Support

For questions or support, please open an issue on the GitHub repository.

---

**Note**: This is a demonstration project and should not be used in production environments without additional security measures and proper database integration.
