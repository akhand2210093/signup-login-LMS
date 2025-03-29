# Eduverse Learning Management System Authentication

This is the authentication backend for the **Eduverse Learning Management System**. It provides APIs for user registration, login (with password and OTP), logout, and password change.

## Deployed API
The API is live at: [Eduverse Authentication Backend](https://eduversetryagain.onrender.com)

## Features
- User registration
- Login with username/password or OTP
- Token-based authentication
- Logout functionality
- Password change API

## API Endpoints

### 1. Register a new user
**Endpoint:** `POST /register/`
- Accepts user details and registers them in the system.

### 2. User login with username/password
**Endpoint:** `POST /login/`
- Accepts `username` and `password`.
- Returns an authentication token.

### 3. User logout
**Endpoint:** `POST /logout/`
- Requires authentication.
- Deletes the user's token to log them out.

### 4. Login with OTP
**Endpoint:** `POST /login-with-otp/`
- Accepts `email`.
- Sends an OTP to the user's email.

### 5. Validate OTP and login
**Endpoint:** `POST /validate-otp/`
- Accepts `email` and `otp`.
- Returns an authentication token upon successful validation.

### 6. Change Password
**Endpoint:** `POST /change_password/`
- Requires authentication.
- Accepts `old_password` and `new_password`.

## Deployment
The project is deployed on **Render** and accessible via [Eduverse Authentication Backend](https://eduversetryagain.onrender.com).

## Technologies Used
- **Django Rest Framework (DRF)**
- **Token-based authentication**
- **OTP-based authentication**

## Contributors
- Developed by [Akhand]

