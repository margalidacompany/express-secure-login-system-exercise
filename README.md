# express-secure-login-system-exercise

This project implements a secure authentication system using:
- express.js as the backend framework.
- Passport.js for authentication handling.
- Argon2 for password hashing.
- JSON Web Tokens (JWT) for stateless sessions.
- HTTPS for secure communication.
- User storage in a JSON file (can be adapted to a database).

### Features:
- User registration with password hashing (Argon2).  
- Secure login with JWT-based authentication.  
- Protected routes requiring authentication.  
- Logout mechanism by clearing the authentication cookie.  

### Requirements:
- Node.js
- npm
