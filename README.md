# express-secure-login-system-exercise

This project implements a secure authentication system using:
- express.js as the backend framework.
- Passport.js for authentication handling.
- Argon2 for password hashing.
- JSON Web Tokens (JWT) for stateless sessions.
- HTTPS for secure communication.
- FreeRADIUS server integration for RADIUS authentication.
- OpenID Connect (OIDC) and OAuth 2.0 authentication with Google.
- User storage in a JSON file (easily adaptable to a real database).

### Features:
- User registration with password hashing (Argon2).  
- Secure login with JWT-based authentication.  
- OAuth 2.0 login with Google.
- OpenID Connect (OIDC) login with Google.
- RADIUS login with a local FreeRADIUS server.
- Protected routes requiring authentication.
- Logout mechanism by clearing the authentication cookie.

### Requirements:
- Node.js
- npm
- FreeRADIUS (for RADIUS login)
- Google Cloud Project (for OAuth 2.0 / OIDC)

### Notes
The project uses .env files to manage sensitive credentials (Google OAuth, OIDC, session secrets, etc.).

JWT tokens are generated and stored in secure cookies with expiration times.

Users authenticated via different methods (local, Google OAuth, OIDC, RADIUS) are stored in a single users.json file for simplicity.
