# Auth App – Authentication & Database Integration

A complete user authentication system built with **Node.js, Express, MongoDB (Mongoose) and EJS**.

**Live demo:** https://auth-app-crit.onrender.com

## Features
Sign-up · Login · Logout · Password reset (email/token) · Server-side sessions stored in MongoDB · Form validation · Error handling · Protected routes (`/dashboard`)

## Tech stack
Express, Mongoose/MongoDB Atlas, express-session + connect-mongo, bcryptjs, express-validator, helmet, express-rate-limit, nodemailer, EJS

## Run locally
```bash
git clone <your-repo-url> && cd auth-app
npm install
cp .env.example .env     # fill in MONGODB_URI and SESSION_SECRET
npm start                # http://localhost:3000
```

## Project structure
```
server.js            app setup, sessions, CSRF, error handlers
models/User.js       user schema, password hashing
routes/auth.js       all auth routes + validation
middleware/auth.js   requireAuth / guestOnly
views/               EJS pages
```

## Auth flow
1. **Sign-up** – `POST /register` validates input (name, email, strong password, confirmation), rejects duplicate emails, hashes the password with bcrypt, saves the user in MongoDB and logs them in.
2. **Login** – `POST /login` validates input, finds the user, compares the password hash, then creates a fresh session (`session.regenerate`) and stores the user id/name/email in it. The session lives server-side in MongoDB; the browser only holds an opaque session-ID cookie.
3. **Protected routes** – `requireAuth` middleware checks `req.session.user`; unauthenticated visitors are redirected to `/login`. `guestOnly` keeps logged-in users off login/register.
4. **Logout** – `POST /logout` destroys the server-side session and clears the cookie.
5. **Password reset** – `POST /forgot-password` generates a random 32-byte token, stores only its SHA-256 hash with a 15-minute expiry, and emails a link (or logs it / shows it in demo mode). `GET/POST /reset-password/:token` verifies the hash and expiry, validates the new password, saves it hashed, and invalidates the token (single use).

## Security measures
- **Password hashing** with bcrypt (cost 12); plain passwords are never stored or logged.
- **Strong password policy** enforced server-side (8+ chars, upper, lower, number).
- **Input validation & sanitisation** with express-validator; EJS escapes output (XSS protection).
- **Secure sessions**: `httpOnly`, `sameSite=lax`, `secure` in production, 1-day expiry, session ID regenerated on login (prevents session fixation), session store in MongoDB.
- **CSRF protection**: per-session token required on every POST.
- **Rate limiting** on auth endpoints (20 requests / 15 min per IP) against brute force.
- **No user enumeration**: identical error for wrong email/password; identical response on forgot-password.
- **Reset tokens**: random, hashed at rest, expiring, single-use.
- **Security headers** via Helmet.
- **Secrets in environment variables** (`.env` is git-ignored).
- **Generic error pages**: internal errors are logged server-side, never leaked to users.

## Deployment (Render + MongoDB Atlas)
Build command `npm install`, start command `npm start`. Environment variables: `MONGODB_URI`, `SESSION_SECRET`, `BASE_URL` (your Render URL), `NODE_ENV=production`, `DEMO_SHOW_RESET_LINK`.
