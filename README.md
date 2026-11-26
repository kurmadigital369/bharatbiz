# BharatBiz — Full-Stack All-India Business Directory

This package includes a real **Node.js + Express + SQLite + Nodemailer** backend with:
- Real **Email + Password Registration** with **6-digit SMTP Email OTP verification**
- Real **JWT authentication** (`bcryptjs` password hashing + `jsonwebtoken`)
- Persistent **SQLite database** (`bharatbiz.db`) for users, business listings, and customer reviews

## Setup & Run Locally

1. **Install dependencies** (requires Node.js 18+):
   ```bash
   npm install
   ```

2. **Configure real email sending**:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` and fill in `JWT_SECRET` plus your SMTP credentials (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`).
   - For **Gmail**: enable 2-Step Verification and generate an **App Password**, then use `smtp.gmail.com` on port `587`.
   - If `SMTP_USER` / `SMTP_PASS` are left blank, the server logs the OTP in the terminal so you can still test locally.

3. **Start the server**:
   ```bash
   npm start
   ```

4. Open **http://localhost:3000** in your browser.
