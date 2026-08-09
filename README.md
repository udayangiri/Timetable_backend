# Smart Timetable Scheduler — Backend

A Node.js + Express + SQLite backend that gives the timetable HTML app proper multi-user data storage and access control.

## Quick Start

```bash
# 1. Install dependencies (already done if you unzipped this)
npm install

# 2. Configure environment
cp .env.example .env
# Edit .env and set a strong JWT_SECRET

# 3. Start the server
npm start
# → http://localhost:3000

# 4. Open in browser
# → http://localhost:3000
# Default admin: admin@school.edu / admin123
# CHANGE THE PASSWORD IMMEDIATELY after first login.
```

## What Changes vs Standalone HTML

| Feature | Standalone HTML | With Backend |
|---|---|---|
| Data storage | localStorage (per browser) | SQLite database (shared, persistent) |
| Auth users | localStorage (per browser) | Database (shared across devices) |
| Multi-user | Same browser only | Any device, any browser |
| Timetable sharing | Manual JSON export | Auto-saved, all users see same data |
| Audit log | None | Full action log in Admin tab |
| Password security | SHA-256 in browser | bcrypt (server-side, never exposed) |

## API Overview

| Route | Method | Auth | Description |
|---|---|---|---|
| `/api/health` | GET | None | Server health check |
| `/api/auth/login` | POST | None | Get JWT token |
| `/api/auth/me` | GET | Token | Get current user info |
| `/api/auth/change-password` | POST | Token | Change own password |
| `/api/admin/users` | GET/POST | Admin | List / add users |
| `/api/admin/users/:id/permissions` | PATCH | Admin | Edit tab permissions |
| `/api/admin/users/:id/revoke` | PATCH | Admin | Revoke access |
| `/api/admin/users/:id/restore` | PATCH | Admin | Restore access |
| `/api/admin/users/:id/reset-password` | POST | Admin | Reset any user's password |
| `/api/admin/audit-log` | GET | Admin | View all actions |
| `/api/instances` | GET/POST | Token | List / create instances |
| `/api/sync` | POST | Edit perm | Push full data to server |
| `/api/sync/:id` | GET | Token | Pull full data from server |
| `/api/faculty` | GET/POST/DELETE | Tab 1 perm | Faculty CRUD |
| `/api/subjects` | GET/POST/DELETE | Tab 2 perm | Subjects CRUD |
| `/api/sections` | GET/POST/DELETE | Tab 3 perm | Sections CRUD |
| `/api/assignments` | GET/POST/DELETE | Tab 4 perm | Assignments CRUD |
| `/api/timetable/:id` | GET/POST | Tab 5 perm | Save / load timetable |

## Deployment Options

### Option A — Local Network (school LAN)
Run on a school PC and share the IP:
```bash
npm start
# Share: http://192.168.x.x:3000
```

### Option B — Free Cloud (Render.com)
1. Push this folder to a GitHub repo
2. Go to render.com → New Web Service → connect repo
3. Build command: `npm install`
4. Start command: `npm start`
5. Add environment variable: `JWT_SECRET=your_long_random_string`
6. Free tier gives you a public URL

### Option C — Railway / Fly.io
Similar to Render — connect GitHub repo, set JWT_SECRET, deploy.

## Database
SQLite file: `timetable.db` — back this up regularly.
For production with many concurrent users, swap better-sqlite3 for PostgreSQL
(change the db calls to use `pg` pool — all queries are standard SQL).

## Security Notes
- Change the default admin password immediately
- Set a strong `JWT_SECRET` (32+ random characters) before going live
- Tokens expire after 8 hours — users need to log in again daily
- All passwords stored as bcrypt hashes (never reversible)
- Revocation takes effect instantly on the next API call
