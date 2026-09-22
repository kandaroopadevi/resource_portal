# GVPW Student Resource Portal

A unified PHP and SQLite full-stack portal for managing academic resources. The project runs from a single front controller, `index.php`, instead of separate student, admin, faculty, upload, search, and management modules.

## Features

- Student-facing search by keyword and category
- Single full-stack entry point for student, admin, and faculty workflows
- Admin login with seeded demo credentials
- Admin-created faculty login credentials
- Upload academic resources with category metadata
- Manage, preview, and delete uploaded files
- SQLite runtime database with automatic seed data from `uploads`
- Responsive dashboard styling for desktop and mobile

## Tech Stack

- PHP 8+
- SQLite via PDO
- HTML5 and CSS3
- XAMPP Apache server

## Demo Login

- Username: `admin`
- Password: `admin123`

The demo admin is created automatically when the app starts and no admin account exists.

## Faculty Login Flow

1. Log in as the main admin.
2. Open `Faculty Logins` from the dashboard sidebar.
3. Create a faculty name, username, and temporary password.
4. Share those credentials with the faculty member.
5. Faculty can log in from the same login page and upload or manage files.

## Local Setup

1. Copy this folder to `C:\xampp\htdocs\gvp_portal` for direct Apache access, or keep it in `D:\gvp_portal` and configure Apache to point there.
2. Start Apache in XAMPP.
3. Open `http://localhost/gvp_portal/index.php` when placed inside `htdocs`.
4. For the admin and faculty area, use `http://localhost/gvp_portal/index.php?view=login`.

For quick testing without Apache virtual host setup:

`C:\xampp\php\php.exe -S localhost:8088 -t D:\gvp_portal`

Then open:

`http://localhost:8088/index.php`

## Project Structure

- `index.php` - unified full-stack app with routing, authentication, upload handling, search, and role-based dashboards
- `css/style.css` - shared responsive UI styling
- `uploads/` - seed academic files shown in the portal
- `storage/` - placeholder folder; runtime SQLite storage defaults to `%TEMP%\gvp_portal_<project-hash>`

## Runtime Data

By default, the app stores the SQLite database and newly uploaded files in:

`%TEMP%\gvp_portal_<project-hash>`

To use a custom storage folder, set the `GVP_PORTAL_STORAGE` environment variable before starting Apache.

## Interview Talking Points

- Uses prepared statements for database queries.
- Stores admin passwords with `password_hash`.
- Protects admin-only routes with sessions.
- Supports role-based access for admin and faculty users.
- Uses CSRF tokens on write actions.
- Uses a single front controller for a cohesive full-stack architecture.
- Restricts upload file extensions.
- Seeds existing academic files into SQLite for a realistic demo.
