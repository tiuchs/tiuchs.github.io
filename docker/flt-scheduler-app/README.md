# Flight Scheduler MVP

Small Flask + SQLite web app for planning weekly training/mission flights and generating a daily consolidated mission list.

## Run with Docker

From repo root:

```bash
docker compose -f docker/flt-scheduler up --build
```

Open:

`http://localhost:8080`

## Authentication and roles

- Sign in is required for app access.
- Default first-run admin account:
  - Username: `admin`
  - Password: `admin123`
- Change default admin credentials with environment variables:
  - `DEFAULT_ADMIN_USER`
  - `DEFAULT_ADMIN_PASSWORD`
  - `SECRET_KEY`

Roles:

- `user`: view flights and export daily CSV.
- `scheduler`: add/delete flight schedules.
- `approver`: approve/cancel flight status.
- `admin`: full access + user management.

## Mission IDs

- Each flight is assigned a mission ID in `YYYYDDD-###` format.
- `YYYYDDD` is the Julian date portion (year + day-of-year).
- `###` is a sequence number for that Julian date.
- Example: `2026042-003` = 3rd mission on Feb 11, 2026.

## What it does

- Stores flights in SQLite (`docker/flt-scheduler-app/data/scheduler.db`)
- User management for admins (create users and assign role/status)
- Audit log for auth, flight changes, and admin user-management actions
- Default dashboard visibility: today + next 48 hours
- Weekly schedule view
- Daily consolidated mission list
- Approve/cancel/delete workflows
- CSV export for daily crew notifications (`/daily.csv?date=YYYY-MM-DD`)
