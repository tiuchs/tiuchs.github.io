# Flight Scheduler MVP

Small Flask + SQLite web app for planning weekly training/mission flights and generating a daily consolidated mission list.

## Run with Docker

From repo root:

```bash
docker compose -f docker/flt-scheduler up --build
```

Open:

`http://localhost:8080`

Notes:

- This Compose setup works on both Intel/AMD (`amd64`) and ARM (`arm64`) hosts.
- For multi-arch image publishing (instead of local build), use `docker buildx` with both platforms.

## Kubernetes Manifest

- A Kubernetes manifest is included at:
  - `docker/flt-scheduler-app/manifest.yaml`
- It defines:
  - `PersistentVolumeClaim` for SQLite data
  - `Deployment` for the Flask app
  - `Service` exposing port `8080`
  - Node affinity for both `amd64` (Intel/AMD) and `arm64` processors
- Note:
  - The container image must be published as multi-arch (`linux/amd64` and `linux/arm64`) for this to work on mixed clusters.

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
- `admin`: full access + settings management.

## Mission IDs

- Each flight is assigned a mission ID in `YYYYDDD-###` format.
- `YYYYDDD` is the Julian date portion (year + day-of-year).
- `###` is a sequence number for that Julian date.
- Example: `2026042-003` = 3rd mission on Feb 11, 2026.

## Flight Planning Fields

- Crew planning is structured:
  - `Pilot in Command` (dropdown from active crew roster)
  - `PIC is also AMC` (checkbox)
  - `Pilot` (dropdown from active crew roster)
  - `Crew Members` (text)
  - `Non-rated Crew` (text)
- Team flight support:
  - `Team flight` checkbox
  - If checked, `AMC Mission ID` is required
- Actual times:
  - Per-flight `Actual Takeoff` and `Actual Arrival` fields
  - Auto-calculated `Actual Hours (Decimal)` shown in daily view and CSV
- Daily closeout:
  - `Close Out` action in Daily Consolidated Missions saves actuals + closeout comments
  - If mission status is `cancelled`, closeout includes reason checkboxes:
    - Weather
    - Maintenance
    - Other (with details)
- Scheduler prerequisites:
  - Add active crew and aircraft entries in `/settings` before creating flights

## What it does

- Stores flights in SQLite (`docker/flt-scheduler-app/data/scheduler.db`)
- Settings page for admins (`/settings`) with:
  - Admin settings (`/settings/admin`)
  - Crew management (`/settings/crew`)
  - Aircraft management (`/settings/aircraft`)
  - Website UI theme (light/dark)
  - Bulk import for crew and aircraft (paste CSV/text or upload `.csv`/`.txt`)
  - Date-range export for scheduled flights CSV
- Audit log for auth, flight changes, and settings/admin actions
- Default dashboard visibility: today + next 48 hours
- Weekly schedule view
- Daily consolidated mission list
- Approve/cancel/delete workflows
- CSV export for daily crew notifications (`/daily.csv?date=YYYY-MM-DD`)

## Bulk Import Formats

- Crew:
  - `name,active` CSV header optional
  - Example:
    - `John Smith,1`
    - `Jane Doe,0`
  - You can also provide one crew name per line.
- Aircraft:
  - `tail_number,model,active` CSV (header optional)
  - Example:
    - `A123,UH-60M,1`
    - `A124,UH-60L,1`
- Route planning:
  - Optional `Route` field between origin and destination
  - Included in SkyVector `fpl` as `origin route destination`
  - Example: `fpl=%20KHLR%2022XS%20KTPL`
- Mission edit workflow:
  - In Daily Consolidated Missions, schedulers/admins can click a mission ID to load that mission into Add Flight for editing.
  - Saving changes resets mission status to `planned` so it can be re-approved.
