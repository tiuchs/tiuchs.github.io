# Flight Scheduler MVP

Small Flask + SQLite web app for planning weekly training/mission flights and generating a daily consolidated mission list.

## Documentation

📚 **Complete documentation for users and administrators:**

| Document | Purpose | Audience |
|----------|---------|----------|
| **[USER_GUIDE.md](USER_GUIDE.md)** | Comprehensive guide with troubleshooting, best practices, FAQ | All users, admins |
| **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** | Quick reference card for daily operations and emergencies | Daily operators |
| **[BACKUP_WORKFLOW.md](BACKUP_WORKFLOW.md)** | Visual guide to backup system with flowcharts and scenarios | Admins, operators |
| **[README.md](README.md)** | Technical reference and installation guide | Administrators, developers |

**📖 Getting Started Paths:**

- **New User?** → Start with [User Guide](USER_GUIDE.md) → Keep [Quick Reference](QUICK_REFERENCE.md) handy
- **Admin Setup?** → Read [README.md](README.md) → Review [Backup Workflow](BACKUP_WORKFLOW.md)
- **Need Help?** → Check [Quick Reference](QUICK_REFERENCE.md) → See [Troubleshooting](USER_GUIDE.md#troubleshooting) in User Guide
- **Understanding Backups?** → Read [Backup Workflow](BACKUP_WORKFLOW.md) for visual explanations

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
  - Database backup management
- Audit log for auth, flight changes, and settings/admin actions
- Default dashboard visibility: today + next 48 hours
- Weekly schedule view
- Daily consolidated mission list
- Approve/cancel/delete workflows
- CSV export for daily crew notifications (`/daily.csv?date=YYYY-MM-DD`)
- Soft delete for flights with admin recovery capabilities

## Soft Delete for Flights

Flight deletions are "soft" - they are marked as deleted but preserved in the database:

- **Deleted flights**: Hidden from normal views but preserved in database
- **Recovery**: Admins can restore soft-deleted flights via `/settings/deleted-flights`
- **Permanent deletion**: Admins can purge flights permanently if needed
- **Audit trail**: All delete, restore, and purge actions are logged

### Admin Recovery Interface

Admins have access to a dedicated interface to manage deleted flights:

1. Navigate to Settings → Admin Settings
2. Click "View Deleted Flights"
3. View all soft-deleted flights with full details
4. Options for each deleted flight:
   - **Restore**: Undelete and return to active status
   - **Purge**: Permanently remove from database (cannot be undone)

This ensures accidental deletions can be recovered while still allowing permanent cleanup when necessary.

## Database Backups

### Automatic Backups

- Backups are created automatically on app startup
- Daily backups run every 24 hours in the background
- Backups are stored in `docker/flt-scheduler-app/data/backups/`
- Old backups are automatically deleted after 7 days
- Backup files use format: `scheduler-backup-YYYYMMDD-HHMMSS.db`

### Manual Backups

Admins can create manual backups from the Admin Settings page:

1. Navigate to `/settings/admin`
2. Click "Create Backup Now" in the Database Backups section
3. View, download, or manage existing backups from the same page

### Backup Features

- **WAL Checkpoint**: Before each backup, the Write-Ahead Log is checkpointed to ensure all data is in the main database file
- **Integrity Check**: Each backup is verified for database integrity before being saved
- **Retention Policy**: Backups older than 7 days are automatically removed to save disk space
- **Download**: Admins can download any backup file directly from the settings page

### Restoring from Backup

To restore from a backup:

1. Stop the application: `docker compose -f docker/flt-scheduler down`
2. Replace the current database with a backup:
   ```bash
   cp docker/flt-scheduler-app/data/backups/scheduler-backup-YYYYMMDD-HHMMSS.db \
      docker/flt-scheduler-app/data/scheduler.db
   ```
3. Restart the application: `docker compose -f docker/flt-scheduler up -d`

## Health Check Endpoint

The application provides a `/health` endpoint for monitoring and orchestration:

```bash
curl http://localhost:8080/health
```

**Response Example:**
```json
{
  "status": "healthy",
  "timestamp": "2026-02-14 17:25",
  "checks": {
    "database_connectivity": "ok",
    "database_integrity": "ok",
    "disk_space": {
      "free_mb": 157548.71,
      "total_mb": 948584.16,
      "percent_free": 16.61,
      "status": "ok"
    },
    "backups": {
      "count": 2,
      "status": "ok"
    }
  }
}
```

**Status Codes:**
- `200 OK` - System is healthy or degraded (minor issues)
- `503 Service Unavailable` - System is unhealthy (critical issues)

**Docker Integration:**
- Health checks run every 30 seconds
- Container marked unhealthy after 3 consecutive failures
- Configured in docker-compose.yml

**Kubernetes Integration:**
- Liveness probe checks `/health` every 30 seconds
- Readiness probe checks `/health` every 10 seconds
- Configured in manifest.yaml

## Database Stability Features

The application uses several SQLite optimizations for improved stability and performance:

- **Write-Ahead Logging (WAL)**: Enables concurrent reads during writes, improving performance by 2-3x
- **Foreign Key Constraints**: Enforces referential integrity to prevent orphaned records
- **Busy Timeout**: Automatically waits up to 5 seconds if the database is locked instead of failing immediately
- **Cache Size**: 64MB in-memory cache for faster queries on frequently accessed data
- **Integrity Checks**: Automatic database health checks on startup with corrupt database quarantine

These settings ensure the database remains stable even under concurrent access and reduces the risk of corruption or data loss.

## Structured Logging

The application uses Python's logging module for comprehensive, structured logging:

### Log Outputs

**Console (stderr):**
- Format: `TIMESTAMP [LEVEL] logger - message`
- Example: `2026-02-14 17:54:42 [INFO] scheduler - Created backup: scheduler-backup-20260214-175442.db (0.05 MB)`
- Visible in Docker logs: `docker compose logs`

**File (data/logs/scheduler.log):**
- Format: `TIMESTAMP [LEVEL] logger [file:line] - message`
- Example: `2026-02-14 17:54:42 [INFO] scheduler [app.py:145] - Created backup: scheduler-backup-20260214-175442.db (0.05 MB)`
- Includes source file and line number for debugging
- Automatic rotation: 10 MB per file, 5 backup files retained
- Total log storage: ~50 MB maximum

### Log Levels

- **DEBUG**: Detailed diagnostic information (file only)
- **INFO**: General operational messages (console + file)
- **WARNING**: Warning messages for potential issues (console + file)
- **ERROR**: Error messages with stack traces (console + file)
- **CRITICAL**: Critical failures requiring immediate attention (console + file)

### What Gets Logged

1. **Application Lifecycle:**
   - Startup and shutdown
   - Configuration changes
   - Component initialization

2. **Database Operations:**
   - Backup creation and rotation
   - Database corruption detection
   - Integrity check results

3. **Audit Trail:**
   - All user authentication (login/logout)
   - Flight operations (create, update, delete, restore)
   - Settings changes
   - Admin actions

4. **System Health:**
   - Scheduled backup operations
   - Disk space warnings
   - Database connectivity issues

### Viewing Logs

**Real-time monitoring:**
```bash
# Container logs (stderr only)
docker compose -f docker/flt-scheduler logs -f

# File logs with tail
docker exec flt-scheduler-flt-scheduler-1 tail -f data/logs/scheduler.log
```

**Historical logs:**
```bash
# View last 100 lines
docker compose -f docker/flt-scheduler logs --tail=100

# Search for errors
docker compose -f docker/flt-scheduler logs | grep ERROR

# View rotated log files
docker exec flt-scheduler-flt-scheduler-1 ls -lh data/logs/
```

### Log Rotation

- **Max file size**: 10 MB
- **Backup count**: 5 files
- **Naming pattern**: `scheduler.log`, `scheduler.log.1`, `scheduler.log.2`, etc.
- **Total storage**: ~50 MB (prevents disk space issues)
- **Automatic cleanup**: Oldest logs deleted when limit reached

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
