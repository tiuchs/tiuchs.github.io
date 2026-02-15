# Flight Scheduler User Guide

## Table of Contents

- [Getting Started](#getting-started)
- [Docker Container Operations](#docker-container-operations)
- [Version Control](#version-control)
- [Database Backups](#database-backups)
- [Database Stability Features](#database-stability-features)
- [Soft Delete for Flights](#soft-delete-for-flights)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)
- [FAQ](#faq)

---

## Getting Started

### First Time Setup

1. **Start the application:**
   ```bash
   docker compose -f docker/flt-scheduler up -d
   ```

2. **Access the web interface:**
   - Open your browser to `http://localhost:8080`

3. **Sign in with default admin credentials:**
   - Username: `admin`
   - Password: `admin123`
   - **⚠️ IMPORTANT:** Change these credentials immediately in production!

4. **Initial configuration:**
   - Navigate to Settings → Admin Settings
   - Add crew members in Crew Management
   - Add aircraft in Aircraft Management

### Changing Default Admin Password

1. Sign in as admin
2. Go to Settings → Admin Settings
3. Find your admin user in the User Management table
4. Enter a new password in the "Reset Password" field
5. Click "Update"

---

## Docker Container Operations

This section covers how to manage the Flight Scheduler Docker container, including building, deploying, starting, stopping, and viewing logs.

### Prerequisites

- Docker and Docker Compose installed on your system
- Terminal/command line access
- Navigate to the project directory: `/Users/timiuchs/Documents/tiuchs.github.io/docker`

### Building the Container

**Build the container image:**

```bash
docker compose -f flt-scheduler build
```

**Build without using cache (force rebuild):**

```bash
docker compose -f flt-scheduler build --no-cache
```

**When to rebuild:**
- After modifying the Dockerfile
- After updating application code
- When dependencies have changed
- To ensure you have the latest version

### Starting/Deploying the Container

**Start the container in detached mode (recommended):**

```bash
docker compose -f flt-scheduler up -d
```

**Start with rebuild (build and start in one command):**

```bash
docker compose -f flt-scheduler up -d --build
```

**Start in foreground (logs visible, blocks terminal):**

```bash
docker compose -f flt-scheduler up
```

**What happens when starting:**
1. Container starts with health check monitoring
2. Application initializes on port 8080
3. Automatic startup backup is created
4. Health check begins after 40-second startup period
5. Health checks run every 30 seconds

### Stopping the Container

**Stop the running container:**

```bash
docker compose -f flt-scheduler stop
```

**Stop and remove the container:**

```bash
docker compose -f flt-scheduler down
```

**Stop, remove, and delete volumes (⚠️ WARNING: This deletes your data!):**

```bash
docker compose -f flt-scheduler down -v
```

### Restarting the Container

**Restart the container:**

```bash
docker compose -f flt-scheduler restart
```

**Stop, rebuild, and start (full refresh):**

```bash
docker compose -f flt-scheduler down
docker compose -f flt-scheduler build
docker compose -f flt-scheduler up -d
```

### Viewing Container Status

**Check if container is running:**

```bash
docker compose -f flt-scheduler ps
```

**View detailed container information:**

```bash
docker inspect flt-scheduler-flt-scheduler-1
```

**Check container health status:**

```bash
docker compose -f flt-scheduler ps
```

Look for the "STATUS" column - it should show "Up" and "(healthy)" when running properly.

### Viewing Logs

**View all logs:**

```bash
docker compose -f flt-scheduler logs
```

**View logs with real-time follow (live updates):**

```bash
docker compose -f flt-scheduler logs -f
```

**View last 100 lines of logs:**

```bash
docker compose -f flt-scheduler logs --tail 100
```

**View logs with timestamps:**

```bash
docker compose -f flt-scheduler logs -t
```

**View logs and follow with tail:**

```bash
docker compose -f flt-scheduler logs -f --tail 50
```

**Search logs for specific text (using grep):**

```bash
docker compose -f flt-scheduler logs | grep "ERROR"
docker compose -f flt-scheduler logs | grep "backup"
docker compose -f flt-scheduler logs | grep "Flight created"
```

### Common Docker Operations

**View disk space used by containers:**

```bash
docker system df
```

**Remove stopped containers and unused images (cleanup):**

```bash
docker system prune
```

**View all running containers:**

```bash
docker ps
```

**View all containers (including stopped):**

```bash
docker ps -a
```

**Execute command inside running container (access shell):**

```bash
docker compose -f flt-scheduler exec flt-scheduler /bin/sh
```

### Environment Variables

The container uses these environment variables (defined in the compose file):

- `SECRET_KEY` - Flask session encryption key (default: `dev-change-me`)
- `DEFAULT_ADMIN_USER` - Initial admin username (default: `admin`)
- `DEFAULT_ADMIN_PASSWORD` - Initial admin password (default: `admin123`)

**Override defaults at startup:**

```bash
SECRET_KEY=your-secret-key \
DEFAULT_ADMIN_USER=youradmin \
DEFAULT_ADMIN_PASSWORD=yourpassword \
docker compose -f flt-scheduler up -d
```

### Port Configuration

The application runs on **port 8080** by default.

**If port 8080 is already in use:**

1. Find what's using port 8080:
   ```bash
   lsof -i :8080
   ```

2. Stop the conflicting container:
   ```bash
   docker stop <container-name>
   ```

3. Or modify the compose file to use a different port:
   ```yaml
   ports:
     - "8081:8080"  # Access on http://localhost:8081
   ```

### Troubleshooting Docker Issues

**Container won't start:**

```bash
# Check logs for errors
docker compose -f flt-scheduler logs

# Verify no port conflicts
lsof -i :8080

# Try rebuilding
docker compose -f flt-scheduler down
docker compose -f flt-scheduler build --no-cache
docker compose -f flt-scheduler up -d
```

**Container is unhealthy:**

```bash
# Check health check output
docker inspect flt-scheduler-flt-scheduler-1 | grep -A 10 Health

# View recent logs
docker compose -f flt-scheduler logs --tail 50

# Verify the health endpoint
curl http://localhost:8080/health
```

**Database issues after restart:**

```bash
# Check if data volume is mounted
docker compose -f flt-scheduler ps -v

# Verify database file exists
ls -lh flt-scheduler-app/data/
```

---

## Version Control

The Flight Scheduler uses semantic versioning to track releases and changes. The current version is displayed in the application footer and available via the health endpoint.

### Current Version

**v0.9.0-beta** - Beta release (pre-1.0)

The application is currently in beta, meaning it's feature-complete but still undergoing testing and refinement before the official 1.0 production release.

### Checking the Version

**In the Web Interface:**

The version is displayed at the bottom of every page in the footer:
- Look for the version tag (e.g., `v0.9.0-beta`) at the bottom of any page
- The footer shows: "1-227 AB Flight Scheduler v0.9.0-beta"

**Via Health Endpoint:**

```bash
curl http://localhost:8080/health
```

Response includes version information:
```json
{
  "status": "healthy",
  "version": "0.9.0-beta",
  "timestamp": "2026-02-14 12:00:00"
}
```

**In Docker Image:**

View image labels to see version metadata:

```bash
docker inspect flt-scheduler:0.9.0-beta | grep -A 10 Labels
```

### Version Numbering Scheme

The application follows [Semantic Versioning](https://semver.org/):

**Format: MAJOR.MINOR.PATCH[-PRERELEASE]**

- **MAJOR** (e.g., 1.x.x) - Incompatible API changes or major overhauls
- **MINOR** (e.g., x.1.x) - New features, backwards-compatible
- **PATCH** (e.g., x.x.1) - Bug fixes, backwards-compatible
- **PRERELEASE** (e.g., -beta, -rc1) - Pre-release versions

**Examples:**
- `0.9.0-beta` - Current beta version
- `0.9.1-beta` - Bug fix in beta
- `0.10.0-beta` - New features in beta
- `1.0.0` - First production release
- `1.1.0` - New features in production
- `1.1.1` - Bug fix in production

### Beta Phase (0.x.x)

The application is currently in **beta** (versions 0.x.x), which means:

✅ **What Beta Means:**
- All core features are implemented and working
- Application is stable for testing and evaluation
- Suitable for training and development environments
- Actively receiving bug fixes and improvements
- Documentation is comprehensive

⚠️ **Beta Considerations:**
- Still undergoing testing and refinement
- Minor issues may be discovered
- Features may be adjusted based on feedback
- Version 1.0.0 will be released when production-ready

### Updating to a New Version

**Step 1: Check for updates**

Review the [CHANGELOG.md](CHANGELOG.md) file to see what's new:

```bash
cat flt-scheduler-app/CHANGELOG.md
```

**Step 2: Update the VERSION file**

Edit the VERSION file with the new version number:

```bash
echo "0.9.1-beta" > flt-scheduler-app/VERSION
```

**Step 3: Rebuild and deploy**

```bash
# Stop the current container
docker compose -f flt-scheduler down

# Rebuild with new version
VERSION=0.9.1-beta docker compose -f flt-scheduler build

# Start the updated container
docker compose -f flt-scheduler up -d

# Verify the new version
curl http://localhost:8080/health | grep version
```

### Release History

See [CHANGELOG.md](CHANGELOG.md) for complete release history and detailed change notes.

### Roadmap to 1.0

**Planned before 1.0.0 release:**
- Complete user acceptance testing
- Performance optimization
- Final documentation review
- Security audit
- Production deployment testing

**Version 1.0.0** will be released when:
- All critical bugs are resolved
- User acceptance testing is complete
- Documentation is finalized
- Application is approved for full production deployment

---

## Database Backups

### Overview

The Flight Scheduler automatically protects your flight data with automated backups. This ensures you can recover your mission schedules, crew assignments, and flight records if anything goes wrong.

### Automatic Backup Features

**What Happens Automatically:**

1. **Startup Backup** - A backup is created every time the application starts
2. **Daily Backup** - A new backup is created every 24 hours
3. **Automatic Cleanup** - Backups older than 7 days are automatically deleted to save disk space
4. **Integrity Checks** - Every backup is verified to ensure it's not corrupted

**Where Backups Are Stored:**

```
docker/flt-scheduler-app/data/backups/
└── scheduler-backup-YYYYMMDD-HHMMSS.db
```

Example: `scheduler-backup-20260214-113045.db` (backup created on Feb 14, 2026 at 11:30:45 UTC)

### Creating Manual Backups

**When to Create Manual Backups:**

- Before making major changes (mass deletions, bulk imports)
- Before software updates
- At the end of important operations periods
- Before database maintenance

**How to Create a Manual Backup:**

1. Sign in as an admin user
2. Navigate to **Settings** → **Admin Settings**
3. Scroll to the **Database Backups** section
4. Click the **"Create Backup Now"** button
5. The page will refresh and your new backup will appear in the list

### Viewing Available Backups

1. Go to **Settings** → **Admin Settings**
2. Scroll to the **Database Backups** section
3. You'll see a table showing:
   - **Backup File** - The filename with timestamp
   - **Size** - File size in megabytes
   - **Created (UTC)** - When the backup was made
   - **Age** - How many days old the backup is
   - **Download** - Button to download the backup file

### Downloading Backups

**To download a backup for safekeeping:**

1. Navigate to the Database Backups section
2. Find the backup you want to download
3. Click the **"Download"** button next to it
4. Save the file to a safe location (external drive, cloud storage, etc.)

**Recommended Download Schedule:**
- Download a backup weekly and store it off-server
- Keep monthly backups for historical records
- Store backups in multiple locations for disaster recovery

### Restoring from a Backup

**⚠️ WARNING:** Restoring a backup will replace all current data with the data from the backup. Any changes made after the backup was created will be lost.

**Step-by-Step Restore Process:**

1. **Stop the application:**
   ```bash
   docker compose -f docker/flt-scheduler down
   ```

2. **Identify the backup file you want to restore:**
   - List available backups:
     ```bash
     ls -lh docker/flt-scheduler-app/data/backups/
     ```
   - Choose the appropriate backup file

3. **Backup your current database (optional but recommended):**
   ```bash
   cp docker/flt-scheduler-app/data/scheduler.db \
      docker/flt-scheduler-app/data/scheduler-before-restore-$(date +%Y%m%d-%H%M%S).db
   ```

4. **Restore the backup:**
   ```bash
   cp docker/flt-scheduler-app/data/backups/scheduler-backup-YYYYMMDD-HHMMSS.db \
      docker/flt-scheduler-app/data/scheduler.db
   ```
   Replace `YYYYMMDD-HHMMSS` with your actual backup timestamp.

5. **Restart the application:**
   ```bash
   docker compose -f docker/flt-scheduler up -d
   ```

6. **Verify the restore:**
   - Sign in to the application
   - Check that your data is correct
   - Verify recent flights and schedules

**Common Restore Scenarios:**

| Scenario | What to Restore |
|----------|----------------|
| Accidental deletion of flights today | Last night's automatic backup |
| Data corruption discovered | Most recent verified good backup |
| Need to undo bulk import | Backup created before the import |
| System crash recovery | Most recent available backup |

---

## Database Stability Features

### What Makes Your Data Safe

The Flight Scheduler uses several advanced database features to protect your data:

#### 1. Write-Ahead Logging (WAL)

**What it does:**
- Allows multiple users to view data while updates are happening
- Prevents database locks that can slow down the application
- Improves performance by 2-3x for typical flight scheduling operations

**What you'll notice:**
- Faster page loads when multiple users are active
- No "database is locked" errors
- Smoother operation during peak usage times

**Technical details:**
- Creates additional files: `scheduler.db-wal` and `scheduler.db-shm`
- These are temporary working files - don't delete them!
- They're automatically merged back into the main database

#### 2. Automatic Integrity Checks

**What it does:**
- Checks database health every time the application starts
- Detects corruption before it causes problems
- Automatically quarantines corrupted databases

**What you'll notice:**
- Application starts with a clean, verified database
- Corrupted databases are backed up with `.corrupt-TIMESTAMP.bak` extension
- A fresh database is created if corruption is detected

#### 3. Foreign Key Constraints

**What it does:**
- Ensures data relationships remain valid
- Prevents orphaned records (e.g., flights referencing deleted aircraft)
- Maintains data consistency

**What you'll notice:**
- Can't delete crew members assigned to future flights
- Can't delete aircraft with scheduled missions
- Data integrity warnings instead of silent data loss

#### 4. Connection Timeouts

**What it does:**
- Waits up to 5 seconds if database is temporarily locked
- Automatically retries operations instead of failing immediately
- Handles concurrent access gracefully

**What you'll notice:**
- Fewer "database busy" errors
- Operations complete even during high usage
- Better reliability with multiple simultaneous users

#### 5. Large Memory Cache

**What it does:**
- Keeps 64MB of frequently accessed data in memory
- Reduces disk reads for common queries
- Speeds up dashboard and schedule views

**What you'll notice:**
- Faster page loads for frequently viewed data
- Quick access to today's flight schedule
- Responsive UI even with large flight databases

---

## Soft Delete for Flights

### What is Soft Delete?

When you delete a flight in the Flight Scheduler, it's not permanently removed from the database. Instead, it's **soft deleted** - marked as deleted but preserved in case you need to recover it later.

**Key benefits:**
- **Accident protection**: Recover flights deleted by mistake
- **Audit trail**: Maintain complete history of all flight operations
- **Data preservation**: No permanent data loss from accidental deletions
- **Admin control**: Only admins can permanently remove flights

### How Soft Delete Works

#### For Schedulers (Normal Delete)

When a scheduler deletes a flight:

1. Click the "Delete" button on any flight
2. The flight disappears from all normal views (dashboard, weekly, daily)
3. The flight is preserved in the database with a "deleted" flag
4. An audit log entry records who deleted it and when

**What you'll notice:**
- Deleted flights don't appear in any schedules or exports
- The mission ID is released and can be reused
- No confirmation required (soft delete is safe)

#### For Admins (Recovery Interface)

Admins have special access to view and manage deleted flights:

**Access the deleted flights page:**
1. Sign in as admin
2. Navigate to Settings → Admin Settings
3. Scroll to "Deleted Flights" section
4. Click "View Deleted Flights"

**What you can do:**

- **View all deleted flights**: See complete details of every soft-deleted flight
  - When it was deleted
  - Original mission details (date, time, crew, aircraft, etc.)
  - Original status (planned, approved, cancelled)

- **Restore a flight**: Bring back an accidentally deleted flight
  - Click "Restore" button next to the flight
  - Flight returns to active status with all original details
  - Audit log records the restoration
  - Flight appears in schedules again immediately

- **Purge permanently**: Remove a flight forever
  - Click "Purge" button (requires confirmation)
  - **WARNING**: This cannot be undone!
  - Flight is completely removed from the database
  - Useful for cleaning up truly unwanted records

### Common Scenarios

#### Scenario 1: Accidental Deletion

**Problem**: A scheduler accidentally deleted tomorrow's important mission.

**Solution**:
1. Admin goes to Settings → Admin Settings → View Deleted Flights
2. Find the mission (sorted by deletion time, newest first)
3. Click "Restore"
4. Mission immediately reappears in schedules

**Time to recover**: Under 30 seconds

#### Scenario 2: Cleaning Up Old Test Data

**Problem**: Database has months of old test flights from initial setup.

**Solution**:
1. Scheduler deletes all test flights (normal delete)
2. Admin reviews deleted flights to confirm they're test data
3. Admin purges unwanted flights permanently
4. Database stays clean and manageable

**Best practice**: Review deleted flights monthly, purge confirmed unwanted data

### Technical Details

- Deleted flights have two special fields:
  - `deleted`: Flag (0 = active, 1 = deleted)
  - `deleted_at`: Timestamp of deletion (UTC)

- All flight queries automatically filter out deleted flights
- Deleted flights are excluded from all normal views and exports

### Best Practices

1. **Regular review**: Check deleted flights monthly
2. **Quick recovery**: Restore accidental deletions immediately
3. **Quarterly cleanup**: Purge confirmed unwanted flights every 3 months
4. **Before purging**: Verify you have recent backups
5. **Train users**: Explain that delete is safe and reversible

---

## Troubleshooting

### Backup Issues

#### Problem: "No backups available yet"

**Symptoms:**
- Backup list shows no files
- Fresh installation

**Solution:**
1. Wait a few minutes after first startup
2. Check application logs:
   ```bash
   docker compose -f flt-scheduler logs flt-scheduler | grep backup
   ```
3. Look for "[backup] Created backup" message
4. If no backup was created, check disk space

#### Problem: Backup failed

**Symptoms:**
- Error message when creating manual backup
- Logs show "[backup] Backup failed"

**Possible Causes & Solutions:**

1. **Insufficient disk space:**
   ```bash
   df -h docker/flt-scheduler-app/data/
   ```
   - Free up space if less than 100MB available
   - Delete old backups manually if needed

2. **Permission issues:**
   ```bash
   ls -la docker/flt-scheduler-app/data/
   ```
   - Ensure backup directory is writable
   - Fix permissions:
     ```bash
     chmod 755 docker/flt-scheduler-app/data/backups
     ```

3. **Database corruption:**
   - Check logs for "integrity check failed"
   - See [Database Corruption](#database-corruption) section

#### Problem: Can't download backup

**Symptoms:**
- Download button doesn't work
- Gets redirected to login page

**Solution:**
1. Ensure you're logged in as an admin user
2. Check that you have the "admin" role in User Management
3. Try logging out and back in
4. Clear browser cache and cookies

### Database Issues

#### Problem: "Database is locked" errors

**Symptoms:**
- Error message when saving flights
- Operations fail with timeout

**Solution:**
1. **Wait and retry** - The 5-second timeout should handle this automatically
2. **Check for long-running operations:**
   ```bash
   docker compose -f flt-scheduler logs -f
   ```
3. **Restart the application:**
   ```bash
   docker compose -f flt-scheduler restart
   ```

#### Problem: Database corruption detected

**Symptoms:**
- Application won't start
- Logs show "Quarantined corrupt database"
- Error messages about integrity check failures

**Solution:**

1. **Locate the quarantined database:**
   ```bash
   ls -lh docker/flt-scheduler-app/data/*.corrupt-*.bak
   ```

2. **Restore from latest backup:**
   ```bash
   # Stop the application
   docker compose -f flt-scheduler down

   # Find the most recent good backup
   ls -lt docker/flt-scheduler-app/data/backups/

   # Restore it
   cp docker/flt-scheduler-app/data/backups/scheduler-backup-YYYYMMDD-HHMMSS.db \
      docker/flt-scheduler-app/data/scheduler.db

   # Restart
   docker compose -f flt-scheduler up -d
   ```

3. **Verify restoration:**
   - Sign in and check data
   - Review recent flights
   - Create a new manual backup

#### Problem: WAL files growing very large

**Symptoms:**
- `scheduler.db-wal` file is over 100MB
- Slow performance
- High disk usage

**Solution:**

1. **Checkpoint the WAL manually:**
   ```bash
   docker exec -it flt-scheduler-flt-scheduler-1 python3 -c "
   import sqlite3
   conn = sqlite3.connect('data/scheduler.db')
   conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
   conn.close()
   print('WAL checkpoint completed')
   "
   ```

2. **Restart the application:**
   ```bash
   docker compose -f flt-scheduler restart
   ```

3. **Check WAL file size:**
   ```bash
   ls -lh docker/flt-scheduler-app/data/scheduler.db-wal
   ```

### Application Issues

#### Problem: Application won't start

**Symptoms:**
- Container starts but crashes immediately
- Can't access web interface
- Logs show errors

**Diagnostic Steps:**

1. **Check container status:**
   ```bash
   docker compose -f flt-scheduler ps
   ```

2. **View recent logs:**
   ```bash
   docker compose -f flt-scheduler logs --tail=50 flt-scheduler
   ```

3. **Common error patterns:**

   **"Database error during integrity check"**
   - Database is corrupted
   - Follow [Database Corruption](#database-corruption) steps

   **"Permission denied"**
   - File permissions issue
   - Fix with:
     ```bash
     chmod -R 755 docker/flt-scheduler-app/data
     ```

   **"Port already in use"**
   - Another service is using port 8080
   - Change port in docker-compose file or stop conflicting service

#### Problem: Slow performance

**Symptoms:**
- Pages load slowly
- Delays when saving flights
- Laggy user interface

**Solutions:**

1. **Check database size:**
   ```bash
   ls -lh docker/flt-scheduler-app/data/scheduler.db
   ```
   - If over 500MB, consider archiving old flights

2. **Restart application:**
   ```bash
   docker compose -f flt-scheduler restart
   ```

3. **Check system resources:**
   ```bash
   docker stats flt-scheduler-flt-scheduler-1
   ```
   - Look for high CPU or memory usage

4. **Create a manual backup and restart:**
   - This triggers WAL checkpoint
   - Optimizes database structure

---

## Best Practices

### Daily Operations

1. **Start your day with a quick check:**
   - Verify backup was created overnight (check logs)
   - Review today's flight schedule
   - Confirm all crew and aircraft are current

2. **Before bulk changes:**
   - Create a manual backup
   - Document what you're about to change
   - Verify the backup completed successfully

3. **End of day:**
   - Complete all flight closeouts
   - Verify tomorrow's schedule is approved
   - Check that backups are running (occasional spot check)

### Weekly Maintenance

1. **Monday morning:**
   - Review last week's audit log for anomalies
   - Download a backup for off-site storage
   - Clean up old cancelled missions if needed

2. **Backup hygiene:**
   - Download and archive one weekly backup
   - Store it in a different location than the server
   - Label it clearly with the date range it covers

### Monthly Tasks

1. **Security review:**
   - Review user accounts and deactivate unused ones
   - Ensure all users have appropriate roles
   - Consider changing admin password

2. **Data review:**
   - Check database size and growth trend
   - Review audit logs for unusual activity
   - Archive completed missions if database is large

### Disaster Recovery Planning

1. **Backup strategy:**
   - Automatic daily backups (enabled by default) ✓
   - Weekly manual backup downloads ✓
   - Monthly archive backups stored off-site ✓
   - Test restore procedure quarterly

2. **What to backup:**
   - Database files (handled automatically)
   - Docker compose configuration
   - Environment variables and settings
   - Custom crew/aircraft lists

3. **Recovery time objectives:**
   - Database restore: 5-10 minutes
   - Full system rebuild: 30-60 minutes
   - Data loss: Maximum 24 hours (last daily backup)

---

## FAQ

### General Questions

**Q: How much disk space do I need?**

A: Minimum recommendations:
- Fresh install: 100 MB
- Small unit (1-2 aircraft): 500 MB
- Medium unit (3-5 aircraft): 1 GB
- Large unit (6+ aircraft): 2+ GB

Account for backups: Add 7x your database size for the 7-day retention.

**Q: How many users can use the system simultaneously?**

A: The application supports multiple concurrent users thanks to WAL mode. Typical deployments handle:
- 5-10 active users: Excellent performance
- 10-20 active users: Good performance
- 20+ active users: May see slowdowns during peak times

**Q: What happens if the server crashes?**

A: Your data is protected:
1. WAL mode ensures database integrity even during crashes
2. Latest backup (max 24 hours old) can be restored
3. All completed transactions are preserved
4. Uncommitted changes are safely rolled back

### Backup Questions

**Q: Why are there multiple database files?**

A: You'll see three files:
- `scheduler.db` - Main database (your actual data)
- `scheduler.db-wal` - Write-Ahead Log (temporary working file)
- `scheduler.db-shm` - Shared memory index (temporary working file)

All three work together. Never delete the WAL or SHM files while the app is running!

**Q: Can I manually delete old backups?**

A: Yes, but normally you don't need to:
- Backups older than 7 days are auto-deleted
- You can safely delete backups from the `data/backups/` directory
- Keep at least one recent backup before deleting others
- Downloaded backups stored elsewhere are safe to keep indefinitely

**Q: What's the difference between automatic and manual backups?**

A: They're identical in content and quality:
- **Automatic**: Created on schedule (startup + daily)
- **Manual**: Created when you click the button
- Both use the same backup process
- Both are subject to the 7-day retention policy
- Both appear in the backup list

**Q: Can I schedule backups more frequently?**

A: Currently daily backups are standard. For more frequent backups:
- Use the manual backup button before major operations
- Contact your system administrator to modify `BACKUP_RETENTION_DAYS`
- Consider implementing external backup tools if needed

### Database Questions

**Q: What does "WAL checkpoint" mean?**

A: WAL (Write-Ahead Log) checkpoint is the process of:
1. Taking all changes from the temporary WAL file
2. Writing them permanently to the main database
3. Clearing the WAL file

This happens automatically during backups and periodically during normal operation.

**Q: Why do I see deprecation warnings in the logs?**

A: The warnings about `datetime.utcnow()` are normal:
- They don't affect functionality
- They're informational messages for developers
- A future update will resolve them
- Your data and operations are not impacted

**Q: How do I know if my database is healthy?**

A: Check these indicators:
1. Application starts without errors
2. No "corrupt" backup files in the data directory
3. Backups complete successfully
4. No "integrity check failed" in logs

Run a manual integrity check:
```bash
docker exec -it flt-scheduler-flt-scheduler-1 python3 -c "
import sqlite3
conn = sqlite3.connect('data/scheduler.db')
result = conn.execute('PRAGMA integrity_check').fetchone()
print('Database health:', result[0])
conn.close()
"
```

You should see: `Database health: ok`

### Performance Questions

**Q: Why is the first page load slow after restart?**

A: This is normal:
- Database cache is empty after restart
- First queries load data into memory
- Subsequent loads are much faster
- This is the 64MB cache system at work

**Q: Does creating backups slow down the application?**

A: Minimal impact:
- Backup process takes 1-5 seconds for typical databases
- WAL checkpoint happens automatically
- Daily backups run in background
- Manual backups may cause brief pause (< 1 second)

**Q: How can I improve performance?**

A: Performance optimization tips:
1. Restart application weekly
2. Keep database under 500MB
3. Archive old completed missions
4. Ensure adequate system resources
5. Use SSD storage if possible
6. Close unused browser tabs

---

## Health Monitoring

### Health Check Endpoint

The application provides a `/health` endpoint for automated monitoring:

```bash
curl http://localhost:8080/health
```

### Understanding Health Status

**Status Values:**
- `healthy` - All systems operational
- `degraded` - Minor issues detected (still functional)
- `unhealthy` - Critical issues detected (service unavailable)

**Health Checks Performed:**

1. **Database Connectivity** - Can the app connect to the database?
2. **Database Integrity** - Is the database structure valid?
3. **Disk Space** - Is there enough free disk space?
4. **Backups** - Are backups being created?

### Reading Health Check Results

**Example Healthy Response:**
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

**What Each Check Means:**

| Check | OK Status | Warning Status | Failed Status |
|-------|-----------|----------------|---------------|
| **database_connectivity** | Can connect | N/A | Cannot connect |
| **database_integrity** | Database valid | Structure issues | Corruption detected |
| **disk_space** | > 100 MB free | 50-100 MB free | < 50 MB free |
| **backups** | Backups exist | No recent backups | Backup system failed |

### Using Health Checks for Monitoring

**Manual Check:**
```bash
# Simple check
curl http://localhost:8080/health

# Formatted output
curl -s http://localhost:8080/health | python3 -m json.tool

# Check status code
curl -w "%{http_code}" -o /dev/null -s http://localhost:8080/health
```

**Expected Output:**
- `200` - Healthy or degraded (still usable)
- `503` - Unhealthy (service down)

**Automated Monitoring:**

The health endpoint is automatically used by:
- Docker health checks (every 30 seconds)
- Kubernetes liveness/readiness probes
- External monitoring tools (Prometheus, Nagios, etc.)

**Docker Health Status:**
```bash
docker compose -f flt-scheduler ps
```

Look for `(healthy)`, `(unhealthy)`, or `(starting)` in the STATUS column.

### Responding to Health Issues

**If `database_connectivity` fails:**
1. Check if container is running
2. Check database file exists
3. Check file permissions
4. Restart application

**If `database_integrity` fails:**
1. Stop application immediately
2. Restore from latest backup
3. Do NOT attempt to repair
4. See [Database Corruption](#database-corruption) section

**If `disk_space` is critical:**
1. Delete old backups manually
2. Clean up log files
3. Archive old flight data
4. Add more storage if possible

**If `backups` shows warning:**
1. Check backup logs
2. Verify backup directory exists
3. Create manual backup
4. Check disk space

---

## Getting Help

### Check Logs First

Most issues can be diagnosed from logs:

```bash
# View recent logs
docker compose -f flt-scheduler logs --tail=100 flt-scheduler

# Follow logs in real-time
docker compose -f flt-scheduler logs -f flt-scheduler

# Search for errors
docker compose -f flt-scheduler logs flt-scheduler | grep -i error

# Search for backup issues
docker compose -f flt-scheduler logs flt-scheduler | grep backup
```

### Common Log Messages

| Log Message | Meaning | Action Needed |
|-------------|---------|---------------|
| `[backup] Created backup` | Backup succeeded | None - normal operation |
| `[backup] Backup failed` | Backup failed | Check disk space, permissions |
| `[db-recovery] Quarantined corrupt database` | Database corruption detected | Restore from backup |
| `[backup] Deleted old backup` | Routine cleanup | None - normal operation |
| `Integrity check failed` | Database health issue | Restore from backup |

### Information to Gather for Support

If you need help, collect this information:

1. **System information:**
   ```bash
   docker --version
   docker compose version
   uname -a
   ```

2. **Application logs:**
   ```bash
   docker compose -f flt-scheduler logs --tail=200 > flight-scheduler-logs.txt
   ```

3. **Database information:**
   ```bash
   ls -lh docker/flt-scheduler-app/data/
   ```

4. **Error description:**
   - What were you trying to do?
   - What happened instead?
   - When did it start happening?
   - Can you reproduce it?

### Emergency Contact

For critical issues affecting flight operations:

1. **Immediate workaround:** Restore from last night's backup
2. **Document the issue:** Save logs and error messages
3. **Contact your system administrator**
4. **Report the issue:** Include all gathered information

---

## Glossary

- **Admin** - User role with full system access
- **Audit Log** - Record of all system changes and user actions
- **Backup** - Copy of the database at a specific point in time
- **Checkpoint** - Process of merging WAL changes to main database
- **Corruption** - Database damage that prevents normal operation
- **Foreign Key** - Database link ensuring data relationships remain valid
- **Integrity Check** - Verification that database structure is valid
- **Quarantine** - Isolating a corrupt database file with .bak extension
- **Retention** - How long backups are kept before deletion
- **Restore** - Replacing current database with a backup copy
- **Scheduler** - User role that can create/edit flight schedules
- **WAL** - Write-Ahead Logging, a database performance feature
- **Approver** - User role that can approve/cancel flight status
