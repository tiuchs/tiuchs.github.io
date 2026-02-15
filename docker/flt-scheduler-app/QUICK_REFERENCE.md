# Flight Scheduler - Quick Reference Guide

**⚠️ Print this page and post it near your workstation**

---

## Emergency Procedures

### Application Won't Start

```bash
# 1. Check status
docker compose -f docker/flt-scheduler ps

# 2. View logs
docker compose -f docker/flt-scheduler logs --tail=50

# 3. Restart
docker compose -f docker/flt-scheduler restart

# 4. If still failing, restore from backup (see Restore section)
```

### Restore from Backup (Emergency)

```bash
# Stop application
docker compose -f docker/flt-scheduler down

# List available backups
ls -lt docker/flt-scheduler-app/data/backups/

# Restore the backup
cp docker/flt-scheduler-app/data/backups/scheduler-backup-YYYYMMDD-HHMMSS.db \
   docker/flt-scheduler-app/data/scheduler.db

# Start application
docker compose -f docker/flt-scheduler up -d
```

---

## Daily Checklist

### Morning Startup

- [ ] Verify application is running: `http://localhost:8080`
- [ ] Check that backup ran overnight (check logs once weekly)
- [ ] Review today's flight schedule

### Before Major Changes

- [ ] Create manual backup (Settings → Admin → Create Backup Now)
- [ ] Wait for confirmation message
- [ ] Verify backup appears in list

### End of Day

- [ ] Complete all flight closeouts
- [ ] Approve tomorrow's flights
- [ ] Save any in-progress work

---

## Common Commands

### View Application Status
```bash
docker compose -f docker/flt-scheduler ps
```

### View Recent Logs
```bash
docker compose -f docker/flt-scheduler logs --tail=100 flt-scheduler
```

### Restart Application
```bash
docker compose -f docker/flt-scheduler restart
```

### Stop Application
```bash
docker compose -f docker/flt-scheduler down
```

### Start Application
```bash
docker compose -f docker/flt-scheduler up -d
```

### Check Disk Space
```bash
df -h docker/flt-scheduler-app/data/
```

### List Backups
```bash
ls -lh docker/flt-scheduler-app/data/backups/
```

---

## Access Information

### Default Login (First Time Only)
- **URL:** `http://localhost:8080`
- **Username:** `admin`
- **Password:** `admin123`
- **⚠️ CHANGE IMMEDIATELY IN PRODUCTION**

### Change Admin Password
1. Sign in as admin
2. Settings → Admin Settings
3. Find admin user → Enter new password → Update

---

## User Roles

| Role | Permissions |
|------|-------------|
| **User** | View flights, export CSV |
| **Scheduler** | + Create/edit/delete flights |
| **Approver** | + Approve/cancel flights |
| **Admin** | + Full system access, settings, backups |

---

## Backup Information

### Automatic Backups
- **When:** Every 24 hours + on startup
- **Retention:** 7 days
- **Location:** `data/backups/`
- **Format:** `scheduler-backup-YYYYMMDD-HHMMSS.db`

### Manual Backup
1. Settings → Admin Settings
2. Scroll to "Database Backups"
3. Click "Create Backup Now"
4. Verify backup appears in list

### Download Backup (for off-site storage)
1. Settings → Admin Settings → Database Backups
2. Click "Download" next to desired backup
3. Save to external drive or cloud storage

---

## Troubleshooting Quick Guide

### Problem: Can't Access Website

**Check:**
```bash
docker compose -f docker/flt-scheduler ps
```

**Solution:**
```bash
docker compose -f docker/flt-scheduler restart
```

---

### Problem: "Database is Locked"

**Solution:**
- Wait 5-10 seconds and try again
- If persists, restart application

---

### Problem: Changes Not Saving

**Check:**
1. Are you logged in?
2. Do you have the right role (Scheduler/Admin)?
3. Are all required fields filled?

**Solution:**
- Log out and back in
- Try again with all fields completed

---

### Problem: Backup Failed

**Check Disk Space:**
```bash
df -h docker/flt-scheduler-app/data/
```

**Solution:**
- Free up space (delete old downloads, logs)
- Delete old backups manually if needed
- Restart application

---

### Problem: Database Corrupted

**Check Logs:**
```bash
docker compose -f docker/flt-scheduler logs | grep -i corrupt
```

**Emergency Restore:**
```bash
# Stop
docker compose -f docker/flt-scheduler down

# Restore latest backup
cp docker/flt-scheduler-app/data/backups/$(ls -t docker/flt-scheduler-app/data/backups/ | head -1) \
   docker/flt-scheduler-app/data/scheduler.db

# Start
docker compose -f docker/flt-scheduler up -d
```

---

## File Locations

### Important Files
```
docker/flt-scheduler-app/data/
├── scheduler.db              # Main database
├── scheduler.db-wal          # Working file (don't delete!)
├── scheduler.db-shm          # Working file (don't delete!)
└── backups/                  # Backup directory
    └── scheduler-backup-*.db # Backup files
```

### Corrupted Database Archives
```
docker/flt-scheduler-app/data/
└── scheduler.db.corrupt-TIMESTAMP.bak
```

---

## Warning Signs

### Immediate Action Required

- ❌ Application won't start
- ❌ "Database corrupted" in logs
- ❌ Can't create backups
- ❌ WAL file over 100MB

**Action:** Restore from backup immediately

### Monitor Closely

- ⚠️ Slow performance
- ⚠️ Frequent "database locked" errors
- ⚠️ Backup failures
- ⚠️ Disk space under 100MB

**Action:** Schedule maintenance window

### Normal Operations

- ✅ Backups completing daily
- ✅ Fast page loads
- ✅ No errors in logs
- ✅ Multiple users working smoothly

**Action:** Continue normal operations

---

## Weekly Maintenance Tasks

### Monday Morning (5 minutes)

1. Download last week's backup for off-site storage
2. Quick log review for errors:
   ```bash
   docker compose -f docker/flt-scheduler logs | grep -i error
   ```
3. Verify disk space is adequate

### Backup Verification (monthly)

1. Download a backup file
2. Test restore on a test system (if available)
3. Verify data integrity
4. Document the test

---

## Getting Help

### Information to Gather

Before contacting support:

1. **Save the logs:**
   ```bash
   docker compose -f docker/flt-scheduler logs --tail=200 > flight-scheduler-logs.txt
   ```

2. **Note the error:**
   - What were you doing?
   - What error appeared?
   - When did it start?

3. **System info:**
   ```bash
   docker --version
   docker compose version
   ls -lh docker/flt-scheduler-app/data/
   ```

### Support Resources

1. **User Guide:** `USER_GUIDE.md` (comprehensive documentation)
2. **README:** `README.md` (technical reference)
3. **Logs:** Most issues show up in logs first
4. **System Administrator:** Contact for critical issues

---

## Health Check Commands

### Quick Health Check (NEW!)

```bash
# Check application health (fastest method)
curl -s http://localhost:8080/health | python3 -m json.tool

# Just check if healthy (returns HTTP status code)
curl -w "%{http_code}\n" -o /dev/null -s http://localhost:8080/health
```

**Expected Output:**
- Status: `"status": "healthy"`
- HTTP Code: `200` (healthy/degraded) or `503` (unhealthy)

### Is the Application Healthy?

```bash
# Check Docker health status
docker compose -f docker/flt-scheduler ps

# Check if running
docker compose -f docker/flt-scheduler ps

# Check recent activity
docker compose -f docker/flt-scheduler logs --tail=20

# Manual database integrity check (if health endpoint unavailable)
docker exec -it flt-scheduler-flt-scheduler-1 python3 -c "
import sqlite3
conn = sqlite3.connect('data/scheduler.db')
result = conn.execute('PRAGMA integrity_check').fetchone()
print('Database:', result[0])
conn.close()
"
```

**Expected Output:**
- Docker PS: `(healthy)` in STATUS column
- Database: `ok`

### Check Backup System

```bash
# View backup logs
docker compose -f docker/flt-scheduler logs | grep backup

# List backups
ls -lh docker/flt-scheduler-app/data/backups/

# Check last backup time
ls -lt docker/flt-scheduler-app/data/backups/ | head -2
```

**Expected:** Backup from within last 24 hours

---

## Quick Status Dashboard

### 🟢 All Systems Normal

- Application accessible at http://localhost:8080
- Backups created within last 24 hours
- No errors in recent logs
- Disk space > 500MB free
- WAL file < 50MB

### 🟡 Attention Needed

- Slow performance
- Backups older than 24 hours
- Warnings in logs
- Disk space < 500MB
- WAL file 50-100MB

### 🔴 Critical - Take Action

- Application down
- Database corruption detected
- No backups available
- Disk space < 100MB
- WAL file > 100MB

**Action:** Follow emergency procedures above or restore from backup

---

## Contacts

**System Administrator:** _____________________

**Backup Storage Location:** _____________________

**Emergency Restore Procedure:** See "Restore from Backup" section above

**Last Updated:** February 14, 2026

---

**💡 Pro Tip:** Bookmark this page in your browser for quick access during emergencies!
