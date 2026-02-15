# Backup System - Visual Workflow Guide

## Backup System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Flight Scheduler Application                  │
│                                                                  │
│  ┌────────────────┐         ┌──────────────────┐               │
│  │   Main Database │         │  Backup System   │               │
│  │ scheduler.db   │◄────────│  (Automated)     │               │
│  │                │         │                  │               │
│  │  - Flights     │         │  Runs:           │               │
│  │  - Crew        │         │  • On startup    │               │
│  │  - Aircraft    │         │  • Every 24 hrs  │               │
│  │  - Users       │         │                  │               │
│  └────────────────┘         └──────────────────┘               │
│         │                            │                          │
│         │                            ▼                          │
│         │                   ┌──────────────────┐               │
│         │                   │ Backup Directory │               │
│         │                   │  data/backups/   │               │
│         │                   │                  │               │
│         │                   │ • Day 1 backup   │               │
│         │                   │ • Day 2 backup   │               │
│         └──────────────────►│ • Day 3 backup   │               │
│                             │ • ... (7 days)   │               │
│                             └──────────────────┘               │
│                                      │                          │
└──────────────────────────────────────┼──────────────────────────┘
                                       │
                                       ▼
                        ┌──────────────────────────┐
                        │   Auto-Rotation After    │
                        │       7 Days             │
                        │                          │
                        │  Deletes backups older   │
                        │  than 7 days to save     │
                        │  disk space              │
                        └──────────────────────────┘
```

## Backup Creation Flow

```
Start
  │
  ▼
[Backup Triggered]
  │
  ├─► Automatic (Daily Timer)
  │
  └─► Manual (Admin Button)
  │
  ▼
[Checkpoint WAL]
  │ (Merge temp changes to main database)
  │
  ▼
[Copy Database File]
  │
  ├─► scheduler.db
  ├─► scheduler.db-wal (if exists)
  └─► scheduler.db-shm (if exists)
  │
  ▼
[Verify Integrity]
  │
  ├─► OK ────────────┐
  │                  │
  └─► FAILED ───► [Delete Bad Backup]
                     │
                     └─► [Log Error]
                          │
                          └─► End
  │
  ▼
[Save to Backups Directory]
  │
  └─► scheduler-backup-YYYYMMDD-HHMMSS.db
  │
  ▼
[Rotate Old Backups]
  │
  └─► Delete files older than 7 days
  │
  ▼
[Log Success]
  │
  ▼
End
```

## Restore Flow

```
Problem Detected
  │
  ▼
[Decision: Restore Needed?]
  │
  ├─► NO ──► Continue Normal Operations
  │
  └─► YES
      │
      ▼
  [Stop Application]
      │
      ▼
  [Choose Backup]
      │
      ├─► Last Night (most recent data)
      ├─► Specific Date (known good state)
      └─► Before Incident (undo changes)
      │
      ▼
  [Optional: Backup Current DB]
      │
      └─► scheduler-before-restore-TIMESTAMP.db
      │
      ▼
  [Copy Backup to Main DB]
      │
      └─► cp backup → scheduler.db
      │
      ▼
  [Start Application]
      │
      ▼
  [Verify Data]
      │
      ├─► OK ────► Operations Restored ✓
      │
      └─► PROBLEM ──► Try Older Backup
                      │
                      └─► (Repeat Process)
```

## Daily Backup Timeline

```
Time (UTC)  │  Event
────────────┼──────────────────────────────────────
00:00       │  Application running
            │
06:00       │  Users start working
            │  (Previous day backup available)
            │
12:00       │  Peak usage
            │
18:00       │  Users finish work
            │
23:45       │  ✓ Daily backup triggered (24h since last)
            │
23:46       │  Backup created: scheduler-backup-20260214-234600.db
            │  Old backup deleted: scheduler-backup-20260207-234500.db
            │
00:00       │  Next day begins
            │  7 backups available (Days 8-14)
```

## Backup States

```
┌─────────────────────────────────────────────────────────────┐
│                    Backup File States                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  🟢 FRESH (0-1 days old)                                    │
│     • Most recent backup                                     │
│     • Use for routine restores                              │
│     • Minimal data loss if restored                         │
│                                                              │
│  🟡 RECENT (1-3 days old)                                   │
│     • Good for recent data recovery                         │
│     • Use if today's backup is corrupted                    │
│     • Some data loss acceptable                             │
│                                                              │
│  🟠 OLDER (3-6 days old)                                    │
│     • Use for specific date recovery                        │
│     • Known good state before incident                      │
│     • Significant data loss expected                        │
│                                                              │
│  🔴 EXPIRING (6-7 days old)                                 │
│     • Will be deleted soon                                  │
│     • Download if needed for archive                        │
│     • Last chance to preserve this data                     │
│                                                              │
│  ⚫ ARCHIVED (downloaded off-site)                          │
│     • Safe from auto-deletion                               │
│     • Monthly/weekly archives                               │
│     • Long-term historical record                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Data Protection Layers

```
Layer 1: Real-Time Protection
┌─────────────────────────────────┐
│  Write-Ahead Logging (WAL)      │
│  • Crash-resistant              │
│  • Transaction safety           │
│  • Concurrent access            │
└─────────────────────────────────┘
         │
         ▼
Layer 2: Automatic Health Checks
┌─────────────────────────────────┐
│  Database Integrity Checks      │
│  • On every startup             │
│  • After every backup           │
│  • Quarantine if corrupted      │
└─────────────────────────────────┘
         │
         ▼
Layer 3: Automated Backups
┌─────────────────────────────────┐
│  Daily Backup System            │
│  • Startup backup               │
│  • 24-hour scheduled backups    │
│  • 7-day retention              │
└─────────────────────────────────┘
         │
         ▼
Layer 4: Manual Backups
┌─────────────────────────────────┐
│  Admin-Triggered Backups        │
│  • Before major changes         │
│  • On-demand protection         │
│  • Pre-update snapshots         │
└─────────────────────────────────┘
         │
         ▼
Layer 5: Off-Site Storage
┌─────────────────────────────────┐
│  Downloaded Archives            │
│  • Weekly downloads             │
│  • External storage             │
│  • Disaster recovery            │
└─────────────────────────────────┘
```

## Common Scenarios

### Scenario 1: Accidental Deletion (Same Day)

```
09:00 - Scheduler deletes 20 flights by mistake
09:01 - Realizes error
09:02 - Admin restores from last night's backup (23:45)
09:05 - System restored, only missing this morning's data
09:10 - Re-enter morning flights manually
        ✓ Problem solved in 10 minutes
```

**Data Loss:** ~9 hours (overnight to incident)
**Recovery Time:** 5-10 minutes
**Best Backup:** Last night's automatic backup

---

### Scenario 2: Database Corruption (Next Day)

```
Day 1, 14:00 - Unknown corruption begins
Day 1, 23:45 - Backup runs (captures corruption)
Day 2, 08:00 - Application won't start
Day 2, 08:05 - Check logs: "Database corrupted"
Day 2, 08:10 - Restore from Day 0 backup (2 days old)
Day 2, 08:15 - System operational
Day 2, 08:30 - Manual data entry for missing days
              ✓ Problem solved in 30 minutes
```

**Data Loss:** ~42 hours (2 days)
**Recovery Time:** 10-30 minutes
**Best Backup:** Oldest available (before corruption)

---

### Scenario 3: Bad Bulk Import

```
10:00 - Admin imports 100 crew members
10:01 - Realizes file had wrong data
10:02 - Click "Create Backup Now" (captures mistake)
10:03 - Wait... should have backed up BEFORE import!
10:04 - Restore from last night's backup
10:05 - System restored, bad import gone
10:06 - Re-do import with correct file
        ✓ Problem solved in 6 minutes
```

**Lesson:** Always backup BEFORE major changes!
**Data Loss:** Morning's work only
**Recovery Time:** 5 minutes
**Best Backup:** Last automatic backup (before import)

---

### Scenario 4: Planned Maintenance

```
Friday 16:00 - Create manual backup before update
Friday 16:01 - Download backup to laptop (off-site)
Friday 16:05 - Perform software update
Friday 16:10 - Test new version
Friday 16:15 - Problem found, need to rollback
Friday 16:16 - Restore from pre-update backup
Friday 16:20 - System back to working state
              ✓ Clean rollback completed
```

**Data Loss:** None (planned)
**Recovery Time:** 5 minutes
**Best Backup:** Pre-maintenance manual backup

---

## Backup Decision Tree

```
                     [Need to Restore?]
                            │
                ┌───────────┴───────────┐
                │                       │
              YES                      NO
                │                       │
                ▼                       └──► Continue Operations
    [When was last good state?]
                │
    ┌───────────┼───────────┐
    │           │           │
  TODAY    YESTERDAY   OLDER
    │           │           │
    ▼           ▼           ▼
  Last      Last Night   Specific
  Backup    Backup       Date Backup
    │           │           │
    └───────────┼───────────┘
                │
                ▼
        [Stop Application]
                │
                ▼
        [Restore Backup]
                │
                ▼
        [Start Application]
                │
                ▼
        [Verify Data]
                │
         ┌──────┴──────┐
         │             │
    Data OK?      Data Bad?
         │             │
         ▼             ▼
    Operations    Try Older
    Restored      Backup
         ✓             │
                       └──► (Repeat)
```

## Monitoring Your Backups

### Daily Check (30 seconds)

```bash
# View latest backup
ls -lt docker/flt-scheduler-app/data/backups/ | head -2

Expected output:
total 416
-rw-r--r--  1 user  staff  52K Feb 14 23:45 scheduler-backup-20260214-234500.db
```

✅ Backup is less than 24 hours old
✅ File size is reasonable (not 0 bytes)

### Weekly Check (2 minutes)

```bash
# Count backups (should be ~7)
ls docker/flt-scheduler-app/data/backups/ | wc -l

# Check for errors in logs
docker compose -f flt-scheduler logs | grep -i "backup failed"

# Verify oldest backup
ls -lt docker/flt-scheduler-app/data/backups/ | tail -2
```

✅ 7 backups present
✅ No backup failures
✅ Oldest backup is ~7 days old

### Monthly Check (10 minutes)

1. Download a backup
2. Verify it opens (sqlite3 or DB Browser)
3. Spot-check data integrity
4. Archive for long-term storage

## Backup Storage Requirements

### Calculation

```
Database Size: X MB

Daily Backups (7 days) = X MB × 7 = Y MB
Safety Buffer (50%)    = Y MB × 1.5 = Z MB

Recommended Free Space: Z MB
```

### Examples

| Database Size | 7 Backups | With Buffer | Recommended |
|--------------|-----------|-------------|-------------|
| 10 MB        | 70 MB     | 105 MB      | 150 MB      |
| 50 MB        | 350 MB    | 525 MB      | 600 MB      |
| 100 MB       | 700 MB    | 1,050 MB    | 1.2 GB      |
| 500 MB       | 3.5 GB    | 5.25 GB     | 6 GB        |

**Pro Tip:** Set up a disk space alert at 80% capacity

---

## Quick Commands Reference

### Check Latest Backup
```bash
ls -lth docker/flt-scheduler-app/data/backups/ | head -2
```

### Count Backups
```bash
ls -1 docker/flt-scheduler-app/data/backups/ | wc -l
```

### Find Specific Date Backup
```bash
ls docker/flt-scheduler-app/data/backups/ | grep 20260214
```

### Check Disk Space
```bash
df -h docker/flt-scheduler-app/data/
```

### Emergency Restore (Latest)
```bash
docker compose -f flt-scheduler down
cp docker/flt-scheduler-app/data/backups/$(ls -t docker/flt-scheduler-app/data/backups/ | head -1) \
   docker/flt-scheduler-app/data/scheduler.db
docker compose -f flt-scheduler up -d
```

---

## Summary: Backup Best Practices

✅ **DO:**
- Create manual backup before major changes
- Download weekly backups for off-site storage
- Monitor backup logs occasionally
- Keep adequate disk space available
- Test restore procedure quarterly

❌ **DON'T:**
- Delete WAL/SHM files while app is running
- Manually modify database files
- Ignore backup failure warnings
- Let disk space run low
- Forget to verify backups occasionally

🎯 **REMEMBER:**
- Backups run automatically every 24 hours
- Last 7 days are always available
- Manual backups available anytime
- Restore takes 5-10 minutes
- Data is your most valuable asset - protect it!

---

**This document is a visual companion to the [USER_GUIDE.md](USER_GUIDE.md)**
