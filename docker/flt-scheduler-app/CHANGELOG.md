# Changelog

All notable changes to the 1-227 AB Flight Scheduler will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Site identity settings (title, tagline, logo, branding)
- Admin email configuration
- Date format customization
- Additional reporting features
- Email notifications for approvals
- Mobile app support

## [0.10.2-beta] - 2026-02-22

### Fixed
- Daily Consolidated Missions table column alignment
  - Added missing Non-rated Crew data column
  - Corrected Team flight boolean column position
  - Fixed AMC Mission ID column alignment
  - All table columns now properly align with their headers

## [0.10.1-beta] - 2026-02-22

### Changed
- Improved Add Flight form layout with logical grouping
  - Group 1: Flight Date & Time (date, launch, recovery)
  - Group 2: Mission Details (type, mission title, ATP company)
  - Group 3: Aircraft & Route (tail number, origin, route, destination)
  - Group 4: Crew & Additional Information (PIC, pilot, crew members, notes)
  - Added visual section headers with accent colors and border separators
  - Enhanced form readability and user experience

## [0.10.0-beta] - 2026-02-22

### Added
- PostgreSQL support alongside SQLite
  - New environment variables: DATABASE_TYPE, DATABASE_URL, SQLITE_DB_PATH
  - Automatic database abstraction layer
  - Connection pooling for PostgreSQL (ThreadedConnectionPool)
  - Migration script for SQLite to PostgreSQL data transfer
- Audit log archiving system
  - Automatic archiving of logs older than 90 days
  - Archive table (audit_logs_archive) for historical data
  - Integrated with daily backup task
  - Maintains query performance at scale
- Configurable database path
  - SQLITE_DB_PATH environment variable (required in production)
  - Development default for local testing
  - Flexible deployment options

### Changed
- Increased Gunicorn workers from 4 to 8 for better concurrency
- SQLite connections use check_same_thread=False for multi-worker safety
- Database path now configurable via environment variable

### Performance
- 2x worker increase improves request throughput
- Audit log archiving maintains query performance over time
- Connection pooling for PostgreSQL deployments
- Optimized for 10-50 concurrent users

### Infrastructure
- PostgreSQL migration path for high-scale deployments
- Backward compatible with existing SQLite deployments
- Health checks support both database types

### Migration Notes
- **BREAKING:** SQLITE_DB_PATH environment variable is now required in production
  - Development: defaults to `data/scheduler.db` with warning
  - Production: must explicitly set SQLITE_DB_PATH (e.g., `/app/data/scheduler.db`)
- For PostgreSQL migration, use migrate_to_postgresql.py script
- Existing SQLite deployments: add `SQLITE_DB_PATH=/app/data/scheduler.db` to environment

### Dependencies
- Added psycopg2-binary==2.9.9 for PostgreSQL support

## [0.9.2-beta] - 2026-02-15

### Added
- Backup management feature
  - Delete backups from Settings page
  - Confirmation dialog with warning to prevent accidents
  - Safety measure: Cannot delete most recent backup
  - Audit logging for backup deletions
  - Delete button disabled for most recent backup with explanatory tooltip

### Security
- Backup deletion restricted to admin users only
- Validation to ensure only scheduler backup files can be deleted
- Protection against deleting the most recent backup

## [0.9.1-beta] - 2026-02-15

### Added
- Timezone configuration setting
  - Admin can set application timezone in Settings
  - Supports US time zones (Eastern, Central, Mountain, Pacific, Alaska, Hawaii)
  - Includes common international time zones (UTC, London, Paris, Tokyo, Shanghai, Sydney)
  - Default timezone: UTC

### Fixed
- Database locking error when deleting flights
  - Fixed concurrent database connection issue in audit logging
  - `write_audit()` now reuses existing connections when available
  - Resolves "database is locked" errors during delete, restore, purge, and update operations

### Dependencies
- Added `pytz==2024.2` for timezone support

## [0.9.0-beta] - 2026-02-14

### Added
- Version control system with semantic versioning
- Version display in application footer
- Version information in `/health` endpoint
- Docker image labels with version metadata
- Responsive web design improvements
  - Enhanced touch targets (44-48px) for mobile devices
  - Fluid typography scaling (14-16px base)
  - Five breakpoint system (extra-small, mobile, tablet, desktop, extra-large)
  - Scroll indicators for tables
  - Print-optimized styles
- Dashboard statistics
  - Total flights today counter
  - Hours flown counter
  - Pending approvals counter
  - Active aircraft counter
- Table sorting functionality
  - Sortable columns for mission ID, tail number, crew, hours
  - Visual sort direction indicators
- Real-time search and filter
  - Search by mission ID, tail, crew, mission type
  - Real-time filtering without page reload
- Confirmation dialogs
  - Delete flight confirmation
  - Cancel flight confirmation
  - Prevents accidental data loss
- Accessibility improvements
  - Enhanced focus states
  - Keyboard navigation support
  - WCAG 2.1 AA compliance for touch targets

### Changed
- Centered responsive layout with adaptive padding
  - Mobile: 1rem horizontal padding
  - Tablet: 1.25rem horizontal padding
  - Desktop: 2rem horizontal padding
  - Extra-large: 3rem horizontal padding

### Fixed
- Hours calculation type error when closing out flights
  - Fixed string-to-float conversion in Jinja2 template
  - Now properly initializes total hours as float (0.0)

### Infrastructure
- Automated database backups
  - Startup backup on container launch
  - Daily automatic backups
  - 7-day retention policy
  - Integrity verification
- Database stability features
  - WAL mode for better concurrency
  - Integrity checks on startup
  - Automatic corruption quarantine
  - Per-connection PRAGMA settings
- Soft delete for flights
  - Deleted flights marked as deleted, not removed
  - Admin can view deleted flights
  - Permanent deletion available to admins
- Health monitoring
  - HTTP health check endpoint
  - Docker health checks every 30s
  - Database connectivity verification

## Version Numbering Scheme

**Current State: Beta (0.x.x)**

While in beta (versions 0.x.x), the application is feature-complete but still undergoing testing and refinement. Version 1.0.0 will be released when the application is deemed production-ready for full deployment.

**Version Format: MAJOR.MINOR.PATCH[-PRERELEASE]**

- **MAJOR**: Incremented for incompatible API changes or major feature overhauls
- **MINOR**: Incremented for new features added in a backwards-compatible manner
- **PATCH**: Incremented for backwards-compatible bug fixes
- **PRERELEASE**: Optional tag (e.g., `-beta`, `-rc1`) for pre-release versions

**Examples:**
- `0.9.0-beta` - Beta release with version 0.9.0
- `0.9.1-beta` - Bug fix release in beta
- `0.10.0-beta` - New feature release in beta
- `1.0.0` - First production release
- `1.0.1` - Bug fix to production release
- `1.1.0` - New feature in production

## Release Process

1. Update VERSION file with new version number
2. Update CHANGELOG.md with release notes
3. Commit changes: `git commit -m "Release vX.Y.Z"`
4. Create git tag: `git tag -a vX.Y.Z -m "Version X.Y.Z"`
5. Build Docker image: `docker compose -f flt-scheduler build`
6. Tag image: `docker tag flt-scheduler:X.Y.Z-beta flt-scheduler:latest`
7. Push to registry (if applicable)
8. Deploy to production

## Upgrade Notes

### From pre-versioned to 0.9.0-beta
- No database migrations required
- Automatic VERSION file detection
- Version displayed in footer automatically
- Health endpoint now includes version information
