#!/usr/bin/env python3
"""
Migrate SQLite data to PostgreSQL.

Usage:
    python migrate_to_postgresql.py <sqlite_db_path> <postgresql_url>

Example:
    python migrate_to_postgresql.py data/scheduler.db "postgresql://user:password@localhost:5432/flight_scheduler"
"""

import sqlite3
import sys
import psycopg2
import psycopg2.extras


def migrate(sqlite_path, pg_url):
    """Migrate all data from SQLite to PostgreSQL."""
    print(f"Connecting to SQLite database: {sqlite_path}")
    sqlite_conn = sqlite3.connect(sqlite_path)
    sqlite_conn.row_factory = sqlite3.Row

    print(f"Connecting to PostgreSQL database...")
    pg_conn = psycopg2.connect(pg_url)

    # Tables to migrate (in dependency order)
    tables = ['users', 'crew', 'aircraft', 'app_settings', 'flights', 'audit_logs', 'audit_logs_archive']

    total_rows = 0

    for table in tables:
        print(f"\nMigrating table: {table}")
        try:
            rows = sqlite_conn.execute(f"SELECT * FROM {table}").fetchall()

            if not rows:
                print(f"  No rows to migrate in {table}")
                continue

            # Get column names from first row
            columns = rows[0].keys()
            placeholders = ','.join(['%s'] * len(columns))
            columns_str = ','.join(columns)

            # Insert into PostgreSQL
            with pg_conn.cursor() as cur:
                insert_count = 0
                for row in rows:
                    try:
                        cur.execute(
                            f"INSERT INTO {table} ({columns_str}) VALUES ({placeholders})",
                            tuple(row)
                        )
                        insert_count += 1
                    except psycopg2.IntegrityError as e:
                        # Skip duplicate key errors (e.g., if re-running migration)
                        print(f"  Warning: Skipping duplicate row in {table}: {e}")
                        pg_conn.rollback()
                        continue

            pg_conn.commit()
            print(f"  Migrated {insert_count}/{len(rows)} rows")
            total_rows += insert_count

        except sqlite3.OperationalError as e:
            print(f"  Table {table} does not exist in SQLite: {e}")
            continue
        except psycopg2.Error as e:
            print(f"  PostgreSQL error migrating {table}: {e}")
            pg_conn.rollback()
            continue

    print(f"\n{'='*60}")
    print(f"Migration complete!")
    print(f"Total rows migrated: {total_rows}")
    print(f"{'='*60}")

    sqlite_conn.close()
    pg_conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)

    sqlite_path = sys.argv[1]
    pg_url = sys.argv[2]

    migrate(sqlite_path, pg_url)
