"""ClassPulse SQLite schema. Fresh installs start with no demo records."""
import sqlite3
from contextlib import contextmanager
from flask import current_app, g

SCHEMA = r'''
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS tab_sessions (
 token TEXT PRIMARY KEY,
 session_data TEXT NOT NULL,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 login_id TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','student','team')),
 is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS students (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
 prn TEXT NOT NULL UNIQUE,
 full_name TEXT NOT NULL,
 batch TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS teams (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 team_name TEXT NOT NULL UNIQUE,
 user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS team_members (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
 student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
 joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
 UNIQUE(team_id, student_id)
);
CREATE TABLE IF NOT EXISTS activities (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 description TEXT NOT NULL DEFAULT '',
 category TEXT NOT NULL CHECK(category IN ('Technical','Communication','Cultural','Sports')),
 difficulty TEXT NOT NULL DEFAULT 'Beginner',
 max_marks REAL NOT NULL CHECK(max_marks > 0),
 deadline TEXT,
 created_by INTEGER REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1))
);
CREATE TABLE IF NOT EXISTS activity_assignments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 activity_id INTEGER NOT NULL REFERENCES activities(id),
 target_type TEXT NOT NULL CHECK(target_type IN ('student','team')),
 student_id INTEGER REFERENCES students(id),
 team_id INTEGER REFERENCES teams(id),
 assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 status TEXT NOT NULL DEFAULT 'Assigned' CHECK(status IN ('Assigned','In Progress','Submitted','Completed','Overdue')),
 CHECK((target_type='student' AND student_id IS NOT NULL AND team_id IS NULL) OR
       (target_type='team' AND team_id IS NOT NULL AND student_id IS NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_student_assignment ON activity_assignments(activity_id, student_id) WHERE student_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_team_assignment ON activity_assignments(activity_id, team_id) WHERE team_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS submissions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 assignment_id INTEGER NOT NULL UNIQUE REFERENCES activity_assignments(id) ON DELETE CASCADE,
 submitted_by INTEGER NOT NULL REFERENCES users(id),
 submission_text TEXT NOT NULL DEFAULT '', submission_url TEXT NOT NULL DEFAULT '',
 submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 status TEXT NOT NULL DEFAULT 'Submitted' CHECK(status IN ('Submitted','Reviewed'))
);
CREATE TABLE IF NOT EXISTS evaluations (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 assignment_id INTEGER NOT NULL UNIQUE REFERENCES activity_assignments(id) ON DELETE CASCADE,
 student_id INTEGER REFERENCES students(id), team_score REAL, individual_score REAL,
 feedback TEXT NOT NULL DEFAULT '', evaluated_by INTEGER NOT NULL REFERENCES users(id),
 evaluated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CHECK(team_score IS NULL OR team_score >= 0), CHECK(individual_score IS NULL OR individual_score >= 0)
);
CREATE TABLE IF NOT EXISTS recommendations (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER REFERENCES users(id), team_id INTEGER REFERENCES teams(id), activity_id INTEGER REFERENCES activities(id),
 reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Active' CHECK(status IN ('Active','Completed','Dismissed')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 message TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id), action TEXT NOT NULL,
 entity_type TEXT NOT NULL, entity_id INTEGER, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS ix_assign_student ON activity_assignments(student_id);
CREATE INDEX IF NOT EXISTS ix_assign_team ON activity_assignments(team_id);
CREATE INDEX IF NOT EXISTS ix_assign_status ON activity_assignments(status);
CREATE INDEX IF NOT EXISTS ix_activity_category ON activities(category);
'''

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DATABASE'], detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
    return g.db

@contextmanager
def transaction():
    db = get_db()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise

def close_db(_=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()
