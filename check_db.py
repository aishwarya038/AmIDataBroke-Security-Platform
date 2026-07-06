import sqlite3

conn = sqlite3.connect('database.db')

print("Tables:")
print(conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall())

print("\nUsers:")
print(conn.execute("SELECT id, email FROM users").fetchall())

print("\nTotal security logs:")
print(conn.execute("SELECT COUNT(*) FROM security_logs").fetchall())

conn.close()