import sqlite3

conn = sqlite3.connect("data/soc.db")
c = conn.cursor()
tables = [
    r[0]
    for r in c.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence'"
    ).fetchall()
]
print("Tables found:", tables)
for t in tables:
    c.execute(f"DELETE FROM {t};")
    print(f"  Cleared: {t}")
try:
    c.execute("DELETE FROM sqlite_sequence;")
except Exception:
    pass
conn.commit()
conn.close()
print(">>> SUCCESS: All tables truncated and counters reset in data/soc.db")
