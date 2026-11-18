import sqlite3

conn = sqlite3.connect("analysis_workspace/workbench.db")
c = conn.cursor()

c.execute("SELECT COUNT(*) FROM investigations")
inv_count = c.fetchone()[0]

c.execute("SELECT COUNT(*) FROM evidence_items")
ev_count = c.fetchone()[0]

print(f"Investigations count: {inv_count}")
print(f"Evidence items count: {ev_count}")

c.execute("PRAGMA table_info(app_settings)")
cols = c.fetchall()
print("\napp_settings columns:", [col[1] for col in cols])

c.execute("SELECT * FROM app_settings")
rows = c.fetchall()
print(f"\napp_settings rows ({len(rows)}):")
for r in rows:
    print(" ", r)

conn.close()
