import sqlite3

conn = sqlite3.connect('analysis_workspace/workbench.db')
cursor = conn.cursor()

cursor.execute('PRAGMA integrity_check;')
integrity = cursor.fetchall()
print('PRAGMA integrity_check:', integrity)

cursor.execute('SELECT COUNT(*) FROM investigations;')
total_inv = cursor.fetchone()[0]

cursor.execute("SELECT COUNT(*) FROM investigations WHERE id LIKE 'INV-%';")
historical_inv = cursor.fetchone()[0]

cursor.execute("SELECT COUNT(*) FROM investigations WHERE id NOT LIKE 'INV-%';")
synthetic_inv = cursor.fetchone()[0]

print(f'Total investigations: {total_inv}')
print(f'  Historical investigations (INV-...): {historical_inv}')
print(f'  Synthetic test investigations: {synthetic_inv}')

cursor.execute('SELECT COUNT(*) FROM chain_of_custody;')
total_coc = cursor.fetchone()[0]
print(f'Total Chain-of-Custody records: {total_coc}')

cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = [r[0] for r in cursor.fetchall()]
print('Database tables:', sorted(tables))

for t in sorted(tables):
    try:
        cursor.execute(f'SELECT COUNT(*) FROM {t};')
        cnt = cursor.fetchone()[0]
        print(f'  Table {t}: {cnt} rows')
    except Exception as e:
        print(f'  Table {t}: error {e}')

conn.close()

