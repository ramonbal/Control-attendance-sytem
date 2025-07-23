"""Debug script to check subjects in the database"""
import sqlite3

# Connect to the database
conn = sqlite3.connect('attendance.db')
cursor = conn.cursor()

print("=== DATABASE SUBJECTS DEBUG ===")

# Check if subjects table exists
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='subjects';")
table_exists = cursor.fetchone()
print(f"Subjects table exists: {table_exists is not None}")

if table_exists:
    # Get table schema
    cursor.execute("PRAGMA table_info(subjects)")
    schema = cursor.fetchall()
    print("\nTable Schema:")
    for col in schema:
        print(f"  {col}")

    # Get all subjects
    cursor.execute('SELECT id, subject_code, subject_name, description FROM subjects ORDER BY subject_name')
    results = cursor.fetchall()
    print(f"\nTotal subjects in database: {len(results)}")
    
    print("\nRaw database results:")
    for i, row in enumerate(results):
        print(f"  {i+1}. {row}")
    
    # Convert to dictionaries like in get_subjects()
    subjects = []
    for row in results:
        subject_dict = {
            'id': row[0],
            'subject_code': row[1],
            'subject_name': row[2],
            'description': row[3]
        }
        subjects.append(subject_dict)
    
    print("\nConverted to dictionaries:")
    for i, subject in enumerate(subjects):
        print(f"  {i+1}. {subject}")
        print(f"      ID type: {type(subject['id'])}, value: {subject['id']}")

conn.close()
