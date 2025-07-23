#!/usr/bin/env python3
"""Test script to debug subject data"""

import sqlite3
from app_bleak import MultiModalAttendanceSystem

# Create instance and test get_subjects
att = MultiModalAttendanceSystem()
subjects = att.get_subjects()

print("get_subjects() returned:")
print(f"Type: {type(subjects)}")
print(f"Length: {len(subjects)}")
print("Data:")
for i, subject in enumerate(subjects):
    print(f"  Subject {i}: {subject}")
    print(f"  Type: {type(subject)}")
    if isinstance(subject, dict):
        print(f"  Keys: {list(subject.keys())}")
        print(f"  Values: {list(subject.values())}")

# Also test direct database query
print("\nDirect database query:")
conn = sqlite3.connect('attendance.db')
cursor = conn.cursor()
cursor.execute('SELECT id, subject_code, subject_name, description FROM subjects ORDER BY subject_name')
results = cursor.fetchall()
conn.close()

print(f"Database results: {results}")
