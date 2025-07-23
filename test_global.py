#!/usr/bin/env python3
"""Test script to debug Flask global variables"""

# Test if we can access the same global instance as Flask
import sys
import os
sys.path.insert(0, os.getcwd())

# Import the global instance like Flask does
from app_bleak import attendance_system

print("Global attendance_system instance:")
print(f"Type: {type(attendance_system)}")
print(f"ID: {id(attendance_system)}")

subjects = attendance_system.get_subjects()
print(f"\nSubjects from global instance:")
print(f"Count: {len(subjects)}")
for i, subject in enumerate(subjects):
    print(f"  Subject {i}: {subject}")
