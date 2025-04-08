from app import db, User, Room, app, Schedule
import pandas as pd
import os
from external_api import sync_class_schedules


def create_tables():
    print("Creating database tables...")
    with app.app_context():
        db.create_all()

        # Create admin user
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                full_name='Administrator',
                role='admin',
                email='admin@university.edu',
                status='active'
            )
            admin.set_password('admin')  # Change in production
            db.session.add(admin)
            print("Created default admin user")

        # Create security user
        security = User.query.filter_by(username='security').first()
        if not security:
            security = User(
                username='security',
                full_name='Security Officer',
                role='security',
                email='security@university.edu',
                status='active'
            )
            security.set_password('security')  # Change in production
            db.session.add(security)
            print("Created default security user")

        # Create sample rooms
        if Room.query.count() == 0:
            sample_rooms = [
                {'name': 'Room 101', 'category': 'Classroom', 'capacity': 30},
                {'name': 'Room 102', 'category': 'Classroom', 'capacity': 25},
                {'name': 'Room 201', 'category': 'Laboratory', 'capacity': 20},
                {'name': 'Conference Room A', 'category': 'Meeting Room', 'capacity': 15},
                {'name': 'Auditorium', 'category': 'Lecture Hall', 'capacity': 100}
            ]

            for room_data in sample_rooms:
                room = Room(**room_data)
                db.session.add(room)
            print(f"Created {len(sample_rooms)} sample rooms")

        db.session.commit()
        print("Database tables initialized successfully!")


def load_students_from_excel():
    excel_file = 'students.xlsx'

    print(f"Looking for student data in '{excel_file}'...")

    if os.path.exists(excel_file):
        try:
            # First ensure openpyxl is properly installed
            try:
                import openpyxl
                print(f"Using openpyxl version: {openpyxl.__version__}")
            except ImportError:
                print("Error: openpyxl not properly installed. Trying to install...")
                import subprocess
                subprocess.check_call(["pip", "install", "openpyxl"])
                print("openpyxl installed successfully. Continuing...")

            with app.app_context():
                print(f"Reading student data from '{excel_file}'...")
                df = pd.read_excel(excel_file)
                print(f"Found {len(df)} student records in Excel file")

                students_added = 0

                for _, row in df.iterrows():
                    username = str(row['id'])
                    user = User.query.filter_by(username=username).first()

                    if not user:
                        user = User(
                            username=username,
                            full_name=row['full_name'],
                            email=row['email'],
                            group=row['group'],
                            course=row['course'],
                            faculty=row['faculty'],
                            role='student',
                            status='active'
                        )
                        db.session.add(user)
                        students_added += 1

                db.session.commit()
                print(f"Imported {students_added} new students from Excel")
        except Exception as e:
            print(f"Error importing students: {e}")
    else:
        print(f"Warning: '{excel_file}' not found. No students imported.")
        print("You should create this file with columns: id, full_name, email, group, course, faculty")


def initialize_system():
    print("\n=== ROOM BOOKING SYSTEM INITIALIZATION ===\n")

    create_tables()
    print("\n--- Student Data Import ---")
    load_students_from_excel()

    print("\n--- External Class Schedule Import ---")
    try:
        print("Starting synchronization of class schedules from external API...")
        sync_class_schedules(app, db, Room, Schedule)
    except Exception as e:
        print(f"Error syncing class schedules: {e}")

    print("\n=== INITIALIZATION COMPLETE ===")
    print("You can now run the application with: python app.py")


if __name__ == "__main__":
    initialize_system()