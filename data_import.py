import pandas as pd
import sqlite3
import os


def import_student_data(excel_file='students.xlsx', db_file='booking_system.db'):
    """
    Import student data from Excel file to SQLite database.
    This is for initial setup or periodic updates.
    """
    if not os.path.exists(excel_file):
        print(f"Error: {excel_file} not found")
        return

    try:
        # Read Excel file
        df = pd.read_excel(excel_file)

        # Connect to SQLite database
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        # Check if user table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
        if not cursor.fetchone():
            print("Error: 'user' table not found in database")
            conn.close()
            return

        # Get existing usernames
        cursor.execute("SELECT username FROM user")
        existing_users = [row[0] for row in cursor.fetchall()]

        # Insert or update students
        for _, row in df.iterrows():
            username = str(row['id'])

            if username in existing_users:
                # User exists, update information but don't change password
                cursor.execute("""
                    UPDATE user 
                    SET full_name=?, email=?, group=?, course=?, faculty=? 
                    WHERE username=?
                """, (row['full_name'], row['email'], row['group'],
                      row['course'], row['faculty'], username))
            else:
                # New user, insert without password
                cursor.execute("""
                    INSERT INTO user (username, full_name, email, group, course, faculty, role, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (username, row['full_name'], row['email'], row['group'],
                      row['course'], row['faculty'], 'student', 'active'))

        conn.commit()
        print(f"Successfully imported/updated {len(df)} students")

    except Exception as e:
        print(f"Error importing student data: {e}")
    finally:
        if 'conn' in locals():
            conn.close()


if __name__ == "__main__":
    import_student_data()