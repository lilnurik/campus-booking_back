import requests
import json
from datetime import datetime, timedelta
import time

# Constants for API access
API_BASE_URL = "https://bot.turin.uz/api"
API_HEADERS = {
    'gmail': 'your@gmail.com',
    'password': 'test#007',
    'domain': 'ttpu',
    'token': 'fAquXMI1SAoPxEcm',
    'Content-Type': 'application/json'
}


def get_groups():
    """Fetch all groups from the Turin API"""
    url = f"{API_BASE_URL}/groups/"

    print(f"Fetching groups from {url}...")

    try:
        response = requests.get(url, headers=API_HEADERS)
        response.raise_for_status()
        groups = response.json()
        print(f"Successfully fetched {len(groups)} groups")
        return groups
    except requests.exceptions.RequestException as e:
        print(f"Error fetching groups: {e}")
        return []


def get_weekly_timetable(group_id, group_name, retry=True):
    """Fetch weekly timetable for a specific group"""
    url = f"{API_BASE_URL}/weekly_timetable/"

    # Calculate the start date (beginning of current week)
    today = datetime.now()
    start_of_week = today - timedelta(days=today.weekday())
    start_date = start_of_week.strftime("%Y-%m-%d")

    # Prepare payload according to API documentation
    payload = {
        "GroupId": group_id,
        "GroupName": group_name,
        "StartDate": start_date
    }

    print(f"Fetching timetable for group {group_name} (ID: {group_id})...")

    try:
        # Use json parameter instead of data for proper JSON formatting
        response = requests.post(url, headers=API_HEADERS, json=payload)
        response.raise_for_status()
        timetable = response.json()

        # Count classes
        class_count = 0
        for day, classes in timetable.items():
            class_count += len(classes)

        print(f"Successfully fetched timetable for {group_name}: {class_count} classes across {len(timetable)} days")
        return timetable
    except requests.exceptions.RequestException as e:
        print(f"Error fetching timetable for group {group_name}: {e}")

        # Implement a retry with small delay if needed
        if retry:
            print(f"Retrying after 2 seconds...")
            time.sleep(2)
            return get_weekly_timetable(group_id, group_name, retry=False)

        return {}


def get_all_schedules():
    """Get schedules for all groups and all rooms"""
    groups = get_groups()
    all_schedules = []
    processed_count = 0
    total_groups = len(groups)

    print(f"\nProcessing timetables for {total_groups} groups...")

    # Process each group
    for group in groups:
        processed_count += 1
        group_id = str(group['class_id'])
        group_name = group['short']

        print(f"\nProcessing group {processed_count}/{total_groups}: {group_name}")

        # Get timetable for this group
        timetable = get_weekly_timetable(group_id, group_name)

        # Process each day's schedule
        for date, classes in timetable.items():
            for class_info in classes:
                classroom = class_info.get('classroom')
                if not classroom:
                    continue

                # Create a schedule entry
                schedule_entry = {
                    'room_name': classroom,
                    'from_date': f"{date} {class_info['start_time']}",
                    'until_date': f"{date} {class_info['end_time']}",
                    'subject': class_info['subject'],
                    'group': group_name
                }

                all_schedules.append(schedule_entry)

        # To avoid overwhelming the API, add a short delay between requests
        if processed_count < total_groups:
            time.sleep(0.5)

    print(f"\nCompleted processing of {total_groups} groups. Found {len(all_schedules)} class schedules total.")
    return all_schedules


def sync_class_schedules(app, db, Room, Schedule):
    """Sync class schedules from external API to our database"""
    print("\n=== Starting Class Schedule Synchronization ===")
    print("This may take a few minutes depending on the number of groups.\n")

    with app.app_context():
        all_schedules = get_all_schedules()

        if not all_schedules:
            print("No schedules found to sync.")
            return

        print(f"\nProcessing {len(all_schedules)} class schedules to update database...")
        rooms_created = 0
        schedules_created = 0

        # Get all existing rooms or create new ones if they don't exist
        for idx, schedule in enumerate(all_schedules):
            if idx % 50 == 0:
                print(f"Progress: {idx}/{len(all_schedules)} schedules processed")

            room_name = schedule['room_name']

            # Check if room exists
            room = Room.query.filter_by(name=room_name).first()
            if not room:
                # Create room if it doesn't exist
                room = Room(
                    name=room_name,
                    category="Classroom",
                    capacity=30,  # Default capacity
                    status="available"
                )
                db.session.add(room)
                db.session.commit()
                rooms_created += 1

            # Convert string dates to datetime objects
            try:
                from_date = datetime.fromisoformat(schedule['from_date'])
                until_date = datetime.fromisoformat(schedule['until_date'])
            except ValueError as e:
                print(f"Error parsing date: {e}. Skipping this schedule entry.")
                continue

            # Check for existing schedules to avoid duplicates
            existing_schedule = Schedule.query.filter_by(
                room_id=room.id,
                from_date=from_date,
                until_date=until_date,
                type='class'
            ).first()

            if not existing_schedule:
                # Create a new schedule entry
                new_schedule = Schedule(
                    room_id=room.id,
                    from_date=from_date,
                    until_date=until_date,
                    type='class'  # This is a class schedule, not a booking
                )
                db.session.add(new_schedule)
                schedules_created += 1

        db.session.commit()
        print(f"\n=== Synchronization Complete ===")
        print(f"- Created {rooms_created} new rooms")
        print(f"- Added {schedules_created} new class schedules")
        print(f"- Total schedules in system: {len(all_schedules)}")


# For testing purposes - can be used to verify API connection
def test_api_connection():
    """Test the API connection by fetching groups and a sample timetable"""
    print("Testing API connection...")

    groups = get_groups()
    if not groups:
        print("Failed to fetch groups")
        return False

    print(f"Successfully fetched {len(groups)} groups")

    # Try to get timetable for first group
    if groups:
        first_group = groups[0]
        group_id = str(first_group['class_id'])
        group_name = first_group['short']

        timetable = get_weekly_timetable(group_id, group_name)
        if timetable:
            days_with_classes = sum(1 for classes in timetable.values() if classes)
            print(f"Successfully fetched timetable for {group_name}: {days_with_classes} days with classes")
            return True
        else:
            print(f"Failed to fetch timetable for {group_name}")

    return False