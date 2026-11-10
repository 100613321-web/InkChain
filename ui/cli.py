from services.auth import register_user, login_user, AuthError
from services.diary import create_entry, get_entries, verify_diary, DiaryError
from getpass import getpass

def show_main_menu():
    print("\n" + "=" * 35)
    print("          INKCHAIN")
    print("      Your Secure Diary")
    print("=" * 35)
    print("1. Register")
    print("2. Login")
    print("3. Exit")
    print("=" * 35)


def show_diary_menu(username):
    print("\n" + "=" * 35)
    print(f"       Welcome, {username}!")
    print("=" * 35)
    print("1. Write a new entry")
    print("2. View diary entries")
    print("3. Verify diary integrity")
    print("4. Logout")
    print("=" * 35)


def get_choice():
    return input("Choose an option: ").strip()


def register():
    print("\n--- Register ---")

    username = input("Enter username: ").strip()
    password = getpass("Enter password: ") #using getpass to hide password when typing it in
    confirm_password = getpass("Confirm password: ")

    if password != confirm_password:
        print("Passwords do not match.")
        return

    try:
        register_user(username, password)
        print("Registration successful! You can now log in!")

    except AuthError as error:
        print(f"Registration failed: {error}")

def login():
    print("\n--- Login ---")

    username = input("Enter username: ").strip()
    password = getpass("Enter password: ")

    try:
        session = login_user(username, password)
        print(f"\nLogin successful! Welcome, {session.username}!")
        return session

    except AuthError as error:
        print(f"Login failed: {error}")
        return None

def write_entry(session):
    print("\n--- New Diary Entry ---")
    plaintext = input("Write your diary entry: ")

    try: 
        create_entry(session, plaintext)
        print("Your diary entry has been saved securely!")

    except DiaryError as error:
        print(f"Could not save entry: {error}")

def view_entries(session):
    print("\n--- Your Diary Entries ---")

    try:
        entries = get_entries(session)

        if not entries: 
            print("Your diary is empty.")
            return

        for entry in entries:
            timestamp = entry["timestamp"]

            print("\n" + "-" * 35)
            print(f"Entry #{entry['index'] + 1}")
            print(f"Date: {timestamp}")
            print(entry["text"])
            print("-" * 35)

    except DiaryError as error:
        print(f"Could not retrieve diary entries: {error}")

def check_integrity(session):
    print("\n--- Diary Integrity Check ---")

    try:
        results = verify_diary(session)
        if not results:
            print("Your diary is empty. There's nothing to verify.")
            return
        
        all_valid = True

        for index, valid, reason in results:
            if valid:
                print(f"Entry {index + 1}: VALID")
            else:
                print(f"Entry {index + 1}: INVALID - {reason}")
                all_valid = False

        if all_valid:
            print("\nAll diary entries passed verification.")
        else:
            print("\nWARNING: Diary integrity check failed!")

    except DiaryError as error:
        print(f"Verification failed: {error}")

def diary_menu(session):
    while True:
        show_diary_menu(session.username)
        choice = get_choice()

        if choice == "1":
            write_entry(session)

        elif choice == "2":
            view_entries(session)

        elif choice == "3":
            check_integrity(session)

        elif choice == "4":
            print("Logging out...")
            break

        else:
            print("Invalid option. Please try again.")

def main_menu():
    while True:
        show_main_menu()
        choice = get_choice()

        if choice == "1":
            register()

        elif choice == "2":
            session = login()
            if session is not None:
                diary_menu(session)

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main_menu()
