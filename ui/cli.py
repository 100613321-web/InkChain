"""Command line interface. It only talks to the services layer, never to crypto or files directly."""
from datetime import datetime
from services.auth import register_user, login_user, AuthError, MIN_PASSWORD_LEN
from services.diary import create_entry, verify_diary, DiaryError, get_entry_list, get_entry
from getpass import getpass

def format_timestamp(timestamp: int) -> str:
    """Unix time -> 2026-11-26 14:30. If the number is nonsense, just show it as it is."""
    try:
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")
    except(OverflowError, OSError, ValueError):
        return str(timestamp)

def show_main_menu():
    # start screen
    print("\n" + "=" * 35)
    print("          INKCHAIN")
    print("      Your Secure Diary")
    print("=" * 35)
    print("1. Register")
    print("2. Login")
    print("3. Exit")
    print("=" * 35)


def show_diary_menu(username):
    # menu after login
    print("\n" + "=" * 35)
    print(f"       Welcome, {username}!")
    print("=" * 35)
    print("1. Write a new entry")
    print("2. View diary entries")
    print("3. Verify diary integrity")
    print("4. Logout")
    print("=" * 35)


def get_choice():
    # one place for the "Choose an option" prompt
    return input("Choose an option: ").strip()


def register():
    """Ask for username and password twice, then create the account."""
    print("\n--- Register ---")

    username = input("Enter username: ").strip()
    print(f"Password: at least {MIN_PASSWORD_LEN} characters, mixing 3 of: lowercase, uppercase, digits, symbols.")
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
    """Ask for credentials. Returns the session, or None if the login failed."""
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

def read_multiline(prompt):
    """input() reads one line only, so keep reading until the user sends an empty line."""
    print(f"{prompt} (finish with an empty line):")
    lines = []
    while True:
        line = input()
        if not line:
            break
        lines.append(line)
    return "\n".join(lines)

def write_entry(session):
    """Ask for a title and a text, then save the entry (encrypted by the service)."""
    print("\n--- New Diary Entry ---")
    title = input("Title: ")
    plaintext = read_multiline("Write your diary entry: ")

    try: 
        create_entry(session, plaintext, title=title)
        print("Your diary entry has been saved securely!")

    except DiaryError as error:
        print(f"Could not save entry: {error}")

def show_entry(session, index):
    """Print one decrypted entry. (get_entry verifies the whole diary first.)"""
    entry = get_entry(session, index)
    print("\n" + "-" * 35)
    print(f"Entry #{entry['index'] + 1}: {entry['title'] or '(untitled)'}")
    print(f"Date: {format_timestamp(entry['timestamp'])}")
    print()
    print(entry["text"])
    print("-" * 35)


def view_entries(session):
    """Show the list of entries, then let the user open one by its number."""
    print("\n--- Your Diary Entries ---")

    try:
        entries = get_entry_list(session)

        if not entries: 
            print("Your diary is empty.")
            return

        for entry in entries:
            print(f"{entry['index'] + 1:>3}. {format_timestamp(entry['timestamp'])}  {entry['title'] or '(untitled)'}")

        while True:
            choice = input("\nEntry number to open (Enter to go back): ").strip()

            if not choice:
                return

            if not choice.isdigit():
                print("Please enter a number.")
                continue

            try:
                show_entry(session, int(choice) - 1)
            except DiaryError as error:
                print(error)

    except DiaryError as error:
        print(f"Could not retrieve diary entries: {error}")

def check_integrity(session):
    """Print one line per entry: VALID, or INVALID with the reason. Row "Diary" = the signed head."""
    print("\n--- Diary Integrity Check ---")

    try:
        results = verify_diary(session)
        if not results:
            print("Your diary is empty. There's nothing to verify.")
            return
        
        all_valid = True

        for index, valid, reason in results:
            label = "Diary" if index is None else f"Entry {index + 1}"
            if valid:
                print(f"{label}: VALID")
            else:
                print(f"{label}: INVALID - {reason}")
                all_valid = False

        if all_valid:
            print("\nAll diary entries passed verification.")
        else:
            print("\nWARNING: Diary integrity check failed!")

    except DiaryError as error:
        print(f"Verification failed: {error}")

def diary_menu(session):
    """Menu loop for a logged-in user. The finally makes sure the keys are dropped on ANY exit."""
    try:
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
    finally: 
        session.close()

def main_menu():
    """Start screen loop. Ctrl+C or Ctrl+D ends the program politely instead of showing a traceback."""
    try:
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

    except(KeyboardInterrupt, EOFError):
        print("\nGoodbye!")

if __name__ == "__main__":
    main_menu()
