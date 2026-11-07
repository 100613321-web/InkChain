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


def main_menu():
    while True:
        show_main_menu()
        choice = get_choice()

        if choice == "1":
            print("Registration selected.")

        elif choice == "2":
            print("Login selected.")

        elif choice == "3":
            print("Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main_menu()