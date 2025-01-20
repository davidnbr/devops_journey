import sys


def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: python enter_values.py add <text>")
    else:
        if sys.argv[1] == "add":
            with open("values.txt", "a") as file:
                file.write(sys.argv[2] + "\n")
        elif sys.argv[1] == "list":
            with open("values.txt", "r") as file:
                for line in file:
                    print(line)


if __name__ == "__main__":
    main()
