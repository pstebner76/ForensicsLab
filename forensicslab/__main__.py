"""Let ``python -m forensicslab`` run the same entry point as the console script."""

from forensicslab.cli import console_main

if __name__ == "__main__":
    console_main()
