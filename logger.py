from datetime import datetime


def log_event(message, filename="log.txt"):
    """Write a timestamped event to the project log file."""
    entry = f"{datetime.now():%Y-%m-%d %H:%M:%S} - {message}"
    try:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception as exc:
        print(f"Logger error: {exc}")
