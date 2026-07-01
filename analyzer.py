import os

print("===================================")
print(" Project Falcon - Log Analyzer")
print("===================================\n")

log_file = input("Enter the path to a text log file: ")

if not os.path.exists(log_file):
    print("\nError: File not found.")
    exit()

failed = 0
errors = 0
warnings = 0

with open(log_file, "r", encoding="utf-8", errors="ignore") as file:
    for line in file:
        text = line.lower()

        if "failed" in text:
            failed += 1

        if "error" in text:
            errors += 1

        if "warning" in text:
            warnings += 1

print("\n========== Analysis Complete ==========")
print(f"Failed Events : {failed}")
print(f"Errors        : {errors}")
print(f"Warnings      : {warnings}")
print("=======================================")
