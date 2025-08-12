import hashlib
import os
import time
import json

# Default folder to monitor (change if needed)
FOLDER_TO_MONITOR = r"C:\Users\Admin\Desktop"

# File to store hashes
HASH_FILE = "file_hashes.json"

# Function to calculate SHA-256 hash of a file
def calculate_hash(file_path):
    hash_obj = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except FileNotFoundError:
        return None

# Load stored hashes
def load_hashes():
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, "r") as f:
            return json.load(f)
    return {}

# Save updated hashes
def save_hashes(hashes):
    with open(HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=4)

# Monitor the folder for changes
def monitor_directory():
    print(f"Monitoring changes in: {FOLDER_TO_MONITOR}")
    stored_hashes = load_hashes()

    while True:
        current_hashes = {}
        changes_detected = False

        for root, _, files in os.walk(FOLDER_TO_MONITOR):
            for file in files:
                file_path = os.path.join(root, file)
                file_hash = calculate_hash(file_path)

                current_hashes[file_path] = file_hash

                if file_path not in stored_hashes:
                    print(f"[NEW FILE] {file_path}")
                    changes_detected = True
                elif stored_hashes[file_path] != file_hash:
                    print(f"[CHANGED] {file_path}")
                    changes_detected = True

        for file_path in stored_hashes:
            if file_path not in current_hashes:
                print(f"[DELETED] {file_path}")
                changes_detected = True

        if changes_detected:
            save_hashes(current_hashes)
            print("[INFO] Hashes updated.\n")
        else:
            print("[INFO] No changes detected.\n")

        time.sleep(10)  # Check every 10 seconds

if __name__ == "__main__":
    monitor_directory()