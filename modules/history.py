import json
import os

HISTORY_FILE = "scan_history.json"

def save_to_history(scan_data):
    """Save the scan results to history."""
    if not os.path.exists(HISTORY_FILE):
        # Initialize with an empty list if file doesn't exist
        with open(HISTORY_FILE, "w") as f:
            json.dump([], f)
    
    # Load the current history as a list
    with open(HISTORY_FILE, "r+") as f:
        history = json.load(f)
        
        # Ensure history is a list, append the new scan data
        if isinstance(history, list):
            history.append(scan_data)
        else:
            # If it's not a list, reset it to an empty list and append the data
            history = [scan_data]
        
        # Save the updated history back to the file
        f.seek(0)
        json.dump(history, f, indent=4)

def load_history():
    """Load scan history."""
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            return json.load(f)
    return []

def get_scan_by_uuid(scan_uuid, scan_type):
    """Retrieve a scan by UUID and type from the history."""
    history = load_history()
    for scan in history:
        if scan["uuid"] == scan_uuid and scan["scantype"] == scan_type:
            return scan
    return None
