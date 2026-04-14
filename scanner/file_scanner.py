import os
import hashlib
import sys
import time

def file_hash(file_path):
    """
    Calculates SHA256 hash of a given file.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None


def scan_directory(dir_path):
    """
    Scans a directory recursively and returns list of all files with SHA256 hash.
    Displays a real-time progress bar in the terminal.
    """
    files_to_scan = []

    # Step 1: Collect all files
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            full_path = os.path.join(root, file)
            if os.path.isfile(full_path):
                files_to_scan.append(full_path)

    total_files = len(files_to_scan)
    files_scanned = []
    start_time = time.time()

    # Step 2: Iterate through and compute hashes
    for idx, path in enumerate(files_to_scan, start=1):
        try:
            if os.path.getsize(path) > 50 * 1024 * 1024:  # skip files > 50MB
                continue
            hash_val = file_hash(path)
            files_scanned.append({'file': path, 'hash': hash_val})
        except Exception:
            continue

        # Step 3: Progress bar update
        progress = int((idx / total_files) * 20)  # 20-segment bar
        bar = '#' * progress + '.' * (20 - progress)
        percent = (idx / total_files) * 100

        sys.stdout.write(f"\r[{bar}] {percent:.1f}% | {idx}/{total_files} files scanned")
        sys.stdout.flush()

    end_time = time.time()
    print(f"\nScan completed in {end_time - start_time:.2f} seconds.")
    print(f"Total files scanned: {len(files_scanned)}")

    return files_scanned
