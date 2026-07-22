import os
import sys
import subprocess
import re

FILES_TO_MERGE = [
    "src/metadata.py",
    "src/utils.py",
    "src/cores.py",
    "src/hooks.py",
    "src/main.py"
]

OUTPUT_FILE = "GreenPass.plugin"

def build():
    print("Starting build...")
    output_content = []

    for file_path in FILES_TO_MERGE:
        if not os.path.exists(file_path):
            print(f"Error: {file_path} not found!")
            sys.exit(1)
            
        print(f"Processing {file_path}...")
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        # Strip local imports, adjust author, version, and update URL
        cleaned_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("from src.") or stripped.startswith("import src."):
                # Comment out or skip the local imports so the combined file remains valid
                continue
            
            if stripped.startswith("__author__ ="):
                line = '__author__ = "@likenoneother / gemini"\n'
            elif stripped.startswith("__version__ ="):
                match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', line)
                if match:
                    orig_version = match.group(1)
                    if not orig_version.endswith('f'):
                        line = f'__version__ = "{orig_version}f"\n'
            elif stripped.startswith("GREENPASS_UPDATE_URL ="):
                line = 'GREENPASS_UPDATE_URL = ""\n'
                        
            cleaned_lines.append(line)
            
        output_content.extend(cleaned_lines)

    # Write output file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
        out.write("".join(output_content))

    print(f"Successfully generated {OUTPUT_FILE}")

    # Verify syntax
    print("Verifying syntax...")
    try:
        # Run py_compile to check syntax
        result = subprocess.run([sys.executable, "-m", "py_compile", OUTPUT_FILE], 
                                capture_output=True, text=True)
        if result.returncode == 0:
            print("Syntax check passed! The plugin compiles successfully.")
        else:
            print("Syntax check failed!")
            print(result.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"Could not run syntax check: {e}")

if __name__ == "__main__":
    build()
