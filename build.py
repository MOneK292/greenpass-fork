import os
import sys
import subprocess

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
            
        # Strip local imports starting with "from src." or "import src"
        cleaned_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("from src.") or stripped.startswith("import src."):
                # Comment out or skip the local imports so the combined file remains valid
                continue
            cleaned_lines.append(line)
            
        output_content.writelines(cleaned_lines) if hasattr(output_content, 'writelines') else output_content.extend(cleaned_lines)

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
