import idaapi
import idautils
import idc
import os
import sys

# List of banned/vulnerable functions
BANNED_FUNCTIONS = [
    "strcpy", "strcat", "sprintf", "gets", 
    "scanf", "sscanf", "fscanf", "vscanf", 
    "vsscanf", "vfscanf", "system", "popen"
]

def check_banned_functions():
    """Check the binary for banned functions."""
    found_functions = []
    for func_name in BANNED_FUNCTIONS:
        func_ea = idc.get_name_ea_simple(func_name)
        if func_ea != idc.BADADDR:
            found_functions.append(func_name)
    return found_functions

def analyze_binary(binary_path):
    """Analyze a single binary for banned functions."""
    print(f"Analyzing: {binary_path}")
    if not idaapi.load_and_run_plugin("idaload", 0):
        print(f"Failed to load binary: {binary_path}")
        return []

    found_functions = check_banned_functions()
    idaapi.qexit(0)  # Close IDA after the analysis

    return found_functions

def main():
    if len(sys.argv) != 2:
        print("Usage: idat64 -S<path_to_script> <directory_path>")
        return

    directory_path = sys.argv[1]
    if not os.path.isdir(directory_path):
        print(f"Invalid directory: {directory_path}")
        return

    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            print(f"\n--- Processing {filename} ---")
            found_functions = analyze_binary(file_path)
            if found_functions:
                print(f"  Banned functions found in {filename}: {', '.join(found_functions)}")
            else:
                print(f"  No banned functions found in {filename}.")

if __name__ == "__main__":
    main()
