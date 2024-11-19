import idaapi
import idautils
import idc
import os
import sys
import shutil

# List of banned/vulnerable functions
BANNED_FUNCTIONS = [
    "strcpy", "strcat", "sprintf", "gets",
    "scanf", "sscanf", "fscanf", "vscanf",
    "vsscanf", "vfscanf", "system", "popen"
]

def find_paths_to_function(start_ea, target_ea, visited=None, path=None):
    """Recursively find paths from a start address to a target address."""
    if visited is None:
        visited = set()
    if path is None:
        path = []

    if start_ea in visited:
        return []
    visited.add(start_ea)
    path.append(start_ea)

    if start_ea == target_ea:
        return [list(path)]

    paths = []
    for succ_ea in idautils.CodeRefsFrom(start_ea, 0):
        paths.extend(find_paths_to_function(succ_ea, target_ea, visited, path))

    path.pop()
    return paths

def get_function_paths(func_name):
    """Get paths from main to a specific function."""
    main_ea = idc.get_name_ea_simple("main")
    func_ea = idc.get_name_ea_simple(func_name)
    if main_ea == idc.BADADDR or func_ea == idc.BADADDR:
        return []
    return find_paths_to_function(main_ea, func_ea)

def check_banned_functions():
    """Check the binary for banned functions and find paths."""
    found_functions = {}
    for func_name in BANNED_FUNCTIONS:
        func_ea = idc.get_name_ea_simple(func_name)
        if func_ea != idc.BADADDR:
            paths = get_function_paths(func_name)
            found_functions[func_name] = paths
    return found_functions

def analyze_binary(binary_path):
    """Analyze a single binary for banned functions."""
    print(f"Analyzing: {binary_path}")
    if not idaapi.load_and_run_plugin("idaload", 0):
        print(f"Failed to load binary: {binary_path}")
        return {}

    found_functions = check_banned_functions()
    idaapi.qexit(0)  # Close IDA after the analysis

    return found_functions

def write_paths_to_file(file_path, func_paths, output_dir):
    """Write the paths to a text file for the binary."""
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{os.path.basename(file_path)}_paths.txt")
    with open(output_file, "w") as f:
        for func_name, paths in func_paths.items():
            f.write(f"Function: {func_name}\n")
            for path in paths:
                f.write(" -> ".join([hex(addr) for addr in path]) + "\n")
            f.write("\n")
    print(f"Paths written to {output_file}")

def copy_to_target_dir(file_path, target_dir):
    """Copy a file to the target directory."""
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, os.path.basename(file_path))
    shutil.copy2(file_path, target_path)
    print(f"Copied {file_path} to {target_path}")

def main():
    if len(sys.argv) != 2:
        print("Usage: idat64 -S<path_to_script> <directory_path>")
        return

    directory_path = sys.argv[1]
    if not os.path.isdir(directory_path):
        print(f"Invalid directory: {directory_path}")
        return

    target_dir = os.path.join(directory_path, "target_binaries")
    paths_dir = os.path.join(directory_path, "paths")
    for filename in os.listdir(directory_path):
        file_path = os.path.join(directory_path, filename)
        if os.path.isfile(file_path):
            print(f"\n--- Processing {filename} ---")
            func_paths = analyze_binary(file_path)
            if func_paths:
                print(f"  Banned functions found in {filename}: {', '.join(func_paths.keys())}")
                copy_to_target_dir(file_path, target_dir)
                write_paths_to_file(file_path, func_paths, paths_dir)
            else:
                print(f"  No banned functions found in {filename}.")

if __name__ == "__main__":
    main()
