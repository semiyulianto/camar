import os
import re
from datetime import datetime

def load_webshell_signatures(filename):
    """
    Load webshell signatures from the specified file.
    Each signature is a pattern to look for in the directory scan.
    """
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
            signatures = [line.strip() for line in file if line.strip()]
        if not signatures:
            raise ValueError("Signature file is empty or not loaded correctly.")
        print(f"Loaded {len(signatures)} signatures from {filename}")
        print()
        return [re.compile(re.escape(sig), re.IGNORECASE) for sig in signatures]  # Compile regex patterns for exact match
    except Exception as e:
        print(f"Error loading signatures from {filename}: {e}")
        return []

def is_webshell_file(file_name, signature_patterns):
    """
    Check if a file matches any webshell signature pattern.
    """
    return any(pattern.fullmatch(file_name) for pattern in signature_patterns)

def scan_directory(directory, signature_patterns, excluded_files):
    """
    Scan the given directory for files matching the loaded signature patterns.
    Exclude specified files from the scan.
    """
    potential_webshells = []
    common_false_positives = {"README.md", ".gitignore", "LICENSE"}
    included_extensions = ('.php', '.asp', '.asp.net', '.js', '.jsp', '.pl', '.ps1')

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            abs_file_path = os.path.abspath(file_path)
            if abs_file_path in excluded_files or file in common_false_positives:
                continue  # Skip the excluded files and common false positives
            # Only include specific extensions
            if not file.lower().endswith(included_extensions):
                continue
            # Exclude files without an extension or with the extension .sample
            if '.' not in file or file.lower().endswith('.sample'):
                continue
            print(f"Scanning {file_path}")
            # Check if the filename matches any signature pattern
            if is_webshell_file(file, signature_patterns):
                potential_webshells.append(file_path)
                print(f"Potential webshell detected: {file_path}")
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    print(f"--- Content of {file_path} ---")
                    print(f.read())
                    print(f"--- End of {file_path} ---\n")
    return potential_webshells

def save_report(potential_webshells, report_filename, tool_name, description):
    """
    Save the scan results to a report file.
    """
    with open(report_filename, 'w', encoding='utf-8') as report_file:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_file.write(f"{tool_name}\n{description}\n\n")
        report_file.write("WebShell Analysis Summary\n")
        report_file.write(f"Created: {current_time}\n\n")
        if potential_webshells:
            report_file.write("Potential webshells found:\n")
            for webshell in potential_webshells:
                report_file.write(f"{webshell}\n")
        else:
            report_file.write("No potential webshells found.\n")
        
        report_file.write("\nWARNING! Please conduct a thorough manual review of the file contents to ensure precise detection.\n")
        
    print(f"\nReport saved to {report_filename}")

def main():
    """
    Main function to execute the webshell scanning tool.
    """
    tool_name = "Camar v0.1"
    description = "The Intelligent WebShell Scanner"
    signature_file = 'webshells.sig'
    report_file = 'analysis_summary.log'
    script_file = os.path.abspath(__file__)

    print(f"{tool_name}\n{description}\n")

    signature_patterns = load_webshell_signatures(signature_file)
    if not signature_patterns:
        print("No signatures to scan for. Exiting.")
        return

    directory_to_scan = input("Enter the directory to scan: ")
    
    if not os.path.isdir(directory_to_scan):
        print("Invalid directory.")
        return

    excluded_files = {
        os.path.abspath(signature_file),
        os.path.abspath(report_file),
        script_file
    }

    potential_webshells = scan_directory(directory_to_scan, signature_patterns, excluded_files)
    
    if potential_webshells:
        print("\nPotential webshells found:")
        for webshell in potential_webshells:
            print(webshell)
    else:
        print("\nNo potential webshells found.")
    
    print("\nWARNING! Please conduct a thorough manual review of the file contents to ensure precise detection.")
    
    save_report(potential_webshells, report_file, tool_name, description)

if __name__ == "__main__":
    main()
