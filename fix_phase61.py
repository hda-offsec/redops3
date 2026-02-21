
import os

target_file = 'scan_engine/orchestrator.py'

def fix_phase_6_1():
    with open(target_file, 'r') as f:
        lines = f.readlines()

    new_lines = []
    
    # We need to handle 1-based line numbers from the view
    # Line 1667 is the comment header
    # Line 1668 is the first line of code to wrap
    # Line 1713 is the except block
    
    start_wrap_line = 1668
    end_wrap_line = 1712
    
    # Validation: Check if line 1713 is indeed the except
    # Adjust index for 0-based
    
    if "except Exception" not in lines[1712]: # Line 1713
         print(f"Warning: Line 1713 does not look like the expected except block. Content: {lines[1712]}")
         # It might have shifted if previous edits changed line counts.
         # But based on the view, it should be there.
    
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # Insert try before line 1668
        if line_num == start_wrap_line:
            new_lines.append("        try:\n")
            
        # Indent lines in range
        if start_wrap_line <= line_num <= end_wrap_line:
            # Check if line is empty/just whitespace?
            if line.strip():
                new_lines.append("    " + line)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    with open(target_file, 'w') as f:
        f.writelines(new_lines)
    
    print(f"Fixed Phase 6.1 in {target_file}")

if __name__ == "__main__":
    fix_phase_6_1()
