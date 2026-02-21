
import os

target_file = 'scan_engine/orchestrator.py'

def fix_indentation():
    with open(target_file, 'r') as f:
        lines = f.readlines()

    new_lines = []
    # Adjust ranges because list checks are 0-indexed, line numbers are 1-indexed
    # Also removing lines changes indices for subsequent operations if not careful.
    # But here we are building a new list, so we just iterate original lines.
    
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # Remove dangling except block at the end
        if 2189 <= line_num <= 2194:
            continue

        # Indent Phase 1 loop body
        if 182 <= line_num <= 218:
            new_lines.append("    " + line)
        # Indent Phase 2.5 loop body
        elif 237 <= line_num <= 241:
            new_lines.append("    " + line)
        # Indent Phase 4 + OSINT block
        elif 247 <= line_num <= 979:
            new_lines.append("    " + line)
        else:
            new_lines.append(line)

    with open(target_file, 'w') as f:
        f.writelines(new_lines)
    
    print(f"Fixed indentation in {target_file}")

if __name__ == "__main__":
    fix_indentation()
