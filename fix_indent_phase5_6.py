
import os

target_file = 'scan_engine/orchestrator.py'

def fix_indentation():
    with open(target_file, 'r') as f:
        lines = f.readlines()

    new_lines = []
    
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # Indent Phase 5 try block (1319-1476)
        if 1319 <= line_num <= 1476:
            new_lines.append("    " + line)
        # Indent Phase 6 try block (1533-1667)
        elif 1533 <= line_num <= 1667:
            new_lines.append("    " + line)
        else:
            new_lines.append(line)

    with open(target_file, 'w') as f:
        f.writelines(new_lines)
    
    print(f"Fixed indentation for Phase 5 and 6 in {target_file}")

if __name__ == "__main__":
    fix_indentation()
