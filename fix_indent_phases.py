
import os

target_file = 'scan_engine/orchestrator.py'

def fix_indentation():
    with open(target_file, 'r') as f:
        lines = f.readlines()

    new_lines = []
    
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # Indent Phase 3.5 try block
        if 1243 <= line_num <= 1264:
            new_lines.append("    " + line)
        # Indent Phase 3.7 try block
        elif 1268 <= line_num <= 1289:
            new_lines.append("    " + line)
        else:
            new_lines.append(line)

    with open(target_file, 'w') as f:
        f.writelines(new_lines)
    
    print(f"Fixed indentation for Phase 3.5 and 3.7 in {target_file}")

if __name__ == "__main__":
    fix_indentation()
