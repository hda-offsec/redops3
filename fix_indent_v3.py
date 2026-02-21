
import os

target_file = 'scan_engine/orchestrator.py'

def fix_indentation():
    with open(target_file, 'r') as f:
        lines = f.readlines()

    new_lines = []
    
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # Indent DNS results block
        if 1024 <= line_num <= 1038:
            new_lines.append("    " + line)
        else:
            new_lines.append(line)

    with open(target_file, 'w') as f:
        f.writelines(new_lines)
    
    print(f"Fixed indentation in {target_file}")

if __name__ == "__main__":
    fix_indentation()
