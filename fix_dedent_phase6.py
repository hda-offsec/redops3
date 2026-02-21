
import os

target_file = 'scan_engine/orchestrator.py'

def fix_dedent():
    with open(target_file, 'r') as f:
        lines = f.readlines()

    new_lines = []
    
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # Dedent Phase 6 body
        if 1539 <= line_num <= 1665:
            # Remove 4 spaces from start defined as 1 level of indentation
            if line.startswith("    "):
                new_lines.append(line[4:])
            else:
                 # Should not happen if indentation logic is consistent
                new_lines.append(line)
        else:
            new_lines.append(line)

    with open(target_file, 'w') as f:
        f.writelines(new_lines)
    
    print(f"Dedented Phase 6 body in {target_file}")

if __name__ == "__main__":
    fix_dedent()
