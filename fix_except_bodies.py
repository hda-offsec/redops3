
import os

target_file = 'scan_engine/orchestrator.py'

def fix_except_bodies():
    with open(target_file, 'r') as f:
        lines = f.readlines()

    new_lines = []
    
    for i, line in enumerate(lines):
        if i > 0:
            prev = lines[i-1]
            # Check if previous line was an except block at 8 spaces
            if (prev.startswith('        except Exception') or prev.startswith('        except Exception:')):
                # Check if current line is at 8 spaces (implying incorrectly indented body)
                # We check for common body starters like self.log, return, pass
                if (line.startswith('        self.log') or 
                    line.startswith('        return') or 
                    line.startswith('        pass') or
                    line.startswith('        print')):
                    new_lines.append("    " + line)
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    with open(target_file, 'w') as f:
        f.writelines(new_lines)
    
    print(f"Fixed except bodies in {target_file}")

if __name__ == "__main__":
    fix_except_bodies()
