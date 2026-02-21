
import re

target_file = 'scan_engine/orchestrator.py'

def is_phase_line(line):
    return line.strip().startswith("# --- PHASE") or line.strip().startswith("# --- PREPARE URLS") or line.strip().startswith("# --- IMPROVED TECH")

def is_except_line(line):
    # exact match for the 8-space indentation except we are seeing
    return line.startswith("        except Exception") or line.startswith("        except Exception:")

def has_try_in_block(lines, start_idx, end_idx):
    for i in range(start_idx, end_idx):
        if lines[i].startswith("        try:"):
            return True
    return False

def fix_try_blocks():
    with open(target_file, 'r') as f:
        lines = f.readlines()

    # Identify Phases
    phase_indices = []
    for i, line in enumerate(lines):
        if is_phase_line(line):
            phase_indices.append(i)
    
    # Identify Excepts (candidates)
    except_indices = []
    for i, line in enumerate(lines):
        if is_except_line(line):
            except_indices.append(i)

    # We will build a new list of lines
    # But since we are inserting, indices shift. 
    # Better to work with separate chunks or do a single pass with buffer.
    
    # Let's map modifications: (insert_at_idx, content), and (indent_from, indent_to)
    
    # Actually, simpler: Determine ranges to wrap.
    ranges_to_wrap = []
    
    for i in range(len(phase_indices)):
        p_start_idx = phase_indices[i]
        p_end_limit = phase_indices[i+1] if i + 1 < len(phase_indices) else len(lines)
        
        # Find if there is an except in this range [p_start_idx, p_end_limit)
        # We look for the LAST except in this range? Or the first? 
        # Usually a phase has one main try/except.
        # But Phase 4 might have inner ones?
        # The dangling ones are at 8 spaces. Inner ones would be indented (ideally).
        # We only care about 8-space excepts.
        
        candidates = [e for e in except_indices if p_start_idx < e < p_end_limit]
        
        if not candidates:
            continue
            
        # If multiple candidates? 
        # e.g. Phase 4 has inner excepts? But are they at 8 spaces? 
        # If we indented Phase 4 correctly, inner excepts are > 8 spaces.
        # So any 8-space except here is likely the main one.
        # If there are multiple 8-space excepts in one phase... that's weird.
        # But let's assume valid structure is one (or sequential try/excepts).
        
        # Let's take the first one?
        # Or wrap each one?
        # If we have:
        # Phase X
        # code
        # except
        # code
        # except
        # Then we need two try blocks.
        
        # Strategy:
        # Iterate through lines in the Phase range.
        # If we encounter code then an except, and no try, we wrap it.
        
        # But simpler: Just wrap from Phase Start to the Except.
        # If there are multiple?
        # Let's take the LAST candidate as the end of the block? 
        # Risk: wrapping too much.
        # Let's take the FIRST candidate.
        target_except = candidates[0]
        
        # Check if try exists
        if has_try_in_block(lines, p_start_idx, target_except):
            print(f"Skipping Phase at line {p_start_idx+1}: already has try.")
            continue
            
        print(f"Fixing Phase at line {p_start_idx+1}: inserting try before {target_except+1}")
        ranges_to_wrap.append((p_start_idx + 1, target_except)) # Insert after start, indent up to except
    
    # Apply changes reverse order to not mess up indices
    ranges_to_wrap.sort(key=lambda x: x[0], reverse=True)
    
    new_lines = list(lines)
    
    for start_idx, end_idx in ranges_to_wrap:
        # start_idx is line index of Phase header + 1 (roughly).
        # We want to insert '        try:\n' after the Phase header (or comments).
        
        # Refine start: skip comments/empty lines after phase header
        insert_pos = start_idx
        while insert_pos < end_idx:
            line = new_lines[insert_pos].strip()
            if not line or line.startswith("#"):
                insert_pos += 1
            else:
                break
        
        # Insert try
        new_lines.insert(insert_pos, "        try:\n")
        
        # Indent lines from insert_pos+1 to end_idx (which is now +1 because of insert)
        # The end_idx was original index of 'except'.
        # Since we inserted 1 line before it, formatting relative logic:
        # range to indent is [insert_pos+1, end_idx+1)
        
        for k in range(insert_pos + 1, end_idx + 1):
             if new_lines[k].strip(): # Only indent non-empty
                 new_lines[k] = "    " + new_lines[k]

    with open(target_file, 'w') as f:
        f.writelines(new_lines)
    
    print("Fixed missing try blocks.")

if __name__ == "__main__":
    fix_try_blocks()
