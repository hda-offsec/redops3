
import os

FILE_PATH = "scan_engine/orchestrator.py"

def fix_orchestrator():
    with open(FILE_PATH, 'r') as f:
        lines = f.readlines()
        
    new_lines = []
    
    # State flags
    in_setup = False
    in_osint = False
    in_takeover = False
    
    # We need to look ahead/behind sometimes
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # 1. Header Try Block Removal
        # Detect try at line 99 approx (indent 8)
        if line.strip() == "try:" and line.startswith("        try:"):
            # Skip this line
            in_setup = True
            i += 1
            continue
            
        # Detect end of setup (Start of Phase 1)
        if "# --- PHASE 1:" in line:
            in_setup = False
            
        # 2. OSINT Block Dedent
        if "# --- PHASE 0:" in line:
            in_osint = True
        # End of OSINT is start of Phase 3 (Deep Analysis) in our new order
        if "# --- PHASE 3:" in line:
            in_osint = False
            
        # 3. Takeover Block Dedent
        if "# --- PHASE 0.8:" in line:
            in_takeover = True
        # End of Takeover is start of Phase 6 (Rest)
        if "# --- PHASE 6:" in line:
            in_takeover = False
            
        # 4. Global Except Removal
        # This is at the end of run_pipeline.
        # It indentation 8.
        # We need to be careful not to remove other excepts.
        # The global try starts at 99. The except is likely near 2200 now.
        # It wraps the whole function.
        # We can detect it if it's "        except Exception as e:" and followed by "return False" or logging "Phase ... failed" generically?
        # Actually, let's look at the very end of the phase blocks. 
        # After Phase 8, it returns success.
        # The global except handles crashes.
        # If we remove global try, we MUST remove global except.
        pass

        # Apply transformations
        if in_setup:
            # Dedent 12 -> 8
            if line.startswith("            "):
                new_lines.append(line.replace("            ", "        ", 1))
            else:
                new_lines.append(line)
                
        elif in_osint:
             # Dedent 12 -> 8
            if line.startswith("            "):
                new_lines.append(line.replace("            ", "        ", 1))
            else:
                new_lines.append(line)
        
        elif in_takeover:
             # Dedent 12 -> 8
            if line.startswith("            "):
                new_lines.append(line.replace("            ", "        ", 1))
            else:
                new_lines.append(line)
                
        else:
            # Check for the Global Except at indentation 8
            # It usually corresponds to the TRY we removed.
            # Since we processed the file linearly, if we see '        except Exception as e:' 
            # AND we are NOT inside a specific phase's try catch (which are usually inner)...
            # But most phases have "try...except" at indent 8 too! (e.g. Phase 1).
            # WAIT.
            # Phase 1: 
            #   try: (12 spaces if nested? No, 8 spaces if inside run_pipeline).
            #   If Phase 1 is at 8 spaces, its try is at 8 spaces?
            #   No, usually:
            #   def run():
            #       phase1()
            #
            #   If Phase 1 has:
            #   try:
            #       ...
            #   except Exception:
            #
            #   The 'try' is at 8 spaces.
            #   So we CANNOT simply remove any 'except' at 8 spaces.
            #   We need to remove ONLY the one corresponding to the global try.
            #   The global try was at line 99.
            #   The global except is likely the LAST one in the run_pipeline method.
            #   Or we can identify it by content?
            #   ScanOrchestrator usually logs "Pipeline failed" or similar?
            #   Let's check the content of the except block if possible.
            #   If we don't remove it, it will be a Syntax Error (unexpected except).
            #   So we MUST remove it.
            #   Strategy: Count open/close blocks? Too hard.
            #   We know it's at the end of the run_pipeline method.
            #   The method ends before `def _analyze_security_headers`.
            #   So we look at the lines just before that def.
            #   If we see an except block there, remove it.
            
            if "def _analyze_security_headers" in line:
                # Look back at recent lines added to new_lines to excise the except block.
                # The except block is likely:
                # except Exception as e:
                #     self.log(...)
                #     return False
                # 
                # We can pop them from new_lines if they match.
                # Let's peek backwards safe-ish.
                # 4 lines?
                idx = len(new_lines) - 1
                cnt = 0
                while idx >= 0 and cnt < 10:
                    l = new_lines[idx]
                    if "def " in l and "run_pipeline" not in l: break # Don't go back too far
                    if "except Exception as e:" in l and l.startswith("        except"):
                         # Found it! Remove from idx to end of new_lines
                         print(f"Removing global except at index {idx}")
                         new_lines = new_lines[:idx]
                         break
                    idx -= 1
                    cnt += 1
                
                new_lines.append(line) # Add the def line
            else:
                new_lines.append(line)
        
        i += 1
        
    with open(FILE_PATH, 'w') as f:
        f.writelines(new_lines)
        
    print("Indentation fixed.")

if __name__ == "__main__":
    fix_orchestrator()
