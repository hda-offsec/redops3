lines = open("ui/web/templates/scan_detail.html").readlines()

# Target broken block around 2741
start_idx = -1
for i, line in enumerate(lines):
    # Looking for the broken syntax
    if "window.updateUI({{ results | tojson | safe }" in line and "}});" not in line:
        start_idx = i
        break

if start_idx != -1:
    print(f"Found broken line at {start_idx+1}: {lines[start_idx].strip()}")
    # Fix it
    lines[start_idx] = "                    window.updateUI({{ results | tojson | safe }});\n"
    # The next line is likely closing brace '}' or garbage, let's just clean it up if needed.
    # Actually, previous manual fix might have failed or shifted lines.
    # Let's see what's physically there.
    if start_idx + 1 < len(lines) and "});" in lines[start_idx+1]:
         lines[start_idx+1] = "" # Remove redundant closing if it was split
    
    with open("ui/web/templates/scan_detail.html", "w") as f:
        f.writelines(lines)
    print("Fixed.")
else:
    print("Could not find the broken line pattern. It might be already fixed or different.")
