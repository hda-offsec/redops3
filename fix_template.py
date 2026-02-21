lines = open("ui/web/templates/scan_detail.html").readlines()
# Target lines are around 2727-2734 (0-indexed: 2726-2733)

# Let's find the broken block
start_idx = -1
for i, line in enumerate(lines):
    if "window.updateUI({{ results | tojson | safe }" in line and "}});" not in line:
        start_idx = i
        break

if start_idx != -1:
    print(f"Found broken line at {start_idx+1}: {lines[start_idx].strip()}")
    # We want to replace this line and the next two lines to look like:
    #                     window.updateUI({{ results | tojson | safe }});
    #                 }
    
    # Check if next lines are the garbage we expect
    print(f"Next 1: {lines[start_idx+1].strip()}")
    print(f"Next 2: {lines[start_idx+2].strip()}")
    
    lines[start_idx] = "                    window.updateUI({{ results | tojson | safe }});\n"
    lines[start_idx+1] = "                }\n"
    lines[start_idx+2] = "" # Delete this line effectively
    
    # We might need to be careful about shifting, but empty string just leaves a blank line or we can pop
    # Actually list assignment keeps the index, just makes it empty.
    # Let's actually pop to be clean.
    # But wait, modify list while iterating is bad? No we are not iterating anymore.
    
    # Resetting the lines
    # It's safer to just set them to what we want.
    
    with open("ui/web/templates/scan_detail.html", "w") as f:
        f.writelines(lines)
    print("Fixed.")
else:
    print("Could not find the broken line pattern.")
