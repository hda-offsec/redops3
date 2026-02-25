import os

dir_path = "/home/doomer/Bureau/redops3/ui/web/templates"

for root, dirs, files in os.walk(dir_path):
    for file in files:
        if file.endswith(".html"):
            filepath = os.path.join(root, file)
            with open(filepath, 'r') as f:
                content = f.read()

            new_content = content.replace("text-cyber", "text-info")
            new_content = new_content.replace("border-cyber", "border-secondary")
            new_content = new_content.replace("glass-panel", "")
            new_content = new_content.replace("bg-black", "")
            new_content = new_content.replace("font-monospace", "")
            new_content = new_content.replace("animate-pulse", "")
            new_content = new_content.replace("text-cyber-red", "text-danger")
            new_content = new_content.replace("cursor-blink", "")
            new_content = new_content.replace("blink-animation", "")
            
            if new_content != content:
                with open(filepath, 'w') as f:
                    f.write(new_content)
                print(f"Updated {filepath}")
print("Done")
