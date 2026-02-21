import ast
import os
import sys
import stdlib_list

# Map specific imports to PyPI package names
PACKAGE_MAPPING = {
    "flask": "Flask",
    "flask_sqlalchemy": "Flask-SQLAlchemy", 
    "flask_socketio": "Flask-SocketIO",
    "flask_login": "Flask-Login",
    "dotenv": "python-dotenv",
    "fpdf": "fpdf2",
    "playwright": "playwright",
    "markdown": "markdown",
    "requests": "requests",
    "celery": "celery",
    "redis": "redis",
    "bs4": "beautifulsoup4",
    "OpenSSL": "pyopenssl",
    "urllib3": "urllib3",
    "termcolor": "termcolor",
    "colorama": "colorama",
    "tqdm": "tqdm",
    "socketio": "python-socketio", 
    "engineio": "python-engineio",
    "dns": "dnspython",
    "jwt": "PyJWT",
    "werkzeug": "Werkzeug",
    "jinja2": "Jinja2",
    "sqlalchemy": "SQLAlchemy",
    "click": "click",
    "itsdangerous": "itsdangerous",
    "gevent": "gevent",
    "greenlet": "greenlet",
    "kombu": "kombu",
    "billiard": "billiard",
    "vine": "vine",
    "amqp": "amqp",
    "mmh3": "mmh3",
}

def get_stdlib():
    try:
        return set(stdlib_list.stdlib_list("3.10"))
    except Exception:
        # Fallback if stdlib_list not installed or fails
        return set(sys.builtin_module_names) | {
            "os", "sys", "re", "json", "time", "datetime", "subprocess", "threading", 
            "socket", "urllib", "random", "shutil", "glob", "argparse", "logging", 
            "collections", "itertools", "functools", "pathlib", "math", "hashlib", 
            "base64", "uuid", "abc", "typing", "statistics", "platform", "signal",
            "io", "tempfile", "shlex", "traceback", "queue", "concurrent", "asyncio",
            "multiprocessing", "pickle", "copy", "struct", "zipfile", "tarfile",
            "csv", "xml", "html", "http", "email", "unittest", "inspect", "enum"
        }

def get_imports_from_file(filepath):
    imports = set()
    with open(filepath, "r", encoding="utf-8") as f:
        try:
            tree = ast.parse(f.read(), filename=filepath)
        except SyntaxError:
            return set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split('.')[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module.split('.')[0])
    return imports

def main():
    root_dir = "/home/doomer/Bureau/redops3"
    all_imports = set()
    stdlib = get_stdlib()

    for dirpath, dirnames, filenames in os.walk(root_dir):
        if "venv" in dirpath or "__pycache__" in dirpath or ".git" in dirpath:
            continue
        for filename in filenames:
            if filename.endswith(".py"):
                filepath = os.path.join(dirpath, filename)
                all_imports.update(get_imports_from_file(filepath))

    # Filter imports
    required_packages = set()
    unknown_modules = set()

    for module in all_imports:
        if module in stdlib:
            continue
        
        # Check mapping
        if module in PACKAGE_MAPPING:
            required_packages.add(PACKAGE_MAPPING[module])
        elif module in ["core", "scan_engine", "ui", "config"]: # Local modules
            continue
        else:
             # Try to guess or flag as unknown
             # Some common ones not in mapping might be direct package names
             unknown_modules.add(module)

    # Add unknown modules if they look like packages (simple heuristic)
    for mod in unknown_modules:
        # If it's installed in venv, we might want to keep it? 
        # For now, let's just log them 
        pass

    # Basic criticals we know we need
    required_packages.add("Flask")
    required_packages.add("Flask-SQLAlchemy")
    required_packages.add("Flask-SocketIO")
    required_packages.add("python-dotenv")
    required_packages.add("celery")
    required_packages.add("redis")
    required_packages.add("playwright")
    
    # Sort and print
    print("\n".join(sorted(required_packages)))
    
    # print("\n# UNKNOWN / POTENTIAL LOCAL MODULES:", file=sys.stderr)
    # print("\n".join(sorted(unknown_modules)), file=sys.stderr)

if __name__ == "__main__":
    main()
