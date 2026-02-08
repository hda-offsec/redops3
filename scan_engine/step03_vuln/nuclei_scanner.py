from scan_engine.helpers.process_manager import ProcessManager

class NucleiScanner:
    def __init__(self, target):
        self.target = target

    def check_tools(self):
        return ProcessManager.find_binary_path("nuclei") is not None

    def get_command(self, port, protocol='http', tags=None):
        path = ProcessManager.find_binary_path("nuclei") or "nuclei"
        url = f"{protocol}://{self.target}:{port}"
        command = [
            path, 
            "-u", url, 
            "-s", "critical,high,medium", 
            "-no-color",
            "-silent"
        ]
        if tags:
            command.extend(["-tags", tags])
        return command

    def stream_vuln_scan(self, port, protocol='http', tags=None):
        """
        Runs Nuclei on the target
        """
        command = self.get_command(port, protocol, tags)
        return ProcessManager.stream_command(command)
