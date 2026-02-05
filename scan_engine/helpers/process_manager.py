import subprocess
import logging
import shlex

logger = logging.getLogger(__name__)


class ProcessManager:
    @staticmethod
    def _prepare_command(command):
        if isinstance(command, (list, tuple)):
            return list(command), False
        return command, True

    @staticmethod
    def _display_command(command):
        if isinstance(command, (list, tuple)):
            return " ".join(shlex.quote(str(part)) for part in command)
        return command

    @staticmethod
    def run_command(command, cwd=None, timeout=None):
        command, use_shell = ProcessManager._prepare_command(command)
        logger.info("Executing command: %s", ProcessManager._display_command(command))
        try:
            result = subprocess.run(
                command,
                shell=use_shell,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=cwd,
                timeout=timeout,
            )
            return True, result.stdout, result.stderr, result.returncode
        except subprocess.CalledProcessError as exc:
            logger.error("Command failed: %s", exc.stderr)
            return False, exc.stdout or "", exc.stderr or "", exc.returncode
        except subprocess.TimeoutExpired:
            logger.error("Command timed out")
            return False, "", "Timeout", None
        except Exception as exc:
            logger.error("Unexpected error: %s", str(exc))
            return False, "", str(exc), None

    @staticmethod
    def stream_command(command, cwd=None):
        command, use_shell = ProcessManager._prepare_command(command)
        logger.info("Streaming command: %s", ProcessManager._display_command(command))
        
        try:
            process = subprocess.Popen(
                command,
                shell=use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                cwd=cwd,
                bufsize=1,  # Line buffered
            )

            # Use iter() for non-blocking readline
            for line in iter(process.stdout.readline, ''):
                if line:
                    yield {"type": "stdout", "line": line.rstrip('\n\r')}

            process.stdout.close()
            return_code = process.wait()
            yield {"type": "exit", "code": return_code}
            
        except Exception as e:
            logger.error(f"Stream command failed: {e}")
            yield {"type": "error", "message": str(e)}
