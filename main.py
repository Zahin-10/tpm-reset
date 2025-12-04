#!/usr/bin/env python3

import subprocess
import sys
import os
from typing import List, Dict, Optional, Tuple

class ScriptRunner:
    """Class to handle running different types of scripts."""
    
    @staticmethod
    def run_filter_trace(args: List[str] = None) -> int:
        """Run the filter trace shell script."""
        command = ["bash", "filter_trace.sh"]
        if args:
            command.extend(args)
        return run_command(command, "Filter Trace Script")

    @staticmethod
    def run_parse_bitlocker(args: List[str] = None) -> int:
        """Run the BitLocker metadata parser."""
        command = ["python", "parse-bitlocker-metadata.py"]
        if args:
            command.extend(args)
        return run_command(command, "Parse BitLocker Metadata")

    @staticmethod
    def run_pcr_extend_parser(args: List[str] = None) -> int:
        """Run the PCR extend parser."""
        command = ["python", "TPM2_PCR_Extend_Command_Parser_CSV.py"]
        if args:
            command.extend(args)
        return run_command(command, "PCR Extend Parser")

    @staticmethod
    def run_unseal(args: List[str] = None) -> int:
        """Run the unseal script."""
        command = ["python", "unseal.py"]
        if args:
            command.extend(args)
        return run_command(command, "Unseal Script")

    @staticmethod
    def run_pcr_extend(args: List[str] = None) -> int:
        """Run the PCR extend script."""
        command = ["python", "run_pcr_extend.py"]
        if args:
            command.extend(args)
        return run_command(command, "Run PCR Extend")

class DockerManager:
    """Class to handle Docker container operations."""
    
    @staticmethod
    def get_compose_path() -> Optional[str]:
        """Get Docker compose file path from environment variable or user input."""
        compose_path = os.getenv('DOCKER_COMPOSE_PATH')
        if not compose_path:
            print("\nDOCKER_COMPOSE_PATH environment variable not set.")
            print("Please enter the path to your docker-compose.yml file:")
            compose_path = input("> ").strip()
        
        if not compose_path:
            print("\nNo docker-compose path provided.")
            return None
        
        compose_path = os.path.expanduser(compose_path)
        if not os.path.isfile(compose_path):
            print(f"\nError: Docker compose file not found at {compose_path}")
            return None
        
        return compose_path

    @staticmethod
    def docker_compose_command(compose_path: str, command: List[str]) -> Tuple[int, str]:
        """Run a docker-compose command and return the exit code and output."""
        try:
            full_command = ["docker", "compose", "-f", compose_path] + command
            result = subprocess.run(
                full_command,
                check=True,
                capture_output=True,
                text=True,
                cwd=os.path.dirname(compose_path)
            )
            return 0, result.stdout
        except subprocess.CalledProcessError as e:
            return e.returncode, e.stderr
        except Exception as e:
            return 1, str(e)

    @staticmethod
    def stop_containers(compose_path: str) -> bool:
        """Stop containers using docker-compose."""
        print("\nStopping containers...")
        exit_code, output = DockerManager.docker_compose_command(compose_path, ["down"])
        if exit_code != 0:
            print(f"Error stopping containers: {output}")
            return False
        print("Containers stopped successfully.")
        return True

    @staticmethod
    def start_containers(compose_path: str) -> bool:
        """Start containers using docker-compose."""
        print("\nStarting containers...")
        exit_code, output = DockerManager.docker_compose_command(compose_path, ["up", "-d"])
        if exit_code != 0:
            print(f"Error starting containers: {output}")
            return False
        print("Containers started successfully.")
        return True

    @staticmethod
    def restart_containers(compose_path: str) -> bool:
        """Restart containers using docker-compose."""
        if not DockerManager.stop_containers(compose_path):
            return False
        return DockerManager.start_containers(compose_path)

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def run_command(command: List[str], script_name: str) -> int:
    """Run a command and handle its output."""
    try:
        print(f"\nExecuting {script_name}...")
        process = subprocess.run(command, check=True)
        print(f"\n{script_name} completed successfully.")
        return process.returncode
    except subprocess.CalledProcessError as e:
        print(f"\nError running {script_name}: {str(e)}")
        return e.returncode
    except Exception as e:
        print(f"\nUnexpected error running {script_name}: {str(e)}")
        return 1

def get_script_input(script_name: str) -> List[str]:
    """Get command line arguments for a script from user input."""
    print(f"\nEnter arguments for {script_name} (press Enter if none):")
    args_input = input("> ").strip()
    return args_input.split() if args_input else []

def display_menu(scripts: Dict[str, Dict]):
    """Display the interactive menu."""
    clear_screen()
    print("=== Trace Parser Script Runner ===\n")
    for idx, (name, info) in enumerate(scripts.items(), 1):
        print(f"{idx}. {info['display_name']}")
    print(f"{len(scripts) + 1}. Restart Docker Containers")
    print("\n0. Exit")
    print("\nEnter your choice (0-{})".format(len(scripts) + 1))

def main():
    # Define available scripts with their commands and display names
    scripts = {
        "filter-trace": {
            "command": ScriptRunner.run_filter_trace,
            "display_name": "Filter Trace Script"
        },
        "parse-bitlocker": {
            "command": ScriptRunner.run_parse_bitlocker,
            "display_name": "Parse BitLocker Metadata"
        },
        "pcr-extend-parser": {
            "command": ScriptRunner.run_pcr_extend_parser,
            "display_name": "PCR Extend Parser"
        },
        "unseal": {
            "command": ScriptRunner.run_unseal,
            "display_name": "Unseal Script"
        },
        "run-pcr-extend": {
            "command": ScriptRunner.run_pcr_extend,
            "display_name": "Run PCR Extend"
        }
    }

    while True:
        display_menu(scripts)
        
        try:
            choice = input("\nChoice: ").strip()
            if not choice.isdigit():
                print("\nPlease enter a number.")
                input("\nPress Enter to continue...")
                continue

            choice = int(choice)
            if choice == 0:
                print("\nGoodbye!")
                return 0
            
            if choice == len(scripts) + 1:
                # Docker container restart option
                compose_path = DockerManager.get_compose_path()
                if compose_path:
                    if DockerManager.restart_containers(compose_path):
                        print("\nDocker containers restarted successfully.")
                    else:
                        print("\nFailed to restart Docker containers.")
                input("\nPress Enter to continue...")
                continue
            
            if choice < 0 or choice > len(scripts) + 1:
                print("\nInvalid choice. Please try again.")
                input("\nPress Enter to continue...")
                continue

            # Get the selected script
            script_name = list(scripts.keys())[choice - 1]
            script_info = scripts[script_name]
            
            # Get arguments if any
            args = get_script_input(script_info['display_name'])
            
            # Run the script using its dedicated function
            return_code = script_info['command'](args)
            
            if return_code != 0:
                print(f"\nScript exited with code {return_code}")
            
            input("\nPress Enter to continue...")

        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            return 1
        except Exception as e:
            print(f"\nAn error occurred: {str(e)}")
            input("\nPress Enter to continue...")

if __name__ == "__main__":
    sys.exit(main())
