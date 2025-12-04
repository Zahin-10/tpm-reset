#!/home/tahmid/miniconda3/bin/python
import csv
import argparse
import getpass
import subprocess

try:
    import paramiko

    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False


def run_commands_locally(csv_filename):
    """Run commands locally from a CSV file."""
    with open(csv_filename, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if not row:
                continue
            command = row[0].strip()
            if not command:
                continue

            print(f"\nRunning command locally: {command}\n{'-' * 50}")
            try:
                result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True)
                print(result.stdout.strip())
            except subprocess.CalledProcessError as e:
                print(f"Command failed with exit code {e.returncode}")
                print(e.stderr.strip())


def run_commands_remote(csv_filename, hostname, username, password=None, key_filename=None):
    """Run commands on a remote machine via SSH from a CSV file."""
    if not PARAMIKO_AVAILABLE:
        print("Paramiko is not installed. Please install it with 'pip install paramiko' to use remote functionality.")
        return

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Attempt to connect
    try:
        if key_filename:
            ssh.connect(hostname, username=username, key_filename=key_filename)
        else:
            ssh.connect(hostname, username=username, password=password)
    except Exception as e:
        print(f"Failed to connect to {hostname}: {e}")
        return

    with open(csv_filename, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if not row:
                continue
            command = row[0].strip()
            if not command:
                continue

            print(f"\nRunning command on {hostname}: {command}\n{'-' * 50}")
            try:
                stdin, stdout, stderr = ssh.exec_command(command)
                exit_status = stdout.channel.recv_exit_status()  # wait for command to complete
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                if exit_status == 0:
                    print(output)
                else:
                    print(f"Command failed with exit status {exit_status}")
                    if error:
                        print(f"Error: {error}")
            except Exception as e:
                print(f"Failed to execute command: {e}")

    ssh.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run commands from a CSV file either locally or remotely via SSH.')
    parser.add_argument('--csv', required=True, help='Path to the CSV file containing commands.')
    parser.add_argument('--remote', action='store_true', help='Run commands on a remote host via SSH.')
    parser.add_argument('--host', help='Remote host address (required if --remote is used).')
    parser.add_argument('--user', help='SSH username (required if --remote is used).')
    parser.add_argument('--password', help='SSH password (optional, if not supplied and no key given, will prompt).')
    parser.add_argument('--key', help='Path to the SSH private key file (optional, used instead of password).')

    args = parser.parse_args()

    if args.remote:
        if not args.host or not args.user:
            parser.error("--remote requires --host and --user.")

        if not args.password and not args.key:
            # Prompt for password if neither password nor key is provided
            args.password = getpass.getpass(prompt='SSH Password: ')

        run_commands_remote(args.csv, args.host, args.user, password=args.password, key_filename=args.key)
    else:
        run_commands_locally(args.csv)