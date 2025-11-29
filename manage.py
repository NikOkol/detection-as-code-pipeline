#!/usr/bin/env python3
import sys
from src.start_flask import main as start_flask_main
from src.orchestrator import destroy_vm, halt_all_vms, vm_statuses



HELP_TEXT = """
Usage: manage.py <command>

Available commands:
  start                     Start flask server
  status                    Show VM's status
  halt                      Halt all VMs
  destroy <Linux/Windows>   Destroy specified VM
"""

def help_command():
    print(HELP_TEXT)

def start():
    start_flask_main()

def status():
    statuses = vm_statuses()
    for vm, status in statuses.items():
        print(f"{vm}: {status}")

def destroy():
    if len(sys.argv) != 3:
        print("Usage: manage.py destroy <Linux/Windows>")
        sys.exit(1)
    os_name = sys.argv[2]
    try:
        destroy_vm(os_name)
    except ValueError as ve:
        print(ve)
        sys.exit(1)
    print(f"{os_name} VM destroyed.")



COMMANDS = {
    "start": start,
    "status": status,
    "halt": halt_all_vms,
    "destroy": destroy,
    "help": help_command,
}

def main():
    if len(sys.argv) < 2:
        help_command()
        sys.exit(1)

    cmd = sys.argv[1]

    # Если команда неизвестна — выводим help
    if cmd not in COMMANDS:
        print(f"Unknown command: {cmd}\n")
        help_command()
        sys.exit(1)

    # Выполнить команду
    COMMANDS[cmd]()

if __name__ == "__main__":
    main()
