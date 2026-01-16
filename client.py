#!/usr/bin/env python3
"""
Simple Python client for iOS shell server.
Supports automatic file download with base64 decoding.
"""

import socket
import sys
import os
import base64
import argparse

def parse_scp_response(response, host_base_path):
    """
    Parse SCP response and save files to host.
    Format: SCP:host_path;FILE:relative_path;base64data\n...
    """
    lines = response.strip().split('\n')
    for line in lines:
        if line.startswith('FILE;'):
            parts = line.split(';', 2)
            if len(parts) == 3:
                relative_path = parts[1]
                b64_data = parts[2]
                try:
                    file_data = base64.b64decode(b64_data)
                    full_path = os.path.join(host_base_path, relative_path)
                    os.makedirs(os.path.dirname(full_path), exist_ok=True)
                    with open(full_path, 'wb') as f:
                        f.write(file_data)
                    print(f"Saved: {full_path}")
                except Exception as e:
                    print(f"Error saving {relative_path}: {e}")
        else:
            if line.strip():  # Only print non-empty unknown lines
                print(f"Unknown SCP line: {line}")

def main():
    parser = argparse.ArgumentParser(description='iOS Shell Client')
    parser.add_argument('command', help='Command to execute on iOS device')
    parser.add_argument('--host', default='localhost', help='Host to connect to (default: localhost)')
    parser.add_argument('--port', type=int, default=8080, help='Port to connect to (default: 8080)')

    args = parser.parse_args()

    try:
        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((args.host, args.port))

        # Send command
        command = args.command + '\n'
        sock.send(command.encode('utf-8'))

        # Receive response
        response = b''
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

        response_str = response.decode('utf-8', errors='ignore')

        # Check if it's SCP download
        if response_str.startswith('SCP:'):
            parts = response_str.split(';', 1)
            if len(parts) == 2:
                host_path = parts[0][4:]  # Remove 'SCP:'
                print(f"Downloading to: {host_path}")
                parse_scp_response(parts[1], host_path)
            else:
                print("Invalid SCP response format")
        else:
            # Regular command output
            print(response_str)

        sock.close()

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()