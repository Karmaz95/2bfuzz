#!/usr/bin/env python3
import argparse
import socket
import os
import subprocess

### PARSER ---
def parse_args():
    parser = argparse.ArgumentParser(description='2bfuzz is a TCP FUZZER and a payload GENERATOR.')
    parser.add_argument('--ip', '-i', help='Server IP address.')
    parser.add_argument('--port', '-p', type=int, help='Server port number.')
    parser.add_argument('--generator', '-g', metavar='path/to/save/', nargs='?', const='payloads/', default=None, help='Path where to save generated payloads.')
    parser.add_argument('--bytes', '-b', action='store_true', help='2-bytes generator.')
    parser.add_argument('--radamsa', '-r', metavar='FILE', help='Radamsa generator with a given pattern stored in a file.')
    parser.add_argument('--count', '-c', type=str, help='Number of payloads to generate with Radamsa.')
    return parser.parse_args()


### PAYLOAD GENERATOS ---
def two_bytes_generator(save_path):
    '''Generate and save 2B payloads'''
    # Check if the directory exist, if not create it
    if not os.path.exists(save_path):
        os.makedirs(save_path)
    # Generates and save 256 single bytes (chars) => \x00-\xff
    for c in range(256):
        with open(f"{save_path}/{c}.2B", "wb") as f:
            f.write(bytes([c]))
    # Generates and save 65536 double bytes (words) => \x00\x00-\xff\xff
    for i in range(256):
        for j in range(256):
            c+=1
            with open(f"{save_path}/{c}.2B", "wb") as f:
                f.write(bytes([i,j]))


def radamsa_generator(pattern_file, count=None, save_path=None):
    if save_path is not None and count is not None:
        if not os.path.exists(save_path):
            os.makedirs(save_path)
        subprocess.check_output(['radamsa', pattern_file, "-n", count, "-o", f"{save_path}/%n.%s"])
        return
    return subprocess.check_output(['radamsa', pattern_file])


### TCP FUZZING ---
def tcp_handshake(ip, port):
    '''Connecting to the service on a given IP:PORT and initialize connection for sending payloads. If the port is opened, returns socket object, else returns None'''
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # SYN, SYN-ACK, and ACK steps of the three-way handshake
    result = sock.connect_ex((ip, port))
    if result == 0:
        return sock
    else:
        return None


def initial_check(ip,port):
    '''Checking if the server is responding before fuzzing and closing the connection.'''
    sock = tcp_handshake(ip, port)
    if sock is not None:
        print(f"[+] The service on: {ip}:{port} is up.")
        sock.close()
        return True
    return False


def send_bytes(sock,payload):
    '''Sending bytes and closing the connection.'''
    sock.sendall(payload)
    sock.close()


def tcp_fuzzer(ip,port,payload,last_payload):
    '''TCP fuzzing engine. Takes the ip:port of the target. Start the connection. Send the payload. If socket is closed returned last used payload and stop the execution.'''
    sock = tcp_handshake(ip, port)
    if sock is not None:
        send_bytes(sock,payload)
        return payload
    else:
        print(f"[+] The service is down. The last payload could crash it.\n\t Content of the last payload: {str(last_payload)}")
        exit(0)


def two_bytes_fuzzer(ip,port):
    '''Fuzz the first two bytes using tcp_fuzzer engine (\x00-\xff\xff)'''
    if initial_check(ip,port):
        print(f"[+] Starting fuzzing first byte.")
        last_payload = b""
        for i in range(256):
            last_payload = tcp_fuzzer(ip,port,bytes([i]),last_payload)
        print(f"[+] Starting fuzzing first 2 bytes.")
        for i in range(256):
            for j in range(256):
                last_payload = tcp_fuzzer(ip,port,bytes([i,j]),last_payload) 
    else:
        print(f"The service on: {ip}:{port} is down.")
        exit(0)


def radamsa_fuzzer(ip,port,pattern_file):
    '''Fuzz the target using the Radamsa engine.'''
    if initial_check(ip,port):
        print(f"[+] Starting fuzzing using Radamsa. Press CTRL+C to stop.")
        last_payload = b""
        while True:
            try:
                payload = radamsa_generator(pattern_file)
                last_payload = tcp_fuzzer(ip,port,payload,last_payload)
            except KeyboardInterrupt:
                print('[+] FUZZING INTERRUPTED BY THE USER')
                exit(0)
    else:
        print(f"The service on: {ip}:{port} is down.") 


def main():
### PARSING ARGUMENTS
    args = parse_args()
    # Validate input - exit if user used both generator and fuzzer.
    if args.generator is not None and (args.ip is not None or args.port is not None):
        print("Error: Cannot use --generator with --ip and --port!")
        return
    elif args.generator is None and (args.ip is None or args.port is None):
        print("Error: (--ip and --port) or --generator required!")
        return
    
### FUZZER PART
    if args.ip is not None and args.port is not None:
        ip = args.ip
        port = args.port
        # 2B fuzzing
        if args.bytes:
            two_bytes_fuzzer(ip,port)
        # RADAMSA fuzzing
        if args.radamsa:
            pattern_file = args.radamsa
            radamsa_fuzzer(ip,port,pattern_file)
    elif args.generator is not None:
### GENERATOR PART
        save_path = args.generator
        if args.bytes:
        # 2B generator
            two_bytes_generator(save_path)
        # RADAMSA generator
        if args.radamsa and args.count is not None:
            pattern_file = args.radamsa
            radamsa_generator(pattern_file, args.count, save_path)
        elif args.radamsa is not None and args.count is None:
            print("You must specify the -r PATTERN_FILE and -c NUMBER_OF_PAYLOADS")
    else:
        return
         

if __name__ == '__main__':
    main()
