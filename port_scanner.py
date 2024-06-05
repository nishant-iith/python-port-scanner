"""
Python Based Fast Port Scanner

This script is designed to perform a fast and efficient port scanning on a specified host within a user-defined range of port numbers. It utilizes multithreading to enhance the scanning speed.

Structure and Flow:
1. Command-line arguments are parsed to configure the scanning parameters including the target IP, port range, number of threads, and verbosity.
2. A generator is prepared to yield ports within the specified range.
3. Multiple threads are initiated to handle the scanning process simultaneously.
4. Each thread picks a port from the generator and attempts to establish a socket connection.
5. Identified open ports are safely added to a shared list.
6. The script outputs the list of open ports and the total time taken for the scan.


Examples of Input and Output for Different Scenarios:

Example 1:
- Command: python port_scanner.py 192.168.1.2 -s 1 -e 100 -t 10 -V
- Output:
  Open port found: 22
  Open port found: 80
  Open Ports Found - [22, 80]
  Time taken - 0.76 seconds

Example 2:
- Command: python port_scanner.py 192.168.1.2
  (Scans all ports from 1 to 65535 using the default of 500 threads without verbose output)
- Output:
  Open Ports Found - [22, 25, 80, 443, ...]
  Time taken - 123.45 seconds

Example 3:
- Command: python port_scanner.py 192.168.1.2 -t 1000
  (Scans all ports from 1 to 65535 using 1000 threads)
- Output:
  Open Ports Found - [22, 25, 80, 443, ...]
  Time taken - 67.89 seconds

Example 4:
- Command: python port_scanner.py 192.168.1.2 -s 80 -e 80
  (Scans only port 80)
- Output:
  Open Ports Found - [80]
  Time taken - 0.02 seconds

Example 5:
- Command: python port_scanner.py 192.168.1.2 -s 1 -e 1000 -t 100 -V
  (Scans ports from 1 to 1000 using 100 threads with verbose output)
- Output:
  Open port found: 22
  Open port found: 80
  Open Ports Found - [22, 80, 443, ...]
  Time taken - 3.56 seconds

Example 6:
- Command: python port_scanner.py 192.168.1.2 -V
  (Scans all ports from 1 to 65535 with verbose output)
- Output:
  Open port found: 22
  Open port found: 25
  Open port found: 80
  Open port found: 443
  Open Ports Found - [22, 25, 80, 443, ...]
  Time taken - 120.76 seconds

These examples illustrate various configurations and show how the scanner can be tailored to specific needs by adjusting the start and end ports, the number of threads, and whether to include verbose output.

"""

from argparse import ArgumentParser
import socket
from threading import Thread
from threading import Lock
from time import time

open_ports = []  # List to store the open ports discovered during the scan
ports_lock = Lock()  # Mutex lock for synchronizing access to the port generator
open_ports_lock = Lock()  # Mutex lock for synchronizing updates to the open_ports list

def prepare_args():
    """
    Parses command-line arguments to configure the port scanner.

    The function uses argparse to handle command-line options, allowing the user to specify the target IP address,
    starting and ending ports, number of threads for parallel scanning, and verbosity for additional output.

    Returns:
        args (argparse.Namespace): An object containing all of the parsed command-line data.
    """
    parser = ArgumentParser(description="Python Based Fast Port Scanner")
    parser.add_argument("ip", metavar="IPv4", help="host to scan")
    parser.add_argument("-s", "--start", dest="start", metavar="", type=int, help="starting port", default=1)
    parser.add_argument("-e", "--end", dest="end", metavar="", type=int, help="ending port", default=65535)
    parser.add_argument("-t", "--threads", dest="threads", metavar="", type=int, help="number of threads to use", default=500)
    parser.add_argument("-V", "--verbose", dest="verbose", action="store_true", help="enable verbose output")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s 1.0", help="display version information")
    args = parser.parse_args()
    return args

def prepare_ports(start: int, end: int):
    """
    Generator that yields ports within a specified range.

    Efficiently generates each port number between the start and end inclusive. This avoids the need to store all port
    numbers in memory, reducing memory usage for large ranges.

    Arguments:
        start (int): The first port in the range.
        end (int): The last port in the range.

    Yields:
        port (int): The next port number in the specified range.
    """
    for port in range(start, end + 1):
        yield port

def prepare_threads(threads: int):
    """
    Initializes and manages threads for concurrent port scanning.

    Creates a list of threads based on the specified number, assigning the scan_port function as the target for each.
    Starts all threads and waits for all to complete, ensuring the scan is fully finished before exiting.

    Arguments:
        threads (int): The number of threads to utilize for scanning.
    """
    thread_list = []
    for _ in range(threads):
        thread = Thread(target=scan_port)
        thread_list.append(thread)
        thread.start()

    for thread in thread_list:
        thread.join()

def scan_port():
    """
    Attempts to connect to a port and checks its availability.

    This function runs in multiple threads, where each thread repeatedly picks the next available port from the shared
    generator and tries to establish a TCP connection using sockets. If successful, the port is considered open and is
    added to the shared list of open_ports.

    Uses locks to ensure thread-safe operations when accessing shared resources like the port generator and the open_ports list.
    """
    global ports, open_ports, arguments

    while True:
        with ports_lock:
            try:
                port = next(ports)  # Obtain the next port to scan
            except StopIteration:
                break  # Exit the loop if no more ports are available

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect((arguments.ip, port))
                with open_ports_lock:
                    open_ports.append(port)  # Add to the list of open ports
                if arguments.verbose:
                    print(f"Open port found: {port}", end="\r")
            except (ConnectionRefusedError, socket.timeout):
                continue  # Ignore closed or unreachable ports
            except Exception as e:
                print(f"Error scanning port {port}: {str(e)}")

if __name__ == "__main__":
    arguments = prepare_args()
    ports = prepare_ports(arguments.start, arguments.end)
    start_time = time()
    prepare_threads(arguments.threads)
    end_time = time()

    if arguments.verbose:
        print()  # Ensure the last verbose output is properly separated
    print(f"Open Ports Found - {open_ports}")
    print(f"Time taken - {round(end_time - start_time, 2)} seconds")
