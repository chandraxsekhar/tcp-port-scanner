#!/usr/bin/env python3
# Small TCP port scanner + banner grabber.
# LAB USE ONLY: only scan machines you own or have permission to test.
#
# usage: python3 port_scanner.py 192.168.56.101 1-1000

import errno
import ipaddress
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

WORKERS = 100    # how many ports we test at the same time
TIMEOUT = 2      # seconds we wait for an answer

ip = ""          # set once in the main block at the bottom, scan() and grab() use it


def scan(port):
    s = None

    try:
        # socket is made inside the try because socket() can fail too
        # (for example "too many open files")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)

        # connect_ex gives back a number, it doesn't raise for a closed port
        code = s.connect_ex((ip, port))

    except Exception:
        return "error"

    finally:
        # always close, or we run out of file descriptors on big scans
        if s is not None:
            s.close()

    # number from the OS -> word
    if code == 0:
        return "open"
    if code == errno.ECONNREFUSED:      # 111, the target said no
        return "closed"
    if code == errno.ECONNABORTED:      # 103, a refusal reported another way
        return "closed"
    if code == errno.EAGAIN:            # 11, no answer in time (not proof of a firewall)
        return "filtered"
    if code == errno.ETIMEDOUT:         # 110
        return "filtered"

    # unknown number, don't guess "closed"
    return "error"


def grab(port):
    try:
        # new connection, scan() already closed its own
        with socket.create_connection((ip, port), TIMEOUT) as s:

            # FTP, SSH and SMTP talk first, so just listen
            try:
                data = s.recv(1024)
            except socket.timeout:
                data = b""

            # still silent, so we talk first (http waits for us)
            if data == b"":
                if port == 80 or port == 443:
                    probe = "GET / HTTP/1.1\r\n"
                    probe = probe + "Host: " + ip + "\r\n"
                    probe = probe + "Connection: close\r\n"
                    probe = probe + "\r\n"
                else:
                    probe = "\r\n"

                s.send(probe.encode())

                # if it is still silent this times out and the except below returns ""
                data = s.recv(1024)

            # ignore bad bytes instead of crashing
            text = data.decode(errors="ignore")
            return text.strip()

    except Exception:
        return ""


def clean(text):
    # the banner comes from the target so don't trust it.
    # escape codes could mess up our terminal, so anything not printable becomes ?
    safe_text = ""

    for character in text:
        if character.isprintable():
            safe_text = safe_text + character
        else:
            safe_text = safe_text + "?"

    # cut it so a long banner doesn't break the table
    return safe_text[:60]


def what_it_says(banner):
    if banner == "":
        return "(no banner)"

    # http: the first line is only "HTTP/1.1 200 OK", we want the Server header
    if banner.startswith("HTTP/"):
        for line in banner.splitlines():

            # blank line = headers are over, the rest is the page
            if line == "":
                break

            if line.lower().startswith("server:"):
                return clean(line)

        return "(HTTP answer, no Server header)"

    # everything else: the first line is the banner
    first_line = banner.splitlines()[0]
    return clean(first_line)


if __name__ == "__main__":

    # sys.argv = [script, target, ports]
    if len(sys.argv) != 3:
        sys.exit("usage: python3 port_scanner.py <ip> <port | first-last>")

    target = sys.argv[1]
    port_text = sys.argv[2]

    # "80" -> 80 to 80,  "1-1000" -> 1 to 1000
    try:
        if "-" in port_text:
            first_text, last_text = port_text.split("-")
            first_port = int(first_text)
            last_port = int(last_text)
        else:
            first_port = int(port_text)
            last_port = first_port
    except ValueError:
        sys.exit("bad ports. Use 80 or 1-1000")

    if first_port < 1:
        sys.exit("ports must start at 1 or more")
    if last_port > 65535:
        sys.exit("ports must end at 65535 or less")
    if first_port > last_port:
        sys.exit("the first port must not be bigger than the last port")

    # look the name up once and scan that same ip the whole time
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        sys.exit("cannot find the address of " + target)

    # private / loopback only. this stops mistakes, it is not permission
    address = ipaddress.ip_address(ip)
    if not address.is_private and not address.is_loopback:
        sys.exit("refusing " + ip + ": not a private or loopback address")

    # +1 because range stops before the end
    ports = range(first_port, last_port + 1)

    scan_start = time.time()

    with ThreadPoolExecutor(WORKERS) as pool:
        # map keeps the order, so states[0] is for the first port and so on
        states = list(pool.map(scan, ports))

    scan_end = time.time()

    print()
    print("PORT".ljust(8) + "WHAT THE PORT SAYS")

    # zip pairs each port with its state (works because the order is kept)
    for port, state in zip(ports, states):
        if state == "open":
            banner = grab(port)
            says = what_it_says(banner)
            print(str(port).ljust(8) + says)

    banner_end = time.time()

    open_count = states.count("open")
    closed_count = states.count("closed")
    filtered_count = states.count("filtered")
    error_count = states.count("error")

    scan_seconds = scan_end - scan_start
    banner_seconds = banner_end - scan_end

    print()
    print(f"{ip}: {len(states)} ports | "
          f"scan {scan_seconds:.2f}s, banners {banner_seconds:.2f}s")
    print(f"health: {open_count} open, {closed_count} closed, "
          f"{filtered_count} filtered, {error_count} error")

    # so a scan that missed ports doesn't look clean
    if filtered_count + error_count > 0:
        print("[!] some ports gave no clear answer. They are UNKNOWN, not closed.")
