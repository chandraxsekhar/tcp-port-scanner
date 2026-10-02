# tcp-port-scanner

A small TCP port scanner and banner grabber in one Python file. No packages to install.

I built it on plain TCP sockets (Python's `socket` module, no scanning libraries) to understand how
tools like Nmap work inside: the TCP handshake, timeouts, threads, and what a service says about itself. The code is written in plain,
spread-out steps so that anyone can read it from top to bottom.

> **Lab use only.** Only scan machines you own or have written permission to test.
> Unauthorized scanning can be illegal. The tool refuses targets that are not private or
> loopback addresses, but that check only prevents accidents. It is not permission.

## Demo

A real run against a Metasploitable2 VM (Kali to Metasploitable2, VirtualBox host-only network):

```
$ python3 port_scanner.py 192.168.56.101 1-1000

PORT    WHAT THE PORT SAYS
21      220 (vsFTPd 2.3.4)
22      SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1
23      ? #'
25      220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
53      (no banner)
80      Server: Apache/2.2.8 (Ubuntu) DAV/2
111     (no banner)
139     (no banner)
445     (no banner)
512     ?Where are you?
513     (no banner)
514     ?getnameinfo: Temporary failure in name resolution

192.168.56.101: 1000 ports | scan 0.23s, banners 20.72s
health: 12 open, 988 closed, 0 filtered, 0 error
```

Nmap found the same 12 open ports. The full output of both tools is in
[docs/sample_run_metasploitable2.txt](docs/sample_run_metasploitable2.txt).

## What it does

1. Reads the target and the port range, and refuses any target that is not private or loopback.
2. Scans the ports with full TCP connects, up to 100 at the same time.
3. Labels every port: `open`, `closed`, `filtered` (no answer) or `error`.
4. Reads each open port and prints what it says: the first line of its banner, or the
   `Server:` header for a web server.
5. Prints a health line, so a scan that missed ports cannot look clean.

## Quick start

Requires Python 3 and nothing else. Download `port_scanner.py` and run it:

```
python3 port_scanner.py <ip or name> <port | first-last>

python3 port_scanner.py 192.168.56.101 1-1000     # a range
python3 port_scanner.py 192.168.56.101 80         # one port
```

Bad input prints a message and exits with code 1. No root is needed.

## How it works

```
 command line  ->  check input  ->  scan ports (100 at a time)  ->  read banners  ->  print
                   refuse public        scan(port) -> one word        grab(port)         table +
                   IPs                  open / closed /               what_it_says()     health line
                                        filtered / error              clean()
```

The four words come from the number the operating system returns when the program tries to connect:

| State | OS number | What it means |
|-------|-----------|---------------|
| open | 0 | the TCP handshake worked |
| closed | 111 or 103 | the target refused the connection |
| filtered | 11 or 110 | no answer before the timeout. This does **not** prove a firewall |
| error | anything else | unknown. The tool never guesses "closed" |

A step-by-step walkthrough of every function, with diagrams and real timings, is in
[docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

## Real lab results

Single runs on my own lab, not a benchmark.

| What | Time |
|------|------|
| `nmap -p 1-1000 --open` (port scan only) | 0.28 s |
| tcp-port-scanner, scan phase (1000 ports, 100 threads) | 0.23 s |
| tcp-port-scanner, banner phase (12 open ports, one at a time) | 20.3 to 20.7 s (two runs) |

- Both tools found the same 12 open ports. The health line reported 0 filtered and 0 error in both runs.
- The scan phase is threaded, so it is as fast as the port scan from Nmap. The banner phase is not
  threaded, and silent ports are slow: four ports cost about 4 seconds each (a timeout before
  our probe and another after it), and two cost about 2 seconds each. That adds up to about 20 seconds.
- Nmap's 0.28 s was a port scan only. A fair comparison would use `nmap -sV`, which reads banners.
- The odd lines are real. Port 23 (telnet) sends raw negotiation bytes, and ports 512 and 514 send a
  control byte before their error text. The tool replaces non-printable characters with `?`.

## Design decisions

| Choice | Why |
|--------|-----|
| `connect_ex()` instead of `connect()` | it returns a number instead of raising an error. Most ports in a scan are closed, so this is simpler |
| Full TCP connect scan, not SYN scan | needs no root. The cost: it is noisy, and the target logs every connection |
| A timeout on every socket | without one, a port that never answers can block for a very long time |
| Socket created inside `try`, closed in `finally` | no leaked file descriptors, and a failure on one port becomes `error` for that port only |
| Threads (100 workers), not asyncio | the work is mostly waiting on the network, so threads overlap the waiting. Asyncio scales further but is harder to explain |
| Four states, and `error` is never `closed` | a scan that missed ports must not look clean |
| Print what the port says, with no version parsing | no regular expressions and no guessing. The tool shows the service's own words |
| Banner text is cleaned | a banner comes from the target, so it is not trusted. Non-printable characters become `?` and a line is cut to 60 characters, so a hostile service cannot send terminal escape codes |
| Name resolved once | the tool scans the IP it resolved at the start of the run |
| Private-IP guard, with no override flag | it prevents accidents. Scanning a public address means editing the code on purpose |

## Limitations

- It is a port scanner and banner grabber, not a vulnerability scanner. It does not match banners to CVEs.
- Banners are read one at a time after the scan, so silent open ports make the run slow (20 s on my lab).
- It sends only two kinds of probe: an empty line, and a web request on ports 80 and 443. Services such as
  DNS, rpcbind and SMB print `(no banner)`. That means "our probes got nothing", not "nothing is there".
- Port 443 is not handled properly: there is no TLS handshake.
- One `recv()` reads at most 1024 bytes.
- A banner can lie, and a version number alone does not prove that a server is vulnerable.
- IPv4 only. The error numbers were checked on Linux only.
- No automated tests yet. It was checked by hand against Metasploitable2 and against small local test services.

## Ideas for next steps

- Read banners in parallel. On my lab I expect about 4 seconds instead of 20 (an estimate, not tested there).
- Protocol-specific probes for more services.
- Extract product and version from banners, then look them up in the NVD API for known CVEs.
- TLS banners for port 443, a retry for unanswered ports, a raw SYN scan with scapy, and an automated test suite.

## Concepts this project covers

Sockets and file descriptors, the TCP three-way handshake, open / closed / filtered ports,
timeouts, threads and the GIL for I/O-bound work, banner grabbing, treating network data as untrusted
input, input validation, and the legal and ethical limits of scanning.

## Project layout

```
port_scanner.py                       the whole tool (about 125 lines of code)
docs/HOW_IT_WORKS.md                  line-by-line explanation with diagrams
docs/sample_run_metasploitable2.txt   the real lab output
```

## How this was built

I built this as a learning project with help from an AI assistant (Claude). I am studying each part so I
can explain how it works, and I tested it on my own Kali and Metasploitable2 lab.

## License and disclaimer

Released under the MIT License (see `LICENSE`). The software is provided as is, and you are responsible
for how you use it. Scan only what you own or have written permission to test.
