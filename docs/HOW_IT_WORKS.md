# How port_scanner.py works

This page walks through the code in the order it runs. Read the code next to it.

How to read the evidence in this page:
- **Measured on my lab** means a real run against Metasploitable2 (see `sample_run_metasploitable2.txt`).
- **Measured on loopback** means a run on 127.0.0.1 against small local test services.
- **Reasoned** means I worked it out from the code or from how TCP works. I did not capture packets.

---

## 1. The whole run

```
python3 port_scanner.py 192.168.56.101 1-1000
        |
        v
+---------------------------------+
| A. CHECK INPUT                  |  command line -> first_port, last_port, one IP
|    refuse if not private        |  exit early if anything is wrong
+---------------------------------+
        |
        v
+---------------------------------+
| B. SCAN  (100 threads)          |  scan(port) for every port
|    port -> one word             |  result: a list of words, in the same order as the ports
+---------------------------------+  ["closed", "closed", "open", ...]
        |
        v   only ports whose word is "open"
+---------------------------------+
| C. BANNERS  (one by one)        |  grab(port)         -> the text the port sent
|                                 |  what_it_says(text) -> one line
|                                 |  clean(line)        -> safe to print
+---------------------------------+
        |
        v
+---------------------------------+
| D. PRINT                        |  table, timing line, health line
+---------------------------------+
```

| Piece | Job |
|-------|-----|
| `scan(port)` | try one port, return `open`, `closed`, `filtered` or `error` |
| `grab(port)` | connect to an open port and read what it says |
| `what_it_says(banner)` | choose the one line worth showing |
| `clean(text)` | make that line safe to print |
| main block | read input, run the steps in order, print |

---

## 2. Settings

```python
WORKERS = 100
TIMEOUT = 2
ip = ""
```

- `WORKERS`: how many ports are tested at the same time.
- `TIMEOUT`: seconds to wait for an answer, for connecting and for reading banners.
- `ip`: the address being scanned. It is set once in the main block. `scan()` and `grab()` read it.
  This keeps the function signatures short, but it means the functions depend on a variable outside them.

---

## 3. scan(port): one port in, one word out

```python
def scan(port):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        code = s.connect_ex((ip, port))
    except Exception:
        return "error"
    finally:
        if s is not None:
            s.close()

    if code == 0:
        return "open"
    if code == errno.ECONNREFUSED:
        return "closed"
    if code == errno.ECONNABORTED:
        return "closed"
    if code == errno.EAGAIN:
        return "filtered"
    if code == errno.ETIMEDOUT:
        return "filtered"
    return "error"
```

| Line | What it does | Why |
|------|--------------|-----|
| `s = None` | makes the name exist before anything can fail | so `finally` can ask "was a socket ever made?" |
| `socket.socket(AF_INET, SOCK_STREAM)` | asks the OS for an IPv4 + TCP socket. No packet is sent yet | it uses one file descriptor |
| `s.settimeout(TIMEOUT)` | wait at most 2 seconds | a port that never answers could otherwise block for a very long time |
| `s.connect_ex((ip, port))` | starts the TCP handshake and returns a number | a closed port is the normal case in a scan, so a number is simpler than an exception |
| `except Exception: return "error"` | any crash inside the `try` becomes `error` for this port | one bad port must not stop the scan |
| `finally: s.close()` | runs on every path | frees the file descriptor. A leak over 1000 ports ends in "Too many open files" |

The socket is created inside the `try` on purpose, because `socket.socket()` itself can fail
(for example when no file descriptors are left). Inside the `try`, that port becomes `error`
and the scan goes on.

### What goes over the wire (reasoned)

```
OPEN                       CLOSED                      NO ANSWER
you        target          you        target           you        target
 |--SYN------->|            |--SYN------->|             |--SYN------->|
 |<--SYN/ACK---|            |<--RST-------|             |   (silence)  |
 |--ACK------->|                                        |   (silence)  |
 connect_ex -> 0            connect_ex -> 111           ... timeout ...
                                                        connect_ex -> 11
```

Measured on loopback, the three numbers were 0, 111 and 11. Because the number for "no answer" is 11
and not an exception, an `except socket.timeout` branch would never run. The code checks the number instead.

| Number | Name | Word |
|--------|------|------|
| 0 | OK | open |
| 111 | ECONNREFUSED | closed |
| 103 | ECONNABORTED | closed (another way the OS can report a refusal) |
| 11 | EAGAIN | filtered |
| 110 | ETIMEDOUT | filtered |
| anything else | - | error |

`filtered` means only "no answer". A dead host, a dropped packet or an overloaded target look the same
as a firewall that drops packets.

---

## 4. Many ports at once

```python
with ThreadPoolExecutor(WORKERS) as pool:
    states = list(pool.map(scan, ports))
```

Almost all of `scan()`'s time is spent waiting for the network. While one thread waits, others work.
`pool.map` gives every port to the pool, and each free worker takes the next one.

Measured on loopback: 10 ports that never answer, timeout 1 second.

```
1 worker    10.02 s     w1 |1s|1s|1s|1s|1s|1s|1s|1s|1s|1s|
5 workers    2.00 s     w1 |1s|1s|  w2 |1s|1s|  ...  w5 |1s|1s|
10 workers   1.00 s     w1 ... w10 |1s|      (all at the same moment)
```

For ports that never answer, the time is about `ceil(ports / workers) * TIMEOUT` (reasoned from those numbers).
Ports that answer at once cost almost nothing, so the total scan time is set by the slow ports.

- **Why threads work here.** Python's GIL lets only one thread run Python code at a time, but a thread
  that is waiting on the network does not hold it. So the waits overlap. This would not help CPU-heavy work.
- **Order is kept.** `map` returns results in input order, even if workers finish in a different order.
  The print loop depends on it: `zip(ports, states)` pairs the 5th port with the 5th word.
- **Why 100 workers.** Too few is barely faster than a loop. Too many sends a burst of SYN packets that can look
  like a SYN flood and can overload a small target, so real open ports may then look closed.
- **If `scan()` raised.** The error would come out of `list(...)` and stop the whole scan. This is why
  nothing in `scan()` sits outside its `try`.

Measured on my lab: 1000 ports, 100 threads, 0.23 seconds, 0 filtered, 0 error.

---

## 5. grab(port): read what an open port says

Some services talk first (FTP, SSH, SMTP). Some wait for the client (HTTP). So: connect, listen, and if the
port stays silent, send a small probe and listen again.

```python
def grab(port):
    try:
        with socket.create_connection((ip, port), TIMEOUT) as s:

            try:
                data = s.recv(1024)
            except socket.timeout:
                data = b""

            if data == b"":
                if port == 80 or port == 443:
                    probe = "GET / HTTP/1.1\r\n"
                    probe = probe + "Host: " + ip + "\r\n"
                    probe = probe + "Connection: close\r\n"
                    probe = probe + "\r\n"
                else:
                    probe = "\r\n"

                s.send(probe.encode())
                data = s.recv(1024)

            text = data.decode(errors="ignore")
            return text.strip()
    except Exception:
        return ""
```

```
create_connection fails? ------------------------------> return ""
        |
        v ok
recv (wait up to 2 s)
   got bytes? -----------------------------------------> decode, return text
   silent (timeout) -> data = b""
        |
        v
send a probe:  port 80 or 443 -> a GET request     other ports -> "\r\n" (an empty line)
recv again (wait up to 2 s)
   got bytes -------------------------------------------> decode, return text
   silent again -> the timeout error goes to the outer except -> return ""
```

```
SPEAKS FIRST (FTP, SSH, SMTP)         SPEAKS LAST (HTTP)
you          server                   you          server
 |--connect-->|                        |--connect-->|
 |<--banner---|  recv() gets it        |   (silence, recv waits 2 s)
                                       |--GET /---->|
                                       |<--headers--|
```

| Piece | What it does | Why |
|-------|--------------|-----|
| `create_connection((ip, port), TIMEOUT)` | makes the socket, sets the timeout and connects. It raises on failure | shorter than setting it up by hand. This is a second connection: `scan()` closed its own |
| `with ... as s` | closes the socket at the end, even after an error | no leaked file descriptors |
| `s.recv(1024)` | reads up to 1024 bytes, once | a banner is short |
| inner `except socket.timeout` | silence is normal here, not a failure | so we can go on to the probe |
| the probe | a GET with a `Host` header (required by HTTP/1.1) and `Connection: close`, ended by a blank line | a web server answers only after the blank line |
| `probe.encode()` | text to bytes | sockets send bytes only |
| `decode(errors="ignore")` | drops bytes that are not valid text | a plain decode would crash on binary data |
| `.strip()` | removes spaces and newlines at the ends | clean text |

### Measured on my lab: what each port cost

| Port | Seconds | What happened (reasoned) |
|------|---------|--------------------------|
| 21, 22, 23, 25, 512, 514 | about 0 | the service speaks first |
| 80 | 2.04 | HTTP waits for us: one timeout, then the GET, then an answer |
| 513 | 2.01 | silent for one timeout, then our probe got no banner |
| 53, 111, 139, 445 | about 4 each | silent before the probe and silent after it |

The total is about 20 seconds. Banners are read one at a time, so the costs add up.

### Limits of grab()

- Port 443 is HTTPS. It expects a TLS handshake, not a plain GET, so the probe gets no useful answer.
- `recv(1024)` reads once. A long banner or header block can be cut.
- A banner can lie. The service decides what it says.
- Two probes are not enough to wake up DNS, rpcbind or SMB. They show as `(no banner)`.

---

## 6. Choosing and cleaning the text

```python
def clean(text):
    safe_text = ""
    for character in text:
        if character.isprintable():
            safe_text = safe_text + character
        else:
            safe_text = safe_text + "?"
    return safe_text[:60]
```

The banner comes from the target, so it is not trusted. A hostile service could send terminal escape codes.
Every character that is not normal printable text becomes `?`, and the line is cut to 60 characters.
Measured on loopback: a banner made of `220 `, an ESC byte, `[2J`, an ESC byte and `[31mhi` printed as `220 ?[2J?[31mhi`.

```python
def what_it_says(banner):
    if banner == "":
        return "(no banner)"

    if banner.startswith("HTTP/"):
        for line in banner.splitlines():
            if line == "":
                break
            if line.lower().startswith("server:"):
                return clean(line)
        return "(HTTP answer, no Server header)"

    first_line = banner.splitlines()[0]
    return clean(first_line)
```

```
banner text
   |
   +-- empty?                 -> "(no banner)"
   |
   +-- starts with "HTTP/" ?
   |       the first line is only "HTTP/1.1 200 OK", so look through the header lines
   |       a blank line = the headers are over, stop (the rest is page text)
   |       a line starting with "server:" -> return it (cleaned)
   |       none found -> "(HTTP answer, no Server header)"
   |
   +-- anything else          -> the first line (cleaned)
```

Because the tool prints what the service says and does not decide what software it is, a Tomcat server
that says `Server: Apache-Coyote/1.1` is shown as exactly that, and is never mislabeled as Apache.

### The odd lines in the lab output (reasoned)

- **Port 23, `? #'`**: telnet sends raw negotiation bytes. The bytes 0xFF and 0xFD are not valid text, so
  `decode(errors="ignore")` drops them. What remains is one control character (shown as `?`), a space, `#` and `'`.
  Running those bytes through the tool's own functions on loopback gives the same line.
- **Ports 512 and 514**: the service sends a 0x01 byte, then an error message. `clean()` shows the 0x01 as `?`.
  Both answered in under 0.02 seconds, so they spoke first, not in reply to our probe.
- **Port 514, "getnameinfo: Temporary failure in name resolution"**: the target tried a DNS lookup of the scanner's
  address and failed. A banner can leak facts about how the target is set up.

---

## 7. The main block

1. **Read the command line.** `sys.argv` is `[script, target, ports]`, so it must have exactly 3 items.
2. **Turn the port text into two numbers.** `"80"` becomes 80 to 80. `"1-1000"` is split at the hyphen into 1 and 1000.
   Text that is not a number, such as `abc` or `1-`, prints `bad ports` and exits with code 1.
3. **Check the limits.** The first port must be at least 1, the last at most 65535, and the first not above the last.
4. **Resolve the name once** with `socket.gethostbyname`. That one IP is scanned for the whole run.
5. **Safety check.** `ipaddress.ip_address(ip)` must be private (10.x, 172.16-31.x, 192.168.x) or loopback (127.x).
   This prevents accidents. It is not permission.
6. **Scan** with the thread pool, with a stopwatch around it.
7. **Print the table.** For each port whose word is `open`: `grab`, `what_it_says`, print.
   `str(port).ljust(8)` pads the port number to 8 characters so the columns line up.
8. **Print the summary.** Counts of each word, the scan and banner times, and a warning if any port was
   `filtered` or `error`: those ports are unknown, not closed.

---

## 8. One real run, end to end (my lab)

```
t = 0 s       1000 ports, 100 threads
              988 ports refuse at once, 12 accept
t = 0.23 s    scan done. Time = the slowest port, not the sum
              banners start, in port order, one at a time:
                21 22 23 25 512 514     about 0 s each
                80                      2 s
                513                     2 s
                53 111 139 445          4 s each
t = about 20.5 s   done
              health: 12 open, 988 closed, 0 filtered, 0 error
```

Nmap reported the same 12 open ports. The scan phase (0.23 s) is comparable to Nmap's port scan (0.28 s).
The banner phase is about 99 percent of the total run time, because it is sequential. Reading banners in
parallel is the obvious next improvement. On loopback, parallel reading took as long as the slowest single
port (4.01 s against 6.01 s one by one). I have not tried it on the lab.

---

## 9. What it does not do

- It does not identify products or versions, and it does not look up CVEs.
- It does not speak TLS, DNS, SMB or other protocols. It sends only two kinds of probe.
- It is a full TCP connect scan, so it is noisy: the target sees and logs every connection.
- It is IPv4 only, and the error numbers were checked on Linux only.
- It has no automated tests yet.
