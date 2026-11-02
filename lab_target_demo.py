"""
Mock Vulnerable Lab Service Simulator (For Safe Testing Only).

Provides lightweight mock network services on localhost for demonstrating:
- Port 2121: Mock FTP service with vsftpd 2.3.4 & anonymous login
- Port 8080: Mock HTTP service with Apache 2.4.49 headers
- Port 6379: Mock Redis service answering PING without authentication

Usage:
    Terminal 1: python lab_target_demo.py
    Terminal 2: python main.py -t 127.0.0.1 -p 2121,8080,6379 -f both
"""

import socket
import threading
import time

RUNNING = True


def run_mock_ftp(host="127.0.0.1", port=2121):
    """Simulates an FTP service vulnerable to anonymous login and vsftpd 2.3.4 signature."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(10)
    s.settimeout(1.0)
    print(f"[*] Mock FTP listening on {host}:{port}")

    while RUNNING:
        try:
            conn, _ = s.accept()
            conn.settimeout(2.0)
            conn.sendall(b"220 (vsFTPd 2.3.4)\r\n")

            while True:
                data = conn.recv(1024)
                if not data:
                    break
                cmd = data.decode("utf-8", errors="ignore").strip().upper()
                if cmd.startswith("USER"):
                    conn.sendall(b"331 Please specify the password.\r\n")
                elif cmd.startswith("PASS"):
                    conn.sendall(b"230 Login successful.\r\n")
                elif cmd.startswith("QUIT"):
                    conn.sendall(b"221 Goodbye.\r\n")
                    break
                else:
                    conn.sendall(b"502 Command not implemented.\r\n")
            conn.close()
        except socket.timeout:
            continue
        except Exception:
            pass

    s.close()


def run_mock_http(host="127.0.0.1", port=8080):
    """Simulates an HTTP server leaking Apache 2.4.49 and PHP headers."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(10)
    s.settimeout(1.0)
    print(f"[*] Mock HTTP listening on {host}:{port}")

    while RUNNING:
        try:
            conn, _ = s.accept()
            conn.settimeout(2.0)
            req = conn.recv(1024)

            response = (
                "HTTP/1.1 200 OK\r\n"
                "Server: Apache/2.4.49 (Unix) OpenSSL/1.1.1\r\n"
                "X-Powered-By: PHP/7.4.3\r\n"
                "Content-Type: text/html; charset=UTF-8\r\n"
                "Connection: close\r\n\r\n"
                "<html><head><title>Lab Target Dashboard</title></head>"
                "<body><h1>Authorized Security Lab Target</h1></body></html>"
            )
            conn.sendall(response.encode("utf-8"))
            conn.close()
        except socket.timeout:
            continue
        except Exception:
            pass

    s.close()


def run_mock_redis(host="127.0.0.1", port=6379):
    """Simulates an unauthenticated Redis instance responding to PING and INFO."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((host, port))
    except OSError:
        # Port might be in use or unavailable
        return

    s.listen(10)
    s.settimeout(1.0)
    print(f"[*] Mock Redis listening on {host}:{port}")

    while RUNNING:
        try:
            conn, _ = s.accept()
            conn.settimeout(2.0)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                if b"PING" in data.upper():
                    conn.sendall(b"+PONG\r\n")
                elif b"INFO" in data.upper():
                    info_payload = (
                        b"$120\r\n"
                        b"# Server\r\n"
                        b"redis_version:6.0.9\r\n"
                        b"os:Linux 5.4.0-x86_64\r\n"
                        b"tcp_port:6379\r\n"
                    )
                    conn.sendall(info_payload)
                else:
                    conn.sendall(b"+OK\r\n")
            conn.close()
        except socket.timeout:
            continue
        except Exception:
            pass

    s.close()


def main():
    threads = [
        threading.Thread(target=run_mock_ftp, daemon=True),
        threading.Thread(target=run_mock_http, daemon=True),
        threading.Thread(target=run_mock_redis, daemon=True),
    ]

    for t in threads:
        t.start()

    print("\n[+] Mock Lab Target running! Press Ctrl+C to terminate.")
    print("[+] Run the scanner in a second window:")
    print("    python main.py -t 127.0.0.1 -p 2121,8080,6379 -f both\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        global RUNNING
        RUNNING = False
        print("\n[*] Shutting down mock lab services...")


if __name__ == "__main__":
    main()
