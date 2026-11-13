import ipaddress
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Tuple

import paramiko

TARGET_HOST = "ssh-lab-target"
TARGET_PORT = 22
ATTEMPT_COUNT = 10
PORT_SCAN_PORTS = (22, 80, 443, 8080, 3306)
LAB_USERNAME = "lab-sim-user"
SERVER_PORT = 8090
RUN_LOCK = threading.Lock()
RUN_RESULTS: Dict[Tuple[int, str], Dict[str, Any]] = {}


def resolve_private_target() -> str:
    addresses = {
        ipaddress.ip_address(item[4][0])
        for item in socket.getaddrinfo(TARGET_HOST, TARGET_PORT, type=socket.SOCK_STREAM)
    }
    if not addresses or any(not address.is_private for address in addresses):
        raise RuntimeError("SSH lab target did not resolve exclusively to private addresses")
    return sorted(str(address) for address in addresses)[0]


def run_ssh_failures(run_id: int) -> Dict[str, Any]:
    target_ip = resolve_private_target()
    attempts_sent = 0
    authentication_failures = 0
    connection_errors = []

    for attempt_number in range(1, ATTEMPT_COUNT + 1):
        transport = None
        try:
            transport = paramiko.Transport((target_ip, TARGET_PORT))
            transport.banner_timeout = 4
            transport.auth_timeout = 4
            transport.start_client(timeout=4)
            attempts_sent += 1
            try:
                transport.auth_password(
                    LAB_USERNAME,
                    f"lab-invalid-credential-{run_id}-{attempt_number}",
                )
            except paramiko.AuthenticationException:
                authentication_failures += 1
            else:
                connection_errors.append("unexpected-authentication-success")
                break
        except (OSError, paramiko.SSHException) as error:
            connection_errors.append(type(error).__name__)
        finally:
            if transport is not None:
                transport.close()

    if authentication_failures == ATTEMPT_COUNT:
        status = "completed"
        result = (
            f"Generated {authentication_failures} failed SSH authentication attempts "
            "against the isolated lab target."
        )
    elif attempts_sent == 0:
        status = "failed"
        result = "No SSH authentication attempts reached the isolated lab target."
    else:
        status = "partial"
        result = (
            f"Sent {attempts_sent} SSH authentication attempts; "
            f"{authentication_failures} were rejected by the lab target."
        )

    return {
        "run_id": run_id,
        "scenario": "ssh_brute_force",
        "target": f"{TARGET_HOST}:{TARGET_PORT}",
        "status": status,
        "attempts_sent": attempts_sent,
        "authentication_failures": authentication_failures,
        "connection_errors": connection_errors,
        "result": result,
    }


def run_port_scan(run_id: int) -> Dict[str, Any]:
    target_ip = resolve_private_target()
    scanned_ports = []
    open_ports = []
    connection_errors = []
    identification_probe_sent = False

    for port in PORT_SCAN_PORTS:
        scanned_ports.append(port)
        try:
            with socket.create_connection((target_ip, port), timeout=0.25) as connection:
                open_ports.append(port)
                if port == TARGET_PORT and not identification_probe_sent:
                    connection.sendall(b"LAB-PORT-SCAN-PROBE\r\n")
                    identification_probe_sent = True
        except (ConnectionRefusedError, TimeoutError, OSError):
            continue

    return {
        "run_id": run_id,
        "scenario": "port_scan",
        "target": TARGET_HOST,
        "status": "completed" if scanned_ports == list(PORT_SCAN_PORTS) else "partial",
        "attempts_sent": len(scanned_ports),
        "ports_tested": scanned_ports,
        "ports_scanned": len(scanned_ports),
        "open_ports": open_ports,
        "service_probe_sent": identification_probe_sent,
        "connection_errors": connection_errors,
        "result": (
            f"Completed a TCP connect scan of {len(scanned_ports)} approved lab ports on {TARGET_HOST}. "
            f"Open ports: {open_ports if open_ports else 'none'}. "
            + ("Sent one benign SSH service-identification probe." if identification_probe_sent else "No SSH service probe was possible.")
        ),
    }


class SimulationHandler(BaseHTTPRequestHandler):
    server_version = "CyberSOCLabSimulator/1.0"

    def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "scope": "isolated-docker-lab"})
            return
        self._send_json(404, {"detail": "Not found"})

    def do_POST(self) -> None:
        if self.path not in {"/run", "/run/port-scan"}:
            self._send_json(404, {"detail": "Not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0 or content_length > 1024:
                raise ValueError("Invalid request size")
            request = json.loads(self.rfile.read(content_length))
            run_id = request.get("run_id")
            scenario = request.get("scenario", "ssh_brute_force")
            if not isinstance(run_id, int) or run_id < 1:
                raise ValueError("run_id must be a positive integer")
            if scenario not in {"ssh_brute_force", "port_scan"}:
                raise ValueError("Unsupported lab scenario")
            if (self.path == "/run/port-scan") != (scenario == "port_scan"):
                raise ValueError("Scenario does not match simulator endpoint")
        except (ValueError, json.JSONDecodeError) as error:
            self._send_json(400, {"detail": str(error)})
            return

        with RUN_LOCK:
            result_key = (run_id, scenario)
            if result_key in RUN_RESULTS:
                self._send_json(200, RUN_RESULTS[result_key])
                return
            try:
                result = run_ssh_failures(run_id) if scenario == "ssh_brute_force" else run_port_scan(run_id)
            except Exception as error:
                self._send_json(502, {"detail": f"Lab simulation failed: {type(error).__name__}"})
                return
            RUN_RESULTS[result_key] = result
            self._send_json(200, result)

    def log_message(self, format_string: str, *args: Any) -> None:
        print("simulator-control: " + format_string % args, flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", SERVER_PORT), SimulationHandler).serve_forever()
