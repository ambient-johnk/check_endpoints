#!/usr/bin/env python3

import hashlib
import socket
import ssl
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit

TIMEOUT = 8
MAX_WORKERS = 20

# Bare hosts use HTTPS; use http:// for HTTP. Both support :port.
ENDPOINTS = [
    "home.ambient.ai",
    "devices.ambient.ai",
    "amq.ambient.ai",
    "signal.ambient.ai",
    "metrics.ambient.ai",
    "pushprox.ambient.ai",
    "registry-1.ambient.ai",
    "archive.ambient.ai",
    "downloads.ambient.ai",
    "gateway.ambient.ai",
    "kinesis.us-west-2.amazonaws.com",
    "ssm.us-west-2.amazonaws.com",
    "sentry.io",
    "o275180.ingest.us.sentry.io",
    "s3.amazonaws.com",
    "s3.us-west-2.amazonaws.com",
    "ambient-ai-activity-monitor-alert-snapshots-prod.s3.us-west-2.amazonaws.com",
    "ambient-ai-checkpoints.s3.us-west-2.amazonaws.com",
    "ambient-ai-edge-artifacts-prod.s3.us-west-2.amazonaws.com",
    "ambient-ai-edge-command-executor-prod.s3.us-west-2.amazonaws.com",
    "ambient-ai-emergent-event-evidence-clips-prod.s3.us-west-2.amazonaws.com",
    "ambient-ai-event-engine-side-input-prod.s3.us-west-2.amazonaws.com",
    "ambient-ai-learning-metadata-prod.s3.us-west-2.amazonaws.com",
    "ambient-ai-learning-timestamp-prod.s3.us-west-2.amazonaws.com",
    "ambient-ai-learning-video-prod.s3.us-west-2.amazonaws.com",
    "ambient-ai-snapshots-prod.s3.us-west-2.amazonaws.com",
    "ambient-ai-stream-prototype-previews-prod.s3.us-west-2.amazonaws.com",
    "ambient-ai-thumbnail-storyboards-prod.s3.us-west-2.amazonaws.com",
    "prod-us-west-2-starport-layer-bucket.s3.us-west-2.amazonaws.com",
]

SUSPICIOUS_ISSUER_TERMS = [
    "zscaler",
    "netskope",
    "fortinet",
    "fortigate",
    "palo alto",
    "blue coat",
    "symantec proxy",
    "umbrella",
    "cisco umbrella",
    "websense",
    "forcepoint",
    "checkpoint",
    "check point",
    "ssl inspection",
    "tls inspection",
    "proxy",
]


def parse_endpoint(value):
    """Read a hostname or HTTP(S) authority; requests always target /."""
    if not isinstance(value, str) or not value or any(
        char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value
    ):
        raise ValueError("endpoint must be a nonempty string without whitespace")
    url = urlsplit(value if "://" in value else "https://" + value)
    if url.scheme not in ("http", "https"):
        raise ValueError("only HTTP and HTTPS are supported")
    if url.username is not None or url.password is not None:
        raise ValueError("URL credentials are not supported")
    if url.path not in ("", "/") or "?" in value or "#" in value:
        raise ValueError("use only a hostname and optional port; requests use HEAD /")
    host = url.hostname
    if not host or ":" in host:
        raise ValueError("use an IPv4 address or hostname, not IPv6")
    host = host.encode("idna").decode("ascii")
    default_port = 443 if url.scheme == "https" else 80
    port = url.port
    if url.netloc.endswith(":"):
        raise ValueError("a port number is required after ':'")
    if port is None:
        port = default_port
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    return {
        "label": value,
        "host": host,
        "scheme": url.scheme,
        "port": port,
        "authority": host if port == default_port else f"{host}:{port}",
    }


def name_to_string(name):
    parts = []

    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")

    return ", ".join(parts)


def sha256_fingerprint(cert_der):
    digest = hashlib.sha256(cert_der).hexdigest().upper()

    return ":".join(
        digest[i:i + 2]
        for i in range(0, len(digest), 2)
    )


def ip_sort_key(ip):
    try:
        return tuple(int(part) for part in ip.split("."))
    except Exception:
        return (999, 999, 999, 999)


def resolve_host(host, port):
    addresses = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_INET,
        type=socket.SOCK_STREAM,
    )

    return sorted(
        {
            entry[4][0]
            for entry in addresses
        },
        key=ip_sort_key,
    )


def read_http_headers(connection):
    data = b""

    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)

        if not chunk:
            break

        data += chunk

        if len(data) > 65536:
            break

    return data.decode(
        "iso-8859-1",
        errors="replace",
    )


def parse_http_response(response_text):
    result = {
        "status": None,
        "reason": None,
        "headers": {},
    }

    lines = response_text.split("\r\n")

    if not lines:
        return result

    status_line = lines[0]

    try:
        parts = status_line.split(" ", 2)

        if len(parts) >= 2:
            result["status"] = int(parts[1])

        if len(parts) >= 3:
            result["reason"] = parts[2]

    except Exception:
        pass

    for line in lines[1:]:
        if not line:
            break

        if ":" not in line:
            continue

        key, value = line.split(":", 1)

        result["headers"][
            key.strip().lower()
        ] = value.strip()

    return result


def check_ip(endpoint, ip):
    host = endpoint["host"]
    port = endpoint["port"]
    use_tls = endpoint["scheme"] == "https"
    result = {
        "host": host,
        "ip": ip,
        "port": port,
        "tls_required": use_tls,
        "tcp": False,
        "tls": False,
        "http": False,
        "warnings": [],
        "error": None,
    }

    sock = None
    tls_sock = None

    try:
        # -------------------------------------------------
        # TCP connection directly to this specific IP
        # -------------------------------------------------

        sock = socket.create_connection(
            (ip, port),
            timeout=TIMEOUT,
        )

        sock.settimeout(TIMEOUT)

        result["tcp"] = True

        # -------------------------------------------------
        # TLS
        #
        # Connect to the specific IP while using the actual
        # hostname for SNI and certificate verification.
        # -------------------------------------------------

        if use_tls:
            context = ssl.create_default_context()

            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

            tls_sock = context.wrap_socket(
                sock,
                server_hostname=host,
            )

            tls_sock.settimeout(TIMEOUT)

            result["tls"] = True
            result["tls_version"] = tls_sock.version()

            cipher = tls_sock.cipher()

            result["cipher"] = (
                cipher[0]
                if cipher
                else "unknown"
            )

            cert = tls_sock.getpeercert()
            cert_der = tls_sock.getpeercert(
                binary_form=True
            )

            result["subject"] = name_to_string(
                cert.get("subject", [])
            )

            result["issuer"] = name_to_string(
                cert.get("issuer", [])
            )

            result["not_before"] = cert.get(
                "notBefore"
            )

            result["not_after"] = cert.get(
                "notAfter"
            )

            result["fingerprint"] = (
                sha256_fingerprint(cert_der)
            )

            result["sans"] = [
                value
                for cert_type, value
                in cert.get("subjectAltName", [])
                if cert_type == "DNS"
            ]

            # -------------------------------------------------
            # Check certificate issuer for obvious signs of
            # SSL/TLS interception.
            # -------------------------------------------------

            issuer_lower = result["issuer"].lower()

            for term in SUSPICIOUS_ISSUER_TERMS:
                if term in issuer_lower:
                    result["warnings"].append(
                        "POSSIBLE TLS INTERCEPTION: "
                        f"issuer contains '{term}'"
                    )

        connection = tls_sock if use_tls else sock

        # -------------------------------------------------
        # HTTP(S) request
        #
        # IMPORTANT:
        # Uses the SAME tested connection and destination IP.
        # HTTPS uses the validated TLS socket.
        # -------------------------------------------------

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {endpoint['authority']}\r\n"
            f"User-Agent: Endpoint-Test/4.0\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )

        connection.sendall(
            request.encode("ascii")
        )

        response_text = read_http_headers(
            connection
        )

        if not response_text:
            result["error"] = (
                "Connection succeeded, but no HTTP "
                "response was received"
            )
            return result

        http = parse_http_response(
            response_text
        )

        result["http"] = True

        result["status"] = http["status"]
        result["reason"] = http["reason"]

        result["server"] = (
            http["headers"].get("server")
        )

        result["location"] = (
            http["headers"].get("location")
        )

        result["x_amz_request_id"] = (
            http["headers"].get(
                "x-amz-request-id"
            )
        )

        result["x_amz_id_2"] = (
            http["headers"].get(
                "x-amz-id-2"
            )
        )

        if result["status"] in (
            301,
            302,
            303,
            307,
            308,
        ):
            result["warnings"].append(
                "HTTP REDIRECT: "
                f"{result['status']} -> "
                f"{result['location'] or 'unknown'}"
            )

    except socket.timeout:
        if not result["tcp"]:
            result["error"] = (
                "TCP connection timed out"
            )

        elif use_tls and not result["tls"]:
            result["error"] = (
                "TLS handshake timed out"
            )

        else:
            result["error"] = (
                "HTTP operation timed out after connection succeeded"
            )

    except ssl.SSLCertVerificationError as exc:
        result["error"] = (
            "TLS CERTIFICATE VERIFICATION "
            f"FAILED: {exc}"
        )

    except ssl.SSLError as exc:
        result["error"] = (
            f"TLS ERROR: {exc}"
        )

    except ConnectionRefusedError as exc:
        result["error"] = (
            f"TCP connection refused: {exc}"
        )

    except ConnectionResetError as exc:
        result["error"] = (
            f"CONNECTION RESET: {exc}"
        )

    except OSError as exc:
        result["error"] = (
            f"OS/network error: {exc}"
        )

    except Exception as exc:
        result["error"] = (
            f"{type(exc).__name__}: {exc}"
        )

    finally:
        try:
            if tls_sock:
                tls_sock.close()

            elif sock:
                sock.close()

        except Exception:
            pass

    return result


def print_ip_result(result):
    ip = result["ip"]

    if (
        result["tcp"]
        and (result["tls"] or not result["tls_required"])
        and result["http"]
    ):
        status = "PASS"
    else:
        status = "FAIL"

    print()
    print(f"  IP: {ip}")
    print(f"  Result    : {status}")

    print(
        f"  TCP/{result['port']}   : "
        f"{'PASS' if result['tcp'] else 'FAIL'}"
    )

    print(
        f"  TLS       : "
        f"{('PASS' if result['tls'] else 'FAIL') if result['tls_required'] else 'N/A (HTTP)'}"
    )

    if result["tls"]:
        print(
            f"  TLS Ver   : "
            f"{result.get('tls_version')}"
        )

        print(
            f"  Cipher    : "
            f"{result.get('cipher')}"
        )

        print(
            f"  Subject   : "
            f"{result.get('subject')}"
        )

        print(
            f"  Issuer    : "
            f"{result.get('issuer')}"
        )

        print(
            f"  Valid From: "
            f"{result.get('not_before')}"
        )

        print(
            f"  Valid To  : "
            f"{result.get('not_after')}"
        )

        print(
            f"  SHA256    : "
            f"{result.get('fingerprint')}"
        )

    if result["http"]:
        status_code = result.get(
            "status"
        )

        reason = (
            result.get("reason")
            or ""
        )

        print(
            f"  HTTP      : "
            f"{status_code} {reason}"
        )

        if result.get("server"):
            print(
                f"  Server    : "
                f"{result['server']}"
            )

        if result.get("location"):
            print(
                f"  Location  : "
                f"{result['location']}"
            )

        if result.get(
            "x_amz_request_id"
        ):
            print(
                f"  AWS Req ID: "
                f"{result['x_amz_request_id']}"
            )

    if result["error"]:
        print(
            f"  ERROR     : "
            f"{result['error']}"
        )

    for warning in result["warnings"]:
        print(
            f"  WARNING   : "
            f"{warning}"
        )


def test_endpoint(endpoint):
    host = endpoint["host"]
    endpoint_result = {
        "host": endpoint["label"],
        "scheme": endpoint["scheme"],
        "port": endpoint["port"],
        "dns": False,
        "ips": [],
        "results": [],
        "error": None,
    }

    try:
        ips = resolve_host(host, endpoint["port"])

        endpoint_result["dns"] = True
        endpoint_result["ips"] = ips

    except Exception as exc:
        endpoint_result["error"] = (
            f"DNS FAILURE: {exc}"
        )

        return endpoint_result

    if not ips:
        endpoint_result["error"] = (
            "DNS succeeded but returned "
            "no IPv4 addresses"
        )
        return endpoint_result

    futures = []

    with ThreadPoolExecutor(
        max_workers=min(
            MAX_WORKERS,
            len(ips),
        )
    ) as executor:

        for ip in ips:
            futures.append(
                executor.submit(
                    check_ip,
                    endpoint,
                    ip,
                )
            )

        for future in as_completed(
            futures
        ):
            endpoint_result[
                "results"
            ].append(
                future.result()
            )

    endpoint_result["results"].sort(
        key=lambda x: ip_sort_key(
            x["ip"]
        )
    )

    return endpoint_result


def print_endpoint_result(endpoint):
    print()
    print("=" * 100)
    print(endpoint["host"])
    print(f"Protocol: {endpoint['scheme'].upper()}   Port: {endpoint['port']}")
    print("=" * 100)

    if not endpoint["dns"]:
        print("DNS       : FAIL")

        print(
            f"ERROR     : "
            f"{endpoint['error']}"
        )

        return

    print("DNS       : PASS")

    print(
        "IP        : "
        + ", ".join(
            endpoint["ips"]
        )
    )

    for result in endpoint["results"]:
        print_ip_result(result)


def summarize(endpoints):
    print()
    print("=" * 120)
    print("SUMMARY")
    print("=" * 120)

    total_ips = 0

    tcp_pass = 0
    tls_pass = 0
    tls_total = 0
    http_pass = 0

    interception_warnings = 0

    failed_endpoints = []
    failed_paths = []

    overall_failure = False

    # ---------------------------------------------------------
    # Endpoint results
    # ---------------------------------------------------------

    print()
    print("ENDPOINT RESULTS")
    print("-" * 120)

    for endpoint in endpoints:
        host = endpoint["host"]

        if not endpoint["dns"]:

            print(
                f"FAIL   "
                f"{host:<80} "
                f"DNS FAILURE"
            )

            failed_endpoints.append(
                host
            )

            overall_failure = True

            continue

        results = endpoint["results"]

        total_ips += len(results)

        endpoint_tcp_pass = sum(
            1
            for result in results
            if result["tcp"]
        )

        endpoint_tls_pass = sum(
            1
            for result in results
            if result["tls"]
        )

        endpoint_http_pass = sum(
            1
            for result in results
            if result["http"]
        )

        tcp_pass += endpoint_tcp_pass
        endpoint_tls_total = sum(r["tls_required"] for r in results)
        tls_total += endpoint_tls_total
        tls_pass += endpoint_tls_pass
        http_pass += endpoint_http_pass

        endpoint_failed = False

        for result in results:

            for warning in result[
                "warnings"
            ]:
                if (
                    "INTERCEPTION"
                    in warning
                ):
                    interception_warnings += 1

            if not (
                result["tcp"]
                and (result["tls"] or not result["tls_required"])
                and result["http"]
            ):
                endpoint_failed = True

                failed_paths.append(
                    {
                        "host": host,
                        "ip": result["ip"],
                        "tcp": result["tcp"],
                        "tls": result["tls"],
                        "tls_required": result["tls_required"],
                        "port": result["port"],
                        "http": result["http"],
                        "error": result.get(
                            "error"
                        ),
                        "warnings": result.get(
                            "warnings",
                            []
                        ),
                    }
                )

        if endpoint_failed:
            status = "FAIL"
            overall_failure = True

            failed_endpoints.append(
                host
            )

        else:
            status = "PASS"

        print(
            f"{status:<6} "
            f"{host:<80} "
            f"TCP {endpoint_tcp_pass}/{len(results)}   "
            f"TLS {endpoint_tls_pass}/{endpoint_tls_total}   "
            f"HTTP {endpoint_http_pass}/{len(results)}"
        )

    # ---------------------------------------------------------
    # Failed IP paths
    # ---------------------------------------------------------

    print()
    print("=" * 120)
    print("FAILED IP PATHS")
    print("=" * 120)

    if not failed_paths:
        print(
            "None. All resolved IP paths passed "
            "TCP, required TLS, and HTTP."
        )

    else:
        current_host = None

        for failure in failed_paths:
            host = failure["host"]

            if host != current_host:
                print()
                print(host)
                print("-" * len(host))

                current_host = host

            if not failure["tcp"]:
                stage = "TCP"

            elif failure["tls_required"] and not failure["tls"]:
                stage = "TLS"

            elif not failure["http"]:
                stage = "HTTP"

            else:
                stage = "UNKNOWN"

            print(
                f"  {failure['ip']}:{failure['port']} "
                f"FAILED AT: {stage:<5}  "
                f"TCP="
                f"{'PASS' if failure['tcp'] else 'FAIL':<4}  "
                f"TLS="
                f"{('PASS' if failure['tls'] else 'FAIL') if failure['tls_required'] else 'N/A':<4}  "
                f"HTTP="
                f"{'PASS' if failure['http'] else 'FAIL':<4}"
            )

            if failure["error"]:
                print(
                    f"      Error: "
                    f"{failure['error']}"
                )

            for warning in failure[
                "warnings"
            ]:
                print(
                    f"      Warning: "
                    f"{warning}"
                )

    # ---------------------------------------------------------
    # Failure breakdown
    # ---------------------------------------------------------

    tcp_failures = []
    tls_failures = []
    http_failures = []

    for failure in failed_paths:

        if not failure["tcp"]:
            tcp_failures.append(
                failure
            )

        elif failure["tls_required"] and not failure["tls"]:
            tls_failures.append(
                failure
            )

        elif not failure["http"]:
            http_failures.append(
                failure
            )

    print()
    print("=" * 120)
    print("FAILURE BREAKDOWN")
    print("=" * 120)

    print(
        f"TCP connection failures : "
        f"{len(tcp_failures)}"
    )

    print(
        f"TLS handshake failures  : "
        f"{len(tls_failures)}"
    )

    print(
        f"HTTP response failures  : "
        f"{len(http_failures)}"
    )

    # ---------------------------------------------------------
    # Unique failed destination IPs
    # ---------------------------------------------------------

    unique_failed_ips = sorted(
        {
            failure["ip"]
            for failure in failed_paths
        },
        key=ip_sort_key,
    )

    print()
    print("UNIQUE FAILING DESTINATION IPs")
    print("-" * 120)

    if unique_failed_ips:
        for ip in unique_failed_ips:
            print(
                f"  {ip}"
            )

    else:
        print("  None")

    # ---------------------------------------------------------
    # TCP failures
    # ---------------------------------------------------------

    if tcp_failures:

        print()
        print("TCP FAILURES")
        print("-" * 120)

        for failure in tcp_failures:

            print(
                f"  {failure['ip']}:{failure['port']} "
                f"{failure['host']}"
            )

            if failure["error"]:
                print(
                    f"      "
                    f"{failure['error']}"
                )

    # ---------------------------------------------------------
    # TLS failures
    # ---------------------------------------------------------

    if tls_failures:

        print()
        print("TLS HANDSHAKE FAILURES")
        print("-" * 120)

        for failure in tls_failures:

            print(
                f"  {failure['ip']}:{failure['port']} "
                f"{failure['host']}"
            )

            if failure["error"]:
                print(
                    f"      "
                    f"{failure['error']}"
                )

    # ---------------------------------------------------------
    # HTTP failures
    # ---------------------------------------------------------

    if http_failures:

        print()
        print("HTTP RESPONSE FAILURES")
        print("-" * 120)

        for failure in http_failures:

            print(
                f"  {failure['ip']}:{failure['port']} "
                f"{failure['host']}"
            )

            if failure["error"]:
                print(
                    f"      "
                    f"{failure['error']}"
                )

    # ---------------------------------------------------------
    # Totals
    # ---------------------------------------------------------

    print()
    print("=" * 120)
    print("TOTALS")
    print("=" * 120)

    print(
        f"Endpoints tested          : "
        f"{len(endpoints)}"
    )

    print(
        f"Endpoints with failures   : "
        f"{len(failed_endpoints)}"
    )

    print(
        f"Resolved IPs tested       : "
        f"{total_ips}"
    )

    print(
        f"TCP passed            : "
        f"{tcp_pass}/{total_ips}"
    )

    print(
        f"TLS passed                : "
        f"{tls_pass}/{tls_total}"
    )

    print(
        f"HTTP responses received   : "
        f"{http_pass}/{total_ips}"
    )

    print(
        f"Failed IP paths           : "
        f"{len(failed_paths)}"
    )

    print(
        f"Unique failing IPs        : "
        f"{len(unique_failed_ips)}"
    )

    print(
        f"TLS interception warnings : "
        f"{interception_warnings}"
    )

    print("=" * 120)

    return (
        1
        if overall_failure
        else 0
    )


def main():
    endpoints = []
    for value in ENDPOINTS:
        try:
            endpoints.append(parse_endpoint(value))
        except ValueError as exc:
            print(f"Invalid endpoint {value!r}: {exc}", file=sys.stderr)
            sys.exit(2)

    print()
    print(
        "Endpoint / Per-IP "
        "TCP + TLS + HTTP(S) Test"
    )

    print("=" * 100)

    print(
        f"Endpoints   : "
        f"{len(ENDPOINTS)}"
    )

    print(
        "Ports       : per endpoint (HTTPS 443 / HTTP 80 defaults)"
    )

    print(
        f"Timeout     : "
        f"{TIMEOUT} seconds"
    )

    print(
        "TLS checks  : "
        "HTTPS only: system CA trust + hostname/SNI validation"
    )

    print(
        "HTTP checks : "
        "HEAD / over the SAME tested connection"
    )

    endpoint_results = []

    # Test each endpoint sequentially.
    # All resolved IPs within an endpoint are tested
    # concurrently.
    for host in endpoints:

        result = test_endpoint(
            host
        )

        endpoint_results.append(
            result
        )

        print_endpoint_result(
            result
        )

    exit_code = summarize(
        endpoint_results
    )

    sys.exit(
        exit_code
    )


if __name__ == "__main__":
    main()