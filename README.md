# Endpoint connectivity checker

Check DNS, TCP, TLS, and HTTP connectivity from an appliance to web hosts and APIs. Uses Python 3's standard library; no third-party dependencies are required.

```sh
python3 check_endpoints.py
```

Edit `ENDPOINTS` near the top of `check_endpoints.py` to add or remove hosts. The existing destination list is retained. Each entry is a quoted string followed by a comma:

```python
ENDPOINTS = [
    "example.com",
    "https://api.example.com",
    "http://internal.example.com",
    "api.example.com:8443",
    "https://api.example.com:8443",
    "http://internal.example.com:8080",
]
```

| Entry | Protocol | Port |
| --- | --- | --- |
| `hostname` | HTTPS | 443 |
| `hostname:8443` | HTTPS | 8443 |
| `https://hostname` | HTTPS | 443 |
| `https://hostname:8443` | HTTPS | 8443 |
| `http://hostname` | HTTP | 80 |
| `http://hostname:8080` | HTTP | 8080 |

There is no automatic fallback from HTTPS to HTTP. Add separate HTTP and HTTPS entries to test both. Entries accept a hostname or IPv4 address, an optional scheme, and an optional port (1–65535). A trailing `/` is allowed; other paths, queries, fragments, credentials, and IPv6 addresses are unsupported. Requests always use `HEAD /`.

For each endpoint, the script resolves IPv4 addresses and tests each IP directly. HTTPS uses the hostname for SNI and certificate verification against system trust, then sends HTTP over the same validated connection. HTTP sends the request directly over TCP and shows TLS as `N/A`. Non-default ports are included in the HTTP Host header.

Endpoints run sequentially; up to 20 IPs per endpoint run concurrently. Socket operations have an 8-second timeout, not a whole-run deadline. DNS resolution has no explicit timeout.

Output includes per-IP results, HTTPS certificate details, response status and headers, redirects, possible TLS-interception warnings, and a failure summary. TLS totals include HTTPS paths only (`0/0` for an HTTP-only endpoint). Failure details identify destination ports.

This checks connectivity, not application health or access permissions. HTTP error statuses such as 403, 405, or 500 still count as responses. Requests are unauthenticated, bodies are not downloaded intentionally, and redirects are not followed. The existing response check counts any nonempty response as HTTP success.

Exit codes: `0` when all tested paths pass, `1` for detected DNS or connection failures, and `2` for invalid endpoint configuration. Warnings alone do not cause failure.

Run the offline tests:

```sh
python3 -B -m unittest discover -s tests -v
```
