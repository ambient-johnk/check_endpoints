import contextlib
import io
import socket
import ssl
import unittest
from unittest.mock import Mock, patch

import check_endpoints as checker


class EndpointTests(unittest.TestCase):
    def test_protocol_and_port_defaults(self):
        for value, scheme, port in [
            ('example.com', 'https', 443),
            ('example.com:8443', 'https', 8443),
            ('https://example.com', 'https', 443),
            ('https://example.com:8443', 'https', 8443),
            ('http://example.com', 'http', 80),
            ('http://example.com:8080', 'http', 8080),
        ]:
            with self.subTest(value=value):
                endpoint = checker.parse_endpoint(value)
                self.assertEqual((endpoint['scheme'], endpoint['port']), (scheme, port))
                self.assertEqual(endpoint['host'], 'example.com')

    def test_reject_invalid_configuration_before_network(self):
        for value in ('ftp://a', 'http://', 'a:0', 'a:65536', 'a:', 'a:abc',
                      'http://user:pass@a', 'a/path', 'a?q=1', 'a#frag',
                      'http://[::1]', 'a\r\nHost: b'):
            with self.subTest(value=value), patch.object(checker, 'ENDPOINTS', [value]), \
                 patch.object(checker.socket, 'getaddrinfo') as dns, \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                checker.main()
            self.assertEqual(exc.exception.code, 2)
            dns.assert_not_called()

    def check(self, value, response=b'HTTP/1.1 403 Forbidden\r\n\r\n', tls_error=None):
        endpoint = checker.parse_endpoint(value)
        raw = Mock()
        tls = Mock()
        connection = tls if endpoint['scheme'] == 'https' else raw
        connection.recv.side_effect = response if isinstance(response, Exception) else [response]
        tls.getpeercert.side_effect = lambda binary_form=False: b'cert' if binary_form else {}
        tls.cipher.return_value = ('cipher', 'TLSv1.3', 256)
        context = Mock()
        context.wrap_socket.return_value = tls
        if tls_error:
            context.wrap_socket.side_effect = tls_error
        with patch.object(checker.socket, 'create_connection', return_value=raw) as connect, \
             patch.object(checker.ssl, 'create_default_context', return_value=context) as create_tls:
            result = checker.check_ip(endpoint, '192.0.2.1')
        connect.assert_called_once_with(('192.0.2.1', endpoint['port']), timeout=checker.TIMEOUT)
        if endpoint['scheme'] == 'https':
            context.wrap_socket.assert_called_once_with(raw, server_hostname='example.com')
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        else:
            create_tls.assert_not_called()
        if not tls_error:
            request = connection.sendall.call_args.args[0]
            self.assertTrue(request.startswith(b'HEAD / HTTP/1.1\r\n'))
            self.assertIn(f"Host: {endpoint['authority']}\r\n".encode(), request)
            connection.close.assert_called_once()
        else:
            raw.sendall.assert_not_called()
            raw.close.assert_called_once()
        return result

    def summary(self, results):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = checker.summarize([dict(host='example.com', dns=True, results=results)])
        return code, output.getvalue()

    def test_https_original_and_custom_port(self):
        for value in ('example.com', 'https://example.com:8443'):
            with self.subTest(value=value):
                result = self.check(value)
                self.assertTrue(result['tcp'] and result['tls'] and result['http'])
                self.assertEqual(self.summary([result])[0], 0)

    def test_http_skips_tls_and_passes(self):
        for value in ('http://example.com', 'http://example.com:8080'):
            with self.subTest(value=value):
                result = self.check(value)
                self.assertFalse(result['tls'])
                code, output = self.summary([result])
                self.assertEqual(code, 0)
                self.assertIn('TLS 0/0', output)
                with contextlib.redirect_stdout(io.StringIO()) as details:
                    checker.print_ip_result(result)
                self.assertIn('N/A (HTTP)', details.getvalue())

    def test_http_failure_is_not_tls_failure(self):
        for response in (b'', socket.timeout()):
            with self.subTest(response=response):
                result = self.check('http://example.com:8080', response)
                code, output = self.summary([result])
                self.assertEqual(code, 1)
                self.assertIn('FAILED AT: HTTP', output)
                self.assertIn('192.0.2.1:8080', output)
                self.assertIn('TLS handshake failures  : 0', output)

    def test_no_fallback_after_tls_failure(self):
        result = self.check('example.com', tls_error=ssl.SSLCertVerificationError('untrusted'))
        code, output = self.summary([result])
        self.assertEqual(code, 1)
        self.assertIn('FAILED AT: TLS', output)
        self.assertFalse(result['http'])

    def test_mixed_tls_totals(self):
        code, output = self.summary([self.check('example.com'), self.check('http://example.com')])
        self.assertEqual(code, 0)
        self.assertIn('TLS 1/1', output)
        self.assertIn('TLS passed                : 1/1', output)

    def test_endpoint_uses_configured_dns_port(self):
        endpoint = checker.parse_endpoint('http://example.com:8080')
        with patch.object(checker.socket, 'getaddrinfo', return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 8080))
        ]) as dns, patch.object(checker, 'check_ip', return_value={'ip': '192.0.2.1'}) as check:
            result = checker.test_endpoint(endpoint)
        dns.assert_called_once_with('example.com', 8080, family=socket.AF_INET, type=socket.SOCK_STREAM)
        check.assert_called_once_with(endpoint, '192.0.2.1')
        self.assertEqual(result['host'], 'http://example.com:8080')


if __name__ == '__main__':
    unittest.main()
