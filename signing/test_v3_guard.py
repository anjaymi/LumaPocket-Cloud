import io
import json
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from unittest.mock import patch

from common import SigningError
from v3_guard import v3_only_server


class Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class FakeUpstream:
    def __init__(self):
        self.requests = []
        self.fail_headers = False

    def open(self, request, timeout):
        self.requests.append((request.get_method(), request.full_url))
        if request.full_url.endswith('/v3/client_info'):
            return Response(b'{"client_info":"fixture"}')
        if request.full_url.endswith('/v3/get_headers') and not self.fail_headers:
            return Response(b'{"X-Apple-I-MD-M":"fixture","X-Apple-I-MD":"fixture"}')
        raise URLError('fixture unavailable')


class GuardTests(unittest.TestCase):
    def test_forwards_v3_but_never_forwards_v1_after_an_outage(self):
        upstream = FakeUpstream()
        with patch('v3_guard.build_opener', return_value=upstream), patch('v3_guard.time.sleep'):
            with v3_only_server('https://fixture.invalid') as server:
                self.assertEqual(json.load(urlopen(server + '/v3/client_info')), {'client_info': 'fixture'})
                body = json.dumps({'identifier': '0' * 32, 'adi_pb': 'fixture'}).encode()
                request = Request(server + '/v3/get_headers', data=body)
                self.assertEqual(urlopen(request).status, 200)
                upstream.fail_headers = True
                with self.assertRaises(HTTPError) as failed:
                    urlopen(request)
                self.assertEqual(failed.exception.code, 502)
                with self.assertRaises(HTTPError) as fallback:
                    urlopen(server)
                self.assertEqual(fallback.exception.code, 404)
        self.assertTrue(all('/v3/' in url for _, url in upstream.requests))

    def test_retries_transient_headers_fetch_without_repeating_apple_operations(self):
        upstream = FakeUpstream()
        original = upstream.open
        failures = []
        def flaky(request, timeout):
            if not failures:
                failures.append('transient')
                raise HTTPError(request.full_url, 503, 'fixture unavailable', {}, None)
            return original(request, timeout)
        with patch('v3_guard.build_opener', return_value=upstream), patch.object(upstream, 'open', side_effect=flaky), patch('v3_guard.time.sleep'):
            reasons = []
            with v3_only_server('https://fixture.invalid', on_failure=reasons.append) as server:
                self.assertEqual(urlopen(server + '/v3/client_info').status, 200)
            self.assertEqual(reasons, ['upstream_http_503'])
        self.assertTrue(all('/v3/' in url for _, url in upstream.requests))

    def test_rejects_non_tls_upstream(self):
        with self.assertRaises(SigningError):
            with v3_only_server('http://fixture.invalid'):
                self.fail('must fail before starting a relay')


if __name__ == '__main__':
    unittest.main()
