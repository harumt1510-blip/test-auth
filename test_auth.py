import http.client
import re
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

from app import AuthServer, digest


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.server = AuthServer(('127.0.0.1', 0), Path(self.directory.name) / 'test.sqlite3')
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie = ''

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.directory.cleanup()

    def request(self, route, fields=None, cookie=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        headers = {'Cookie': self.cookie if cookie is None else cookie}
        body = None
        if fields is not None:
            body = urlencode(fields)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        conn.request('POST' if fields is not None else 'GET', route, body, headers)
        response = conn.getresponse()
        status, result_headers, body = response.status, dict(response.getheaders()), response.read().decode()
        conn.close()
        if 'Set-Cookie' in result_headers:
            self.cookie = result_headers['Set-Cookie'].split(';', 1)[0]
        return status, result_headers, body

    def csrf(self, route='/login'):
        status, _, body = self.request(route)
        self.assertEqual(status, 200)
        return re.search(r'name="csrf"\s+value="([^"]+)"', body)[1]

    def register(self):
        return self.request('/register', {'csrf': self.csrf('/register'),
                                         'username': 'haru_test', 'password': 'practice-only-123'})

    def test_register_logout_login_and_token_revocation(self):
        csrf = self.csrf('/register')
        anonymous_cookie = self.cookie
        status, headers, _ = self.request('/register', {'csrf': csrf,
            'username': 'haru_test', 'password': 'practice-only-123'})
        self.assertEqual(status, 303)
        self.assertIn('HttpOnly', headers['Set-Cookie'])
        self.assertIn('SameSite=Strict', headers['Set-Cookie'])
        self.assertNotEqual(anonymous_cookie, self.cookie)
        authenticated_cookie = self.cookie
        self.assertEqual(self.request('/account', cookie=anonymous_cookie)[0], 303)
        status, headers, body = self.request('/account')
        self.assertEqual(status, 200)
        self.assertIn('haru_test', body)
        self.assertEqual(headers['Cache-Control'], 'no-store')
        csrf = re.search(r'name="csrf"\s+value="([^"]+)"', body)[1]
        self.assertEqual(self.request('/logout')[0], 404)
        self.assertEqual(self.request('/logout', {'csrf': csrf})[0], 303)
        self.assertEqual(self.request('/account', cookie=authenticated_cookie)[0], 303)
        csrf = self.csrf()
        self.assertEqual(self.request('/login', {'csrf': csrf, 'username': 'haru_test',
            'password': 'wrong-password-123'})[0], 401)
        self.assertEqual(self.request('/login', {'csrf': csrf, 'username': 'haru_test',
            'password': 'practice-only-123'})[0], 303)
        with self.server.db() as db:
            user = db.execute('SELECT * FROM users').fetchone()
            self.assertNotEqual(user['password_hash'], 'practice-only-123')
            self.assertEqual(len(user['salt']), 32)
            token = self.cookie.split('=', 1)[1]
            row = db.execute('SELECT * FROM sessions WHERE user_id IS NOT NULL').fetchone()
            self.assertEqual(row['token_hash'], digest(token))
            self.assertNotEqual(row['token_hash'], token)
            db.execute('UPDATE sessions SET expires=0')
        self.assertEqual(self.request('/account')[0], 303)

    def test_csrf_validation_duplicate_and_bad_input(self):
        csrf = self.csrf('/register')
        fields = {'csrf': 'invalid', 'username': 'haru_test', 'password': 'practice-only-123'}
        self.assertEqual(self.request('/register', fields)[0], 403)
        fields['csrf'] = csrf
        fields['username'] = '<script>'
        self.assertEqual(self.request('/register', fields)[0], 400)
        fields['username'] = 'haru_test'
        fields['password'] = 'short'
        self.assertEqual(self.request('/register', fields)[0], 400)
        fields['password'] = 'practice-only-123'
        self.assertEqual(self.request('/register', fields)[0], 303)
        self.cookie = ''
        fields['csrf'] = self.csrf('/register')
        self.assertEqual(self.request('/register', fields)[0], 409)

    def test_rate_limit_and_unknown_user(self):
        csrf = self.csrf()
        fields = {'csrf': csrf, 'username': 'unknown', 'password': 'practice-only-123'}
        for _ in range(10):
            self.assertEqual(self.request('/login', fields)[0], 401)
        self.assertEqual(self.request('/login', fields)[0], 429)


if __name__ == '__main__':
    unittest.main()
