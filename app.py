"""Local authentication demo. Python 3.10+, no external dependencies."""
import hashlib
import hmac
import html
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parent
SESSION_SECONDS = 1800


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1).hex()


class AuthServer(ThreadingHTTPServer):
    def __init__(self, address, database):
        self.database = str(database)
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                    salt TEXT NOT NULL, password_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY, user_id INTEGER,
                    csrf TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts (ip TEXT, created REAL);
            """)
        # Equal work for unknown users and incorrect passwords.
        self.dummy_salt = secrets.token_bytes(16)
        self.dummy_hash = password_hash(secrets.token_urlsafe(32), self.dummy_salt)
        super().__init__(address, Handler)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Avoid logging credentials, cookies, request bodies, or URL queries.
        pass

    def session(self):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get('Cookie', ''))
        except CookieError:
            return None
        token = cookies.get('auth_session')
        if not token:
            return None
        with self.server.db() as db:
            return db.execute(
                'SELECT s.*, u.username FROM sessions s LEFT JOIN users u '
                'ON u.id=s.user_id WHERE token_hash=? AND expires>?',
                (digest(token.value), time.time())).fetchone()

    def new_session(self, user_id=None, previous=None):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.server.db() as db:
            db.execute('DELETE FROM sessions WHERE expires<=?', (time.time(),))
            if previous:
                db.execute('DELETE FROM sessions WHERE token_hash=?',
                           (previous['token_hash'],))
            db.execute('INSERT INTO sessions VALUES (?, ?, ?, ?)',
                       (digest(token), user_id, csrf, time.time() + SESSION_SECONDS))
        return token

    def reply(self, status, body='', token=None, location=None):
        data = body.encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy',
                         "default-src 'none'; style-src 'unsafe-inline'; "
                         "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        if token is not None:
            age = SESSION_SECONDS if token else 0
            self.send_header('Set-Cookie', f'auth_session={token}; Path=/; '
                             f'Max-Age={age}; HttpOnly; SameSite=Strict')
        if location:
            self.send_header('Location', location)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location, token=None):
        self.reply(303, token=token, location=location)

    def page(self, title, content, status=200, token=None):
        self.reply(status, f'''<!doctype html><html lang="ja"><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{html.escape(title)} | 認証アプリ</title><style>
        *{{box-sizing:border-box}}body{{font-family:system-ui,sans-serif;background:#edf2f7;
        color:#243247;margin:0;padding:48px 20px}}main{{max-width:440px;margin:auto;
        background:white;padding:32px;border-radius:20px;box-shadow:0 12px 40px #24324715}}
        h1{{font-size:25px}}label{{display:block;margin-top:18px}}input{{width:100%;
        padding:12px;margin-top:6px;border:1px solid #9aabba;border-radius:8px;font-size:16px}}
        button{{width:100%;padding:13px;margin:24px 0 16px;background:#1768a8;color:white;
        border:0;border-radius:8px;font-size:16px;cursor:pointer}}a{{color:#1768a8}}
        .note{{color:#526579;font-size:14px}}.error{{color:#b42318}}</style>
        <main><p class="note">Python 認証アプリ · ローカル練習用</p>
        <h1>{html.escape(title)}</h1>{content}</main></html>''', token)

    def form(self, route, session, error='', status=200, token=None):
        register = route == '/register'
        title = 'ユーザー登録' if register else 'ログイン'
        alternative = '<a href="/login">ログインへ</a>' if register else '<a href="/register">新しく登録する</a>'
        csrf = session['csrf']
        self.page(title, f'''<p class="error" role="alert">{html.escape(error)}</p>
        <form method="post" action="{route}"><input type="hidden" name="csrf" value="{csrf}">
        <label>ユーザー名<input name="username" required minlength="3" maxlength="32"
        pattern="[A-Za-z0-9_]{{3,32}}" autocomplete="username"></label>
        <p class="note">半角英数字・アンダーバーで3〜32文字</p>
        <label>パスワード<input type="password" name="password" required minlength="12"
        maxlength="256" autocomplete="{'new-password' if register else 'current-password'}"></label>
        <p class="note">12〜256文字。練習専用のパスワードを使用してください。</p>
        <button>{title}</button></form>{alternative}''', status, token)

    def do_GET(self):
        route = self.path.split('?', 1)[0]
        if route not in ('/', '/login', '/register', '/account'):
            self.page('見つかりません', '<a href="/">トップへ</a>', 404)
            return
        session = self.session()
        if route == '/':
            self.redirect('/account' if session and session['user_id'] else '/login')
        elif route == '/account':
            if not session or not session['user_id']:
                self.redirect('/login')
                return
            self.page('ログイン成功', f'''<p>こんにちは、<strong>{html.escape(session['username'])}</strong> さん。</p>
                <p>このページはログインした人だけが開けます。</p>
                <p class="note">ログインの有効期限は30分です。</p>
                <form method="post" action="/logout"><input type="hidden" name="csrf"
                value="{session['csrf']}"><button>ログアウト</button></form>''')
        elif session and session['user_id']:
            self.redirect('/account')
        else:
            token = None
            if not session:
                token = self.new_session()
                with self.server.db() as db:
                    session = db.execute('SELECT * FROM sessions WHERE token_hash=?',
                                         (digest(token),)).fetchone()
            self.form(route, session, token=token)

    def do_POST(self):
        route = self.path.split('?', 1)[0]
        if route not in ('/register', '/login', '/logout'):
            self.reply(404)
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 8192:
                self.reply(413)
                return
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/x-www-form-urlencoded':
                self.reply(415)
                return
            fields = parse_qs(self.rfile.read(length).decode('utf-8'), max_num_fields=8)
        except (ValueError, UnicodeError):
            self.reply(400)
            return
        session = self.session()
        csrf = fields.get('csrf', [''])[0]
        if not session or not hmac.compare_digest(csrf.encode(), session['csrf'].encode()):
            self.page('操作を確認できません', '<p>画面を開き直して操作してください。</p><a href="/login">ログインへ</a>', 403)
            return
        if route == '/logout':
            with self.server.db() as db:
                db.execute('DELETE FROM sessions WHERE token_hash=?', (session['token_hash'],))
            self.redirect('/login', token='')
            return
        username = fields.get('username', [''])[0]
        password = fields.get('password', [''])[0]
        if not re.fullmatch(r'[A-Za-z0-9_]{3,32}', username) or not 12 <= len(password) <= 256:
            self.form(route, session, 'ユーザー名とパスワードの文字数・形式を確認してください。', 400)
            return
        # Bound expensive password operations (including registration) per client IP.
        now = time.time()
        with self.server.db() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM attempts WHERE created<?', (now - 60,))
            count = db.execute('SELECT count(*) FROM attempts WHERE ip=?',
                               (self.client_address[0],)).fetchone()[0]
            if count < 10:
                db.execute('INSERT INTO attempts VALUES (?, ?)', (self.client_address[0], now))
        if count >= 10:
            self.form(route, session, '操作回数が多いため、1分ほど待って再度お試しください。', 429)
            return
        with self.server.db() as db:
            if route == '/register':
                salt = secrets.token_bytes(16)
                hashed = password_hash(password, salt)
                try:
                    user_id = db.execute('INSERT INTO users(username,salt,password_hash) VALUES(?,?,?)',
                                         (username, salt.hex(), hashed)).lastrowid
                except sqlite3.IntegrityError:
                    self.form(route, session, 'このユーザー名は使用されています。', 409)
                    return
            else:
                user = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
                salt = bytes.fromhex(user['salt']) if user else self.server.dummy_salt
                expected = user['password_hash'] if user else self.server.dummy_hash
                valid = hmac.compare_digest(password_hash(password, salt), expected)
                if not user or not valid:
                    self.form(route, session, 'ユーザー名またはパスワードが違います。', 401)
                    return
                user_id = user['id']
        # Replace the anonymous/previous session; do not reuse a login token.
        token = self.new_session(user_id, session)
        self.redirect('/account', token)


if __name__ == '__main__':
    data = ROOT / 'data'
    data.mkdir(mode=0o700, exist_ok=True)
    if os.name == 'posix':
        os.umask(0o077)
    server = AuthServer(('127.0.0.1', 8000), data / 'auth.sqlite3')
    print('認証アプリ: http://127.0.0.1:8000  終了: Ctrl+C')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\n終了しました。')
    finally:
        server.server_close()
