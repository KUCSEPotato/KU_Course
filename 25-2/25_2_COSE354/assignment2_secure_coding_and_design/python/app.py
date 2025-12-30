"""
1. SQL Injection
2. Cross Site Scripting
3. SSRF
4. Command Injection
5. Local File Inclusion (Directory traversal)
"""
import os
import sqlite3
import subprocess
from urllib.parse import unquote

import requests
from flask import Flask, request, session, g, render_template, redirect, url_for


BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, 'database.db')
LOG_DIR = os.path.join(BASE_DIR, 'logs')


app = Flask(__name__)
app.secret_key = 'very_very_secret'


def get_db():
    if not hasattr(g, 'db'):
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    if hasattr(g, 'db'):
        g.db.close()


def init_db():
    os.makedirs(LOG_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS memos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT
        )
        """
    )
    conn.commit()
    conn.close()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/Register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        cur = db.cursor()
        cur.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        db.commit()
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/Login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        db = get_db()
        cur = db.cursor()
        # Vulnerable to SQL Injection
        # need patch
        # if username == admin and password == anything 'or'1'='1 -> always true
        # -> above input makes query like:
        # SELECT * FROM users WHERE username = 'admin' AND password = 'anything' or'1'='1'
        # vulnerable code
        """
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
        try:
            cur.execute(query)
            user = cur.fetchone()
        """
        # patched code
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        try:
            cur.execute(query, (username, password))
            user = cur.fetchone()
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                return redirect(url_for('profile'))
            else:
                error = 'Login failed'
        except Exception as e:
            error = f'SQL error: {e}'
    return render_template('login.html', error=error)


@app.route('/Profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('profile.html', username=session.get('username', 'unknown'))


@app.route('/Memo', methods=['GET', 'POST'])
def memo():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cur = db.cursor()

    if request.method == 'POST':
        content = request.form.get('content', '')
        # Vulnerable to XSS
        # need patch
        # It blocks SQL Injection but allows XSS
        # Their is no sanitization or escaping of user input before storing in DB
        # So if user inputs <script>alert('XSS')</script>, it will be stored
        # patched code should sanitize or escape content before storing or rendering
        """
        cur.execute('INSERT INTO memos (user_id, content) VALUES (?, ?)', (session['user_id'], content))
        """
        import html # patched line
        sanitized_content = html.escape(content)  # patched line
        cur.execute('INSERT INTO memos (user_id, content) VALUES (?, ?)', (session['user_id'], sanitized_content)) # patched line
        db.commit()
        return redirect(url_for('memo'))

    cur.execute('SELECT content FROM memos WHERE user_id = ?', (session['user_id'],))
    memos = cur.fetchall()
    return render_template('memo.html', memos=memos)

# SSRF Vulnerability
""" 
@app.route('/Fetch', methods=['GET', 'POST'])
def fetch():
    content = None
    url = ''
    if request.method == 'POST':
        url = request.form.get('url', '')
        try:
            r = requests.get(url, timeout=10)
            content = r.text[:4096]
        except Exception as e:
            content = f'Error: {e}'
    return render_template('fetch.html', url=url, content=content)
"""
# [Patched Code]
from urllib.parse import urlparse
import ipaddress
import socket
"""
import logging

# 로깅 설정
logging.basicConfig(
    filename=os.path.join(LOG_DIR, 'ssrf_requests.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
"""

@app.route('/Fetch', methods=['GET', 'POST'])
def fetch():
    content = None
    url = ''
    if request.method == 'POST':
        url = request.form.get('url', '')
        
        # Request logging
        logging.info(f"User {session.get('user_id', 'anonymous')} requested URL: {url} from IP: {request.remote_addr}")
        
        try:
            parsed = urlparse(url)
            
            # 1. checking protocol (only http/https)
            if parsed.scheme not in ['http', 'https']:
                content = 'Error: Only HTTP/HTTPS protocols are allowed'
                logging.warning(f"Blocked protocol: {parsed.scheme} for URL: {url}")
                return render_template('fetch.html', url=url, content=content)
            
            # 2. check host presence
            if not parsed.hostname:
                content = 'Error: Invalid URL format'
                logging.warning(f"Invalid URL format: {url}")
                return render_template('fetch.html', url=url, content=content)
            
            # 3. IP address validation
            def is_safe_host(hostname):
                """
                Block internal IP, Private IP, and metadata service IPs
                """
                try:
                    # If format is IP address
                    ip = ipaddress.ip_address(hostname)
                    
                    # Block Private IP (RFC 1918)
                    if ip.is_private:
                        return False
                    
                    # Block Loopback (127.0.0.0/8, ::1)
                    if ip.is_loopback:
                        return False

                    # Block Link-local (169.254.0.0/16)
                    if ip.is_link_local:
                        return False

                    # Block Reserved IPs
                    if ip.is_reserved:
                        return False
                    
                    # Block AWS/GCP/Azure metadata service IP
                    if str(ip) == '169.254.169.254':
                        return False
                    
                    return True
                    
                except ValueError:
                    # If format is domain name, perform DNS resolution and check
                    try:
                        resolved_ip = socket.gethostbyname(hostname)
                        ip = ipaddress.ip_address(resolved_ip)
                        
                        # same checks as above
                        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                            return False
                        if str(ip) == '169.254.169.254':
                            return False
                        
                        return True
                    except socket.gaierror:
                        # DNS resolution failed
                        return False
            
            # check if the host is safe
            if not is_safe_host(parsed.hostname):
                content = 'Error: Access to internal/private networks is forbidden'
                logging.warning(f"Blocked internal IP access: {parsed.hostname} for URL: {url}")
                return render_template('fetch.html', url=url, content=content)
            
            # 4. domain whitelist
            ALLOWED_DOMAINS = [
                'httpbin.org',
                'api.github.com',
                'jsonplaceholder.typicode.com',
                'www.example.com'
            ]
            
            if parsed.hostname not in ALLOWED_DOMAINS:
                content = f'Error: Domain "{parsed.hostname}" is not in the allowed list'
                logging.warning(f"Domain not whitelisted: {parsed.hostname}")
                return render_template('fetch.html', url=url, content=content)
            
            # 5. port restriction (only allow 80, 443)
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            if port not in [80, 443]:
                content = f'Error: Only ports 80 and 443 are allowed (requested: {port})'
                logging.warning(f"Blocked port access: {port} for URL: {url}")
                return render_template('fetch.html', url=url, content=content)
            
            # 6. Make the request with secure settings
            r = requests.get(
                url,
                timeout=5,  # timeout setting
                allow_redirects=False,  # Block redirects
                headers={
                    'User-Agent': 'SecureWebApp/1.0',
                    'Accept': 'text/html,text/plain'
                },
                verify=True  # SSL certificate verification
            )
            
            # 7. Response size limit
            if len(r.content) > 1048576:  # 1MB
                content = 'Error: Response size exceeds 1MB limit'
                logging.warning(f"Response too large for URL: {url}")
            else:
                content = r.text[:4096]
                logging.info(f"Successful fetch from URL: {url}")
                
        except requests.exceptions.SSLError as e:
            content = f'SSL Error: Invalid certificate'
            logging.error(f"SSL error for URL {url}: {e}")
        except requests.exceptions.Timeout:
            content = 'Error: Request timeout'
            logging.error(f"Timeout for URL: {url}")
        except requests.exceptions.RequestException as e:
            content = f'Request error: Connection failed'
            logging.error(f"Request exception for URL {url}: {e}")
        except Exception as e:
            content = f'Validation error: {str(e)}'
            logging.error(f"Unexpected error for URL {url}: {e}")
    
    return render_template('fetch.html', url=url, content=content)

# command injection vulnerability
# need patch
"""
@app.route('/Ping', methods=['GET', 'POST'])
def ping():
    ip_address = ''
    result = None
    if request.method == 'POST':
        ip_address = request.form.get('ip', '') # 사용자 입력: command injection 취약점 존재
        count_flag = '-n' if os.name == 'nt' else '-c'
        command = "ping " + count_flag + " 3 " + ip_address # 문자열 연결로 명령어 조합: command injection 취약점
        try:
            completed = subprocess.run(
                command,
                shell=True, # 쉘 사용: command injection 취약점
                capture_output=True,
                text=True,
                timeout=15,
            )
            result = completed.stdout or completed.stderr
        except Exception as e:
            result = f'Error running command: {e}'
    return render_template('ping.html', ip=ip_address, result=result)
"""
# [Patched Code]
import re
import ipaddress
import logging

@app.route('/Ping', methods=['GET', 'POST'])
def ping():
    ip_address = ''
    result = None
    error = None
    
    if request.method == 'POST':
        ip_address = request.form.get('ip', '').strip()
        
        # request logging
        logging.info(f"User {session.get('user_id', 'anonymous')} attempted ping to: {ip_address} from IP: {request.remote_addr}")
        
        # 1. restrict length
        if len(ip_address) > 45:  # max length of IPv6 address is 39 characters + some buffer
            error = 'Error: IP address too long'
            logging.warning(f"IP address too long: {ip_address}")
            return render_template('ping.html', ip=ip_address, result=error)
        
        # 2. validate IP format using regex
        ipv4_pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        ipv6_pattern = r'^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::1|::)$'
        
        if not (re.match(ipv4_pattern, ip_address) or re.match(ipv6_pattern, ip_address)):
            error = 'Error: Invalid IP address format'
            logging.warning(f"Invalid IP format: {ip_address}")
            return render_template('ping.html', ip=ip_address, result=error)
        
        # 3. validate dangerous characters (additional security layer)
        dangerous_chars = [';', '&', '|', '$', '`', '\n', '\r', '(', ')', '<', '>', '{', '}', '[', ']', '\\', '"', "'"]
        if any(char in ip_address for char in dangerous_chars):
            error = 'Error: Invalid characters detected in IP address'
            logging.warning(f"Dangerous characters detected in IP: {ip_address}")
            return render_template('ping.html', ip=ip_address, result=error)
        
        # 4. ip address validation using ipaddress module
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Block Private IP
            if ip_obj.is_private or ip_obj.is_loopback:
                error = 'Error: Cannot ping private or loopback addresses'
                logging.warning(f"Attempted to ping private/loopback IP: {ip_address}")
                return render_template('ping.html', ip=ip_address, result=error)
            
            # Block Reserved IP
            if ip_obj.is_reserved:
                error = 'Error: Cannot ping reserved IP addresses'
                logging.warning(f"Attempted to ping reserved IP: {ip_address}")
                return render_template('ping.html', ip=ip_address, result=error)
                
        except ValueError:
            error = 'Error: Invalid IP address'
            logging.warning(f"IP parsing failed: {ip_address}")
            return render_template('ping.html', ip=ip_address, result=error)
        
        # 5. Safe command execution (shell=False + list format)
        count_flag = '-n' if os.name == 'nt' else '-c'
        command = ['ping', count_flag, '3', ip_address]  # command as list to avoid shell interpretation
        
        try:
            completed = subprocess.run(
                command,
                shell=False,  # shell=False to prevent command injection
                capture_output=True,
                text=True,
                timeout=15,
            )
            result = completed.stdout or completed.stderr
            logging.info(f"Successful ping to {ip_address}")
            
        except subprocess.TimeoutExpired:
            error = 'Error: Ping request timed out'
            logging.warning(f"Ping timeout for IP: {ip_address}")
        except Exception as e:
            error = f'Error: Command execution failed'
            logging.error(f"Ping execution error for IP {ip_address}: {e}")
    
    return render_template('ping.html', ip=ip_address, result=result)

# Local File Inclusion (Directory Traversal) Vulnerability
"""
@app.route('/ViewFile')
def view_file():
    raw = request.args.get('filename', '')
    content = None
    error = None
    if raw:
        sanitized = raw.replace('../', '', 1)
        decoded = unquote(sanitized)
        file_path = os.path.join(LOG_DIR, decoded + '.log')
        if '\x00' in file_path:
            file_path = file_path.split('\x00', 1)[0]
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            error = str(e)
    return render_template('view.html', filename=raw, content=content, error=error)
"""
# [Patched Code]
from urllib.parse import unquote
import os, re

FNAME_RE = re.compile(r'^[A-Za-z0-9_\-]+$')

@app.route('/ViewFile')
def view_file():
    raw = request.args.get('filename', '')
    content = None
    error = None
    if raw:
        decoded = unquote(raw)
        # 1) Block null byte
        if '\x00' in decoded:
            error = 'Invalid filename'
            return render_template('view.html', filename=raw, content=content, error=error)
        # 2) Validate filename against whitelist
        if not FNAME_RE.match(decoded):
            error = 'Invalid filename'
            return render_template('view.html', filename=raw, content=content, error=error)
        # 3) Path normalization and boundary check
        filename = decoded + '.log'
        file_path = os.path.normpath(os.path.join(LOG_DIR, filename))
        if not file_path.startswith(os.path.realpath(LOG_DIR) + os.sep):
            error = 'Access denied'
            return render_template('view.html', filename=raw, content=content, error=error)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            error = str(e)
    return render_template('view.html', filename=raw, content=content, error=error)


@app.route('/Logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8000, debug=True) # port changed to 8000; i can run flask app in port 5000 in my env
