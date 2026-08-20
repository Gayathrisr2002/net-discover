import http.cookiejar
import re
import urllib.request

base_url = "http://127.0.0.1:5001"
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# 1. GET login
with opener.open(f"{base_url}/login") as resp:
    body = resp.read().decode('utf-8')
    csrf_m = re.search(r'name="_csrf"\s+value="([^"]+)"', body)
    csrf_token = csrf_m.group(1) if csrf_m else ""

# 2. POST login
boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
body_parts = [
    f"--{boundary}\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\n{csrf_token}\r\n",
    f"--{boundary}\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nadmin\r\n",
    f"--{boundary}\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nqwertyuiop1234\r\n",
    f"--{boundary}--\r\n",
]
data = "".join(body_parts).encode("utf-8")
req = urllib.request.Request(f"{base_url}/login", data=data, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
with opener.open(req) as resp:
    print("Login status:", resp.status)

# 3. GET JSON Audit Report API
try:
    with opener.open(f"{base_url}/api/projects/1/audit-report") as resp:
        print("API Audit Report Status:", resp.status)
        print("API Audit Report Body preview:", resp.read().decode('utf-8')[:200])
except urllib.error.HTTPError as e:
    print("API Audit Report HTTPError status:", e.code)
    print("API Audit Report HTTPError body:", e.read().decode('utf-8'))

# 4. GET CSV Download
try:
    with opener.open(f"{base_url}/api/projects/1/audit-report/download?format=csv") as resp:
        print("CSV Download Status:", resp.status)
        print("Headers:", resp.headers)
        print("Body preview:", resp.read().decode('utf-8')[:200])
except urllib.error.HTTPError as e:
    print("Download HTTPError status:", e.code)
    print("Download HTTPError body:", e.read().decode('utf-8'))
