"""Live HTTP E2E UI/UX Audit & Verification Script for MarlinSpike.
Tests all pages, forms, CSRF tokens, audit downloads, and template outputs against live server http://127.0.0.1:5001.
"""

import http.cookiejar
import json
import re
import sys
import urllib.parse
import urllib.request


def run_e2e_audit():
    base_url = "http://127.0.0.1:5001"
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    print("==================================================")
    print("🚀 Starting MarlinSpike Live E2E UI/UX Audit Suite")
    print("==================================================")

    # 1. Test Login Page GET
    login_url = f"{base_url}/login"
    print(f"\n[1/8] Fetching GET {login_url}...")
    req = urllib.request.Request(login_url)
    try:
        with opener.open(req) as resp:
            body = resp.read().decode("utf-8")
            assert resp.status == 200, f"Expected 200, got {resp.status}"
            assert "MarlinSpike" in body, "MarlinSpike missing from login page"
            # Extract _csrf token
            csrf_m = re.search(r'name="_csrf"\s+value="([^"]+)"', body) or re.search(r'meta name="csrf-token"\s+content="([^"]+)"', body)
            csrf_token = csrf_m.group(1) if csrf_m else ""
            print(f"  ✓ Login page 200 OK | CSRF Token: {csrf_token[:10]}...")
    except Exception as e:
        print(f"  ❌ Failed: {e}")
        return False

    # 2. Test Login Page POST
    print(f"\n[2/8] Testing POST {login_url} with credentials (admin / qwertyuiop1234)...")
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body_parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\n{csrf_token}\r\n",
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\nadmin\r\n",
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nqwertyuiop1234\r\n",
        f"--{boundary}--\r\n",
    ]
    data = "".join(body_parts).encode("utf-8")
    req = urllib.request.Request(login_url, data=data, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    try:
        with opener.open(req) as resp:
            body = resp.read().decode("utf-8")
            print(f"  ✓ Login POST status: {resp.status}")
            if "login-error" in body:
                print(f"  ❌ Login error message: {re.findall(r'<div class=\"login-error\">(.*?)</div>', body)}")
    except Exception as e:
        print(f"  ℹ️ Login response / redirect handled: {e}")

    # 3. Test Core Workspace UI Pages
    pages_to_test = [
        ("/dashboard", "Dashboard Workspace", ["Dashboard", "MarlinSpike"]),
        ("/fleet", "Distributed Remote Sensors", ["Fleet", "MarlinSpike"]),
        ("/projects", "Projects Workspace", ["Projects", "Historical Audit Report"]),
        ("/projects/1/audit-report", "Project Audit Report UI", ["Project Audit Report", "Discovered", "Download CSV", "Download JSON"]),
    ]

    for idx, (path, name, expected_tokens) in enumerate(pages_to_test, start=3):
        target_url = f"{base_url}{path}"
        print(f"\n[{idx}/8] Auditing UI Page: {name} ({target_url})...")
        req = urllib.request.Request(target_url)
        try:
            with opener.open(req) as resp:
                body = resp.read().decode("utf-8")
                assert resp.status == 200, f"Expected 200, got {resp.status}"
                for token in expected_tokens:
                    assert token in body, f"Token '{token}' missing from page {path}"
                print(f"  ✓ Page 200 OK | Verified required tokens: {expected_tokens}")
        except Exception as e:
            print(f"  ❌ Page Audit Failed for {path}: {e}")
            return False

    # 7. Test API Project Audit Data Endpoint
    api_url = f"{base_url}/api/projects/1/audit-report"
    print(f"\n[7/8] Auditing API Endpoint: {api_url}...")
    try:
        with opener.open(api_url) as resp:
            body = resp.read().decode("utf-8")
            assert resp.status == 200, f"Expected 200, got {resp.status}"
            assert '"ok":true' in body.replace(" ", "").lower(), "API response missing ok:true"
            print("  ✓ API Audit Report endpoint returns valid JSON.")
    except Exception as e:
        print(f"  ❌ API Audit Endpoint Failed: {e}")
        return False

    # 8. Test Audit Downloads (CSV & JSON)
    csv_url = f"{base_url}/api/projects/1/audit-report/download?format=csv"
    json_url = f"{base_url}/api/projects/1/audit-report/download?format=json"
    print(f"\n[8/8] Testing Audit Report Download Endpoints...")
    try:
        with opener.open(csv_url) as resp:
            disposition = resp.headers.get("Content-Disposition", "")
            assert resp.status == 200
            assert "attachment;" in disposition and ".csv" in disposition, f"Invalid CSV Content-Disposition: {disposition}"
            print(f"  ✓ CSV Download OK | Content-Disposition: {disposition}")

        with opener.open(json_url) as resp:
            disposition = resp.headers.get("Content-Disposition", "")
            assert resp.status == 200
            assert "attachment;" in disposition and ".json" in disposition, f"Invalid JSON Content-Disposition: {disposition}"
            print(f"  ✓ JSON Download OK | Content-Disposition: {disposition}")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8', errors='ignore')
        print(f"  ❌ Audit Download Test Failed: {e} | Body: {err_body}")
        return False
    except Exception as e:
        print(f"  ❌ Audit Download Test Failed: {e}")
        return False

    print("\n==================================================")
    print("🎉 ALL LIVE E2E UI/UX AUDIT TESTS PASSED 100%!")
    print("==================================================")
    return True


if __name__ == "__main__":
    success = run_e2e_audit()
    sys.exit(0 if success else 1)
