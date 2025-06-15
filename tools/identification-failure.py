import requests
import sys
import argparse
from urllib.parse import urlparse
import json

def test_brute_force(url, usernames=["admin", "user"], passwords=["admin", "password", "123456"]):
    results = []
    session = requests.Session()
    
    for username in usernames:
        for password in passwords:
            payload = {"username": username, "password": password}
            try:
                response = session.post(url, data=payload, timeout=5)
                if response.status_code == 200 and "Welcome" in response.text:
                    results.append({"type": "brute_force", "result": "VULNERABILITY", "details": f"Brute-force success: {username}:{password} granted access"})
                elif "Too many attempts" in response.text or "Locked" in response.text:
                    results.append({"type": "brute_force", "result": "PASS", "details": "Rate-limiting or account lockout detected"})
                    break
                else:
                    results.append({"type": "brute_force", "result": "INFO", "details": f"Failed attempt: {username}:{password}"})
            except requests.RequestException as e:
                results.append({"type": "brute_force", "result": "ERROR", "details": f"Request failed: {str(e)}"})
                break
    return results

def check_session_cookies(url):
    results = []
    session = requests.Session()
    try:
        response = session.get(url, timeout=5)
        cookies = session.cookies.get_dict()
        for cookie_name, cookie_value in cookies.items():
            cookie = session.cookies[cookie_name]
            if not hasattr(cookie, 'secure') or not cookie.secure:
                results.append({"type": "cookie_security", "result": "VULNERABILITY", "details": f"Cookie '{cookie_name}' lacks Secure flag"})
            if not hasattr(cookie, 'httponly') or not cookie.httponly:
                results.append({"type": "cookie_security", "result": "VULNERABILITY", "details": f"Cookie '{cookie_name}' lacks HttpOnly flag"})
        if not cookies:
            results.append({"type": "cookie_security", "result": "INFO", "details": "No session cookies found"})
    except requests.RequestException as e:
        results.append({"type": "cookie_security", "result": "ERROR", "details": f"Failed to retrieve cookies: {str(e)}"})
    return results

def main():
    parser = argparse.ArgumentParser(description="Test authentication mechanism for weaknesses")
    parser.add_argument("url", help="URL of the login page (e.g., https://example.com/login)")
    args = parser.parse_args()
    
    url = args.url
    domain = urlparse(url).netloc
    
    output = {
        "scan_info": {
            "target_url": url,
            "domain": domain
        },
        "tests": []
    }
    
    # Run brute force test
    brute_force_results = test_brute_force(url)
    output["tests"].append({
        "name": "Brute-Force Test",
        "results": brute_force_results
    })
    
    # Run cookie security test
    cookie_results = check_session_cookies(url)
    output["tests"].append({
        "name": "Session Cookie Security Test",
        "results": cookie_results
    })
    
    # Generate recommendations
    recommendations = []
    if any(r["result"] == "VULNERABILITY" and r["type"] == "brute_force" for r in brute_force_results):
        recommendations.append("Implement rate-limiting or account lockout after multiple failed attempts.")
    if any(r["result"] == "VULNERABILITY" and "Secure flag" in r["details"] for r in cookie_results):
        recommendations.append("Ensure all session cookies have the Secure flag to enforce HTTPS.")
    if any(r["result"] == "VULNERABILITY" and "HttpOnly flag" in r["details"] for r in cookie_results):
        recommendations.append("Set HttpOnly flag on session cookies to prevent client-side script access.")
    if not any(r["result"] == "VULNERABILITY" for r in brute_force_results + cookie_results):
        recommendations.append("No vulnerabilities detected. Consider additional tests (e.g., SQL injection).")
    
    output["recommendations"] = recommendations
    
    print(json.dumps(output, indent=4))

if __name__ == "__main__":
    main()
