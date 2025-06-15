import requests
import sys
import argparse
from urllib.parse import urlparse

# Function to check for brute-force vulnerability
def test_brute_force(url, usernames=["admin", "user"], passwords=["admin", "password", "123456"]):
    results = []
    session = requests.Session()
    
    for username in usernames:
        for password in passwords:
            payload = {"username": username, "password": password}
            try:
                response = session.post(url, data=payload, timeout=5)
                if response.status_code == 200 and "Welcome" in response.text:
                    results.append(f"[VULNERABILITY] Brute-force success: {username}:{password} granted access")
                elif "Too many attempts" in response.text or "Locked" in response.text:
                    results.append("[PASS] Rate-limiting or account lockout detected")
                    break
                else:
                    results.append(f"[INFO] Failed attempt: {username}:{password}")
            except requests.RequestException as e:
                results.append(f"[ERROR] Request failed: {str(e)}")
                break
    return results

# Function to check session cookie security
def check_session_cookies(url):
    results = []
    session = requests.Session()
    try:
        response = session.get(url, timeout=5)
        cookies = session.cookies.get_dict()
        for cookie_name, cookie_value in cookies.items():
            cookie = session.cookies[cookie_name]
            if not hasattr(cookie, 'secure') or not cookie.secure:
                results.append(f"[VULNERABILITY] Cookie '{cookie_name}' lacks Secure flag")
            if not hasattr(cookie, 'httponly') or not cookie.httponly:
                results.append(f"[VULNERABILITY] Cookie '{cookie_name}' lacks HttpOnly flag")
        if not cookies:
            results.append("[INFO] No session cookies found")
    except requests.RequestException as e:
        results.append(f"[ERROR] Failed to retrieve cookies: {str(e)}")
    return results

# Main function to run tests and print report to terminal
def main():
    # Parse command-line argument
    parser = argparse.ArgumentParser(description="Test authentication mechanism for weaknesses")
    parser.add_argument("url", help="URL of the login page (e.g., https://example.com/login)")
    args = parser.parse_args()
    
    url = args.url
    domain = urlparse(url).netloc
    results = [f"Authentication Vulnerability Report for {url}", "="*50]

    # Run tests
    results.append("\n=== Brute-Force Test ===")
    results.extend(test_brute_force(url))
    
    results.append("\n=== Session Cookie Security Test ===")
    results.extend(check_session_cookies(url))
    
    # Add recommendations
    results.append("\n=== Recommendations ===")
    if any("Brute-force success" in r for r in results):
        results.append("- Implement rate-limiting or account lockout after multiple failed attempts.")
    if any("lacks Secure flag" in r for r in results):
        results.append("- Ensure all session cookies have the Secure flag to enforce HTTPS.")
    if any("lacks HttpOnly flag" in r for r in results):
        results.append("- Set HttpOnly flag on session cookies to prevent client-side script access.")
    if not any("[VULNERABILITY]" in r for r in results):
        results.append("- No vulnerabilities detected. Consider additional tests (e.g., SQL injection).")
    
    # Print results to terminal
    for result in results:
        print(result)

if __name__ == "__main__":
    main()