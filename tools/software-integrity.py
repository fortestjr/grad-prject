import json
import requests
from urllib.parse import urlparse

def load_config(config_path):
    """Load JSON configuration file."""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return None

def is_url_accessible(url):
    """Check if a URL is accessible."""
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code == 200
    except requests.RequestException:
        return False

def check_software_updates(updates):
    """Check software updates for trust issues."""
    issues = []
    for update in updates:
        url = update.get("url", "")
        trusted_source = update.get("trusted_source", "")

        # Validate URL format
        if not url.startswith(("http://", "https://")):
            issues.append(f"Invalid URL format for software update {url}")
            continue

        # Check accessibility
        if not is_url_accessible(url):
            issues.append(f"Inaccessible URL for software update {url}")

        # Check for integrity verification (assume missing metadata is a trust issue)
        issues.append(f"No integrity verification (e.g., hash or signature) for software update {url}")

        # Check trusted source
        if trusted_source:
            domain = urlparse(url).netloc
            trusted_domain = urlparse(trusted_source).netloc
            if domain != trusted_domain:
                issues.append(f"Untrusted source {domain} for software update {url}")

    return issues

def check_critical_data(data_files):
    """Check critical data for trust issues."""
    issues = []
    for data in data_files:
        url = data.get("url", "")

        # Validate URL format
        if not url.startswith(("http://", "https://")):
            issues.append(f"Invalid URL format for critical data {url}")
            continue

        # Check accessibility
        if not is_url_accessible(url):
            issues.append(f"Inaccessible URL for critical data {url}")

        # Assume lack of encryption metadata indicates a trust issue
        issues.append(f"Critical data {url} lacks encryption metadata")

        # Assume lack of access control metadata indicates a trust issue
        issues.append(f"Critical data {url} lacks access control metadata")

    return issues

def check_ci_cd_pipelines(pipelines):
    """Check CI/CD pipelines for trust issues."""
    issues = []
    for pipeline in pipelines:
        url = pipeline.get("url", "")
        repo_url = pipeline.get("repo_url", "")
        trusted_source = pipeline.get("trusted_source", "")

        # Validate URL format
        if not url.startswith(("http://", "https://")):
            issues.append(f"Invalid URL format for CI/CD artifact {url}")
            continue

        # Check accessibility
        if not is_url_accessible(url):
            issues.append(f"Inaccessible URL for CI/CD artifact {url}")

        # Check for integrity verification (assume missing metadata is a trust issue)
        issues.append(f"No integrity verification (e.g., hash or signature) for CI/CD artifact {url}")

        # Check trusted source
        if repo_url and trusted_source:
            repo_domain = urlparse(repo_url).netloc
            trusted_domain = urlparse(trusted_source).netloc
            if repo_domain != trusted_domain:
                issues.append(f"Untrusted source {repo_domain} for CI/CD artifact {url}")

    return issues

def main():
    """Main function to check for trust issues."""
    config_path = "config.json"
    config = load_config(config_path)
    if not config:
        print("Failed to load configuration. Please provide a valid config.json.")
        return

    issues = []
    issues.extend(check_software_updates(config.get("software_updates", [])))
    issues.extend(check_critical_data(config.get("critical_data", [])))
    issues.extend(check_ci_cd_pipelines(config.get("ci_cd_pipelines", [])))

    if issues:
        for issue in issues:
            print(f"Trust issue: {issue}")
    else:
        print("No trust issues found.")

if __name__ == "__main__":
    main()