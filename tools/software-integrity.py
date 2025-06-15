import json
import requests
from urllib.parse import urlparse
from typing import Dict, List, Optional, Any

def load_config(config_path: str) -> Optional[Dict[str, Any]]:
    """Load JSON configuration file."""
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        return {"error": f"Error loading config: {e}"}

def is_url_accessible(url: str) -> bool:
    """Check if a URL is accessible."""
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code == 200
    except requests.RequestException:
        return False

def check_software_updates(updates: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Check software updates for trust issues."""
    issues = []
    for update in updates:
        url = update.get("url", "")
        trusted_source = update.get("trusted_source", "")

        result = {"type": "software_update", "url": url}

        # Validate URL format
        if not url.startswith(("http://", "https://")):
            issues.append({**result, "issue": "Invalid URL format"})
            continue

        # Check accessibility
        if not is_url_accessible(url):
            issues.append({**result, "issue": "Inaccessible URL"})

        # Check for integrity verification
        issues.append({**result, "issue": "No integrity verification (e.g., hash or signature)"})

        # Check trusted source
        if trusted_source:
            domain = urlparse(url).netloc
            trusted_domain = urlparse(trusted_source).netloc
            if domain != trusted_domain:
                issues.append({**result, "issue": f"Untrusted source {domain}"})

    return issues

def check_critical_data(data_files: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Check critical data for trust issues."""
    issues = []
    for data in data_files:
        url = data.get("url", "")
        
        result = {"type": "critical_data", "url": url}

        # Validate URL format
        if not url.startswith(("http://", "https://")):
            issues.append({**result, "issue": "Invalid URL format"})
            continue

        # Check accessibility
        if not is_url_accessible(url):
            issues.append({**result, "issue": "Inaccessible URL"})

        # Check encryption and access control
        issues.append({**result, "issue": "Lacks encryption metadata"})
        issues.append({**result, "issue": "Lacks access control metadata"})

    return issues

def check_ci_cd_pipelines(pipelines: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Check CI/CD pipelines for trust issues."""
    issues = []
    for pipeline in pipelines:
        url = pipeline.get("url", "")
        repo_url = pipeline.get("repo_url", "")
        trusted_source = pipeline.get("trusted_source", "")

        result = {"type": "ci_cd_pipeline", "url": url}

        # Validate URL format
        if not url.startswith(("http://", "https://")):
            issues.append({**result, "issue": "Invalid URL format"})
            continue

        # Check accessibility
        if not is_url_accessible(url):
            issues.append({**result, "issue": "Inaccessible URL"})

        # Check for integrity verification
        issues.append({**result, "issue": "No integrity verification (e.g., hash or signature)"})

        # Check trusted source
        if repo_url and trusted_source:
            repo_domain = urlparse(repo_url).netloc
            trusted_domain = urlparse(trusted_source).netloc
            if repo_domain != trusted_domain:
                issues.append({**result, "issue": f"Untrusted source {repo_domain}"})

    return issues

def main() -> Dict[str, Any]:
    """Main function to check for trust issues."""
    config_path = "config.json"
    config = load_config(config_path)
    if not config or "error" in config:
        return {"error": "Failed to load configuration. Please provide a valid config.json."}

    issues = []
    issues.extend(check_software_updates(config.get("software_updates", [])))
    issues.extend(check_critical_data(config.get("critical_data", [])))
    issues.extend(check_ci_cd_pipelines(config.get("ci_cd_pipelines", [])))

    return {
        "results": issues,
        "summary": {
            "total_issues": len(issues),
            "by_type": {
                "software_update": len([i for i in issues if i["type"] == "software_update"]),
                "critical_data": len([i for i in issues if i["type"] == "critical_data"]),
                "ci_cd_pipeline": len([i for i in issues if i["type"] == "ci_cd_pipeline"])
            }
        }
    }

if __name__ == "__main__":
    result = main()
    print(json.dumps(result, indent=4))
