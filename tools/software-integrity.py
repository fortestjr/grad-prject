import json
import hashlib
import os
import subprocess
import sys
from pathlib import Path
import requests
from packaging import version
import yaml  # pyyaml package needed
import tarfile
import zipfile
import tempfile
import gnupg
import warnings
from datetime import datetime

warnings.filterwarnings('ignore')  # Disable SSL warnings for demo purposes

class SoftwareIntegrityAnalyzer:
    def __init__(self, target_path):
        self.target_path = Path(target_path)
        self.results = {
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "target_path": str(self.target_path),
            "integrity_checks": {}
        }
        self.gpg = gnupg.GPG()

    def analyze(self):
        """Run all integrity checks"""
        self._check_file_integrity()
        self._check_update_mechanisms()
        self._check_ci_cd_integrity()
        self._check_sensitive_data()
        self._check_dependencies()
        self._check_build_process()
        
        return self.results

    def _check_file_integrity(self):
        """Check file hashes and signatures"""
        checks = {}
        
        # Check for common integrity files
        integrity_files = ['SHA256SUMS', 'SHA512SUMS', 'checksums.txt', 'signature.asc']
        found_integrity_files = []
        
        for file in integrity_files:
            if (self.target_path / file).exists():
                found_integrity_files.append(file)
                
        checks['integrity_files_present'] = bool(found_integrity_files)
        checks['found_integrity_files'] = found_integrity_files
        
        # Verify signatures if found
        if 'signature.asc' in found_integrity_files:
            try:
                with open(self.target_path / 'signature.asc', 'rb') as f:
                    verified = self.gpg.verify_file(f, str(self.target_path))
                    checks['gpg_signature_valid'] = verified.valid
                    checks['gpg_signature_trust'] = verified.trust_level is not None and verified.trust_level >= verified.TRUST_FULLY
            except Exception as e:
                checks['gpg_verification_error'] = str(e)
        
        self.results['integrity_checks']['file_integrity'] = checks

    def _check_update_mechanisms(self):
        """Check software update mechanisms for integrity issues"""
        checks = {}
        
        # Common update configuration files
        update_configs = ['update.json', 'updater.ini', 'update.xml', 'appcast.xml']
        found_configs = []
        
        for config in update_configs:
            if (self.target_path / config).exists():
                found_configs.append(config)
                
        checks['update_configs_present'] = bool(found_configs)
        checks['found_update_configs'] = found_configs
        
        # Check for HTTPS usage in update URLs
        insecure_update_urls = []
        secure_update_urls = []
        
        for config_file in found_configs:
            try:
                with open(self.target_path / config_file, 'r') as f:
                    content = f.read()
                    if 'http://' in content:
                        insecure_update_urls.append(f"{config_file}: HTTP URLs found")
                    if 'https://' in content:
                        secure_update_urls.append(f"{config_file}: HTTPS URLs found")
            except Exception as e:
                checks[f'{config_file}_read_error'] = str(e)
                
        checks['insecure_update_urls'] = insecure_update_urls
        checks['secure_update_urls'] = secure_update_urls
        checks['uses_https_for_updates'] = len(secure_update_urls) > 0 and len(insecure_update_urls) == 0
        
        self.results['integrity_checks']['update_mechanisms'] = checks

    def _check_ci_cd_integrity(self):
        """Check CI/CD configuration files for integrity issues"""
        checks = {}
        ci_files = ['.github/workflows', '.gitlab-ci.yml', '.circleci/config.yml', 'azure-pipelines.yml']
        found_ci_files = []
        
        for ci_file in ci_files:
            if (self.target_path / ci_file).exists():
                found_ci_files.append(ci_file)
                
        checks['ci_files_present'] = bool(found_ci_files)
        checks['found_ci_files'] = found_ci_files
        
        # Check for common integrity issues in CI files
        integrity_issues = []
        
        for ci_file in found_ci_files:
            try:
                if ci_file.endswith('.yml') or ci_file.endswith('.yaml'):
                    with open(self.target_path / ci_file, 'r') as f:
                        config = yaml.safe_load(f)
                        
                        # Check for disabled verification steps
                        if isinstance(config, dict):
                            if 'steps' in config:
                                for step in config['steps']:
                                    if 'verify' not in step.get('name', '').lower():
                                        integrity_issues.append(f"{ci_file}: Missing verification step in {step.get('name')}")
                                        
                        # Check for disabled checks
                        if 'skip' in str(config).lower() and 'verify' in str(config).lower():
                            integrity_issues.append(f"{ci_file}: Potential verification skipping")
                            
            except Exception as e:
                checks[f'{ci_file}_parse_error'] = str(e)
                
        checks['ci_integrity_issues'] = integrity_issues
        
        self.results['integrity_checks']['ci_cd_integrity'] = checks

    def _check_sensitive_data(self):
        """Check for sensitive data that should be integrity protected"""
        checks = {}
        sensitive_files = ['secrets.env', 'config.json', 'credentials.xml', '.env']
        found_sensitive_files = []
        unprotected_files = []
        
        for sensitive_file in sensitive_files:
            if (self.target_path / sensitive_file).exists():
                found_sensitive_files.append(sensitive_file)
                # Check if file is in .gitignore
                try:
                    with open(self.target_path / '.gitignore', 'r') as f:
                        gitignore = f.read()
                        if sensitive_file not in gitignore:
                            unprotected_files.append(sensitive_file)
                except FileNotFoundError:
                    unprotected_files.append(sensitive_file)
                except Exception as e:
                    checks['gitignore_read_error'] = str(e)
                    
        checks['sensitive_files_present'] = bool(found_sensitive_files)
        checks['found_sensitive_files'] = found_sensitive_files
        checks['unprotected_sensitive_files'] = unprotected_files
        
        self.results['integrity_checks']['sensitive_data'] = checks

    def _check_dependencies(self):
        """Check dependency management for integrity issues"""
        checks = {}
        dep_files = ['requirements.txt', 'package.json', 'pom.xml', 'build.gradle']
        found_dep_files = []
        integrity_issues = []
        
        for dep_file in dep_files:
            if (self.target_path / dep_file).exists():
                found_dep_files.append(dep_file)
                
                # Check for pinned versions
                try:
                    with open(self.target_path / dep_file, 'r') as f:
                        content = f.read()
                        if '==' not in content and '"' not in content and "'" not in content:
                            integrity_issues.append(f"{dep_file}: Unpinned dependencies detected")
                except Exception as e:
                    checks[f'{dep_file}_read_error'] = str(e)
                    
        checks['dependency_files_present'] = bool(found_dep_files)
        checks['found_dependency_files'] = found_dep_files
        checks['dependency_integrity_issues'] = integrity_issues
        
        self.results['integrity_checks']['dependencies'] = checks

    def _check_build_process(self):
        """Check build process for integrity issues"""
        checks = {}
        build_files = ['Makefile', 'build.sh', 'Dockerfile', 'Jenkinsfile']
        found_build_files = []
        integrity_issues = []
        
        for build_file in build_files:
            if (self.target_path / build_file).exists():
                found_build_files.append(build_file)
                
                # Check for verification steps
                try:
                    with open(self.target_path / build_file, 'r') as f:
                        content = f.read()
                        if 'verify' not in content.lower() and 'check' not in content.lower():
                            integrity_issues.append(f"{build_file}: Missing verification steps in build process")
                except Exception as e:
                    checks[f'{build_file}_read_error'] = str(e)
                    
        checks['build_files_present'] = bool(found_build_files)
        checks['found_build_files'] = found_build_files
        checks['build_integrity_issues'] = integrity_issues
        
        self.results['integrity_checks']['build_process'] = checks

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python software_integrity.py <path_to_analyze>"}, indent=2))
        sys.exit(1)
        
    target_path = sys.argv[1]
    
    if not os.path.exists(target_path):
        print(json.dumps({"error": f"Path does not exist: {target_path}"}, indent=2))
        sys.exit(1)
        
    analyzer = SoftwareIntegrityAnalyzer(target_path)
    results = analyzer.analyze()
    
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()