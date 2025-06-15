import os
import re
import ast
import json

class LoggingMonitorChecker:
    def __init__(self, directory):
        self.directory = directory
        self.issues = []
        self.logging_import_pattern = re.compile(r'import\s+logging\b')
        self.log_usage_pattern = re.compile(r'\blogging\.(debug|info|warning|error|exception)\b')
        self.critical_functions = [
            'login', 'authenticate', 'authorize', 'password', 'session',
            'create_user', 'delete_user', 'update_user', 'access_resource'
        ]
        self.monitoring_libs = ['prometheus_client', 'statsd', 'opentelemetry']

    def check_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
        except Exception as e:
            self.issues.append({
                "file": file_path,
                "issue": "Unable to read file",
                "details": str(e),
                "severity": "error"
            })
            return

        # Check for logging module import
        has_logging_import = bool(self.logging_import_pattern.search(content))
        if not has_logging_import:
            self.issues.append({
                "file": file_path,
                "issue": "No logging module imported",
                "severity": "warning"
            })

        # Parse the file to analyze its AST
        try:
            tree = ast.parse(content)
        except SyntaxError:
            self.issues.append({
                "file": file_path,
                "issue": "Invalid Python syntax",
                "details": "Cannot analyze due to syntax errors",
                "severity": "error"
            })
            return

        # Check for logging usage in critical functions or error handling
        for node in ast.walk(tree):
            # Check function definitions for critical operations
            if isinstance(node, ast.FunctionDef):
                if any(keyword in node.name.lower() for keyword in self.critical_functions):
                    log_found = False
                    for body_node in ast.walk(node):
                        if isinstance(body_node, ast.Call) and isinstance(body_node.func, ast.Attribute):
                            if body_node.func.attr in ('debug', 'info', 'warning', 'error', 'exception'):
                                if isinstance(body_node.func.value, ast.Name) and body_node.func.value.id == 'logging':
                                    log_found = True
                    if not log_found:
                        self.issues.append({
                            "file": file_path,
                            "issue": "Critical function lacks logging",
                            "details": f"Function '{node.name}'",
                            "severity": "warning"
                        })

            # Check for try-except blocks without logging
            if isinstance(node, ast.Try):
                has_logging_in_except = False
                for handler in node.handlers:
                    for handler_node in ast.walk(handler):
                        if isinstance(handler_node, ast.Call) and isinstance(handler_node.func, ast.Attribute):
                            if handler_node.func.attr in ('debug', 'info', 'warning', 'error', 'exception'):
                                if isinstance(handler_node.func.value, ast.Name) and handler_node.func.value.id == 'logging':
                                    has_logging_in_except = True
                if not has_logging_in_except:
                    self.issues.append({
                        "file": file_path,
                        "issue": "Try-except block lacks exception logging",
                        "details": f"At line {node.lineno}",
                        "severity": "warning"
                    })

        # Check for monitoring library imports
        has_monitoring = any(lib in content for lib in self.monitoring_libs)
        if not has_monitoring:
            self.issues.append({
                "file": file_path,
                "issue": "No monitoring libraries detected",
                "details": "Consider adding Prometheus, StatsD, or OpenTelemetry",
                "severity": "info"
            })

    def scan_directory(self):
        if not os.path.isdir(self.directory):
            self.issues.append({
                "file": self.directory,
                "issue": "Invalid directory path",
                "severity": "error"
            })
            return

        python_files_found = False
        for root, _, files in os.walk(self.directory):
            for file in files:
                if file.endswith('.py'):
                    python_files_found = True
                    file_path = os.path.join(root, file)
                    self.check_file(file_path)

        if not python_files_found:
            self.issues.append({
                "file": self.directory,
                "issue": "No Python files found",
                "severity": "error"
            })

    def generate_report(self):
        report = {
            "directory": self.directory,
            "files_scanned": len([issue for issue in self.issues if issue["file"] != self.directory]),
            "issues_found": len(self.issues),
            "issues": self.issues,
            "summary": {
                "error": len([issue for issue in self.issues if issue["severity"] == "error"]),
                "warning": len([issue for issue in self.issues if issue["severity"] == "warning"]),
                "info": len([issue for issue in self.issues if issue["severity"] == "info"])
            }
        }
        
        if not self.issues:
            report["status"] = "success"
            report["message"] = "No issues found. Logging and monitoring appear adequate."
        else:
            report["status"] = "issues_found"
            report["message"] = "Insufficient logging and monitoring issues found."
        
        return report

def main():
    # Prompt user for directory path
    print("Please enter the path to the directory containing Python code to analyze:")
    directory = input().strip()
    
    # Create checker instance and run analysis
    checker = LoggingMonitorChecker(directory)
    checker.scan_directory()
    report = checker.generate_report()
    print(json.dumps(report, indent=4))

if __name__ == "__main__":
    main()
