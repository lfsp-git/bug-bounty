#!/usr/bin/env python3
"""Hunt3r Code Style Checker - Manual compliance verification."""
import os
import re
import sys
from pathlib import Path

class StyleChecker:
    """Check code style compliance without external tools."""
    
    ISSUES = []
    PYTHON_DIR = Path(".")
    
    def __init__(self):
        self.files_checked = 0
        self.issues_found = 0
    
    def check_all_python_files(self):
        """Check all .py files in project."""
        python_files = list(self.PYTHON_DIR.rglob("*.py"))
        python_files = [f for f in python_files if ".git" not in str(f) and "__pycache__" not in str(f)]
        
        print(f"Checking {len(python_files)} Python files...\n")
        
        for filepath in python_files:
            self.check_file(filepath)
        
        self.print_report()
    
    def check_file(self, filepath):
        """Check single Python file."""
        self.files_checked += 1
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            self.check_syntax(filepath, content)
            self.check_line_length(filepath, lines)
            self.check_bare_excepts(filepath, lines)
            self.check_string_formatting(filepath, content)
            self.check_trailing_whitespace(filepath, lines)
            self.check_import_sorting(filepath, lines)
        except Exception as e:
            print(f"Error checking {filepath}: {e}")
    
    def check_syntax(self, filepath, content):
        """Verify Python syntax."""
        try:
            compile(content, str(filepath), 'exec')
        except SyntaxError as e:
            self.log_issue(str(filepath), e.lineno, f"Syntax error: {e.msg}")
    
    def check_line_length(self, filepath, lines):
        """Check for lines exceeding 100 characters."""
        for i, line in enumerate(lines, 1):
            if len(line.rstrip()) > 100:
                # Exclude comments-only lines and URLs
                if not line.strip().startswith('#') and 'http' not in line:
                    self.log_issue(str(filepath), i, f"Line too long ({len(line)} chars)")
    
    def check_bare_excepts(self, filepath, lines):
        """Check for bare except clauses."""
        for i, line in enumerate(lines, 1):
            if re.search(r'except\s*:\s*$', line.rstrip()):
                self.log_issue(str(filepath), i, "Bare except clause (use specific exception types)")
    
    def check_string_formatting(self, filepath, content):
        """Check for old-style string formatting."""
        # Look for .format() calls (prefer f-strings)
        for i, line in enumerate(content.split('\n'), 1):
            if '.format(' in line and 'f"' not in line and "f'" not in line:
                if not line.strip().startswith('#'):
                    self.log_issue(str(filepath), i, "Use f-strings instead of .format()")
    
    def check_trailing_whitespace(self, filepath, lines):
        """Check for trailing whitespace."""
        for i, line in enumerate(lines, 1):
            if line != line.rstrip():
                self.log_issue(str(filepath), i, "Trailing whitespace")
    
    def check_import_sorting(self, filepath, lines):
        """Check if imports are organized (stdlib, 3rd-party, local)."""
        import_groups = {'stdlib': [], '3rd_party': [], 'local': []}
        in_imports = False
        last_group = None
        
        stdlib_modules = {'os', 'sys', 'json', 'logging', 'time', 'threading', 'math', 
                         're', 'csv', 'xml', 'datetime', 'typing', 'pathlib', 'subprocess'}
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('import ') or line.startswith('from '):
                in_imports = True
                
                if line.startswith('from .'):
                    group = 'local'
                elif any(line.startswith(f'{mod}') or line.startswith(f'from {mod}') 
                        for mod in stdlib_modules):
                    group = 'stdlib'
                elif line.startswith(('from core', 'from recon', 'from config')):
                    group = 'local'
                else:
                    group = '3rd_party'
                
                if last_group and last_group != 'local' and group == 'stdlib':
                    self.log_issue(str(filepath), i, "Import groups not properly ordered")
                
                last_group = group
            elif in_imports and line and not line.startswith(('import', 'from')):
                in_imports = False
                last_group = None
    
    def log_issue(self, filepath, lineno, message):
        """Log a style issue."""
        self.issues_found += 1
        rel_path = filepath.replace(str(self.PYTHON_DIR) + '/', '')
        self.ISSUES.append(f"{rel_path}:{lineno}: {message}")
    
    def print_report(self):
        """Print final report."""
        print("\n" + "="*60)
        print(f"Style Check Report")
        print("="*60)
        print(f"Files checked: {self.files_checked}")
        print(f"Issues found: {self.issues_found}")
        
        if self.ISSUES:
            print("\nStyle Issues:\n")
            for issue in self.ISSUES[:20]:  # Show first 20
                print(f"  {issue}")
            
            if len(self.ISSUES) > 20:
                print(f"\n  ... and {len(self.ISSUES)-20} more issues")
        else:
            print("\n✅ No style issues found!")
        
        print("="*60 + "\n")
        
        return 0 if self.issues_found == 0 else 1


if __name__ == "__main__":
    checker = StyleChecker()
    sys.exit(checker.check_all_python_files())
