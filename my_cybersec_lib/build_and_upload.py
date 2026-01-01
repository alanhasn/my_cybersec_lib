"""
Script to build and upload SecureTool package to PyPI.

Usage:
    python build_and_upload.py [--test] [--upload]

Options:
    --test    Upload to TestPyPI instead of PyPI
    --upload  Actually upload (default is dry-run)
"""

import subprocess
import sys
import os
import shutil

def run_command(cmd, check=True):
    """Run a shell command."""
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=check)
    return result

def main():
    # Change to package directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Check if build tools are installed
    try:
        import build
        import twine
    except ImportError:
        print("Installing build tools...")
        run_command([sys.executable, "-m", "pip", "install", "--upgrade", "build", "twine"])
    
    # Clean previous builds
    print("\nCleaning previous builds...")
    for dir_name in ['dist', 'build', '*.egg-info']:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"Removed {dir_name}")
    
    # Build the package
    print("\nBuilding package...")
    run_command([sys.executable, "-m", "build"])
    
    # Check if upload flag is set
    upload = "--upload" in sys.argv
    test_pypi = "--test" in sys.argv
    
    if upload:
        repo = "testpypi" if test_pypi else "pypi"
        print(f"\nUploading to {repo}...")
        run_command([
            sys.executable, "-m", "twine", "upload",
            "dist/*",
            "--repository", repo
        ])
        print(f"\n✅ Package uploaded to {repo}!")
    else:
        print("\n✅ Package built successfully!")
        print("\nTo upload to PyPI, run:")
        print("  python build_and_upload.py --upload")
        print("\nTo upload to TestPyPI first, run:")
        print("  python build_and_upload.py --test --upload")

if __name__ == "__main__":
    main()

