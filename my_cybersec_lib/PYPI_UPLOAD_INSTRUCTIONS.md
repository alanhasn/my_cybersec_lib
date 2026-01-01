# PyPI Upload Instructions

## Prerequisites

1. Make sure you have Python installed and accessible
2. Install build tools:
   ```bash
   pip install --upgrade build twine
   ```

## Build the Package

Navigate to the `my_cybersec_lib` directory and run:

```bash
python -m build
```

This will create:
- `dist/SecureTool-2.1.0-py3-none-any.whl` (wheel distribution)
- `dist/SecureTool-2.1.0.tar.gz` (source distribution)

## Upload to TestPyPI (Recommended First)

1. Create an account on [TestPyPI](https://test.pypi.org/) if you don't have one
2. Create an API token at https://test.pypi.org/manage/account/token/
3. Upload to TestPyPI:
   ```bash
   python -m twine upload --repository testpypi dist/*
   ```
4. Test the installation:
   ```bash
   pip install --index-url https://test.pypi.org/simple/ SecureTool
   ```

## Upload to PyPI

1. Make sure you have a PyPI account
2. Create an API token at https://pypi.org/manage/account/token/
3. Upload to PyPI:
   ```bash
   python -m twine upload dist/*
   ```

## Alternative: Use the Build Script

You can also use the provided script:

```bash
# Build only
python build_and_upload.py

# Build and upload to TestPyPI
python build_and_upload.py --test --upload

# Build and upload to PyPI
python build_and_upload.py --upload
```

## Notes

- The package version is set to `2.1.0` in `setup.py`
- Make sure all dependencies are listed in `setup.py` and `requirement.txt`
- Test the package locally before uploading:
  ```bash
  pip install dist/SecureTool-2.1.0-py3-none-any.whl
  ```

## Troubleshooting

- If you get authentication errors, make sure you're using an API token, not your password
- If the package name already exists, you'll need to increment the version number
- Check that all required files are included in the package

