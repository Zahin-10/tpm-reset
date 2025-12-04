# TpmEventLog Unit Tests

This directory contains unit tests for the TpmEventLog package.

## Running Tests

To run all tests, use:

```bash
cd TpmEventLog
python -m tests.run_tests
```

Or from inside the tests directory:

```bash
cd TpmEventLog/tests
python run_tests.py
```

## Verbose Output

For more detailed test output:

```bash
python run_tests.py -v
```

## Running Specific Tests

To run a specific test case or test method:

```bash
# Run a specific test module
python run_tests.py test_tpm_imports

# Run a specific test class
python run_tests.py test_tpm_imports.TestTpm2PyTssImports

# Run a specific test method
python run_tests.py test_tpm_imports.TestTpm2PyTssImports.test_tpm2_pytss_basic_import
```

## Test Files

- `test_tpm_imports.py`: Tests import functionality for TPM modules
- Add more test files as they are created

## Writing New Tests

To add new tests:
1. Create a new file with name starting with `test_`.
2. Extend `unittest.TestCase` class.
3. Add test methods with names starting with `test_`.

Example:

```python
import unittest

class TestNewFeature(unittest.TestCase):
    def test_something(self):
        self.assertTrue(True)
```

## Testing Strategy

These tests are primarily focused on ensuring:
1. Module import functionality works correctly
2. Basic TPM functionality works as expected
3. Core features of the TpmEventLog package work properly 