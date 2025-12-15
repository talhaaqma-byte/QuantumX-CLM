# Backend Tests

This directory contains unit and integration tests for the QuantumX-CLM backend.

## Structure

```
tests/
├── __init__.py
├── auth/
│   ├── __init__.py
│   └── core/
│       ├── __init__.py
│       └── test_jwt_utils.py  # JWT utilities tests (35 tests)
└── README.md
```

## Running Tests

### Prerequisites

Set up a virtual environment and install dependencies:

```bash
cd /home/engine/project
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt
```

### Run All Tests

```bash
cd backend
pytest tests/ -v
```

### Run Specific Test File

```bash
cd backend
pytest tests/auth/core/test_jwt_utils.py -v
```

### Run Specific Test Class

```bash
cd backend
pytest tests/auth/core/test_jwt_utils.py::TestTokenCreation -v
```

### Run Specific Test

```bash
cd backend
pytest tests/auth/core/test_jwt_utils.py::TestTokenCreation::test_create_access_token_basic -v
```

### Run with Coverage

```bash
cd backend
pytest tests/ --cov=backend --cov-report=html
```

## Test Configuration

Test configuration is in `backend/pytest.ini`:

- Test discovery patterns
- Default options
- Test markers (unit, integration, slow)

## Test Conventions

- **Test files**: `test_*.py`
- **Test classes**: `Test*`
- **Test functions**: `test_*`
- **Fixtures**: Defined in `conftest.py` files
- **Markers**: Use pytest markers for categorization

## JWT Utilities Tests

Location: `tests/auth/core/test_jwt_utils.py`

**Coverage:** 35 tests covering:
- Token creation (access and refresh)
- Token verification and validation
- Expiration handling
- Custom claims
- Error handling
- Edge cases
- Integration scenarios

**Test Results:**
```
35 passed in ~13 seconds
```

## Writing Tests

### Example Test Structure

```python
import pytest
from backend.module import function_to_test

class TestFeature:
    """Tests for specific feature."""
    
    def test_basic_functionality(self):
        """Test basic functionality."""
        result = function_to_test()
        assert result == expected_value
    
    def test_error_handling(self):
        """Test error handling."""
        with pytest.raises(ExpectedException):
            function_to_test(invalid_input)
```

### Best Practices

1. **Descriptive names**: Test names should clearly describe what is being tested
2. **Arrange-Act-Assert**: Structure tests in three phases
3. **One assertion per test**: Keep tests focused (when possible)
4. **Use fixtures**: Share common setup code with fixtures
5. **Test edge cases**: Include boundary conditions and error cases
6. **Keep tests fast**: Mock external dependencies
7. **Independent tests**: Tests should not depend on each other

## Continuous Integration

Tests are automatically run in CI/CD pipelines on:
- Pull requests
- Commits to main branch
- Scheduled runs

## Test Coverage Goals

- **Target**: 80%+ code coverage
- **Critical paths**: 100% coverage for authentication and security code
- **New features**: All new code should include tests

## Adding New Tests

When adding new tests:

1. Create test file matching the module structure
2. Follow naming conventions
3. Add appropriate test markers
4. Include docstrings
5. Test both success and error cases
6. Update this README if adding new test categories

## Troubleshooting

### Tests fail with import errors

Ensure you're running from the `backend` directory and have the virtual environment activated.

### Tests are slow

Use pytest markers to skip slow tests during development:
```bash
pytest tests/ -v -m "not slow"
```

### Database tests fail

Ensure test databases are set up and environment variables are configured.

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-asyncio](https://pytest-asyncio.readthedocs.io/)
- Project documentation: `/home/engine/project/docs/`
