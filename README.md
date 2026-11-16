# JSON-RPC 2.0 Fuzzer

A configurable, property-based fuzzer for testing JSON-RPC 2.0 APIs. It combines **pytest** and **Hypothesis** to generate varied method parameters, exercise API endpoints, and check whether access controls are enforced for users with different privilege levels.

The project is intended for API security testing and robustness testing in a controlled environment. It helps uncover unexpected behavior caused by malformed or unusual parameter values, as well as authorization issues in methods that should be restricted.

## Key Features

- **Method-based fuzzing.** Each JSON-RPC method is described by a specification file in `jsonrpc_methods/`. Hypothesis uses these specifications to generate test inputs.
- **Property-based test generation.** By default, the fuzzer generates up to 1,000 examples for each method.
- **Authorization checks.** A separate test profile can be used to verify that a low-privilege user cannot call methods that require additional permissions.
- **Request traces.** During fuzzing, JSON-RPC requests are recorded in VCR-style logs to help investigate test cases and unexpected API behavior.
- **Specification generator.** `generate_fuzz_method.py` creates an initial method specification from a real JSON-RPC request, reducing the amount of manual setup.
- **Test reports.** The runner produces JUnit results and an Allure report.

## How the Tests Work

The test suite has two main test flows:

| Test | Purpose | Authentication profile |
| --- | --- | --- |
| `test_fuzz_method` | Fuzzes the configured JSON-RPC methods with generated parameter values. Each method is tested with up to `MAX_EXAMPLES` examples. | Main profile (`AUTH_*`), or anonymous requests when it is not configured. |
| `test_permissions` | Checks method access using a user account without the required privileges. The check is performed for methods whose specifications enable permission checking. | Low-privilege profile (`NOPERM_*`). |

For a full run, configure two test accounts:

1. **A privileged user** for the main fuzzing profile. This account should be able to access the methods being tested, so that fuzzing exercises their input handling rather than failing only because of missing permissions.
2. **A low-privilege user** for the permission checks. This account should not have access to most protected methods.

Some methods may intentionally be public. Review their specifications and permission expectations rather than assuming that every method must be denied.

The main authentication profile is optional: without it, the fuzzing test runs anonymously. The low-privilege profile is also optional, but the permission test is skipped when it is not configured.

## Requirements

- Python **3.15 or newer**
- [`uv`](https://docs.astral.sh/uv/) for dependency and project management
- Bash to run `run.sh`
- [Allure Commandline](https://allurereport.org/docs/install/) to generate the HTML report

The Python dependencies are declared in `pyproject.toml`, including `pytest`, `hypothesis`, `requests`, and `allure-pytest`.

## Installation

Clone the repository and install the project dependencies:

```bash
git clone https://github.com/slowy19/jsonrpc-fuzzer.git
cd jsonrpc-fuzzer
uv sync
```

Create a local environment file from the example:

```bash
cp .env.example .env
```

Edit `.env` before running the tests. Do not commit real credentials or access tokens.

## Configuration

The runner reads its configuration from `.env`.

### API endpoint

Set the API server origin and the JSON-RPC endpoint path:

```dotenv
ORIGIN=http://127.0.0.1:8080
API_PATH=/api
```

The final API URL is built by concatenating `ORIGIN` and `API_PATH`. `API_PATH` defaults to `/api` when omitted.

### Main authentication profile

The main profile is used by `test_fuzz_method`. Configure either static authentication or a login flow.

**Option A: static header or cookie**

```dotenv
AUTH_HEADER='Authorization: Bearer YOUR_TOKEN'
# Alternatively, or in addition to a header:
AUTH_COOKIE='access_token=YOUR_TOKEN'
```

**Option B: login flow**

```dotenv
AUTH_LOGIN_URL=http://127.0.0.1:8080/login
AUTH_LOGIN=privileged_user
AUTH_PASSWORD=privileged_password
AUTH_TOKEN_JSON_PATH=token
AUTH_TOKEN_HEADER='Authorization: Bearer {token}'
# Or use a cookie:
# AUTH_TOKEN_COOKIE='access_token={token}'
AUTH_LOGIN_BODY_TEMPLATE='{"username":"{login}","password":"{password}"}'
```

`AUTH_TOKEN_JSON_PATH` is a dot-separated path to the token in the login response. For example, use `data.access_token` if the response contains `{ "data": { "access_token": "..." } }`. The login body template is optional. When provided, the login request uses that JSON body with `{login}` and `{password}` placeholders; otherwise, the login flow uses HTTP Basic authentication.

### Low-privilege authentication profile

Configure the second profile in the same way, using the `NOPERM_` prefix:

```dotenv
NOPERM_LOGIN_URL=http://127.0.0.1:8080/login
NOPERM_LOGIN=user_without_permissions
NOPERM_PASSWORD=user_password
NOPERM_TOKEN_JSON_PATH=token
NOPERM_TOKEN_HEADER='Authorization: Bearer {token}'
NOPERM_LOGIN_BODY_TEMPLATE='{"username":"{login}","password":"{password}"}'
```

You can also use `NOPERM_HEADER` or `NOPERM_COOKIE` for static credentials.

> **Important:** For each profile, choose either static header/cookie authentication or the login flow. Do not leave static `*_HEADER`/`*_COOKIE` values enabled at the same time as `*_LOGIN_URL`; the runner treats that combination as a configuration error. The example file illustrates the available options, so comment out the alternatives you are not using.

### Fuzzing options

The runner supports the following environment setting:

| Variable | Default | Description |
| --- | --- | --- |
| `MAX_EXAMPLES` | `1000` | Maximum number of Hypothesis examples generated for each fuzzed method. |

The runner also passes `--no-shrink` to pytest. This disables Hypothesis shrinking of failing examples, which can improve execution performance but means failures are not automatically reduced to smaller inputs.

## Running the Tests

After configuring `.env` and making sure the target API is available, run:

```bash
bash run.sh
```

The script loads `.env`, builds the API URL, configures the authentication profiles, and runs pytest through `uv`. It also clears the existing `reports/` directory before starting a new run.

Generated reports are placed in:

- `reports/junit.xml` — JUnit test results
- `reports/allure-results/` — raw Allure results
- `reports/allure-report/` — generated HTML Allure report

The Allure report is generated at the end of the run. Make sure the Allure Commandline executable is available in your `PATH`.

## Method Specifications

Every method to be fuzzed is described by a JSON specification file under `jsonrpc_methods/`. Method specifications can be grouped into subdirectories to keep the API organized.

A specification describes the method name and the expected shape of its `params`. For example:

```json
{
  "method": "user.create",
  "params": {
    "type": "object",
    "check_permissions": true,
    "fuzz": true,
    "fields": {
      "name": { "type": "string", "fuzz": true },
      "age": { "type": "integer", "fuzz": true },
      "tags": {
        "type": "array",
        "fuzz": true,
        "items": { "type": "string", "fuzz": true }
      }
    }
  }
}
```

The `fuzz` option enables value generation and, for object parameters, can add extra unexpected keys. `check_permissions` marks the method for permission checking by the test suite. Specifications can be edited manually to add constraints that cannot be inferred from a single example request.

## Generating Method Specifications

`generate_fuzz_method.py` creates initial JSON specification files from real JSON-RPC 2.0 request examples.

### Example input

The input must be a single JSON-RPC request object:

```json
{
  "jsonrpc": "2.0",
  "method": "user.create",
  "params": {
    "name": "John",
    "age": 30,
    "tags": ["a", "b"]
  },
  "id": 1
}
```

### Usage

Generate a specification from one request:

```bash
python generate_fuzz_method.py request.json
```

Generate specifications from all `.json` files in a directory:

```bash
python generate_fuzz_method.py ./examples/ -o jsonrpc_methods
```

Search subdirectories recursively:

```bash
python generate_fuzz_method.py ./examples/ -o jsonrpc_methods -r
```

### Generator behavior

- The input can be a single `.json` file or a directory containing `.json` files.
- The default output directory is `jsonrpc_methods/`; use `-o` / `--output` to choose another directory.
- Use `-r` / `--recursive` to include JSON files in nested directories.
- The output filename is derived from the RPC method name. Characters outside `A-Z`, `a-z`, `0-9`, `_`, and `-` are replaced with underscores. For example, `user.create` becomes `user_create.json`.
- The original method name, including dots, is preserved in the generated file's `method` field.
- Missing output directories are created automatically, including parent directories.
- Existing output files are overwritten with a warning.
- The input request `id` is ignored; the fuzzer generates request IDs during testing.
- If `params` is missing or `null`, the generator creates a parameter template without `fields` and prints a warning.
- Invalid JSON, a missing or empty `method`, or a `params` value other than an object, array, or `null` causes generation to fail for that input file.
- The generator expects one request object per input file. A top-level JSON array (a JSON-RPC batch) is not accepted; generate a specification for each request separately.

### Generator limitations

The generated specification is an initial structural template, not a complete API schema. The following constraints are not inferred automatically and should be added manually when needed:

- `enum`
- `min` / `max`
- `min_items` / `max_items`
- `starts_with` / `ends_with`
- `value`
- `regex`
- `optional`

For arrays, the generator infers the item specification from the **first element** and assumes the array is homogeneous. Make sure this matches the API contract.

JSON integers and floating-point numbers are inferred separately: `1` becomes an `integer`, while `1.0` becomes a `float`.

### Generator defaults

The generator uses the following defaults, which can be changed in `generate_fuzz_method.py` if required:

| Setting | Default | Meaning |
| --- | --- | --- |
| `check_permissions` | `true` | Enables permission checking for object parameters. |
| `fuzz` | `true` | Enables fuzzing for parameter objects and their inferred fields. |
| `fuzz_envelope` | `false` | Disabled by default. When enabled in the generator, the validator can mutate the JSON-RPC envelope (`jsonrpc`, `method`, and `id`) and add unexpected envelope keys. |
| `batch` | `false` | Does not wrap a request in a JSON-RPC batch array by default. |

When `fuzz_envelope` or `batch` is `false`, the corresponding option is omitted from the generated specification.

## Repository Structure

```text
|
├── examples/               # Example JSON-RPC request bodies
├── fuzz_dicts/             # Fuzzing dictionaries
├── jsonrpc_fuzzer/         # Fuzzer implementation
├── jsonrpc_methods/        # Per-method fuzzing specifications
├── tests/                  # pytest test suite
├── generate_fuzz_method.py # Specification generator
├── run.sh                  # Test runner and report generation
├── .env.example            # Example configuration
├── pyproject.toml          # Python project and dependencies
└── uv.lock                 # Locked dependency versions
```

## Safety Notice

Only run this fuzzer against systems that you own or are explicitly authorized to test. Fuzzing intentionally sends unexpected and potentially invalid inputs to the target API and may affect availability or modify test data. Use a dedicated test environment and non-production accounts whenever possible.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.