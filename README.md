# dmsecrets

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/choco-technologies/dmsecrets/actions/workflows/ci.yml/badge.svg)](https://github.com/choco-technologies/dmsecrets/actions/workflows/ci.yml)

A store of secrets - passwords, keys, tokens - in encrypted vaults, for
[DMOD](https://github.com/choco-technologies/dmod).

## Description

A **vault** is a file at a path the caller chooses, holding named records
encrypted (AES-256-GCM, key from a passphrase by PBKDF2) with dmcrypto. A
program can open several vaults - one per library, per purpose, per place - and
a library gives the path of its own or none: the path then comes from the
environment (`DMSECRETS_<DOMAIN>_PATH`, then `DMSECRETS_PATH`). A vault can
unlock itself through a passphrase provider the caller supplies. See
[docs/api-reference.md](docs/api-reference.md) and the file format in
[docs/format.md](docs/format.md).

**Status:** implemented and tested (20 steps: records, unlocking, a wrong
passphrase, a tampered file, a write cut short, a new passphrase, the
passphrase provider, limits). The key derivation is 20000 PBKDF2-HMAC-SHA256
iterations; a vault holds 4096 bytes of records.

## Building

### Using CMake

```bash
mkdir -p build
cd build
cmake ..
cmake --build .
```

Pass `-DDMOD_DIR=/path/to/local/dmod` to build against a local dmod checkout
instead of fetching `develop` from GitHub.

### Using Make

```bash
make DMOD_MODE=DMOD_MODULE DMOD_DIR=/path/to/dmod
```

## Testing

Tests are built automatically alongside the module (see `tests/`). Once built,
run them with `ctest`:

```bash
cd build
ctest --output-on-failure
```

`ctest` installs the test module's dependencies with `dmf-get` and then runs
it through `dmod_loader`. To run it manually instead:

```bash
export DMOD_DMF_DIR=$(pwd)/build/dmf
dmf-get install -d ${DMOD_DMF_DIR}/test_dmsecrets-local.dmd -y
dmod_loader build/dmf/test_dmsecrets.dmf
```

## Usage

<TBD>

This library module provides functions that can be used by other modules:

```c
#include "dmsecrets.h"
```

## API

| Function | Description |
|----------|-------------|
| `dmsecrets_create()` | Create a new `dmsecrets_t` instance. |
| `dmsecrets_destroy()` | Destroy an instance created by `_create()`. |
| `dmsecrets_is_valid()` | Check whether a handle is a valid instance. |

See [include/dmsecrets.h](include/dmsecrets.h) for the full
declarations and [docs/api-reference.md](docs/api-reference.md) for the
complete reference.

## Documentation

See the `docs/` directory:

- **[api-reference.md](docs/api-reference.md)** - Complete API documentation

View documentation using `dmf-man dmsecrets`.
## Project Structure

```
dmsecrets/
├── docs/              # Documentation (markdown format)
├── include/           # Public headers
│   └── dmsecrets.h
├── src/
│   └── dmsecrets.c
├── tests/
│   ├── CMakeLists.txt
│   └── dmsecrets_test.c
├── CMakeLists.txt
├── Makefile
├── dmsecrets.dmr
└── manifest.dmm
```

## Author

Patryk Kubiak

## License

MIT
