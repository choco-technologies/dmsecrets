# dmsecrets - API reference

Declared in `include/dmsecrets.h`; types, limits and results in
`include/dmsecrets_types.h`.

## Vaults

A **vault** is one file, at a path the caller chooses, holding named records
encrypted under a key derived from a passphrase. A program can open as many
vaults as it likes (one per library, per purpose, per place - the SD card, a
USB stick); a vault is open once per system (`-EBUSY` the second time).

## Where a vault is

`dmsecrets_resolve_path(path, domain, ...)` gives the first of:

1. `path` - when the caller gives one (any `dmsecrets_config_t.path`)
2. `DMSECRETS_<DOMAIN>_PATH` - when the caller names a `domain`
   (`"tls"` -> `DMSECRETS_TLS_PATH`; upper case, `-` as `_`)
3. `DMSECRETS_PATH`

There is no built-in default path: a system that wants one sets
`DMSECRETS_PATH` (e.g. in its boot configuration). A library that has a vault of
its own just names its domain; whoever builds the system decides where that
vault lives, without touching the library.

| Function | |
|---|---|
| `resolve_path` | the path above, without opening anything |
| `open` | opens the vault at the resolved path (`config` may be NULL: all defaults). Reads the header only: the vault is **locked** after it |
| `close` | locks (wipes the key and the records from memory) and frees the handle |
| `get_path` | the path it was opened at |

`dmsecrets_config_t` (zero = defaults): `path`, `domain`, `flags`
(`DMSECRETS_OPEN_CREATE`, `DMSECRETS_OPEN_READONLY`),
`passphrase_provider` + `provider_context`.

## Unlocking

| Function | |
|---|---|
| `unlock` | with a passphrase; for a vault that does not exist yet (`..._OPEN_CREATE`) it creates it with this passphrase |
| `lock` | wipes the key and the records |
| `is_unlocked` | |
| `change_passphrase` | re-encrypts under a new passphrase and a new salt |

With a `passphrase_provider` the vault unlocks itself the first time an
operation needs it, by asking the provider (a console prompt, a key derived
from the device, a service) - so a library can use its vault without knowing how
the passphrase is obtained. Without one, the caller calls `unlock`.

## Records

| Function | |
|---|---|
| `set(name, value, size)` | stores (replaces) a record and writes the vault out before returning |
| `get(name, value, size, &length)` | `length` is the value's size also when `value` is NULL or too small |
| `delete(name)` | |
| `count(prefix, &count)` | how many names start with `prefix` |
| `name_at(prefix, index, name, size)` | the index-th such name, in the order stored |

Names are 1..64 bytes (`/` is the conventional separator: `wifi/Home Network`),
values 0..1024 bytes, text or binary. A prefix lists a family:
`count(vault, "wifi/")`, then `name_at` for each.

## Results

`-EACCES` is "locked, or the passphrase is wrong, or the vault was tampered
with" - authenticated encryption cannot tell these apart, and neither should the
caller's error message. The rest is in `dmsecrets_types.h`.

## Depends on

dmcrypto (AES-GCM, PBKDF2, random bytes), dmosi (locks). Writing a vault needs an entropy
source (`dmcrypto_set_entropy()`, the dmcrypto driver's `entropy=`): without one
`set` / `unlock` of a new vault return `-ENODEV`.
