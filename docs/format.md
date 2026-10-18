# The vault file

What `dmsecrets` writes. The implementation follows this; a change of it is a
new `version`.

```
offset  size  field
0       4     magic "DMSV"
4       1     version (1)
5       1     kdf: 1 = PBKDF2-HMAC-SHA256
6       2     reserved (0)
8       4     kdf iterations (little-endian; chosen when the vault is created, e.g. 20000)
12      16    kdf salt (random)
28      4     generation (little-endian; +1 at every write)
32      12    nonce (random, new at every write)
44      4     ciphertext length (little-endian)
48      n     ciphertext: AES-256-GCM of the records
48+n    16    tag
```

- **Key**: `PBKDF2-HMAC-SHA256(passphrase, salt, iterations, 32 bytes)`.
- **AEAD**: AES-256-GCM, a fresh random nonce for every write; the header
  (offsets 0..43 and the length) is the additional authenticated data, so a
  changed header is a failed tag. A wrong passphrase and a changed file both
  fail the tag: `-EACCES`.
- **Records** (inside the ciphertext): a record count, then per record
  `name length (1 byte) | name | value length (2 bytes, LE) | value`, padded
  to a multiple of 64 bytes with random bytes so the size shows the count
  roughly, not exactly.
- **Writing without losing the vault**: the file holds two such slots one after
  the other; a write goes to the slot with the lower generation and only then
  is it the current one. Opening takes the valid slot with the higher
  generation, so a power loss in the middle of a write leaves the previous
  vault whole. (The slots' fixed size - the vault's capacity - is chosen at
  creation; a full vault is `-ENOSPC`.)
- **Nothing in the clear but the header**: not the names, not the count.

What this does not protect against: someone who has the unlocked vault in a
running system (`get` returns the value), and a weak passphrase (PBKDF2 slows a
guess down, nothing more). On a Cortex-M without hardware crypto a key
derivation takes about a second at the iterations above.
