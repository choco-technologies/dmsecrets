# secrets

The secrets of the shell, on dmsecrets: encrypted vaults of named records.

```
secrets [-f FILE] [-d DOMAIN] COMMAND [ARGS]
  create               make a new vault (asks for its passphrase twice)
  list [PREFIX]        the names of the records
  get [-x] NAME        a value as text (-x: in hex, for binary values)
  set NAME [VALUE]     store a record; without VALUE it asks for it (not echoed)
  delete NAME          remove a record
  passwd               change the passphrase
  info                 where the vault is, how many records
```

The vault is `FILE`, else `DMSECRETS_<DOMAIN>_PATH` (with `-d DOMAIN`), else
`DMSECRETS_PATH`:

```
> export DMSECRETS_PATH=/mnt/sd/secrets.vault
> secrets create
New vault - passphrase:
Again:
created
> secrets set wifi/Home
Passphrase:
Value:
> secrets list wifi/
wifi/Home
```

The passphrase is asked for (not echoed) when the vault needs it. Creating a
vault needs an entropy source for dmcrypto (its driver's `entropy=`).
