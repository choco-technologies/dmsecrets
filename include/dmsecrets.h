#ifndef DMSECRETS_H
#define DMSECRETS_H

#include "dmod_types.h"
#include "dmsecrets_defs.h"
#include "dmsecrets_types.h"

/*
 * dmsecrets: a store of secrets in encrypted vaults. See dmsecrets_types.h for
 * the concepts (a vault is a file at a path of the caller's choosing; a program
 * may have several), the limits and the results, and docs/ for the file format.
 *
 * Every function is safe to call from several threads; a vault is serialized
 * by its own lock. The cryptography is dmcrypto's (AES-GCM, PBKDF2, random).
 *
 * Typical use of a library with a vault of its own:
 *
 *     dmsecrets_config_t config = { .domain = "wifi" };    // the path: DMSECRETS_WIFI_PATH
 *     dmsecrets_open(&config, &vault);                     // or DMSECRETS_PATH
 *     dmsecrets_unlock(vault, passphrase, passphrase_size);
 *     dmsecrets_get(vault, "wifi/Home Network", password, sizeof(password), &length);
 */

/**
 * Where a vault would be, without opening it: the first that is given of
 *   1. `path`, when not NULL (and not empty)
 *   2. the environment variable DMSECRETS_<DOMAIN>_PATH, when `domain` is given
 *      (the domain in upper case, '-' as '_': "tls" -> DMSECRETS_TLS_PATH)
 *   3. the environment variable DMSECRETS_PATH
 * There is no built-in default path: a system that wants one sets DMSECRETS_PATH.
 *
 * @return 0 and the path in output, -ENOENT when none of them is set, -ENOSPC when output
 *         is too small, -EINVAL for a bad domain
 */
dmod_dmsecrets_api(1.0, int, _resolve_path, ( const char* path, const char* domain, char* output, size_t output_size ));

/**
 * Opens the vault at the resolved path (dmsecrets_resolve_path of config->path and
 * config->domain). `config` may be NULL: everything is then the default (the path from
 * DMSECRETS_PATH). Opening reads the header only - the vault is LOCKED until
 * dmsecrets_unlock() (or the provider's first use) - so a wrong path or a file that is not
 * a vault is found here.
 *
 * @return 0, -ENOENT (no path, or no vault there without DMSECRETS_OPEN_CREATE), -EBADMSG,
 *         -EBUSY, -EINVAL, -ENOMEM, -EIO
 */
dmod_dmsecrets_api(1.0, int, _open, ( const dmsecrets_config_t* config, dmsecrets_t* vault ));

/**
 * Locks the vault (wipes its key and its records from memory) and frees the handle.
 * Safe with NULL. Everything set is already stored: nothing is lost by closing.
 */
dmod_dmsecrets_api(1.0, void, _close, ( dmsecrets_t vault ));

/**
 * The path the vault was opened at.

 * @return 0, or -ENOSPC when output is too small
 */
dmod_dmsecrets_api(1.0, int, _get_path, ( dmsecrets_t vault, char* output, size_t output_size ));

/**
 * True while the vault's key is in memory.
 */
dmod_dmsecrets_api(1.0, bool, _is_unlocked, ( dmsecrets_t vault ));

/**
 * Unlocks the vault with the passphrase (any bytes, 1 or more). For a vault that does not
 * exist yet (opened with DMSECRETS_OPEN_CREATE) this sets the passphrase and creates it.
 * Deriving the key takes time (PBKDF2 - the iterations are the vault's, chosen when it was
 * created): a second or so on a Cortex-M.
 *
 * @return 0 (also when already unlocked), -EACCES for a wrong passphrase or a damaged vault,
 *         -ENODEV when creating without an entropy source, -EIO
 */
dmod_dmsecrets_api(1.0, int, _unlock, ( dmsecrets_t vault, const void* passphrase, size_t passphrase_size ));

/**
 * Wipes the key and the records from memory; the next operation needs an unlock again
 * (the provider's, when there is one).
 */
dmod_dmsecrets_api(1.0, int, _lock, ( dmsecrets_t vault ));

/**
 * Re-encrypts the vault under a new passphrase (and a new salt). The vault must be unlocked
 * (the provider is asked when there is one).

 * @return 0, -EACCES when locked and unlockable by nobody, -EROFS, -EIO
 */
dmod_dmsecrets_api(1.0, int, _change_passphrase, ( dmsecrets_t vault, const void* passphrase, size_t passphrase_size ));

/**
 * Stores a record, replacing one of that name, and writes the vault out before returning: it
 * is on the storage when this returns 0. A name is a text of 1..DMSECRETS_NAME_MAX bytes;
 * '/' is conventional as a separator ("wifi/Home Network") for dmsecrets_count() / _name_at().
 * A value is 0..DMSECRETS_VALUE_MAX bytes.
 *
 * @return 0, -EACCES (locked), -EROFS, -EFBIG, -ENOSPC (the vault is full), -ENODEV (no entropy
 *         source for the encryption), -EIO, -EINVAL
 */
dmod_dmsecrets_api(1.0, int, _set, ( dmsecrets_t vault, const char* name, const void* value, size_t value_size ));

/**
 * Reads a record. `length` receives the value's size also when value is NULL (to ask how much
 * room is needed) and when it is too small.
 *
 * @return 0, -ENOENT, -ENOSPC (value too small: nothing is copied), -EACCES, -EINVAL
 */
dmod_dmsecrets_api(1.0, int, _get, ( dmsecrets_t vault, const char* name, void* value, size_t value_size, size_t* length ));

/**
 * Removes a record and writes the vault out.

 * @return 0, -ENOENT, -EACCES, -EROFS, -EIO
 */
dmod_dmsecrets_api(1.0, int, _delete, ( dmsecrets_t vault, const char* name ));

/**
 * How many records have a name that starts with prefix (NULL or "": all).

 * @return 0, -EACCES
 */
dmod_dmsecrets_api(1.0, int, _count, ( dmsecrets_t vault, const char* prefix, size_t* count ));

/**
 * The name of the index-th record of those that start with prefix, in the order they were
 * stored (the order is stable until a record is deleted). Together with dmsecrets_count():
 * `for (i = 0; i < count; i++) dmsecrets_name_at(vault, "wifi/", i, ...)`.
 *
 * @return 0, -ENOENT when there is no such index, -ENOSPC when name is too small, -EACCES
 */
dmod_dmsecrets_api(1.0, int, _name_at, ( dmsecrets_t vault, const char* prefix, size_t index, char* name, size_t name_size ));

#endif /* DMSECRETS_H */
