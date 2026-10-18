#ifndef DMSECRETS_TYPES_H
#define DMSECRETS_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * Types of dmsecrets - a store of secrets (passwords, keys, tokens) in
 * encrypted vaults.
 *
 * A VAULT is one file at a path of the caller's choosing, holding named
 * records, encrypted with a key derived from a passphrase (see
 * docs/format.md). A program may open several vaults - one per library, per
 * purpose, per place (the SD card, a USB stick) - and each library gives the
 * path of its own, or none: then the path comes from the environment.
 */

/* ---- Limits ---- */

#define DMSECRETS_NAME_MAX      64      /**< A record's name, without the terminator ("wifi/Home Network") */
#define DMSECRETS_VALUE_MAX     1024    /**< A record's value, in bytes (text or binary) */
#define DMSECRETS_DOMAIN_MAX    32      /**< A vault's domain name (see dmsecrets_config_t.domain) */

/* ---- Results: 0 or a negative errno-compatible code ----
 *
 * -EINVAL    a bad argument (NULL, a name with a '\0' or too long, a bad domain)
 * -ENOENT    no vault path is known (none given, none in the environment), the
 *            vault does not exist (and DMSECRETS_OPEN_CREATE is not set), or no
 *            such record
 * -EACCES    the vault is locked, or the passphrase is wrong, or the vault has
 *            been tampered with (an authenticated encryption cannot tell these
 *            apart)
 * -EBADMSG   the file is not a vault, or of a version this library does not know
 * -EBUSY     the vault is already open (a vault is open once per system)
 * -EROFS     the vault was opened DMSECRETS_OPEN_READONLY
 * -ENOSPC    the buffer is too small, or the vault is full
 * -EFBIG     a value over DMSECRETS_VALUE_MAX
 * -ENODEV    no entropy source (dmcrypto_set_entropy): a vault cannot be written
 * -EIO       the storage failed
 * -ENOMEM    no memory
 */

/* ---- Opening ---- */

#define DMSECRETS_OPEN_CREATE   (1u << 0)   /**< A missing vault is created (at the first unlock) */
#define DMSECRETS_OPEN_READONLY (1u << 1)   /**< No record can be changed */

/**
 * @brief Asks for the passphrase when the vault needs it.
 *
 * Fills passphrase (size bytes at most) and sets *length. creating is true when
 * the vault is new and this passphrase will be its first (a provider that asks a
 * person asks twice). A return of 0 is "here it is"; a negative errno is passed
 * to the caller of the operation that needed the unlock. The function and its
 * context must stay valid while the vault is open; it must be a plain function
 * of a module (not an entry in a table of initialized data: the dmod loader does
 * not relocate those).
 */
typedef int (*dmsecrets_passphrase_fn_t)(void* context, bool creating, void* passphrase, size_t size, size_t* length);

/**
 * @brief How a vault is opened. All zero = the defaults; fields added later come
 * at the end, and zero will stay the default.
 */
typedef struct
{
    /** Where the vault is. NULL: not given by the caller - see dmsecrets_resolve_path(). */
    const char*                 path;

    /** What the vault is for: "wifi", "tls", ... NULL: none. Only used to find the path in the
     *  environment (DMSECRETS_<DOMAIN>_PATH), so that an application's vaults can be moved
     *  without changing the libraries that open them. Letters, digits, '_' and '-'. */
    const char*                 domain;

    /** DMSECRETS_OPEN_* */
    uint32_t                    flags;

    /** NULL: the caller unlocks with dmsecrets_unlock(). Otherwise the vault unlocks itself, the
     *  first time an operation needs it, by asking this function. */
    dmsecrets_passphrase_fn_t   passphrase_provider;
    void*                       provider_context;
} dmsecrets_config_t;

/* ---- Handle ---- */

typedef struct dmsecrets* dmsecrets_t;      /**< An open vault */

#endif /* DMSECRETS_TYPES_H */
