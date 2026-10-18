#define DMOD_ENABLE_REGISTRATION ON
#include "dmod.h"
#include "dmosi.h"
#include "dmcrypto.h"
#include "dmsecrets.h"
#include <errno.h>
#include <string.h>

/*
 * dmsecrets: encrypted vaults of named records. The file format is
 * docs/format.md; the cryptography is dmcrypto's (PBKDF2-HMAC-SHA256,
 * AES-256-GCM, random bytes).
 *
 * The records of an unlocked vault are in memory; every change writes the whole
 * vault into the slot that is not the current one, so a write that is cut
 * short leaves the previous vault whole.
 */

#define FORMAT_MAGIC        "DMSV"
#define FORMAT_VERSION      1
#define KDF_PBKDF2_SHA256   1
#define HEADER_SIZE         48
#define TAG_SIZE            16
#define KEY_SIZE            32
#define SALT_SIZE           16
#define NONCE_SIZE          12
#define CAPACITY_UNIT       64          /* The capacity of a slot is a multiple of this */
#define DEFAULT_CAPACITY    4096        /* Bytes of records a vault holds, chosen at creation */
#define KDF_ITERATIONS      20000
#define PASSPHRASE_MAX      256
#define RECORD_OVERHEAD     3           /* name length (1) + value length (2) */
#define VAULT_MAGIC         0x44535654
#define DEVKEY_NODE         "/dev/devkey"
#define DEVKEY_MAX          64          /* What dmdevfs serves at most */

/* Header offsets */
#define H_MAGIC             0
#define H_VERSION           4
#define H_KDF               5
#define H_CAPACITY          6
#define H_ITERATIONS        8
#define H_SALT              12
#define H_GENERATION        28
#define H_NONCE             32
#define H_LENGTH            44

struct record
{
    char        name[DMSECRETS_NAME_MAX + 1];
    uint16_t    size;
    uint8_t    *value;
};

struct dmsecrets
{
    uint32_t                    magic;
    struct dmsecrets           *next;               /* The list of open vaults */
    char                       *path;
    char                       *domain;             /* The key's label for DMSECRETS_OPEN_DEVICE_KEY, or NULL */
    uint32_t                    flags;
    dmsecrets_passphrase_fn_t   provider;
    void                       *provider_context;
    dmosi_mutex_t               lock;

    bool                        exists;             /* The vault's file is there (a slot was written) */
    bool                        unlocked;
    uint8_t                     key[KEY_SIZE];
    uint8_t                     salt[SALT_SIZE];
    uint32_t                    iterations;
    uint32_t                    generation;
    uint16_t                    capacity_units;

    struct record              *records;
    size_t                      count;
    size_t                      allocated;
};

static struct dmsecrets *g_open;                    /* The open vaults */
static dmosi_mutex_t     g_lock;

/* ---- Little-endian fields ---- */

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void wipe(void *buffer, size_t size)
{
    dmcrypto_wipe(buffer, size);
}

static size_t capacity_of(const struct dmsecrets *v)
{
    return (size_t)v->capacity_units * CAPACITY_UNIT;
}

static size_t slot_size(const struct dmsecrets *v)
{
    return HEADER_SIZE + capacity_of(v) + TAG_SIZE;
}

/* ---- Storage: a file, opened for every access (closing flushes it) ---- */

static int storage_read(const char *path, size_t offset, void *buffer, size_t size)
{
    void *file = Dmod_FileOpen(path, "r");
    int result = 0;

    if (file == NULL)
        return -ENOENT;
    if (Dmod_FileSeek(file, (Dmod_FileOffset_t)offset, DMOD_SEEK_SET) != 0 ||
        Dmod_FileRead(buffer, 1, size, file) != size)
        result = -EIO;
    Dmod_FileClose(file);
    return result;
}

/* create: the file is made (and what was there is gone) */
static int storage_write(const char *path, size_t offset, const void *buffer, size_t size, bool create)
{
    void *file = Dmod_FileOpen(path, create ? "w+" : "r+");
    int result = 0;

    if (file == NULL)
        return -EIO;
    if (Dmod_FileSeek(file, (Dmod_FileOffset_t)offset, DMOD_SEEK_SET) != 0 ||
        Dmod_FileWrite(buffer, 1, size, file) != size)
        result = -EIO;
    Dmod_FileClose(file);
    return result;
}

/* ---- Records in memory ---- */

static void free_record(struct record *r)
{
    if (r->value != NULL)
    {
        wipe(r->value, r->size);
        Dmod_Free(r->value);
    }
    r->value = NULL;
    r->size = 0;
}

static void clear_records(struct dmsecrets *v)
{
    for (size_t i = 0; i < v->count; i++)
        free_record(&v->records[i]);
    Dmod_Free(v->records);
    v->records = NULL;
    v->count = v->allocated = 0;
}

static struct record *find_record(struct dmsecrets *v, const char *name)
{
    for (size_t i = 0; i < v->count; i++)
        if (strcmp(v->records[i].name, name) == 0)
            return &v->records[i];
    return NULL;
}

static int add_slot(struct dmsecrets *v)
{
    if (v->count == v->allocated)
    {
        size_t allocated = v->allocated == 0 ? 8 : v->allocated * 2;
        struct record *grown = Dmod_Malloc(allocated * sizeof(struct record));
        if (grown == NULL)
            return -ENOMEM;
        if (v->count != 0)
            memcpy(grown, v->records, v->count * sizeof(struct record));
        Dmod_Free(v->records);
        v->records = grown;
        v->allocated = allocated;
    }
    return 0;
}

/* The bytes the records take: a count, then per record its name and value */
static size_t records_size(const struct dmsecrets *v)
{
    size_t size = 2;

    for (size_t i = 0; i < v->count; i++)
        size += RECORD_OVERHEAD + strlen(v->records[i].name) + v->records[i].size;
    return size;
}

static void serialize(const struct dmsecrets *v, uint8_t *out)
{
    put16(out, (uint16_t)v->count);
    out += 2;
    for (size_t i = 0; i < v->count; i++)
    {
        const struct record *r = &v->records[i];
        size_t name_length = strlen(r->name);

        *out++ = (uint8_t)name_length;
        memcpy(out, r->name, name_length);
        out += name_length;
        put16(out, r->size);
        out += 2;
        if (r->size != 0)
            memcpy(out, r->value, r->size);
        out += r->size;
    }
}

/* -EBADMSG for records that do not parse (authenticated, so a bug or a newer writer) */
static int parse(struct dmsecrets *v, const uint8_t *in, size_t size)
{
    if (size < 2)
        return -EBADMSG;
    size_t count = get16(in);
    size_t at = 2;

    clear_records(v);
    for (size_t i = 0; i < count; i++)
    {
        if (at + 1 > size)
            goto bad;
        size_t name_length = in[at++];
        if (name_length == 0 || name_length > DMSECRETS_NAME_MAX || at + name_length + 2 > size)
            goto bad;
        if (add_slot(v) != 0)
            goto nomem;
        struct record *r = &v->records[v->count];
        memcpy(r->name, in + at, name_length);
        r->name[name_length] = '\0';
        at += name_length;
        r->size = get16(in + at);
        at += 2;
        if (r->size > DMSECRETS_VALUE_MAX || at + r->size > size)
            goto bad;
        r->value = Dmod_Malloc(r->size != 0 ? r->size : 1);
        if (r->value == NULL)
            goto nomem;
        memcpy(r->value, in + at, r->size);
        at += r->size;
        v->count++;
    }
    return 0;
bad:
    clear_records(v);
    return -EBADMSG;
nomem:
    clear_records(v);
    return -ENOMEM;
}

/* ---- The vault file ---- */

static int derive_key(const void *passphrase, size_t size, const uint8_t *salt, uint32_t iterations, uint8_t *key)
{
    return dmcrypto_pbkdf2_hmac(DMCRYPTO_HASH_SHA256, passphrase, size, salt, SALT_SIZE, iterations, key, KEY_SIZE);
}

/* Writes the vault out as generation + 1 into the slot that is not the current one */
static int write_vault(struct dmsecrets *v)
{
    size_t capacity = capacity_of(v);
    size_t used = records_size(v);

    if (used > capacity)
        return -ENOSPC;
    size_t padded = (used + CAPACITY_UNIT - 1) / CAPACITY_UNIT * CAPACITY_UNIT;
    size_t extra = padded - used;
    uint8_t random[NONCE_SIZE + CAPACITY_UNIT];
    int result = dmcrypto_random(random, NONCE_SIZE + extra);
    if (result != 0)
        return result;                          /* -ENODEV: no entropy source */

    uint8_t *slot = Dmod_Malloc(HEADER_SIZE + padded + TAG_SIZE);
    if (slot == NULL)
        return -ENOMEM;
    uint32_t generation = v->generation + 1;
    uint8_t *header = slot, *body = slot + HEADER_SIZE;

    memcpy(header + H_MAGIC, FORMAT_MAGIC, 4);
    header[H_VERSION] = FORMAT_VERSION;
    header[H_KDF] = KDF_PBKDF2_SHA256;
    put16(header + H_CAPACITY, v->capacity_units);
    put32(header + H_ITERATIONS, v->iterations);
    memcpy(header + H_SALT, v->salt, SALT_SIZE);
    put32(header + H_GENERATION, generation);
    memcpy(header + H_NONCE, random, NONCE_SIZE);
    put32(header + H_LENGTH, (uint32_t)padded);

    serialize(v, body);
    memcpy(body + used, random + NONCE_SIZE, extra);
    result = dmcrypto_aead_encrypt(DMCRYPTO_AEAD_AES_GCM, v->key, KEY_SIZE, header + H_NONCE, NONCE_SIZE,
                                   header, HEADER_SIZE, body, padded, body, body + padded, TAG_SIZE);
    if (result == 0)
    {
        size_t offset = (size_t)((generation - 1) & 1) * slot_size(v);
        result = storage_write(v->path, offset, slot, HEADER_SIZE + padded + TAG_SIZE, !v->exists);
    }
    wipe(slot, HEADER_SIZE + padded + TAG_SIZE);
    Dmod_Free(slot);
    if (result == 0)
    {
        v->generation = generation;
        v->exists = true;
    }
    return result;
}

/* A slot's header is valid when it says it is a vault of this version; nothing more is known
 * before the key */
static bool header_valid(const uint8_t *header)
{
    return memcmp(header + H_MAGIC, FORMAT_MAGIC, 4) == 0 && header[H_VERSION] == FORMAT_VERSION &&
           header[H_KDF] == KDF_PBKDF2_SHA256 && get16(header + H_CAPACITY) != 0;
}

/* Tries one slot with the passphrase: 0, -EACCES (the tag does not match), -EBADMSG, -EIO ... */
static int try_slot(struct dmsecrets *v, size_t slot, const uint8_t *header, const void *passphrase, size_t size,
                    bool *key_known, uint8_t *known_salt, uint32_t *known_iterations)
{
    uint32_t length = get32(header + H_LENGTH);
    uint32_t iterations = get32(header + H_ITERATIONS);
    size_t capacity = (size_t)get16(header + H_CAPACITY) * CAPACITY_UNIT;

    if (length > capacity || length < 2 || iterations == 0)
        return -EBADMSG;
    if (!*key_known || memcmp(known_salt, header + H_SALT, SALT_SIZE) != 0 || *known_iterations != iterations)
    {
        if (derive_key(passphrase, size, header + H_SALT, iterations, v->key) != 0)
            return -EIO;
        memcpy(known_salt, header + H_SALT, SALT_SIZE);
        *known_iterations = iterations;
        *key_known = true;
    }

    size_t offset = slot * (HEADER_SIZE + capacity + TAG_SIZE);
    uint8_t *body = Dmod_Malloc((size_t)length + TAG_SIZE);
    if (body == NULL)
        return -ENOMEM;
    int result = storage_read(v->path, offset + HEADER_SIZE, body, (size_t)length + TAG_SIZE);
    if (result == 0)
    {
        result = dmcrypto_aead_decrypt(DMCRYPTO_AEAD_AES_GCM, v->key, KEY_SIZE, header + H_NONCE, NONCE_SIZE,
                                       header, HEADER_SIZE, body, length, body + length, TAG_SIZE, body);
        if (result == -EBADMSG)
            result = -EACCES;
        if (result == 0)
            result = parse(v, body, length);
    }
    wipe(body, (size_t)length + TAG_SIZE);
    Dmod_Free(body);
    if (result == 0)
    {
        memcpy(v->salt, header + H_SALT, SALT_SIZE);
        v->iterations = iterations;
        v->generation = get32(header + H_GENERATION);
        v->capacity_units = get16(header + H_CAPACITY);
    }
    return result;
}

/* The vault is locked: unlock it (or create it, when it is new) */
static int unlock_locked(struct dmsecrets *v, const void *passphrase, size_t size)
{
    if (v->unlocked)
        return 0;
    if (passphrase == NULL || size == 0)
        return -EINVAL;

    if (!v->exists)
    {
        /* A new vault: its salt is random, its slots are empty */
        int result = dmcrypto_random(v->salt, SALT_SIZE);
        if (result != 0)
            return result;
        v->iterations = KDF_ITERATIONS;
        v->capacity_units = DEFAULT_CAPACITY / CAPACITY_UNIT;
        v->generation = 0;
        if (derive_key(passphrase, size, v->salt, v->iterations, v->key) != 0)
            return -EIO;
        clear_records(v);
        result = write_vault(v);
        if (result != 0)
        {
            wipe(v->key, sizeof(v->key));
            return result;
        }
        v->unlocked = true;
        return 0;
    }

    /* An existing one: the slot with the higher generation, else the other (a write was cut short) */
    uint8_t header[2][HEADER_SIZE];
    bool valid[2] = { false, false };
    uint8_t known_salt[SALT_SIZE];
    uint32_t known_iterations = 0;
    bool key_known = false;
    size_t slot_bytes = HEADER_SIZE + capacity_of(v) + TAG_SIZE;

    for (size_t s = 0; s < 2; s++)
        valid[s] = storage_read(v->path, s * slot_bytes, header[s], HEADER_SIZE) == 0 && header_valid(header[s]);
    if (!valid[0] && !valid[1])
        return -EBADMSG;

    size_t first = (valid[1] && (!valid[0] || get32(header[1] + H_GENERATION) > get32(header[0] + H_GENERATION))) ? 1 : 0;
    int result = -EACCES;
    for (size_t attempt = 0; attempt < 2; attempt++)
    {
        size_t s = attempt == 0 ? first : 1 - first;
        if (!valid[s])
            continue;
        result = try_slot(v, s, header[s], passphrase, size, &key_known, known_salt, &known_iterations);
        if (result == 0)
        {
            v->unlocked = true;
            return 0;
        }
        if (result != -EACCES && result != -EBADMSG)
            break;                              /* the storage or the memory failed: no point in the other */
    }
    wipe(v->key, sizeof(v->key));
    return result == -EBADMSG ? -EACCES : result;
}

static void lock_locked(struct dmsecrets *v)
{
    wipe(v->key, sizeof(v->key));
    clear_records(v);
    v->unlocked = false;
}

/* The passphrase of DMSECRETS_OPEN_DEVICE_KEY: HKDF-SHA256 of the device secret, labelled
 * with the vault's domain, as 64 hex characters. -ENODEV when there is no device secret. */
static int device_key_passphrase(const struct dmsecrets *v, char *out, size_t out_size, size_t *length)
{
    static const char hex[] = "0123456789abcdef";
    const char *node = Dmod_GetEnv("DMSECRETS_DEVKEY_PATH");
    uint8_t secret[DEVKEY_MAX], key[KEY_SIZE];
    char info[16 + DMSECRETS_DOMAIN_MAX + 1] = "dmsecrets/v1/";
    size_t info_length = strlen(info);

    if (out_size < 2 * KEY_SIZE)
        return -ENOSPC;
    if (node == NULL || node[0] == '\0')
        node = DEVKEY_NODE;

    void *file = Dmod_FileOpen(node, "r");
    if (file == NULL)
        return -ENODEV;
    size_t n = Dmod_FileRead(secret, 1, sizeof(secret), file);
    Dmod_FileClose(file);
    if (n == 0)
        return -ENODEV;

    const char *label = (v->domain != NULL) ? v->domain : "default";
    if (strlen(label) > DMSECRETS_DOMAIN_MAX)
    {
        wipe(secret, sizeof(secret));
        return -EINVAL;
    }
    memcpy(info + info_length, label, strlen(label) + 1);
    info_length += strlen(label);

    int result = dmcrypto_hkdf(DMCRYPTO_HASH_SHA256, secret, n, NULL, 0, info, info_length, key, sizeof(key));
    wipe(secret, sizeof(secret));
    if (result == 0)
    {
        for (size_t i = 0; i < KEY_SIZE; i++)
        {
            out[2 * i] = hex[key[i] >> 4];
            out[2 * i + 1] = hex[key[i] & 0x0F];
        }
        *length = 2 * KEY_SIZE;
    }
    wipe(key, sizeof(key));
    return result;
}

/* Unlocked: by the device key when the vault asks for it, else by the provider if need be */
static int ensure_unlocked(struct dmsecrets *v)
{
    uint8_t passphrase[PASSPHRASE_MAX];
    size_t length = 0;
    int result;

    if (v->unlocked)
        return 0;

    if ((v->flags & DMSECRETS_OPEN_DEVICE_KEY) != 0)
    {
        result = device_key_passphrase(v, (char *)passphrase, sizeof(passphrase), &length);
        if (result == 0)
            result = unlock_locked(v, passphrase, length);
        wipe(passphrase, sizeof(passphrase));
        if (result != -ENODEV || v->provider == NULL)
            return result;                      /* unlocked, or no device secret and nobody else to ask */
        length = 0;                             /* no device secret: the provider's passphrase */
    }

    if (v->provider == NULL)
        return -EACCES;

    result = v->provider(v->provider_context, !v->exists, passphrase, sizeof(passphrase), &length);
    if (result == 0)
        result = (length == 0 || length > sizeof(passphrase)) ? -EINVAL : unlock_locked(v, passphrase, length);
    wipe(passphrase, sizeof(passphrase));
    return result;
}

static bool vault_ok(const struct dmsecrets *v)
{
    return v != NULL && v->magic == VAULT_MAGIC;
}

static bool name_ok(const char *name)
{
    if (name == NULL)
        return false;
    size_t length = strlen(name);
    return length >= 1 && length <= DMSECRETS_NAME_MAX;
}

#define ENV_PREFIX      "DMSECRETS_"
#define ENV_SUFFIX      "_PATH"

/* DMSECRETS_<DOMAIN>_PATH: the domain in upper case, '-' as '_' */
static bool domain_variable(const char *domain, char *variable, size_t size)
{
    size_t prefix = sizeof(ENV_PREFIX) - 1, suffix = sizeof(ENV_SUFFIX) - 1, length = strlen(domain);

    if (length == 0 || length > DMSECRETS_DOMAIN_MAX || prefix + length + suffix + 1 > size)
        return false;
    memcpy(variable, ENV_PREFIX, prefix);
    for (size_t i = 0; i < length; i++)
    {
        char c = domain[i];
        if (c >= 'a' && c <= 'z')
            c = (char)(c - 'a' + 'A');
        else if (c == '-')
            c = '_';
        else if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
            return false;
        variable[prefix + i] = c;
    }
    memcpy(variable + prefix + length, ENV_SUFFIX, suffix + 1);
    return true;
}

static int copy_path(const char *path, char *output, size_t output_size)
{
    size_t length = strlen(path);

    if (length + 1 > output_size)
        return -ENOSPC;
    memcpy(output, path, length + 1);
    return 0;
}

dmod_dmsecrets_api_declaration(1.0, int, _resolve_path, ( const char* path, const char* domain, char* output, size_t output_size ))
{
    char variable[sizeof(ENV_PREFIX) + DMSECRETS_DOMAIN_MAX + sizeof(ENV_SUFFIX)];
    const char *value;

    if (output == NULL || output_size == 0)
        return -EINVAL;
    if (path != NULL && path[0] != '\0')
        return copy_path(path, output, output_size);

    if (domain != NULL)
    {
        if (!domain_variable(domain, variable, sizeof(variable)))
            return -EINVAL;
        value = Dmod_GetEnv(variable);
        if (value != NULL && value[0] != '\0')
            return copy_path(value, output, output_size);
    }

    value = Dmod_GetEnv("DMSECRETS_PATH");
    if (value != NULL && value[0] != '\0')
        return copy_path(value, output, output_size);
    return -ENOENT;
}

dmod_dmsecrets_api_declaration(1.0, int, _open, ( const dmsecrets_config_t* config, dmsecrets_t* vault ))
{
    dmsecrets_config_t none;
    char path[160];
    uint8_t header[HEADER_SIZE];

    if (vault == NULL)
        return -EINVAL;
    if (config == NULL)
    {
        memset(&none, 0, sizeof(none));
        config = &none;
    }
    if ((config->flags & DMSECRETS_OPEN_CREATE) != 0 && (config->flags & DMSECRETS_OPEN_READONLY) != 0)
        return -EINVAL;

    int result = dmsecrets_resolve_path(config->path, config->domain, path, sizeof(path));
    if (result != 0)
        return result;

    bool exists = true;
    result = storage_read(path, 0, header, HEADER_SIZE);
    if (result == -ENOENT)
    {
        if ((config->flags & DMSECRETS_OPEN_CREATE) == 0)
            return -ENOENT;
        exists = false;
    }
    else if (result != 0 || !header_valid(header))
    {
        return -EBADMSG;                        /* too short, or not a vault of this version */
    }

    struct dmsecrets *v = Dmod_Malloc(sizeof(*v));
    if (v == NULL)
        return -ENOMEM;
    memset(v, 0, sizeof(*v));
    v->magic = VAULT_MAGIC;
    v->path = Dmod_StrDup(path);
    v->domain = (config->domain != NULL && config->domain[0] != '\0') ? Dmod_StrDup(config->domain) : NULL;
    v->flags = config->flags;
    v->provider = config->passphrase_provider;
    v->provider_context = config->provider_context;
    v->lock = dmosi_mutex_create(false);
    v->exists = exists;
    v->capacity_units = exists ? get16(header + H_CAPACITY) : (uint16_t)(DEFAULT_CAPACITY / CAPACITY_UNIT);
    if (v->path == NULL || v->lock == NULL || (config->domain != NULL && config->domain[0] != '\0' && v->domain == NULL))
    {
        if (v->lock != NULL)
            dmosi_mutex_destroy(v->lock);
        Dmod_Free(v->path);
        Dmod_Free(v->domain);
        Dmod_Free(v);
        return -ENOMEM;
    }

    dmosi_mutex_lock(g_lock);
    for (struct dmsecrets *o = g_open; o != NULL; o = o->next)
    {
        if (strcmp(o->path, v->path) == 0)
        {
            dmosi_mutex_unlock(g_lock);
            dmosi_mutex_destroy(v->lock);
            Dmod_Free(v->path);
            Dmod_Free(v->domain);
            Dmod_Free(v);
            return -EBUSY;
        }
    }
    v->next = g_open;
    g_open = v;
    dmosi_mutex_unlock(g_lock);
    *vault = v;
    return 0;
}

dmod_dmsecrets_api_declaration(1.0, void, _close, ( dmsecrets_t vault ))
{
    if (!vault_ok(vault))
        return;

    dmosi_mutex_lock(g_lock);
    for (struct dmsecrets **p = &g_open; *p != NULL; p = &(*p)->next)
    {
        if (*p == vault)
        {
            *p = vault->next;
            break;
        }
    }
    dmosi_mutex_unlock(g_lock);

    dmosi_mutex_lock(vault->lock);
    lock_locked(vault);
    dmosi_mutex_unlock(vault->lock);
    dmosi_mutex_destroy(vault->lock);
    Dmod_Free(vault->path);
    Dmod_Free(vault->domain);
    vault->magic = 0;
    Dmod_Free(vault);
}

dmod_dmsecrets_api_declaration(1.0, int, _get_path, ( dmsecrets_t vault, char* output, size_t output_size ))
{
    if (!vault_ok(vault) || output == NULL)
        return -EINVAL;
    return copy_path(vault->path, output, output_size);
}

dmod_dmsecrets_api_declaration(1.0, bool, _is_unlocked, ( dmsecrets_t vault ))
{
    if (!vault_ok(vault))
        return false;
    dmosi_mutex_lock(vault->lock);
    bool unlocked = vault->unlocked;
    dmosi_mutex_unlock(vault->lock);
    return unlocked;
}

dmod_dmsecrets_api_declaration(1.0, int, _unlock, ( dmsecrets_t vault, const void* passphrase, size_t passphrase_size ))
{
    if (!vault_ok(vault))
        return -EINVAL;
    dmosi_mutex_lock(vault->lock);
    int result = unlock_locked(vault, passphrase, passphrase_size);
    dmosi_mutex_unlock(vault->lock);
    return result;
}

dmod_dmsecrets_api_declaration(1.0, int, _lock, ( dmsecrets_t vault ))
{
    if (!vault_ok(vault))
        return -EINVAL;
    dmosi_mutex_lock(vault->lock);
    lock_locked(vault);
    dmosi_mutex_unlock(vault->lock);
    return 0;
}

dmod_dmsecrets_api_declaration(1.0, int, _change_passphrase, ( dmsecrets_t vault, const void* passphrase, size_t passphrase_size ))
{
    uint8_t old_key[KEY_SIZE], old_salt[SALT_SIZE];

    if (!vault_ok(vault) || passphrase == NULL || passphrase_size == 0)
        return -EINVAL;
    dmosi_mutex_lock(vault->lock);
    int result = (vault->flags & DMSECRETS_OPEN_READONLY) != 0 ? -EROFS : ensure_unlocked(vault);
    if (result == 0)
    {
        memcpy(old_key, vault->key, KEY_SIZE);
        memcpy(old_salt, vault->salt, SALT_SIZE);
        result = dmcrypto_random(vault->salt, SALT_SIZE);
        if (result == 0)
            result = derive_key(passphrase, passphrase_size, vault->salt, vault->iterations, vault->key) == 0 ? 0 : -EIO;
        if (result == 0)
            result = write_vault(vault);
        if (result == 0)
        {
            /* The slot that is not the current one is under the old passphrase: its header goes */
            uint8_t zeros[HEADER_SIZE] = { 0 };
            size_t other = (size_t)(vault->generation & 1) * slot_size(vault);
            (void)storage_write(vault->path, other, zeros, sizeof(zeros), false);
        }
        else
        {
            memcpy(vault->key, old_key, KEY_SIZE);
            memcpy(vault->salt, old_salt, SALT_SIZE);
        }
        wipe(old_key, sizeof(old_key));
    }
    dmosi_mutex_unlock(vault->lock);
    return result;
}

dmod_dmsecrets_api_declaration(1.0, int, _set, ( dmsecrets_t vault, const char* name, const void* value, size_t value_size ))
{
    if (!vault_ok(vault) || !name_ok(name) || (value == NULL && value_size != 0))
        return -EINVAL;
    if (value_size > DMSECRETS_VALUE_MAX)
        return -EFBIG;

    dmosi_mutex_lock(vault->lock);
    int result = (vault->flags & DMSECRETS_OPEN_READONLY) != 0 ? -EROFS : ensure_unlocked(vault);
    if (result == 0)
    {
        uint8_t *copy = Dmod_Malloc(value_size != 0 ? value_size : 1);
        if (copy == NULL)
        {
            dmosi_mutex_unlock(vault->lock);
            return -ENOMEM;
        }
        if (value_size != 0)
            memcpy(copy, value, value_size);

        struct record *r = find_record(vault, name);
        struct record previous;
        bool added = false;

        if (r == NULL)
            result = add_slot(vault);
        if (result == 0)
        {
            if (r == NULL)
            {
                r = &vault->records[vault->count++];
                memset(r, 0, sizeof(*r));
                memcpy(r->name, name, strlen(name) + 1);
                added = true;
            }
            previous = *r;
            r->value = copy;
            r->size = (uint16_t)value_size;
            result = write_vault(vault);
            if (result != 0)
            {
                /* Not stored: the vault in memory is as it was */
                if (added)
                    vault->count--;
                else
                    *r = previous;
                wipe(copy, value_size);
                Dmod_Free(copy);
            }
            else if (!added)
            {
                wipe(previous.value, previous.size);
                Dmod_Free(previous.value);
            }
        }
        else
        {
            Dmod_Free(copy);
        }
    }
    dmosi_mutex_unlock(vault->lock);
    return result;
}

dmod_dmsecrets_api_declaration(1.0, int, _get, ( dmsecrets_t vault, const char* name, void* value, size_t value_size, size_t* length ))
{
    if (!vault_ok(vault) || !name_ok(name) || length == NULL || (value == NULL && value_size != 0))
        return -EINVAL;

    dmosi_mutex_lock(vault->lock);
    int result = ensure_unlocked(vault);
    if (result == 0)
    {
        struct record *r = find_record(vault, name);
        if (r == NULL)
        {
            result = -ENOENT;
        }
        else
        {
            *length = r->size;
            if (value != NULL && value_size >= r->size)
                memcpy(value, r->value, r->size);
            else if (value != NULL)
                result = -ENOSPC;               /* nothing is copied */
        }
    }
    dmosi_mutex_unlock(vault->lock);
    return result;
}

dmod_dmsecrets_api_declaration(1.0, int, _delete, ( dmsecrets_t vault, const char* name ))
{
    if (!vault_ok(vault) || !name_ok(name))
        return -EINVAL;

    dmosi_mutex_lock(vault->lock);
    int result = (vault->flags & DMSECRETS_OPEN_READONLY) != 0 ? -EROFS : ensure_unlocked(vault);
    if (result == 0)
    {
        struct record *r = find_record(vault, name);
        if (r == NULL)
        {
            result = -ENOENT;
        }
        else
        {
            size_t index = (size_t)(r - vault->records);
            struct record removed = *r;

            memmove(r, r + 1, (vault->count - index - 1) * sizeof(struct record));
            vault->count--;
            result = write_vault(vault);
            if (result != 0)
            {
                /* Not stored: the record is back where it was */
                memmove(&vault->records[index + 1], &vault->records[index], (vault->count - index) * sizeof(struct record));
                vault->records[index] = removed;
                vault->count++;
            }
            else
            {
                wipe(removed.value, removed.size);
                Dmod_Free(removed.value);
            }
        }
    }
    dmosi_mutex_unlock(vault->lock);
    return result;
}

static bool has_prefix(const struct record *r, const char *prefix)
{
    return prefix == NULL || strncmp(r->name, prefix, strlen(prefix)) == 0;
}

dmod_dmsecrets_api_declaration(1.0, int, _count, ( dmsecrets_t vault, const char* prefix, size_t* count ))
{
    if (!vault_ok(vault) || count == NULL)
        return -EINVAL;

    dmosi_mutex_lock(vault->lock);
    int result = ensure_unlocked(vault);
    if (result == 0)
    {
        *count = 0;
        for (size_t i = 0; i < vault->count; i++)
            if (has_prefix(&vault->records[i], prefix))
                (*count)++;
    }
    dmosi_mutex_unlock(vault->lock);
    return result;
}

dmod_dmsecrets_api_declaration(1.0, int, _name_at, ( dmsecrets_t vault, const char* prefix, size_t index, char* name, size_t name_size ))
{
    if (!vault_ok(vault) || name == NULL || name_size == 0)
        return -EINVAL;

    dmosi_mutex_lock(vault->lock);
    int result = ensure_unlocked(vault);
    if (result == 0)
    {
        result = -ENOENT;
        for (size_t i = 0, seen = 0; i < vault->count; i++)
        {
            if (!has_prefix(&vault->records[i], prefix))
                continue;
            if (seen++ == index)
            {
                size_t length = strlen(vault->records[i].name);
                if (length + 1 > name_size)
                {
                    result = -ENOSPC;
                }
                else
                {
                    memcpy(name, vault->records[i].name, length + 1);
                    result = 0;
                }
                break;
            }
        }
    }
    dmosi_mutex_unlock(vault->lock);
    return result;
}

/* ---- DMOD lifecycle ---- */

int dmod_init(const Dmod_Config_t *Config)
{
    (void)Config;
    g_lock = dmosi_mutex_create(false);
    if (g_lock == NULL)
        return -ENOMEM;
    Dmod_Printf("dmsecrets module initialized\n");
    return 0;
}

int dmod_deinit(void)
{
    if (g_open != NULL)
        return -EBUSY;                          /* vaults are open */
    dmosi_mutex_destroy(g_lock);
    g_lock = NULL;
    return 0;
}
