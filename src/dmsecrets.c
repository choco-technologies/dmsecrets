#define DMOD_ENABLE_REGISTRATION ON
#include "dmod.h"
#include "dmsecrets.h"
#include <errno.h>
#include <string.h>

/*
 * TODO(implementation): everything but dmsecrets_resolve_path() returns -ENOSYS
 * until it is written (docs/format.md says what the vault is).
 */

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
    /* TODO(implementation) */
    (void)config;
    (void)vault;
    return -ENOSYS;
}

dmod_dmsecrets_api_declaration(1.0, void, _close, ( dmsecrets_t vault ))
{
    /* TODO(implementation) */
    (void)vault;
}

dmod_dmsecrets_api_declaration(1.0, int, _get_path, ( dmsecrets_t vault, char* output, size_t output_size ))
{
    /* TODO(implementation) */
    (void)vault;
    (void)output;
    (void)output_size;
    return -ENOSYS;
}

dmod_dmsecrets_api_declaration(1.0, bool, _is_unlocked, ( dmsecrets_t vault ))
{
    /* TODO(implementation) */
    (void)vault;
    return false;
}

dmod_dmsecrets_api_declaration(1.0, int, _unlock, ( dmsecrets_t vault, const void* passphrase, size_t passphrase_size ))
{
    /* TODO(implementation) */
    (void)vault;
    (void)passphrase;
    (void)passphrase_size;
    return -ENOSYS;
}

dmod_dmsecrets_api_declaration(1.0, int, _lock, ( dmsecrets_t vault ))
{
    /* TODO(implementation) */
    (void)vault;
    return -ENOSYS;
}

dmod_dmsecrets_api_declaration(1.0, int, _change_passphrase, ( dmsecrets_t vault, const void* passphrase, size_t passphrase_size ))
{
    /* TODO(implementation) */
    (void)vault;
    (void)passphrase;
    (void)passphrase_size;
    return -ENOSYS;
}

dmod_dmsecrets_api_declaration(1.0, int, _set, ( dmsecrets_t vault, const char* name, const void* value, size_t value_size ))
{
    /* TODO(implementation) */
    (void)vault;
    (void)name;
    (void)value;
    (void)value_size;
    return -ENOSYS;
}

dmod_dmsecrets_api_declaration(1.0, int, _get, ( dmsecrets_t vault, const char* name, void* value, size_t value_size, size_t* length ))
{
    /* TODO(implementation) */
    (void)vault;
    (void)name;
    (void)value;
    (void)value_size;
    (void)length;
    return -ENOSYS;
}

dmod_dmsecrets_api_declaration(1.0, int, _delete, ( dmsecrets_t vault, const char* name ))
{
    /* TODO(implementation) */
    (void)vault;
    (void)name;
    return -ENOSYS;
}

dmod_dmsecrets_api_declaration(1.0, int, _count, ( dmsecrets_t vault, const char* prefix, size_t* count ))
{
    /* TODO(implementation) */
    (void)vault;
    (void)prefix;
    (void)count;
    return -ENOSYS;
}

dmod_dmsecrets_api_declaration(1.0, int, _name_at, ( dmsecrets_t vault, const char* prefix, size_t index, char* name, size_t name_size ))
{
    /* TODO(implementation) */
    (void)vault;
    (void)prefix;
    (void)index;
    (void)name;
    (void)name_size;
    return -ENOSYS;
}

/* ---- DMOD lifecycle ---- */

int dmod_init(const Dmod_Config_t *Config)
{
    (void)Config;
    Dmod_Printf("dmsecrets module initialized\n");
    return 0;
}

int dmod_deinit(void)
{
    return 0;
}
