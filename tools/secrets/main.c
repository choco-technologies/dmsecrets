#include "dmod.h"
#include "dmsecrets.h"
#include <errno.h>
#include <string.h>

/**
 * @brief The secrets of the shell: vaults of named records.
 *
 * The passphrase is asked for (not echoed) when the vault needs it - the tool
 * gives the vault a passphrase provider, so a command that does not need the
 * vault (a missing path) never asks.
 */

#define NAME_BUFFER     (DMSECRETS_NAME_MAX + 2)
#define VALUE_BUFFER    (DMSECRETS_VALUE_MAX + 2)
#define PASSPHRASE_MAX  200

static void print_usage(const char *name)
{
    Dmod_Printf("Usage: %s [-f FILE] [-d DOMAIN] [-k] COMMAND [ARGS]\n", name);
    Dmod_Printf("  list [PREFIX]        the names of the records (those that start with PREFIX)\n");
    Dmod_Printf("  get [-x] NAME        a record's value as text; -x: in hex (for binary values)\n");
    Dmod_Printf("  set NAME [VALUE]     stores a record; without VALUE it asks for it (not echoed)\n");
    Dmod_Printf("  delete NAME          removes a record\n");
    Dmod_Printf("  create               makes a new vault (asks for its passphrase twice)\n");
    Dmod_Printf("  passwd               changes the vault's passphrase\n");
    Dmod_Printf("  info                 where the vault is and how many records it has\n");
    Dmod_Printf("The vault: FILE, else DMSECRETS_<DOMAIN>_PATH (with -d DOMAIN), else DMSECRETS_PATH.\n");
    Dmod_Printf("-k: unlock with the key of the device secret (/dev/devkey, labelled by DOMAIN) - no passphrase.\n");
}

/* Reads a line from the terminal without echoing it: false when it cannot be read.
 * Dmod_Gets leaves "text\n" and does not terminate it: zeroed first, cut at the end of the line */
static bool ask(const char *prompt, char *out, size_t size, size_t *length)
{
    uint32_t flags = Dmod_Stdin_GetFlags();

    Dmod_Printf("%s", prompt);
    (void)Dmod_Stdin_SetFlags((flags & ~(uint32_t)DMOD_STDIN_FLAG_ECHO) | DMOD_STDIN_FLAG_CANONICAL);
    memset(out, 0, size);
    char *line = Dmod_Gets(out, (int)size - 1);
    (void)Dmod_Stdin_SetFlags(flags);
    Dmod_Printf("\n");
    if (line == NULL)
        return false;
    for (size_t i = 0; i < size; i++)
    {
        if (out[i] == '\n' || out[i] == '\r')
        {
            memset(out + i, 0, size - i);
            break;
        }
    }
    *length = strlen(out);
    return true;
}

/* dmsecrets_passphrase_fn_t: a plain function of this module */
static int passphrase_provider(void *context, bool creating, void *passphrase, size_t size, size_t *length)
{
    char first[PASSPHRASE_MAX + 2], again[PASSPHRASE_MAX + 2];
    size_t n = 0, m = 0;

    (void)context;
    if (!ask(creating ? "New vault - passphrase: " : "Passphrase: ", first, sizeof(first), &n))
        return -ECANCELED;
    if (creating)
    {
        if (!ask("Again: ", again, sizeof(again), &m))
            return -ECANCELED;
        if (n != m || memcmp(first, again, n) != 0)
        {
            Dmod_Printf("secrets: the passphrases differ\n");
            memset(first, 0, sizeof(first));
            memset(again, 0, sizeof(again));
            return -EINVAL;
        }
        memset(again, 0, sizeof(again));
    }
    if (n == 0 || n > size)
    {
        memset(first, 0, sizeof(first));
        return -EINVAL;
    }
    memcpy(passphrase, first, n);
    *length = n;
    memset(first, 0, sizeof(first));
    return 0;
}

static void print_hex(const uint8_t *data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        Dmod_Printf("%02x", data[i]);
    Dmod_Printf("\n");
}

static const char *explain(int result)
{
    switch (result)
    {
        case -ENOENT: return "no such vault or record";
        case -EACCES: return "wrong passphrase, or the vault was changed";
        case -EBADMSG: return "not a vault";
        case -EBUSY: return "the vault is open elsewhere";
        case -ENODEV: return "no entropy source for dmcrypto (see dmcrypto's driver, entropy=)";
        case -ENOSPC: return "the vault is full";
        case -ECANCELED: return "no passphrase";
        default: return "failed";
    }
}

int main(int argc, char **argv)
{
    const char *path = NULL, *domain = NULL;
    uint32_t extra_flags = 0;
    int i = 1;

    while (i < argc && argv[i][0] == '-')
    {
        if (strcmp(argv[i], "-k") == 0)
        {
            extra_flags |= DMSECRETS_OPEN_DEVICE_KEY;
            i++;
        }
        else if (i + 1 < argc && strcmp(argv[i], "-f") == 0)
        {
            path = argv[i + 1];
            i += 2;
        }
        else if (i + 1 < argc && strcmp(argv[i], "-d") == 0)
        {
            domain = argv[i + 1];
            i += 2;
        }
        else
        {
            break;
        }
    }
    const char *command = (i < argc) ? argv[i] : "help";
    const char *arg1 = (i + 1 < argc) ? argv[i + 1] : NULL;
    const char *arg2 = (i + 2 < argc) ? argv[i + 2] : NULL;

    if (strcmp(command, "-h") == 0 || strcmp(command, "--help") == 0 || strcmp(command, "help") == 0)
    {
        print_usage(argv[0]);
        return 0;
    }

    bool creating = strcmp(command, "create") == 0;
    bool known = creating || strcmp(command, "passwd") == 0 || strcmp(command, "info") == 0 ||
                 strcmp(command, "list") == 0 ||
                 ((strcmp(command, "get") == 0 || strcmp(command, "delete") == 0) && arg1 != NULL) ||
                 (strcmp(command, "set") == 0 && arg1 != NULL);
    if (!known)
    {
        print_usage(argv[0]);
        return -1;
    }

    dmsecrets_config_t config;
    dmsecrets_t vault = NULL;
    memset(&config, 0, sizeof(config));

    if (creating)
    {
        /* Not over a vault that is there: opening it without CREATE says */
        config.path = path;
        config.domain = domain;
        if (dmsecrets_open(&config, &vault) == 0)
        {
            dmsecrets_close(vault);
            Dmod_Printf("secrets: the vault exists already\n");
            return -EEXIST;
        }
    }
    config.path = path;
    config.domain = domain;
    config.flags = (creating ? DMSECRETS_OPEN_CREATE : 0) | extra_flags;
    config.passphrase_provider = passphrase_provider;

    int ret = dmsecrets_open(&config, &vault);
    if (ret != 0)
    {
        Dmod_Printf("secrets: cannot open the vault (%d): %s\n", ret,
                    ret == -ENOENT ? "no path (-f, -d, DMSECRETS_PATH) or no such vault (create)" : explain(ret));
        return ret;
    }

    if (creating)
    {
        /* The first use asks for the passphrase twice and writes the vault */
        size_t count = 0;
        ret = dmsecrets_count(vault, NULL, &count);
        if (ret == 0)
            Dmod_Printf("created\n");
    }
    else if (strcmp(command, "info") == 0)
    {
        char where[160];
        size_t count = 0;
        (void)dmsecrets_get_path(vault, where, sizeof(where));
        Dmod_Printf("vault: %s\n", where);
        ret = dmsecrets_count(vault, NULL, &count);
        if (ret == 0)
            Dmod_Printf("records: %u\n", (unsigned)count);
    }
    else if (strcmp(command, "list") == 0)
    {
        size_t count = 0;
        char name[NAME_BUFFER];
        ret = dmsecrets_count(vault, arg1, &count);
        for (size_t n = 0; ret == 0 && n < count; n++)
        {
            ret = dmsecrets_name_at(vault, arg1, n, name, sizeof(name));
            if (ret == 0)
                Dmod_Printf("%s\n", name);
        }
    }
    else if (strcmp(command, "get") == 0 || strcmp(command, "delete") == 0)
    {
        bool hex = strcmp(command, "get") == 0 && strcmp(arg1, "-x") == 0 && arg2 != NULL;
        const char *name = hex ? arg2 : arg1;

        if (strcmp(command, "delete") == 0)
        {
            ret = dmsecrets_delete(vault, name);
        }
        else
        {
            uint8_t value[VALUE_BUFFER];
            size_t length = 0;
            ret = dmsecrets_get(vault, name, value, DMSECRETS_VALUE_MAX, &length);
            if (ret == 0 && hex)
            {
                print_hex(value, length);
            }
            else if (ret == 0)
            {
                value[length] = '\0';
                Dmod_Printf("%s\n", (const char *)value);
            }
            memset(value, 0, sizeof(value));
        }
    }
    else if (strcmp(command, "set") == 0)
    {
        char typed[VALUE_BUFFER];
        size_t length = 0;
        const char *value = arg2;

        if (value == NULL)
        {
            if (!ask("Value: ", typed, sizeof(typed), &length))
                ret = -ECANCELED;
            value = typed;
        }
        else
        {
            length = strlen(value);
        }
        if (ret == 0)
            ret = dmsecrets_set(vault, arg1, value, length);
        memset(typed, 0, sizeof(typed));
    }
    else    /* passwd */
    {
        char first[PASSPHRASE_MAX + 2], again[PASSPHRASE_MAX + 2];
        size_t n = 0, m = 0;

        /* the old passphrase is asked for first, by the vault, when it needs it */
        ret = dmsecrets_count(vault, NULL, &n);
        if (ret == 0 && (!ask("New passphrase: ", first, sizeof(first), &n) || !ask("Again: ", again, sizeof(again), &m)))
            ret = -ECANCELED;
        if (ret == 0 && (n == 0 || n != m || memcmp(first, again, n) != 0))
        {
            Dmod_Printf("secrets: the passphrases differ (or are empty)\n");
            ret = -EINVAL;
        }
        if (ret == 0)
            ret = dmsecrets_change_passphrase(vault, first, n);
        memset(first, 0, sizeof(first));
        memset(again, 0, sizeof(again));
    }

    dmsecrets_close(vault);
    if (ret != 0)
        Dmod_Printf("secrets: %s failed (%d): %s\n", command, ret, explain(ret));
    return ret;
}
