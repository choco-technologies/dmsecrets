#define DMOD_ENABLE_REGISTRATION ON
#include "dmod_test.h"
#include "dmsecrets.h"
#include "dmcrypto.h"
#include <errno.h>
#include <string.h>

/*
 * dmsecrets: where a vault is found, and the vault itself (records, unlocking,
 * a wrong passphrase, a tampered file, a write cut short, a new passphrase).
 * The vaults are files under /tmp (the host): dmcrypto's software port and a
 * deterministic entropy source do the cryptography.
 */

#define VAULT_PATH  "/tmp/dmsecrets_test.vault"
#define VAULT_PATH2 "/tmp/dmsecrets_test2.vault"
#define PASS        "correct horse"
#define PASS_LEN    13

static uint8_t g_counter;

static int test_entropy(void *context, void *buffer, size_t size)
{
    (void)context;
    for (size_t i = 0; i < size; i++)
        ((uint8_t *)buffer)[i] = (uint8_t)(g_counter++ * 37 + 11);
    return 0;
}

static void clear_environment(void)
{
    Dmod_SetEnv("DMSECRETS_PATH", "", 1);
    Dmod_SetEnv("DMSECRETS_WIFI_PATH", "", 1);
    Dmod_SetEnv("DMSECRETS_MY_LIB_PATH", "", 1);
}

void dmod_test_setup(void)
{
    clear_environment();
    Dmod_FileRemove(VAULT_PATH);
    Dmod_FileRemove(VAULT_PATH2);
    dmcrypto_set_entropy(test_entropy, NULL);
}

void dmod_test_teardown(void)
{
    clear_environment();
    Dmod_FileRemove(VAULT_PATH);
    Dmod_FileRemove(VAULT_PATH2);
    dmcrypto_set_entropy(NULL, NULL);
}

DMOD_TEST_STEP(no_path_anywhere_is_enoent)
{
    char path[64];

    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path(NULL, NULL, path, sizeof(path)), -ENOENT);
    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path("", "wifi", path, sizeof(path)), -ENOENT);
}

DMOD_TEST_STEP(a_given_path_wins)
{
    char path[64];

    Dmod_SetEnv("DMSECRETS_PATH", "/env/default.vault", 1);
    Dmod_SetEnv("DMSECRETS_WIFI_PATH", "/env/wifi.vault", 1);
    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path("/mnt/mine.vault", "wifi", path, sizeof(path)), 0);
    DMOD_TEST_EXPECT_EQ(strcmp(path, "/mnt/mine.vault"), 0);
}

DMOD_TEST_STEP(the_domain_variable_comes_before_the_default)
{
    char path[64];

    Dmod_SetEnv("DMSECRETS_PATH", "/env/default.vault", 1);
    Dmod_SetEnv("DMSECRETS_WIFI_PATH", "/env/wifi.vault", 1);
    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path(NULL, "wifi", path, sizeof(path)), 0);
    DMOD_TEST_EXPECT_EQ(strcmp(path, "/env/wifi.vault"), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path(NULL, "WiFi", path, sizeof(path)), 0);      /* any case */
    DMOD_TEST_EXPECT_EQ(strcmp(path, "/env/wifi.vault"), 0);

    /* a domain with no variable of its own falls back to the default */
    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path(NULL, "tls", path, sizeof(path)), 0);
    DMOD_TEST_EXPECT_EQ(strcmp(path, "/env/default.vault"), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path(NULL, NULL, path, sizeof(path)), 0);
    DMOD_TEST_EXPECT_EQ(strcmp(path, "/env/default.vault"), 0);
}

DMOD_TEST_STEP(a_dash_in_the_domain_is_an_underscore_in_the_variable)
{
    char path[64];

    Dmod_SetEnv("DMSECRETS_MY_LIB_PATH", "/env/my-lib.vault", 1);
    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path(NULL, "my-lib", path, sizeof(path)), 0);
    DMOD_TEST_EXPECT_EQ(strcmp(path, "/env/my-lib.vault"), 0);
}

DMOD_TEST_STEP(bad_arguments_and_small_buffers)
{
    char path[8], big[64];

    Dmod_SetEnv("DMSECRETS_PATH", "/a/long/path/to.vault", 1);
    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path(NULL, NULL, path, sizeof(path)), -ENOSPC);
    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path("/x/y/z/w/v.vault", NULL, path, sizeof(path)), -ENOSPC);
    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path(NULL, NULL, NULL, 10), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path(NULL, NULL, big, 0), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path(NULL, "a b", big, sizeof(big)), -EINVAL);        /* not a variable name */
    DMOD_TEST_EXPECT_EQ(dmsecrets_resolve_path(NULL, "waytoolongadomainnamethatdoesnotfitinside", big, sizeof(big)), -EINVAL);
}

/* ---- Vaults ---- */

static dmsecrets_t open_vault(const char *path, uint32_t flags)
{
    dmsecrets_config_t config = { .path = path, .flags = flags };
    dmsecrets_t vault = NULL;

    return dmsecrets_open(&config, &vault) == 0 ? vault : NULL;
}

/* A vault with a few records, closed again */
static bool make_vault(void)
{
    dmsecrets_t v = open_vault(VAULT_PATH, DMSECRETS_OPEN_CREATE);
    bool ok = v != NULL && dmsecrets_unlock(v, PASS, PASS_LEN) == 0 &&
              dmsecrets_set(v, "wifi/Home", "hunter2", 7) == 0 &&
              dmsecrets_set(v, "wifi/Work", "p4ssw0rd!", 9) == 0 &&
              dmsecrets_set(v, "mqtt/broker", "token", 5) == 0;
    dmsecrets_close(v);
    return ok;
}

DMOD_TEST_STEP(a_missing_vault_needs_create)
{
    dmsecrets_config_t config = { .path = VAULT_PATH };
    dmsecrets_t vault = NULL;

    DMOD_TEST_EXPECT_EQ(dmsecrets_open(&config, &vault), -ENOENT);
    DMOD_TEST_EXPECT_EQ(dmsecrets_open(NULL, &vault), -ENOENT);                  /* no path at all */
    config.flags = DMSECRETS_OPEN_CREATE | DMSECRETS_OPEN_READONLY;
    DMOD_TEST_EXPECT_EQ(dmsecrets_open(&config, &vault), -EINVAL);
}

DMOD_TEST_STEP(a_new_vault_is_created_by_its_first_unlock_and_kept)
{
    dmsecrets_t v = open_vault(VAULT_PATH, DMSECRETS_OPEN_CREATE);
    char value[32], path[64];
    size_t length = 0;

    DMOD_TEST_EXPECT_NOT_NULL(v);
    DMOD_TEST_EXPECT_FALSE(dmsecrets_is_unlocked(v));
    DMOD_TEST_EXPECT_EQ(dmsecrets_get_path(v, path, sizeof(path)), 0);
    DMOD_TEST_EXPECT_EQ(strcmp(path, VAULT_PATH), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "x", value, sizeof(value), &length), -EACCES);   /* locked */
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), 0);
    DMOD_TEST_EXPECT_TRUE(dmsecrets_is_unlocked(v));
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "wifi/Home", "hunter2", 7), 0);
    dmsecrets_close(v);

    /* a new open finds it, locked; the passphrase opens it and the record is there */
    v = open_vault(VAULT_PATH, 0);
    DMOD_TEST_EXPECT_NOT_NULL(v);
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "wifi/Home", value, sizeof(value), &length), 0);
    DMOD_TEST_EXPECT_EQ(length, 7);
    DMOD_TEST_EXPECT_EQ(memcmp(value, "hunter2", 7), 0);
    dmsecrets_close(v);
}

DMOD_TEST_STEP(a_wrong_passphrase_is_eacces_and_the_right_one_still_works)
{
    DMOD_TEST_EXPECT_TRUE(make_vault());
    dmsecrets_t v = open_vault(VAULT_PATH, 0);

    DMOD_TEST_EXPECT_NOT_NULL(v);
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, "wrong", 5), -EACCES);
    DMOD_TEST_EXPECT_FALSE(dmsecrets_is_unlocked(v));
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), 0);
    dmsecrets_close(v);
}

DMOD_TEST_STEP(records_are_set_read_replaced_listed_and_deleted)
{
    DMOD_TEST_EXPECT_TRUE(make_vault());
    dmsecrets_t v = open_vault(VAULT_PATH, 0);
    char value[16], name[32];
    size_t length = 0, count = 0;

    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), 0);

    DMOD_TEST_EXPECT_EQ(dmsecrets_count(v, NULL, &count), 0);
    DMOD_TEST_EXPECT_EQ(count, 3);
    DMOD_TEST_EXPECT_EQ(dmsecrets_count(v, "wifi/", &count), 0);
    DMOD_TEST_EXPECT_EQ(count, 2);
    DMOD_TEST_EXPECT_EQ(dmsecrets_name_at(v, "wifi/", 0, name, sizeof(name)), 0);
    DMOD_TEST_EXPECT_EQ(strcmp(name, "wifi/Home"), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_name_at(v, "wifi/", 1, name, sizeof(name)), 0);
    DMOD_TEST_EXPECT_EQ(strcmp(name, "wifi/Work"), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_name_at(v, "wifi/", 2, name, sizeof(name)), -ENOENT);
    DMOD_TEST_EXPECT_EQ(dmsecrets_name_at(v, "wifi/", 0, name, 4), -ENOSPC);

    /* get: the length comes also for no buffer and for one that is too small */
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "wifi/Work", NULL, 0, &length), 0);
    DMOD_TEST_EXPECT_EQ(length, 9);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "wifi/Work", value, 4, &length), -ENOSPC);
    DMOD_TEST_EXPECT_EQ(length, 9);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "nope", value, sizeof(value), &length), -ENOENT);

    /* replaced, an empty value, deleted - and it is all still so after a reopen */
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "wifi/Home", "new", 3), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "empty", NULL, 0), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_delete(v, "mqtt/broker"), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_delete(v, "mqtt/broker"), -ENOENT);
    dmsecrets_close(v);

    v = open_vault(VAULT_PATH, 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "wifi/Home", value, sizeof(value), &length), 0);
    DMOD_TEST_EXPECT_EQ(length, 3);
    DMOD_TEST_EXPECT_EQ(memcmp(value, "new", 3), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "empty", value, sizeof(value), &length), 0);
    DMOD_TEST_EXPECT_EQ(length, 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "mqtt/broker", value, sizeof(value), &length), -ENOENT);
    DMOD_TEST_EXPECT_EQ(dmsecrets_count(v, NULL, &count), 0);
    DMOD_TEST_EXPECT_EQ(count, 3);
    dmsecrets_close(v);
}

DMOD_TEST_STEP(lock_wipes_and_an_open_vault_is_open_once)
{
    DMOD_TEST_EXPECT_TRUE(make_vault());
    dmsecrets_t v = open_vault(VAULT_PATH, 0);
    dmsecrets_t again = NULL;
    dmsecrets_config_t config = { .path = VAULT_PATH };
    char value[16];
    size_t length = 0;

    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_open(&config, &again), -EBUSY);
    DMOD_TEST_EXPECT_EQ(dmsecrets_lock(v), 0);
    DMOD_TEST_EXPECT_FALSE(dmsecrets_is_unlocked(v));
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "wifi/Home", value, sizeof(value), &length), -EACCES);
    dmsecrets_close(v);

    again = open_vault(VAULT_PATH, 0);                           /* closed: it can be opened again */
    DMOD_TEST_EXPECT_NOT_NULL(again);
    dmsecrets_close(again);
    dmsecrets_close(NULL);
}

DMOD_TEST_STEP(two_vaults_are_independent)
{
    dmsecrets_t a = open_vault(VAULT_PATH, DMSECRETS_OPEN_CREATE);
    dmsecrets_t b = open_vault(VAULT_PATH2, DMSECRETS_OPEN_CREATE);
    char value[16];
    size_t length = 0;

    DMOD_TEST_EXPECT_NOT_NULL(a);
    DMOD_TEST_EXPECT_NOT_NULL(b);
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(a, "first", 5), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(b, "second", 6), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(a, "k", "in-a", 4), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(b, "k", "in-b", 4), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(a, "k", value, sizeof(value), &length), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(value, "in-a", 4), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(b, "k", value, sizeof(value), &length), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(value, "in-b", 4), 0);
    dmsecrets_close(a);
    dmsecrets_close(b);
}

DMOD_TEST_STEP(a_read_only_vault_changes_nothing)
{
    DMOD_TEST_EXPECT_TRUE(make_vault());
    dmsecrets_t v = open_vault(VAULT_PATH, DMSECRETS_OPEN_READONLY);
    char value[16];
    size_t length = 0;

    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "wifi/Home", value, sizeof(value), &length), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "x", "y", 1), -EROFS);
    DMOD_TEST_EXPECT_EQ(dmsecrets_delete(v, "wifi/Home"), -EROFS);
    DMOD_TEST_EXPECT_EQ(dmsecrets_change_passphrase(v, "new", 3), -EROFS);
    dmsecrets_close(v);
}

DMOD_TEST_STEP(the_passphrase_can_be_changed)
{
    DMOD_TEST_EXPECT_TRUE(make_vault());
    dmsecrets_t v = open_vault(VAULT_PATH, 0);
    char value[16];
    size_t length = 0;

    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_change_passphrase(v, "a new one", 9), 0);
    dmsecrets_close(v);

    v = open_vault(VAULT_PATH, 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), -EACCES);       /* the old one is gone, even from the older slot */
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, "a new one", 9), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "wifi/Work", value, sizeof(value), &length), 0);
    DMOD_TEST_EXPECT_EQ(length, 9);
    dmsecrets_close(v);
}

/* The file is changed behind the vault's back */
static void flip_byte(const char *path, size_t offset)
{
    void *file = Dmod_FileOpen(path, "r+");
    uint8_t byte = 0;

    Dmod_FileSeek(file, (Dmod_FileOffset_t)offset, 0);
    Dmod_FileRead(&byte, 1, 1, file);
    byte ^= 0x01;
    Dmod_FileSeek(file, (Dmod_FileOffset_t)offset, 0);
    Dmod_FileWrite(&byte, 1, 1, file);
    Dmod_FileClose(file);
}

DMOD_TEST_STEP(a_tampered_vault_is_not_opened)
{
    dmsecrets_t v = open_vault(VAULT_PATH, DMSECRETS_OPEN_CREATE);

    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "k", "v", 1), 0);
    dmsecrets_close(v);

    flip_byte(VAULT_PATH, 60);              /* the first slot's ciphertext */
    flip_byte(VAULT_PATH, 4160 + 20);       /* ... and the second slot's salt: no slot is whole */
    v = open_vault(VAULT_PATH, 0);
    DMOD_TEST_EXPECT_NOT_NULL(v);
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), -EACCES);
    dmsecrets_close(v);
}

DMOD_TEST_STEP(a_write_cut_short_leaves_the_previous_vault)
{
    dmsecrets_t v = open_vault(VAULT_PATH, DMSECRETS_OPEN_CREATE);
    char value[16];
    size_t length = 0;

    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), 0);       /* generation 1, slot 0 */
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "k", "old", 3), 0);           /* generation 2, slot 1 */
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "k", "new", 3), 0);           /* generation 3, slot 0 */
    dmsecrets_close(v);

    /* generation 3 (slot 0) is damaged in the middle: what is left is generation 2 */
    flip_byte(VAULT_PATH, 60);
    v = open_vault(VAULT_PATH, 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "k", value, sizeof(value), &length), 0);
    DMOD_TEST_EXPECT_EQ(memcmp(value, "old", 3), 0);
    dmsecrets_close(v);
}

DMOD_TEST_STEP(a_file_that_is_not_a_vault_is_ebadmsg)
{
    void *file = Dmod_FileOpen(VAULT_PATH, "w+");
    dmsecrets_config_t config = { .path = VAULT_PATH };
    dmsecrets_t vault = NULL;

    Dmod_FileWrite("this is not a vault, but it is long enough to have a header", 1, 60, file);
    Dmod_FileClose(file);
    DMOD_TEST_EXPECT_EQ(dmsecrets_open(&config, &vault), -EBADMSG);

    file = Dmod_FileOpen(VAULT_PATH, "w+");                       /* and one that is too short */
    Dmod_FileWrite("DMSV", 1, 4, file);
    Dmod_FileClose(file);
    DMOD_TEST_EXPECT_EQ(dmsecrets_open(&config, &vault), -EBADMSG);
}

DMOD_TEST_STEP(without_an_entropy_source_nothing_is_written)
{
    dmsecrets_t v = open_vault(VAULT_PATH, DMSECRETS_OPEN_CREATE);

    DMOD_TEST_EXPECT_EQ(dmcrypto_set_entropy(NULL, NULL), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), -ENODEV);
    DMOD_TEST_EXPECT_FALSE(dmsecrets_is_unlocked(v));
    dmsecrets_close(v);
    DMOD_TEST_EXPECT_FALSE(Dmod_FileAvailable(VAULT_PATH));
}

DMOD_TEST_STEP(limits_and_bad_arguments)
{
    dmsecrets_t v = open_vault(VAULT_PATH, DMSECRETS_OPEN_CREATE);
    uint8_t big[DMSECRETS_VALUE_MAX + 1] = { 0 };
    uint8_t chunk[1000] = { 0 };
    char longname[DMSECRETS_NAME_MAX + 2];
    char value[8];
    size_t length = 0;

    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "big", big, sizeof(big)), -EFBIG);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "", "x", 1), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, NULL, "x", 1), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "k", NULL, 1), -EINVAL);
    memset(longname, 'n', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, longname, "x", 1), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "k", value, sizeof(value), NULL), -EINVAL);
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, NULL, 0), 0);          /* already unlocked */

    /* the vault is full at some point (4096 bytes of records): the record that does not fit is not kept */
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "a", chunk, sizeof(chunk)), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "b", chunk, sizeof(chunk)), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "c", chunk, sizeof(chunk)), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "d", chunk, sizeof(chunk)), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "e", chunk, sizeof(chunk)), -ENOSPC);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "e", value, sizeof(value), &length), -ENOENT);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "d", NULL, 0, &length), 0);
    DMOD_TEST_EXPECT_EQ(length, 1000);
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "d", "short", 5), 0);    /* replacing one with a smaller one fits again */
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "e", chunk, sizeof(chunk)), 0);
    dmsecrets_close(v);
}

/* ---- The passphrase provider ---- */

static int provider_calls;
static bool provider_creating;

static int test_provider(void *context, bool creating, void *passphrase, size_t size, size_t *length)
{
    const char *text = context;

    provider_calls++;
    provider_creating = creating;
    if (text == NULL)
        return -ECANCELED;
    *length = strlen(text);
    if (*length > size)
        return -ENOSPC;
    memcpy(passphrase, text, *length);
    return 0;
}

DMOD_TEST_STEP(a_provider_unlocks_the_vault_on_first_use)
{
    dmsecrets_config_t config = { .path = VAULT_PATH, .flags = DMSECRETS_OPEN_CREATE,
                                  .passphrase_provider = test_provider, .provider_context = PASS };
    dmsecrets_t v = NULL;
    char value[16];
    size_t length = 0;

    provider_calls = 0;
    DMOD_TEST_EXPECT_EQ(dmsecrets_open(&config, &v), 0);
    DMOD_TEST_EXPECT_EQ(provider_calls, 0);                          /* open does not ask */
    DMOD_TEST_EXPECT_EQ(dmsecrets_set(v, "k", "secret", 6), 0);      /* the first use does: creating */
    DMOD_TEST_EXPECT_EQ(provider_calls, 1);
    DMOD_TEST_EXPECT_TRUE(provider_creating);
    DMOD_TEST_EXPECT_TRUE(dmsecrets_is_unlocked(v));
    DMOD_TEST_EXPECT_EQ(dmsecrets_lock(v), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "k", value, sizeof(value), &length), 0);   /* locked: asked again */
    DMOD_TEST_EXPECT_EQ(provider_calls, 2);
    DMOD_TEST_EXPECT_FALSE(provider_creating);
    DMOD_TEST_EXPECT_EQ(length, 6);
    dmsecrets_close(v);

    /* a provider that fails: its error is the operation's */
    config.provider_context = NULL;
    config.flags = 0;
    DMOD_TEST_EXPECT_EQ(dmsecrets_open(&config, &v), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "k", value, sizeof(value), &length), -ECANCELED);
    dmsecrets_close(v);

    /* a provider with the wrong passphrase */
    config.provider_context = "wrong";
    DMOD_TEST_EXPECT_EQ(dmsecrets_open(&config, &v), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "k", value, sizeof(value), &length), -EACCES);
    dmsecrets_close(v);
}

DMOD_TEST_STEP(a_vault_opens_by_its_domain_from_the_environment)
{
    dmsecrets_config_t config = { .domain = "wifi", .flags = DMSECRETS_OPEN_CREATE };
    dmsecrets_t v = NULL;
    char path[64];

    DMOD_TEST_EXPECT_EQ(dmsecrets_open(&config, &v), -ENOENT);                 /* nowhere to put it */
    Dmod_SetEnv("DMSECRETS_WIFI_PATH", VAULT_PATH, 1);
    DMOD_TEST_EXPECT_EQ(dmsecrets_open(&config, &v), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get_path(v, path, sizeof(path)), 0);
    DMOD_TEST_EXPECT_EQ(strcmp(path, VAULT_PATH), 0);
    dmsecrets_close(v);
}

/* ---- The secrets tool (run as a module; it asks for a passphrase only once a vault is opened) ---- */

DMOD_TEST_STEP(tool_prints_its_usage)
{
    char* help[] = { "secrets", "--help" };
    char* nothing[] = { "secrets", "frobnicate" };
    char* no_name[] = { "secrets", "get" };

    DMOD_TEST_EXPECT_EQ(Dmod_RunModule("secrets", 2, help), 0);
    DMOD_TEST_EXPECT_NE(Dmod_RunModule("secrets", 2, nothing), 0);
    DMOD_TEST_EXPECT_NE(Dmod_RunModule("secrets", 2, no_name), 0);
    DMOD_TEST_EXPECT_FALSE(Dmod_IsModuleLoaded("secrets"));
}

DMOD_TEST_STEP(tool_without_a_vault_fails_before_asking_anything)
{
    char* nowhere[] = { "secrets", "list" };                                   /* no path: the environment is empty */
    char* missing[] = { "secrets", "-f", "/tmp/dmsecrets_test_missing.vault", "list" };

    DMOD_TEST_EXPECT_NE(Dmod_RunModule("secrets", 2, nowhere), 0);
    DMOD_TEST_EXPECT_NE(Dmod_RunModule("secrets", 4, missing), 0);
}

DMOD_TEST_STEP(tool_does_not_create_over_a_vault)
{
    char* create[] = { "secrets", "-f", VAULT_PATH, "create" };

    DMOD_TEST_EXPECT_TRUE(make_vault());
    DMOD_TEST_EXPECT_NE(Dmod_RunModule("secrets", 4, create), 0);               /* "exists already", no prompt */

    /* and the vault is what it was */
    dmsecrets_t v = open_vault(VAULT_PATH, 0);
    char value[16];
    size_t length = 0;
    DMOD_TEST_EXPECT_EQ(dmsecrets_unlock(v, PASS, PASS_LEN), 0);
    DMOD_TEST_EXPECT_EQ(dmsecrets_get(v, "wifi/Home", value, sizeof(value), &length), 0);
    dmsecrets_close(v);
}
