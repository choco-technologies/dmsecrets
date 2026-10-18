#define DMOD_ENABLE_REGISTRATION ON
#include "dmod_test.h"
#include "dmsecrets.h"
#include <errno.h>
#include <string.h>

/* The interface: where a vault is found (the rest of the API is not written yet) */

static void clear_environment(void)
{
    Dmod_SetEnv("DMSECRETS_PATH", "", 1);
    Dmod_SetEnv("DMSECRETS_WIFI_PATH", "", 1);
    Dmod_SetEnv("DMSECRETS_MY_LIB_PATH", "", 1);
}

void dmod_test_setup(void)
{
    clear_environment();
}

void dmod_test_teardown(void)
{
    clear_environment();
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
