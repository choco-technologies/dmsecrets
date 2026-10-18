#define DMOD_ENABLE_REGISTRATION ON
#include "dmod_test.h"
#include "dmsecrets.h"

static dmsecrets_t g_handle = NULL;

void dmod_test_setup(void)
{
    g_handle = dmsecrets_create();
}

void dmod_test_teardown(void)
{
    dmsecrets_destroy(g_handle);
    g_handle = NULL;
}

DMOD_TEST_STEP(dmsecrets_create)
{
    DMOD_TEST_EXPECT_NOT_NULL(g_handle);
}

DMOD_TEST_STEP(dmsecrets_is_valid)
{
    DMOD_TEST_EXPECT_TRUE(dmsecrets_is_valid(g_handle));
}

DMOD_TEST_STEP(dmsecrets_destroy_null)
{
    /* Destroying NULL must not crash. */
    dmsecrets_destroy(NULL);
}
