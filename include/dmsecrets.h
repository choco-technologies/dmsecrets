#ifndef DMSECRETS_H
#define DMSECRETS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "dmod_types.h"
#include "dmsecrets_defs.h"

/**
 * Public API for the dmsecrets module.
 *
 * Functions are declared with the dmod_dmsecrets_api(...) macro - dmod's
 * standard pattern for functions callable from other modules (or from this
 * module's own tests/), resolved dynamically by the loader rather than
 * through normal static linkage. See dm_sw_ring/include/dm_sw_ring.h for a
 * fully worked real-world example of the same shape.
 *
 * Definitions in src/dmsecrets.c use the matching
 * dmod_dmsecrets_api_declaration(...) macro - a plain C function
 * definition here will NOT satisfy these declarations at link time.
 *
 * This is an example interface using the usual "opaque handle" pattern -
 * replace the handle, functions, and struct definition in
 * src/dmsecrets.c with your module's real API.
 */

/* Opaque handle - the real struct is defined in src/dmsecrets.c */
typedef struct dmsecrets* dmsecrets_t;

/**
 * Create a new dmsecrets instance.
 *
 * @return A valid handle on success, or NULL on allocation failure.
 */
dmod_dmsecrets_api(1.0, dmsecrets_t, _create, ( void ));

/**
 * Destroy an instance created by dmsecrets_create(). Safe to call with
 * NULL.
 */
dmod_dmsecrets_api(1.0, void, _destroy, ( dmsecrets_t handle ));

/**
 * Example accessor - replace with your module's real API.
 *
 * @return true if handle is a valid, non-NULL instance.
 */
dmod_dmsecrets_api(1.0, bool, _is_valid, ( dmsecrets_t handle ));

#endif // DMSECRETS_H
