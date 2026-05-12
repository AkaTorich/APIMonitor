#ifndef APIMON_RING_H
#define APIMON_RING_H

#include "hook_common.h"
#include "../apimon_proto.h"

/* Set up the shared-memory ring (per-pid file mapping). One-time, called
 * before HooksInstall. */
BOOL RingInit(void);
void RingShutdown(void);

/* Register slot_id -> (module, name) so the GUI can decode events.
 * Called once per hooked function, during HooksInstall (still under
 * g_in_init, so reentry is harmless). */
void RingRegisterSlot(UINT32 slot_id, const char *module, const char *name);

/* Hot-path event push. Pure memory operations - no kernel32 call.
 * caller_addr: return-address of the original call site - GUI resolves
 * it to the source module's full path.
 * args[0..11]: argument values (args[arity..] may be garbage). */
void RingPush(UINT32 slot_id, ULONG_PTR caller_addr, const ULONG_PTR *args12);

#endif
