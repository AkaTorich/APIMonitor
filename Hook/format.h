#ifndef APIMON_FORMAT_H
#define APIMON_FORMAT_H

#include "hook_common.h"

/*
 * Each formatter writes into 'out' (size = chars including NUL) and returns
 * the resulting length in chars (excluding NUL). On a bogus pointer they
 * emit "<bad ptr 0x...>" instead of crashing.
 */
DWORD FmtPath        (LPCWSTR p,    LPWSTR out, DWORD cch);
DWORD FmtAccessRights(DWORD access, LPWSTR out, DWORD cch);
DWORD FmtShareMode   (DWORD share,  LPWSTR out, DWORD cch);
DWORD FmtCreateDisp  (DWORD disp,   LPWSTR out, DWORD cch);
DWORD FmtPageProtect (DWORD prot,   LPWSTR out, DWORD cch);
DWORD FmtAllocType   (DWORD t,      LPWSTR out, DWORD cch);
DWORD FmtProcCreate  (DWORD f,      LPWSTR out, DWORD cch);
DWORD FmtClsCtx      (DWORD c,      LPWSTR out, DWORD cch);
DWORD FmtCoInit      (DWORD c,      LPWSTR out, DWORD cch);
DWORD FmtHResult     (HRESULT hr,   LPWSTR out, DWORD cch);
DWORD FmtGuid        (const GUID *g, LPWSTR out, DWORD cch);

#endif
