/*
 * format.c - flag/path/GUID decoders for hooks_simple.c. CRT-free; built around wsprintfW.
 */
#include "hook_common.h"
#include "format.h"

static DWORD FmtAppend(LPWSTR out, DWORD cch, DWORD pos, LPCWSTR text)
{
    DWORD i = 0;
    while (text[i] != L'\0' && pos + 1 < cch) out[pos++] = text[i++];
    out[pos] = L'\0';
    return pos;
}

static DWORD FmtAppendBitWord(LPWSTR out, DWORD cch, DWORD pos, BOOL isFirst, LPCWSTR word)
{
    if (!isFirst) pos = FmtAppend(out, cch, pos, L"|");
    return FmtAppend(out, cch, pos, word);
}

DWORD FmtPath(LPCWSTR p, LPWSTR out, DWORD cch)
{
    DWORD pos = 0;
    DWORD i;
    if (p == NULL) return (DWORD)wsprintfW(out, L"NULL");

    __try {
        pos = FmtAppend(out, cch, 0, L"\"");
        for (i = 0; i < 200 && p[i] != L'\0' && pos + 2 < cch; i++) {
            WCHAR ch = p[i];
            if (ch == L'\\' && pos + 3 < cch) { out[pos++] = L'\\'; out[pos++] = L'\\'; }
            else if (ch == L'"'  && pos + 3 < cch) { out[pos++] = L'\\'; out[pos++] = L'"';  }
            else                                   { out[pos++] = ch; }
        }
        if (i == 200 && p[i] != L'\0') pos = FmtAppend(out, cch, pos, L"...");
        pos = FmtAppend(out, cch, pos, L"\"");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        pos = (DWORD)wsprintfW(out, L"<bad ptr 0x%p>", p);
    }
    return pos;
}

#define BIT(name, bit) do { if ((flags & (bit)) == (bit)) { pos = FmtAppendBitWord(out,cch,pos,first,name); first = FALSE; flags &= ~(bit); } } while (0)

DWORD FmtAccessRights(DWORD access, LPWSTR out, DWORD cch)
{
    DWORD pos = 0; BOOL first = TRUE; DWORD flags = access;
    if (access == 0) return (DWORD)wsprintfW(out, L"0");
    BIT(L"GENERIC_READ",    0x80000000);
    BIT(L"GENERIC_WRITE",   0x40000000);
    BIT(L"GENERIC_EXECUTE", 0x20000000);
    BIT(L"GENERIC_ALL",     0x10000000);
    BIT(L"FILE_READ_DATA",  0x0001);
    BIT(L"FILE_WRITE_DATA", 0x0002);
    BIT(L"FILE_APPEND_DATA",0x0004);
    BIT(L"PROCESS_ALL_ACCESS", 0x1FFFFF);
    BIT(L"SYNCHRONIZE",     0x100000);
    if (flags) { WCHAR t[24]; wsprintfW(t, L"0x%X", flags); pos = FmtAppendBitWord(out,cch,pos,first,t); }
    return pos;
}

DWORD FmtShareMode(DWORD share, LPWSTR out, DWORD cch)
{
    DWORD pos = 0; BOOL first = TRUE; DWORD flags = share;
    if (share == 0) return (DWORD)wsprintfW(out, L"0");
    BIT(L"FILE_SHARE_READ",   0x1);
    BIT(L"FILE_SHARE_WRITE",  0x2);
    BIT(L"FILE_SHARE_DELETE", 0x4);
    if (flags) { WCHAR t[16]; wsprintfW(t, L"0x%X", flags); pos = FmtAppendBitWord(out,cch,pos,first,t); }
    return pos;
}

DWORD FmtCreateDisp(DWORD disp, LPWSTR out, DWORD cch)
{
    switch (disp) {
        case 1: return (DWORD)wsprintfW(out, L"CREATE_NEW");
        case 2: return (DWORD)wsprintfW(out, L"CREATE_ALWAYS");
        case 3: return (DWORD)wsprintfW(out, L"OPEN_EXISTING");
        case 4: return (DWORD)wsprintfW(out, L"OPEN_ALWAYS");
        case 5: return (DWORD)wsprintfW(out, L"TRUNCATE_EXISTING");
        default: return (DWORD)wsprintfW(out, L"%u", disp);
    }
}

DWORD FmtPageProtect(DWORD prot, LPWSTR out, DWORD cch)
{
    switch (prot & 0xFF) {
        case 0x01: return (DWORD)wsprintfW(out, L"PAGE_NOACCESS");
        case 0x02: return (DWORD)wsprintfW(out, L"PAGE_READONLY");
        case 0x04: return (DWORD)wsprintfW(out, L"PAGE_READWRITE");
        case 0x08: return (DWORD)wsprintfW(out, L"PAGE_WRITECOPY");
        case 0x10: return (DWORD)wsprintfW(out, L"PAGE_EXECUTE");
        case 0x20: return (DWORD)wsprintfW(out, L"PAGE_EXECUTE_READ");
        case 0x40: return (DWORD)wsprintfW(out, L"PAGE_EXECUTE_READWRITE");
        case 0x80: return (DWORD)wsprintfW(out, L"PAGE_EXECUTE_WRITECOPY");
        default:   return (DWORD)wsprintfW(out, L"0x%X", prot);
    }
}

DWORD FmtAllocType(DWORD t, LPWSTR out, DWORD cch)
{
    DWORD pos = 0; BOOL first = TRUE; DWORD flags = t;
    if (t == 0) return (DWORD)wsprintfW(out, L"0");
    BIT(L"MEM_COMMIT",      0x1000);
    BIT(L"MEM_RESERVE",     0x2000);
    BIT(L"MEM_RESET",       0x80000);
    BIT(L"MEM_LARGE_PAGES", 0x20000000);
    BIT(L"MEM_TOP_DOWN",    0x100000);
    if (flags) { WCHAR tmp[16]; wsprintfW(tmp, L"0x%X", flags); pos = FmtAppendBitWord(out,cch,pos,first,tmp); }
    return pos;
}

DWORD FmtProcCreate(DWORD f, LPWSTR out, DWORD cch)
{
    DWORD pos = 0; BOOL first = TRUE; DWORD flags = f;
    if (f == 0) return (DWORD)wsprintfW(out, L"0");
    BIT(L"CREATE_SUSPENDED",   0x4);
    BIT(L"CREATE_NEW_CONSOLE", 0x10);
    BIT(L"DEBUG_PROCESS",      0x1);
    BIT(L"DEBUG_ONLY_THIS_PROCESS", 0x2);
    BIT(L"DETACHED_PROCESS",   0x8);
    BIT(L"CREATE_NO_WINDOW",   0x08000000);
    BIT(L"CREATE_UNICODE_ENVIRONMENT", 0x400);
    if (flags) { WCHAR t[16]; wsprintfW(t, L"0x%X", flags); pos = FmtAppendBitWord(out,cch,pos,first,t); }
    return pos;
}

DWORD FmtClsCtx(DWORD c, LPWSTR out, DWORD cch)
{
    DWORD pos = 0; BOOL first = TRUE; DWORD flags = c;
    if (c == 0) return (DWORD)wsprintfW(out, L"0");
    BIT(L"CLSCTX_INPROC_SERVER",  0x1);
    BIT(L"CLSCTX_INPROC_HANDLER", 0x2);
    BIT(L"CLSCTX_LOCAL_SERVER",   0x4);
    BIT(L"CLSCTX_REMOTE_SERVER",  0x10);
    if (flags) { WCHAR t[16]; wsprintfW(t, L"0x%X", flags); pos = FmtAppendBitWord(out,cch,pos,first,t); }
    return pos;
}

DWORD FmtCoInit(DWORD c, LPWSTR out, DWORD cch)
{
    DWORD pos = 0; BOOL first = TRUE; DWORD flags = c;
    if ((c & 3) == 0) {
        pos = FmtAppendBitWord(out, cch, pos, first, L"COINIT_MULTITHREADED");
        first = FALSE;
    } else if ((c & 2) == 2) {
        pos = FmtAppendBitWord(out, cch, pos, first, L"COINIT_APARTMENTTHREADED");
        first = FALSE;
    }
    flags &= ~3u;
    BIT(L"COINIT_DISABLE_OLE1DDE",  0x4);
    BIT(L"COINIT_SPEED_OVER_MEMORY",0x8);
    if (flags) { WCHAR t[16]; wsprintfW(t, L"0x%X", flags); pos = FmtAppendBitWord(out,cch,pos,first,t); }
    return pos;
}

#undef BIT

DWORD FmtHResult(HRESULT hr, LPWSTR out, DWORD cch)
{
    switch ((DWORD)hr) {
        case 0x00000000: return (DWORD)wsprintfW(out, L"S_OK");
        case 0x00000001: return (DWORD)wsprintfW(out, L"S_FALSE");
        case 0x80004001: return (DWORD)wsprintfW(out, L"E_NOTIMPL");
        case 0x80004002: return (DWORD)wsprintfW(out, L"E_NOINTERFACE");
        case 0x80004003: return (DWORD)wsprintfW(out, L"E_POINTER");
        case 0x80004004: return (DWORD)wsprintfW(out, L"E_ABORT");
        case 0x80004005: return (DWORD)wsprintfW(out, L"E_FAIL");
        case 0x80070005: return (DWORD)wsprintfW(out, L"E_ACCESSDENIED");
        case 0x8007000E: return (DWORD)wsprintfW(out, L"E_OUTOFMEMORY");
        case 0x80040154: return (DWORD)wsprintfW(out, L"REGDB_E_CLASSNOTREG");
        default:         return (DWORD)wsprintfW(out, L"0x%08X", (DWORD)hr);
    }
}

typedef struct { GUID guid; LPCWSTR name; } KNOWN_GUID;
static const KNOWN_GUID g_known[] = {
    { { 0x00020400, 0x0000, 0x0000, { 0xC0,0,0,0,0,0,0,0x46 } }, L"IID_IDispatch" },
    { { 0x00000000, 0x0000, 0x0000, { 0xC0,0,0,0,0,0,0,0x46 } }, L"IID_IUnknown" },
    { { 0x00000001, 0x0000, 0x0000, { 0xC0,0,0,0,0,0,0,0x46 } }, L"IID_IClassFactory" },
    { { 0x00021401, 0x0000, 0x0000, { 0xC0,0,0,0,0,0,0,0x46 } }, L"CLSID_ShellLink" },
    { { 0x000214EE, 0x0000, 0x0000, { 0xC0,0,0,0,0,0,0,0x46 } }, L"IID_IShellLinkA" },
    { { 0x000214F9, 0x0000, 0x0000, { 0xC0,0,0,0,0,0,0,0x46 } }, L"IID_IShellLinkW" },
    { { 0x0000010B, 0x0000, 0x0000, { 0xC0,0,0,0,0,0,0,0x46 } }, L"IID_IPersistFile" },
};

static BOOL GuidEqual(const GUID *a, const GUID *b)
{
    const DWORD *pa = (const DWORD *)a;
    const DWORD *pb = (const DWORD *)b;
    return pa[0] == pb[0] && pa[1] == pb[1] && pa[2] == pb[2] && pa[3] == pb[3];
}

DWORD FmtGuid(const GUID *g, LPWSTR out, DWORD cch)
{
    DWORD i;
    if (g == NULL) return (DWORD)wsprintfW(out, L"NULL");

    __try {
        for (i = 0; i < ARRAYSIZE(g_known); i++)
            if (GuidEqual(&g_known[i].guid, g))
                return (DWORD)wsprintfW(out, L"%s", g_known[i].name);

        return (DWORD)wsprintfW(
            out,
            L"{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            g->Data1, g->Data2, g->Data3,
            g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3],
            g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7]);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return (DWORD)wsprintfW(out, L"<bad guid ptr>");
    }
}
