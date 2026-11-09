/* Benign REA fixture for emulated unpacking (never run natively; see build.sh).
 *
 * The shape of a custom loader, with nothing hostile: it decrypts an embedded benign PE (the
 * fixture sample.exe) into a VirtualAlloc'd buffer, maps its sections into a second buffer,
 * VirtualProtects that RX, decrypts a few bytes of shellcode (mov eax, 42; ret) into another
 * buffer, makes it RX and calls it. Its strings (a URL, a user agent) are decrypted at run time
 * and passed to WinINet, so they appear only in API arguments. Built as unpack.exe (the work
 * runs from the entry point) and unpack.dll (DllMain does nothing; the export Stage runs it). */
#include <windows.h>
#include <wininet.h>
#include "stage.h"

static unsigned int next(unsigned int *s) {
    unsigned int x = *s;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *s = x;
    return x;
}

static void decrypt(volatile unsigned char *dst, const unsigned char *src, unsigned int n, unsigned int seed) {
    unsigned int s = seed;
    for (unsigned int i = 0; i < n; i++)
        dst[i] = src[i] ^ (unsigned char)next(&s);
}

static void copy(volatile unsigned char *dst, const volatile unsigned char *src, unsigned int n) {
    for (unsigned int i = 0; i < n; i++)
        dst[i] = src[i];
}

static int run(void) {
    char url[STR_URL_LEN], agent[STR_AGENT_LEN];
    DWORD old;
    decrypt((volatile unsigned char *)url, str_url, STR_URL_LEN, SEED_STR);
    decrypt((volatile unsigned char *)agent, str_agent, STR_AGENT_LEN, SEED_STR);
    CreateMutexA(NULL, FALSE, "Local\\LoadoutFixtureMutex");

    unsigned char *raw = VirtualAlloc(NULL, STAGE_ENC_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!raw) return 1;
    decrypt(raw, stage_enc, STAGE_ENC_LEN, SEED_STAGE);
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(raw + ((IMAGE_DOS_HEADER *)raw)->e_lfanew);
    unsigned int size = nt->OptionalHeader.SizeOfImage;
    unsigned char *img = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!img) return 2;
    copy(img, raw, nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        copy(img + sec[i].VirtualAddress, raw + sec[i].PointerToRawData, sec[i].SizeOfRawData);
    VirtualProtect(img, size, PAGE_EXECUTE_READ, &old);

    unsigned char *sc = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!sc) return 3;
    decrypt(sc, sc_enc, SC_ENC_LEN, SEED_SC);
    VirtualProtect(sc, 0x1000, PAGE_EXECUTE_READ, &old);
    int r = ((int (*)(void))sc)();

    HINTERNET net = InternetOpenA(agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (net) {
        HINTERNET h = InternetOpenUrlA(net, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (h) InternetCloseHandle(h);
        InternetCloseHandle(net);
    }
    return r;
}

#ifdef FIXTURE_DLL
BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)inst; (void)reason; (void)reserved;
    return TRUE;
}

__declspec(dllexport) int Stage(void) { return run(); }
#else
void start(void) { ExitProcess((UINT)run()); }
#endif
