/* Benign REA fixture: imports nothing and resolves its APIs by walking the PEB and hashing
 * kernel32's export names (ror13), the way shellcode and stagers do (never run natively; see
 * build.sh). It creates a mutex and exits. */
#include <windows.h>
#include <winternl.h>


static unsigned int ror13(const char *s) {
    unsigned int h = 0;
    while (*s) { h = (h >> 13) | (h << 19); h += (unsigned char)*s++; }
    return h;
}

static int lower_eq(const WCHAR *w, unsigned short nbytes, const char *a) {
    unsigned short n = nbytes / 2;
    for (unsigned short i = 0; i < n; i++, a++) {
        WCHAR c = w[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        if (!*a || c != (WCHAR)*a) return 0;
    }
    return *a == 0;
}

static void *find(unsigned char *base, unsigned int want) {
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    IMAGE_DATA_DIRECTORY d = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *ex = (IMAGE_EXPORT_DIRECTORY *)(base + d.VirtualAddress);
    unsigned int *names = (unsigned int *)(base + ex->AddressOfNames);
    unsigned short *ords = (unsigned short *)(base + ex->AddressOfNameOrdinals);
    unsigned int *fns = (unsigned int *)(base + ex->AddressOfFunctions);
    for (unsigned int i = 0; i < ex->NumberOfNames; i++)
        if (ror13((const char *)base + names[i]) == want)
            return base + fns[ords[i]];
    return 0;
}

static unsigned char *kernel32(void) {
    PEB *peb = (PEB *)__readgsqword(0x60);
    LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
        LDR_DATA_TABLE_ENTRY *m = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        UNICODE_STRING *name = (UNICODE_STRING *)&m->Reserved4;  /* BaseDllName */
        if (name->Buffer && lower_eq(name->Buffer, name->Length, "kernel32.dll"))
            return (unsigned char *)m->DllBase;
    }
    return 0;
}

typedef HANDLE (WINAPI *create_mutex_t)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
typedef void (WINAPI *exit_process_t)(UINT);
typedef void (WINAPI *sleep_t)(DWORD);

void start(void) {
    unsigned char *k32 = kernel32();
    if (!k32) return;
    create_mutex_t create_mutex = (create_mutex_t)find(k32, 0x4ee4a045u);
    sleep_t sleep_fn = (sleep_t)find(k32, 0xdb2d49b0u);
    exit_process_t exit_process = (exit_process_t)find(k32, 0x73e2d87eu);
    if (create_mutex) create_mutex(NULL, FALSE, "Global\\LoadoutPebFixture");
    if (sleep_fn) sleep_fn(10);
    if (exit_process) exit_process(0);
}
