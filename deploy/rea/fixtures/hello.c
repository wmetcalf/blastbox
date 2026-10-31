/* Benign REA engine fixture: the same program is built as a PE (with an icon
 * resource) and an ELF. See build.sh; nothing here is malicious. */
#include <stdio.h>
static int add(int a, int b) { return a * 3 + b; }
int main(int argc, char **argv) {
    (void)argv;
    int v = add(argc, 7);
    printf("hello loadout %d\n", v);
    return v & 1;
}
