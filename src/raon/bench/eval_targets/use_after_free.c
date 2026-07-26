/* eval target: heap-use-after-free. Trigger: input of 5+ bytes. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *p = (char *)malloc(16);
    p[0] = (char)size;
    free(p);
    if (size > 4) {
        return p[0]; /* use after free */
    }
    return 0;
}
