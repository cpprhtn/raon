/* eval target: heap-buffer-overflow. Trigger: input longer than 8 bytes. */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *buf = (char *)malloc(8);
    memcpy(buf, data, size); /* overflow if size > 8 */
    int r = buf[0];
    free(buf);
    (void)r;
    return 0;
}
