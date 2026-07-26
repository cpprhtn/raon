/* eval target: stack-buffer-overflow. Trigger: input longer than 16 bytes. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char buf[16];
    if (size) {
        memcpy(buf, data, size); /* overflow if size > 16 */
    }
    return buf[0];
}
