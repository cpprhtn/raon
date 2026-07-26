/* eval target: global-buffer-overflow. Trigger: input longer than 16 bytes. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static char g_buf[16];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size) {
        memcpy(g_buf, data, size); /* overflow if size > 16 */
    }
    return g_buf[0];
}
