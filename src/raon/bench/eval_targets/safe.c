/* eval target: SAFE (no bug). Used as a false-positive check — raon should
 * find no crash here. All reads/writes are bounded. */
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    unsigned sum = 0;
    for (size_t i = 0; i < size; i++) {
        sum += data[i];
    }
    return (int)(sum & 0x7f);
}
