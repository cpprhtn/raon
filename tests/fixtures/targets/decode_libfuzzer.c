/* libFuzzer 하네스 — LLVMFuzzerTestOneInput.
 * size > 8 이면 heap-buffer-overflow. libFuzzer가 커버리지 유도로 빠르게 크래시를 찾는다.
 * Linux clang(libFuzzer 런타임 포함)에서만 빌드/실행된다.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *buf = (char *)malloc(8);
    memcpy(buf, data, size); /* size > 8 이면 오버플로우 */
    int r = buf[0];
    free(buf);
    (void)r;
    return 0;
}
