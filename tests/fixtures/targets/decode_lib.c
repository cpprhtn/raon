/* main 없는 라이브러리 함수 — 하네스 자동합성 대상.
 * LLM이 이 함수를 호출하는 하네스(main)를 합성해야 한다.
 * size > 8 이면 heap-buffer-overflow.
 */
#include <stdlib.h>
#include <string.h>

int decode(const unsigned char *data, size_t size) {
    char *buf = (char *)malloc(8);
    memcpy(buf, data, size);
    int r = buf[0];
    free(buf);
    return r;
}
