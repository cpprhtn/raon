/* 의도적으로 취약한 데모 타겟 + FILE_ARG 하네스.
 * decode()는 입력이 8바이트를 넘으면 heap-buffer-overflow를 일으킨다.
 * raon 수직 슬라이스(P1) 검증용: 컴파일 → 크래시 → 파싱 → Finding.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int decode(const unsigned char *data, size_t size) {
    char *buf = (char *)malloc(8);
    memcpy(buf, data, size); /* size > 8 이면 오버플로우 */
    int r = buf[0];
    free(buf);
    return r;
}

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    unsigned char b[65536];
    size_t n = fread(b, 1, sizeof b, f);
    fclose(f);
    return decode(b, n);
}
