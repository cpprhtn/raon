/* 범용 FILE_ARG 드라이버: LLVMFuzzerTestOneInput 타겟을 파일 입력으로 한 번 실행한다.
 * 실험(raon.bench.experiment)이 libFuzzer 타겟을 libFuzzer 런타임 없이(ASan만) 재현하는 데
 * 쓴다 — macOS 포함 어디서나 동작. 이 파일 자체는 버그가 없다.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    static unsigned char buf[1 << 20];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    return LLVMFuzzerTestOneInput(buf, n);
}
