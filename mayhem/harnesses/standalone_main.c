/*
 * standalone_main.c — run-once driver for liboqs' libFuzzer harnesses without the libFuzzer runtime.
 *
 * Reads a single input file and calls LLVMFuzzerTestOneInput once, so a crashing input found by
 * Mayhem/libFuzzer can be replayed under a debugger or ASan standalone.
 *
 * liboqs' harnesses declare LLVMFuzzerTestOneInput with differing first-arg types (const char* for
 * fuzz_test_kem/sig, const uint8_t* for the stateful ones). We forward-declare it as taking a void*
 * to stay compatible with either signature at link time (it is the same calling convention).
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const void *data, size_t size);

int main(int argc, char **argv) {
	if (argc != 2) {
		fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
		return 1;
	}
	FILE *f = fopen(argv[1], "rb");
	if (f == NULL) {
		fprintf(stderr, "failed to open %s\n", argv[1]);
		return 2;
	}
	fseek(f, 0, SEEK_END);
	long size = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (size < 0) {
		fclose(f);
		return 3;
	}
	uint8_t *data = malloc((size_t)size ? (size_t)size : 1);
	if (data == NULL) {
		fclose(f);
		return 3;
	}
	size_t got = (size > 0) ? fread(data, 1, (size_t)size, f) : 0;
	fclose(f);
	LLVMFuzzerTestOneInput(data, got);
	free(data);
	return 0;
}
