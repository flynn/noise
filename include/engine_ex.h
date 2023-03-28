
#include <stdint.h>

void EncryptText_GO(unsigned char *key, uint64_t keyLength,
                    unsigned char *input, uint64_t inputLength,
                    unsigned char *output, uint64_t *outputLength);

void DecryptText_GO(unsigned char *key, uint64_t keyLength,
                    unsigned char *input, uint64_t inputLength,
                    unsigned char *output, uint64_t *outputLength);
