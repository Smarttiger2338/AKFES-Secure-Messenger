#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../AKFES_Device_Authenticator/akfes_sha256.h"

static void toHex(const uint8_t *input, size_t length, char *output) {
  static const char alphabet[] = "0123456789abcdef";
  for (size_t index = 0; index < length; ++index) {
    output[index * 2U] = alphabet[input[index] >> 4U];
    output[index * 2U + 1U] = alphabet[input[index] & 0x0fU];
  }
  output[length * 2U] = '\0';
}

int main() {
  uint8_t digest[32];
  char digestHex[65];

  akfes_crypto::Sha256Context shaContext;
  akfes_crypto::sha256Init(shaContext);
  const uint8_t abc[] = {'a', 'b', 'c'};
  akfes_crypto::sha256Update(shaContext, abc, sizeof(abc));
  akfes_crypto::sha256Final(shaContext, digest);
  toHex(digest, sizeof(digest), digestHex);
  if (strcmp(digestHex,
             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") != 0) {
    fprintf(stderr, "SHA-256 self-test failed: %s\n", digestHex);
    return 1;
  }

  uint8_t key[32];
  for (uint8_t index = 0; index < sizeof(key); ++index) {
    key[index] = index;
  }
  const uint8_t nonce[] =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  akfes_crypto::hmacSha256(key, nonce, sizeof(nonce) - 1U, digest);
  toHex(digest, sizeof(digest), digestHex);
  if (strcmp(digestHex,
             "ca7eb12f3689793fd47c65dcd0f01941299e641cc5db4f838f5c9f38e75c423b") != 0) {
    fprintf(stderr, "HMAC-SHA-256 self-test failed: %s\n", digestHex);
    return 2;
  }

  puts("AKFES Arduino SHA-256/HMAC-SHA-256 self-test PASS");
  return 0;
}
