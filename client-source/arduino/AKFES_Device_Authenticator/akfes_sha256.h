#ifndef AKFES_SHA256_H
#define AKFES_SHA256_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Small, allocation-free SHA-256/HMAC-SHA-256 implementation for AVR and
// other Arduino-compatible boards. AKFES uses a fixed 32-byte HMAC key.
namespace akfes_crypto {

struct Sha256Context {
  uint8_t block[64];
  uint32_t blockLength;
  uint64_t bitLength;
  uint32_t state[8];
};

static const uint32_t kRoundConstants[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL,
};

static inline uint32_t rotateRight(uint32_t value, uint8_t count) {
  return (value >> count) | (value << (32U - count));
}

static inline void secureZero(void *pointer, size_t length) {
  volatile uint8_t *bytes = static_cast<volatile uint8_t *>(pointer);
  while (length-- > 0) {
    *bytes++ = 0;
  }
}

static inline void transform(Sha256Context &context, const uint8_t block[64]) {
  uint32_t words[64];
  for (uint8_t index = 0; index < 16; ++index) {
    const uint8_t offset = static_cast<uint8_t>(index * 4U);
    words[index] = (static_cast<uint32_t>(block[offset]) << 24U) |
                   (static_cast<uint32_t>(block[offset + 1U]) << 16U) |
                   (static_cast<uint32_t>(block[offset + 2U]) << 8U) |
                   static_cast<uint32_t>(block[offset + 3U]);
  }
  for (uint8_t index = 16; index < 64; ++index) {
    const uint32_t previous15 = words[index - 15U];
    const uint32_t previous2 = words[index - 2U];
    const uint32_t sigma0 = rotateRight(previous15, 7U) ^
                            rotateRight(previous15, 18U) ^
                            (previous15 >> 3U);
    const uint32_t sigma1 = rotateRight(previous2, 17U) ^
                            rotateRight(previous2, 19U) ^
                            (previous2 >> 10U);
    words[index] = words[index - 16U] + sigma0 + words[index - 7U] + sigma1;
  }

  uint32_t a = context.state[0];
  uint32_t b = context.state[1];
  uint32_t c = context.state[2];
  uint32_t d = context.state[3];
  uint32_t e = context.state[4];
  uint32_t f = context.state[5];
  uint32_t g = context.state[6];
  uint32_t h = context.state[7];

  for (uint8_t index = 0; index < 64; ++index) {
    const uint32_t sum1 = rotateRight(e, 6U) ^ rotateRight(e, 11U) ^
                          rotateRight(e, 25U);
    const uint32_t choice = (e & f) ^ ((~e) & g);
    const uint32_t temporary1 = h + sum1 + choice + kRoundConstants[index] +
                                words[index];
    const uint32_t sum0 = rotateRight(a, 2U) ^ rotateRight(a, 13U) ^
                          rotateRight(a, 22U);
    const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    const uint32_t temporary2 = sum0 + majority;
    h = g;
    g = f;
    f = e;
    e = d + temporary1;
    d = c;
    c = b;
    b = a;
    a = temporary1 + temporary2;
  }

  context.state[0] += a;
  context.state[1] += b;
  context.state[2] += c;
  context.state[3] += d;
  context.state[4] += e;
  context.state[5] += f;
  context.state[6] += g;
  context.state[7] += h;
  secureZero(words, sizeof(words));
}

static inline void sha256Init(Sha256Context &context) {
  context.blockLength = 0;
  context.bitLength = 0;
  context.state[0] = 0x6a09e667UL;
  context.state[1] = 0xbb67ae85UL;
  context.state[2] = 0x3c6ef372UL;
  context.state[3] = 0xa54ff53aUL;
  context.state[4] = 0x510e527fUL;
  context.state[5] = 0x9b05688cUL;
  context.state[6] = 0x1f83d9abUL;
  context.state[7] = 0x5be0cd19UL;
}

static inline void sha256Update(Sha256Context &context, const uint8_t *data,
                                size_t length) {
  for (size_t index = 0; index < length; ++index) {
    context.block[context.blockLength++] = data[index];
    if (context.blockLength == 64U) {
      transform(context, context.block);
      context.bitLength += 512U;
      context.blockLength = 0;
    }
  }
}

static inline void sha256Final(Sha256Context &context, uint8_t digest[32]) {
  uint32_t index = context.blockLength;
  context.block[index++] = 0x80U;
  if (index > 56U) {
    while (index < 64U) {
      context.block[index++] = 0;
    }
    transform(context, context.block);
    index = 0;
  }
  while (index < 56U) {
    context.block[index++] = 0;
  }

  context.bitLength += static_cast<uint64_t>(context.blockLength) * 8U;
  for (uint8_t byteIndex = 0; byteIndex < 8U; ++byteIndex) {
    context.block[63U - byteIndex] =
        static_cast<uint8_t>(context.bitLength >> (byteIndex * 8U));
  }
  transform(context, context.block);

  for (uint8_t wordIndex = 0; wordIndex < 8U; ++wordIndex) {
    digest[wordIndex * 4U] =
        static_cast<uint8_t>(context.state[wordIndex] >> 24U);
    digest[wordIndex * 4U + 1U] =
        static_cast<uint8_t>(context.state[wordIndex] >> 16U);
    digest[wordIndex * 4U + 2U] =
        static_cast<uint8_t>(context.state[wordIndex] >> 8U);
    digest[wordIndex * 4U + 3U] =
        static_cast<uint8_t>(context.state[wordIndex]);
  }
}

static inline void hmacSha256(const uint8_t key[32], const uint8_t *message,
                              size_t messageLength, uint8_t digest[32]) {
  uint8_t innerPad[64];
  uint8_t outerPad[64];
  uint8_t innerDigest[32];
  for (uint8_t index = 0; index < 64U; ++index) {
    const uint8_t keyByte = index < 32U ? key[index] : 0U;
    innerPad[index] = static_cast<uint8_t>(keyByte ^ 0x36U);
    outerPad[index] = static_cast<uint8_t>(keyByte ^ 0x5cU);
  }

  Sha256Context context;
  sha256Init(context);
  sha256Update(context, innerPad, sizeof(innerPad));
  sha256Update(context, message, messageLength);
  sha256Final(context, innerDigest);

  sha256Init(context);
  sha256Update(context, outerPad, sizeof(outerPad));
  sha256Update(context, innerDigest, sizeof(innerDigest));
  sha256Final(context, digest);

  secureZero(&context, sizeof(context));
  secureZero(innerPad, sizeof(innerPad));
  secureZero(outerPad, sizeof(outerPad));
  secureZero(innerDigest, sizeof(innerDigest));
}

}  // namespace akfes_crypto

#endif
