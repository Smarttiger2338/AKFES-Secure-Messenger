#include <Arduino.h>
#include "akfes_sha256.h"

// Filled by the AKFES Windows client. The server master secret and the user's
// PIN are never placed in this firmware.
#ifndef AKFES_DEVICE_SECRET_HEX
#define AKFES_DEVICE_SECRET_HEX "AKFES_DEVICE_SECRET_HEX_PLACEHOLDER"
#endif
#ifndef AKFES_KEYPAD_COLUMNS
#define AKFES_KEYPAD_COLUMNS 3
#endif
#ifndef AKFES_KEYPAD_ROW_PINS
#define AKFES_KEYPAD_ROW_PINS {2, 3, 4, 5}
#endif
#ifndef AKFES_KEYPAD_COLUMN_PINS
#define AKFES_KEYPAD_COLUMN_PINS {6, 7, 8}
#endif
#ifndef AKFES_KEYPAD_KEYMAP
#define AKFES_KEYPAD_KEYMAP "123456789*0#"
#endif
#ifndef AKFES_KEYPAD_CLEAR_KEY
#define AKFES_KEYPAD_CLEAR_KEY '*'
#endif
#ifndef AKFES_KEYPAD_CONFIRM_KEY
#define AKFES_KEYPAD_CONFIRM_KEY '#'
#endif

static const char kDeviceSecretHex[] = AKFES_DEVICE_SECRET_HEX;
static const uint8_t kRowPins[4] = AKFES_KEYPAD_ROW_PINS;
static const uint8_t kColumnPins[AKFES_KEYPAD_COLUMNS] = AKFES_KEYPAD_COLUMN_PINS;
static const char kKeymap[] = AKFES_KEYPAD_KEYMAP;
static const char kClearKey = AKFES_KEYPAD_CLEAR_KEY;
static const char kConfirmKey = AKFES_KEYPAD_CONFIRM_KEY;
static const uint32_t kBaudRate = 115200UL;
static const char kChallengePrefix[] = "CHALLENGE ";
static const char kAuthPrefix[] = "AUTH ";
static const size_t kNonceHexLength = 64U;
static const size_t kCommandMaxLength = 10U + kNonceHexLength;
static const size_t kMinPinLength = 6U;
static const size_t kMaxPinLength = 12U;
static const uint32_t kPinEntryTimeoutMs = 60000UL;
static char inputLine[kCommandMaxLength + 1U];
static size_t inputLength = 0;
static bool inputOverflow = false;

static int8_t hexValue(char value) {
  if (value >= '0' && value <= '9') return static_cast<int8_t>(value - '0');
  if (value >= 'a' && value <= 'f') return static_cast<int8_t>(value - 'a' + 10);
  if (value >= 'A' && value <= 'F') return static_cast<int8_t>(value - 'A' + 10);
  return -1;
}

static bool decodeDeviceSecret(uint8_t output[32]) {
  if (strlen(kDeviceSecretHex) != 64U) return false;
  for (size_t index = 0; index < 32U; ++index) {
    const int8_t high = hexValue(kDeviceSecretHex[index * 2U]);
    const int8_t low = hexValue(kDeviceSecretHex[index * 2U + 1U]);
    if (high < 0 || low < 0) {
      akfes_crypto::secureZero(output, 32U);
      return false;
    }
    output[index] = static_cast<uint8_t>((high << 4U) | low);
  }
  return true;
}

static bool isHexNonce(const char *nonce) {
  for (size_t index = 0; index < kNonceHexLength; ++index) {
    if (hexValue(nonce[index]) < 0) return false;
  }
  return nonce[kNonceHexLength] == '\0';
}

static void writeHex(const uint8_t *bytes, size_t length) {
  static const char kHexAlphabet[] = "0123456789abcdef";
  for (size_t index = 0; index < length; ++index) {
    Serial.write(kHexAlphabet[bytes[index] >> 4U]);
    Serial.write(kHexAlphabet[bytes[index] & 0x0fU]);
  }
}

static void configureKeypad() {
  for (size_t row = 0; row < 4U; ++row) pinMode(kRowPins[row], INPUT_PULLUP);
  for (size_t column = 0; column < AKFES_KEYPAD_COLUMNS; ++column) {
    pinMode(kColumnPins[column], OUTPUT);
    digitalWrite(kColumnPins[column], HIGH);
  }
}

static char scanKeypad() {
  for (size_t column = 0; column < AKFES_KEYPAD_COLUMNS; ++column) {
    digitalWrite(kColumnPins[column], LOW);
    delayMicroseconds(4U);
    for (size_t row = 0; row < 4U; ++row) {
      if (digitalRead(kRowPins[row]) == LOW) {
        digitalWrite(kColumnPins[column], HIGH);
        return kKeymap[row * AKFES_KEYPAD_COLUMNS + column];
      }
    }
    digitalWrite(kColumnPins[column], HIGH);
  }
  return '\0';
}

static char readDebouncedKey() {
  const char first = scanKeypad();
  if (first == '\0') return '\0';
  delay(25U);
  if (scanKeypad() != first) return '\0';
  while (scanKeypad() == first) delay(5U);
  return first;
}

static bool readPinFromKeypad(char output[kMaxPinLength + 1U]) {
  size_t length = 0U;
  const uint32_t started = millis();
  Serial.println(F("PIN_REQUIRED"));
  Serial.flush();
  while (static_cast<uint32_t>(millis() - started) < kPinEntryTimeoutMs) {
    const char key = readDebouncedKey();
    if (key == '\0') { delay(5U); continue; }
    if (key == kClearKey) {
      akfes_crypto::secureZero(output, kMaxPinLength + 1U);
      length = 0U;
      Serial.println(F("PIN_CLEARED"));
      continue;
    }
    if (key == kConfirmKey) {
      if (length >= kMinPinLength) {
        output[length] = '\0';
        return true;
      }
      akfes_crypto::secureZero(output, kMaxPinLength + 1U);
      length = 0U;
      Serial.println(F("PIN_TOO_SHORT"));
      continue;
    }
    if (key >= '0' && key <= '9' && length < kMaxPinLength) {
      output[length++] = key;
      Serial.println(F("PIN_KEY"));
    }
  }
  akfes_crypto::secureZero(output, kMaxPinLength + 1U);
  Serial.println(F("ERROR PIN_TIMEOUT"));
  return false;
}

static void enrollPinFromKeypad() {
  uint8_t deviceSecret[32];
  if (!decodeDeviceSecret(deviceSecret)) {
    Serial.println(F("ERROR NOT_PROVISIONED"));
    return;
  }
  char first[kMaxPinLength + 1U] = {0};
  char confirmation[kMaxPinLength + 1U] = {0};
  Serial.println(F("PIN_NEW"));
  if (!readPinFromKeypad(first)) {
    akfes_crypto::secureZero(deviceSecret, sizeof(deviceSecret));
    return;
  }
  Serial.println(F("PIN_CONFIRM"));
  if (!readPinFromKeypad(confirmation)) {
    akfes_crypto::secureZero(first, sizeof(first));
    akfes_crypto::secureZero(deviceSecret, sizeof(deviceSecret));
    return;
  }
  uint8_t difference = 0U;
  for (size_t index = 0; index < sizeof(first); ++index) {
    difference |= static_cast<uint8_t>(first[index] ^ confirmation[index]);
  }
  if (difference != 0U) {
    Serial.println(F("ERROR PIN_MISMATCH"));
    akfes_crypto::secureZero(first, sizeof(first));
    akfes_crypto::secureZero(confirmation, sizeof(confirmation));
    akfes_crypto::secureZero(deviceSecret, sizeof(deviceSecret));
    return;
  }
  char pinMessage[14U + kMaxPinLength] = {0};
  strcpy(pinMessage, "akfes-pin-v1:");
  strcat(pinMessage, first);
  uint8_t pinKey[32];
  akfes_crypto::hmacSha256(deviceSecret,
      reinterpret_cast<const uint8_t *>(pinMessage), strlen(pinMessage), pinKey);
  Serial.print(F("PINKEY "));
  writeHex(pinKey, sizeof(pinKey));
  Serial.println();
  Serial.flush();
  akfes_crypto::secureZero(first, sizeof(first));
  akfes_crypto::secureZero(confirmation, sizeof(confirmation));
  akfes_crypto::secureZero(pinMessage, sizeof(pinMessage));
  akfes_crypto::secureZero(pinKey, sizeof(pinKey));
  akfes_crypto::secureZero(deviceSecret, sizeof(deviceSecret));
}

static void processCommand(char *line) {
  if (strcmp(line, "ENROLL") == 0) {
    enrollPinFromKeypad();
    return;
  }
  const bool keypadAuthentication = strncmp(line, kAuthPrefix, 5U) == 0;
  const bool provisioningProbe = strncmp(line, kChallengePrefix, 10U) == 0;
  char *nonce = keypadAuthentication ? line + 5U : (provisioningProbe ? line + 10U : nullptr);
  if (nonce == nullptr || !isHexNonce(nonce)) {
    Serial.println(F("ERROR INVALID_COMMAND"));
    return;
  }

  uint8_t deviceSecret[32];
  if (!decodeDeviceSecret(deviceSecret)) {
    Serial.println(F("ERROR NOT_PROVISIONED"));
    return;
  }

  uint8_t challengeKey[32] = {0};
  const uint8_t *activeKey = deviceSecret;
  char pin[kMaxPinLength + 1U] = {0};
  char pinMessage[14U + kMaxPinLength] = {0};
  if (keypadAuthentication) {
    if (!readPinFromKeypad(pin)) {
      akfes_crypto::secureZero(deviceSecret, sizeof(deviceSecret));
      return;
    }
    strcpy(pinMessage, "akfes-pin-v1:");
    strcat(pinMessage, pin);
    akfes_crypto::hmacSha256(deviceSecret,
        reinterpret_cast<const uint8_t *>(pinMessage), strlen(pinMessage), challengeKey);
    activeKey = challengeKey;
  }

  uint8_t response[32];
  akfes_crypto::hmacSha256(activeKey, reinterpret_cast<const uint8_t *>(nonce),
                          kNonceHexLength, response);
  Serial.print(F("RESPONSE "));
  writeHex(response, sizeof(response));
  Serial.println();
  Serial.flush();

  akfes_crypto::secureZero(pin, sizeof(pin));
  akfes_crypto::secureZero(pinMessage, sizeof(pinMessage));
  akfes_crypto::secureZero(deviceSecret, sizeof(deviceSecret));
  akfes_crypto::secureZero(challengeKey, sizeof(challengeKey));
  akfes_crypto::secureZero(response, sizeof(response));
}

void setup() {
  Serial.begin(kBaudRate);
  configureKeypad();
}

void loop() {
  while (Serial.available() > 0) {
    const char incoming = static_cast<char>(Serial.read());
    if (incoming == '\r') continue;
    if (incoming == '\n') {
      if (inputOverflow) Serial.println(F("ERROR LINE_TOO_LONG"));
      else if (inputLength > 0U) {
        inputLine[inputLength] = '\0';
        processCommand(inputLine);
      }
      akfes_crypto::secureZero(inputLine, sizeof(inputLine));
      inputLength = 0U;
      inputOverflow = false;
      continue;
    }
    if (!inputOverflow && inputLength < kCommandMaxLength) inputLine[inputLength++] = incoming;
    else inputOverflow = true;
  }
}
