#include "Arduino.h"

FakeSerialPort Serial;

#define AKFES_DEVICE_SECRET_HEX \
  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
#include "../AKFES_Device_Authenticator/AKFES_Device_Authenticator.ino"

#include <stdio.h>

int main() {
  setup();
  Serial.input =
      "CHALLENGE "
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
  loop();
  const std::string expected =
      "RESPONSE "
      "ca7eb12f3689793fd47c65dcd0f01941299e641cc5db4f838f5c9f38e75c423b\n";
  if (Serial.output != expected) {
    fprintf(stderr, "firmware response mismatch: %s", Serial.output.c_str());
    return 1;
  }

  Serial.input = "BAD COMMAND\n";
  Serial.inputOffset = 0;
  Serial.output.clear();
  loop();
  if (Serial.output != "ERROR INVALID_COMMAND\n") {
    fprintf(stderr, "firmware invalid-command handling failed: %s",
            Serial.output.c_str());
    return 2;
  }

  puts("AKFES Arduino firmware protocol self-test PASS");
  return 0;
}
