#ifndef AKFES_TEST_ARDUINO_H
#define AKFES_TEST_ARDUINO_H

#include <stdint.h>
#include <string>

#define F(value) value
#define INPUT_PULLUP 2
#define OUTPUT 1
#define HIGH 1
#define LOW 0

inline void pinMode(uint8_t, uint8_t) {}
inline void digitalWrite(uint8_t, uint8_t) {}
inline int digitalRead(uint8_t) { return HIGH; }
inline void delayMicroseconds(unsigned int) {}
inline void delay(unsigned long) {}
inline uint32_t millis() { static uint32_t now = 0; return ++now; }

class FakeSerialPort {
 public:
  std::string input;
  std::string output;
  size_t inputOffset = 0;

  void begin(uint32_t) {}
  int available() const {
    return inputOffset < input.size()
               ? static_cast<int>(input.size() - inputOffset)
               : 0;
  }
  int read() {
    return inputOffset < input.size()
               ? static_cast<unsigned char>(input[inputOffset++])
               : -1;
  }
  size_t write(uint8_t value) {
    output.push_back(static_cast<char>(value));
    return 1;
  }
  size_t print(const char *value) {
    output.append(value);
    return std::char_traits<char>::length(value);
  }
  size_t println(const char *value) {
    const size_t written = print(value);
    output.push_back('\n');
    return written + 1U;
  }
  size_t println() {
    output.push_back('\n');
    return 1;
  }
  void flush() {}
};

extern FakeSerialPort Serial;

#endif
