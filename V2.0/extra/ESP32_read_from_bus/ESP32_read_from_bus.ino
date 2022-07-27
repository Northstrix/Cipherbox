/*
Cipherbox
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://github.com/Northstrix/Cipherbox
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/adafruit/Adafruit_BusIO
https://github.com/GyverLibs/GyverBus
https://github.com/PaulStoffregen/PS2Keyboard
https://github.com/siara-cc/esp32_arduino_sqlite3_lib
https://github.com/miguelbalboa/rfid
https://github.com/intrbiz/arduino-crypto
https://github.com/Chris--A/Keypad
https://github.com/platisd/nokia-5110-lcd-library
*/
#include <SoftwareSerial.h>
SoftwareSerial mySerial(34, 35); // RX, TX
#include "GBUS.h"
GBUS bus(&mySerial, 3, 10);

struct myStruct {
  char x;
};

void setup() {
  Serial.begin(115200);
  mySerial.begin(9600);
}

void loop() {
  bus.tick();

  if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    Serial.println(int(data.x));
    Serial.println();
  }
}
