/*
Cipherbox
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://github.com/Northstrix/Cipherbox
https://sourceforge.net/projects/mcu-cipherbox
https://osdn.net/projects/cipherbox
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_ILI9341
https://github.com/adafruit/Adafruit_BusIO
https://github.com/GyverLibs/GyverBus
https://github.com/siara-cc/esp32_arduino_sqlite3_lib
https://github.com/miguelbalboa/rfid
https://github.com/intrbiz/arduino-crypto
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/GyverLibs/EncButton
https://github.com/mathworks/thingspeak-arduino
*/
#include <SoftwareSerial.h>
SoftwareSerial mySerial(34, 35); // RX, TX

#include "GBUS.h"
GBUS bus(&mySerial, 3, 2);

struct myStruct {
  char x;
  bool d;
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
    Serial.println(data.d);
    Serial.println(int(data.x));
    Serial.println();
  }
}
