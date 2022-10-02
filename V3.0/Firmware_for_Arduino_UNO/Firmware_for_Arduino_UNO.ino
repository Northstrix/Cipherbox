/*
Cipherbox
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://github.com/Northstrix/Cipherbox
https://sourceforge.net/projects/mcu-cipherbox
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
#include <SPI.h>
#include <MFRC522.h>
#include <SoftwareSerial.h>
#include <EncButton2.h>
EncButton2 < EB_BTN > a_button(INPUT, 7);
EncButton2 < EB_BTN > b_button(INPUT, 8);
SoftwareSerial mySerial(5, 4);
#include "GBUS.h";
GBUS bus( & mySerial, 6, 2);
#define SS_PIN 10
#define RST_PIN 9
MFRC522 mfrc522(SS_PIN, RST_PIN);

struct myStruct {
  char x;
  bool d;
};

void setup() {
  //Serial.begin(115200);
  SPI.begin();
  mfrc522.PCD_Init();
  //Serial.println("Approximate four cards to the reader...");
  mySerial.begin(9600);
}

void loop() {
  a_button.tick();
  if (a_button.press()) {
    myStruct data;
    data.d = true;
    data.x = 1;
    bus.sendData(3, data);
  }
  
  b_button.tick();
  if (b_button.press()) {
    myStruct data;
    data.d = true;
    data.x = 2;
    bus.sendData(3, data);
  }
  
  if (!mfrc522.PICC_IsNewCardPresent()) {
    return;
  }
  if (!mfrc522.PICC_ReadCardSerial()) {
    return;
  }
  for (int i = 0; i < 4; i++) {
    //Serial.println(mfrc522.uid.uidByte[i]);
    myStruct data;
    data.d = false;
    data.x = (char) int(mfrc522.uid.uidByte[i]);
    bus.sendData(3, data);
    delay(12);
    if (i == 3) {
      delay(700);
    }
  }
  //Serial.println();
}
