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
https://github.com/platisd/nokia-5110-lcd-library
*/
#include <SPI.h>
#include <MFRC522.h>
#include <SoftwareSerial.h>
#include <PS2Keyboard.h>
SoftwareSerial mySerial(5, 4);
#include "GBUS.h"
GBUS bus(&mySerial, 6, 10);
#define SS_PIN 10
#define RST_PIN 9
MFRC522 mfrc522(SS_PIN, RST_PIN);
const int DataPin = 6;
const int IRQpin =  3;
PS2Keyboard keyboard;
int act;

struct myStruct {
  char x;
};
void setup() 
{
  //Serial.begin(115200);
  act = 0;
  SPI.begin();
  mfrc522.PCD_Init();
  pinMode(8, OUTPUT);
  digitalWrite(8, LOW);
  //Serial.println("Approximate four cards to the reader...");
  mySerial.begin(9600);
  keyboard.begin(DataPin, IRQpin);
}
void loop() 
{

  if (keyboard.available()) {
    myStruct data;
    // read the next key
    char c = keyboard.read();
    //Serial.print(c);
    data.x = c;
    bus.sendData(3, data);
  }
  
  if (act < 15){
    if ( ! mfrc522.PICC_IsNewCardPresent()) 
    {
      return;
    }
    if ( ! mfrc522.PICC_ReadCardSerial()) 
    {
      return;
    }
    for (int i = 0; i<4; i++){
      //Serial.println(mfrc522.uid.uidByte[i]);
      myStruct data;
      data.x = (char) int(mfrc522.uid.uidByte[i]);
      bus.sendData(3, data);
      digitalWrite(8, HIGH);
      delay(12);
      act ++;
      if (i == 3){
        delay(700);
        digitalWrite(8, LOW);
      }
    }
    //Serial.println();
  }
}
