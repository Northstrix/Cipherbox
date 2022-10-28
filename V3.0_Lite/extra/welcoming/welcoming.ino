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
https://github.com/adafruit/Adafruit-PCD8544-Nokia-5110-LCD-library
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/siara-cc/esp32_arduino_sqlite3_lib
https://github.com/intrbiz/arduino-crypto
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/GyverLibs/EncButton
https://github.com/mathworks/thingspeak-arduino
*/
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_PCD8544.h>
#include "cboxicon.h"

Adafruit_PCD8544 display = Adafruit_PCD8544(18, 23, 4, 15, 2);
int contrastValue = 60; // Contrast Value

void display_cipherbox_icon(){
  display.clearDisplay();
  for (int i = 0; i < 84; i++){
    for (int j = 0; j < 10; j++){
      if (cbicon[i][j] == false)
        display.drawPixel(i, j, BLACK); 
    }
  }
  for (int i = 0; i < 3; i++){
    display.drawPixel(13, 10 + i, BLACK);
    display.drawPixel(14, 10 + i, BLACK);
  }
  display.display();
}

void setup()
{
  display.begin();
  display.setContrast(contrastValue);
  display_cipherbox_icon();
  display.setTextColor(BLACK, WHITE);
  display.setTextSize(1);
  display.setCursor(0,16);
  display.print("Cipherbox V3.0");
  display.setCursor(0,25);
  display.println("     Lite");
  display.display();
  delay(100);
  for(int i = 0; i < 84; i++){
    display.drawPixel(i, 45, BLACK);
    display.drawPixel(i, 46, BLACK);
    display.drawPixel(i, 47, BLACK);
    display.display();
    delay(30);
  }
  display.clearDisplay();
  display.setTextSize(1);
  display.setCursor(0,0);
  display.print("Cipherbox V3.0");
  display.setCursor(0,9);
  display.println("     Lite");
  display.setCursor(0,23);
  display.println(" Double-click");
  display.setCursor(0,32);
  display.println("encoder button");
  display.setCursor(9,41);
  display.println("to continue");
  display.display();
}

void loop()
{
}
