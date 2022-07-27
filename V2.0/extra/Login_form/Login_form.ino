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
#include <Adafruit_GFX.h>                                                   // include Adafruit graphics library
#include <Adafruit_ILI9341.h>                                               // include Adafruit ILI9341 TFT library
#define TFT_CS    15                                                        // TFT CS  pin is connected to ESP32 pin D15
#define TFT_RST   4                                                         // TFT RST pin is connected to ESP32 pin D4
#define TFT_DC    2                                                         // TFT DC  pin is connected to ESP32 pin D2
                                                                            // SCK (CLK) ---> ESP32 pin D18
                                                                            // MOSI(DIN) ---> ESP32 pin D23

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);

void log_in(){
   tft.fillScreen(0x1557);
   tft.fillRect(25, 25, 190, 220, 0x08c5);

   tft.setTextColor(0xffff, 0x08c5);
   tft.setTextSize(3);
   tft.setCursor(40,40);
   tft.print("Cipherbox");

   tft.setTextColor(0x1557, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,85);
   tft.print("Username");

   tft.setTextColor(0xffff, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,102);
   tft.print("Enter your username...");
   
   tft.drawLine(40, 111, 200, 111, 0xffff);

   tft.setTextColor(0x1557, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,135);
   tft.print("Password");

   tft.setTextColor(0xffff, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,152);
   tft.print("Enter your password...");
   //tft.print("***************************");
   
   tft.drawLine(40, 161, 200, 161, 0xffff);

   tft.setTextColor(0x1557, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,183);
   tft.print("Press Tab to move between");

   tft.setCursor(40,195);
   tft.print("fields.");

   tft.setCursor(40,212);
   tft.print("Press Enter to log in.");

   tft.setTextColor(0x08c5, 0x1557);
   tft.setTextSize(2);
   tft.setCursor(14,302);
   tft.print("Username Length:");
   tft.setCursor(206,302);
   tft.print("99"); 
}

void setup() {
   tft.begin(); 
   tft.setRotation(0);
   log_in();
}
void loop(){
  
}
