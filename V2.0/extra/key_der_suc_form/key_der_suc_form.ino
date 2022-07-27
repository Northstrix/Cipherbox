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
#include <Adafruit_GFX.h>                                                   // include Adafruit graphics library
#include <Adafruit_ILI9341.h>                                               // include Adafruit ILI9341 TFT library
#define TFT_CS    15                                                        // TFT CS  pin is connected to ESP32 pin D15
#define TFT_RST   4                                                         // TFT RST pin is connected to ESP32 pin D4
#define TFT_DC    2                                                         // TFT DC  pin is connected to ESP32 pin D2
                                                                            // SCK (CLK) ---> ESP32 pin D18
                                                                            // MOSI(DIN) ---> ESP32 pin D23

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);

void setup() {
   tft.begin(); 
   tft.setRotation(0);
   tft.fillScreen(0x1557);
   tft.fillRect(25, 70, 190, 82, 0x08c5);

   tft.setTextColor(0x1557, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,85);
   tft.print("Keys derived successfully.");

   tft.setTextColor(0xffff, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,102);
   tft.printf("Verification number is %d", 1239);

   tft.setTextColor(0x1557, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,119);
   tft.print("Press any key to get to the");
   tft.setCursor(40,129);
   tft.print("main menu.");

}
void loop(){
  
}
