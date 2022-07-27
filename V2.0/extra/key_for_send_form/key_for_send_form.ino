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

int q = 0;
int w = 0;
int e = 0; 

void key_setup_for_send_feature(int firstnum, int secondnum, int thirdnum){
   tft.fillScreen(0x5170);
   tft.setTextSize(2);
   tft.fillRect(25, 20, 190, 170, 0x08c5);
   tft.setTextColor(0x155b, 0x08c5);
   tft.setCursor(42,35);
   tft.print("Type this key");
   tft.setCursor(36,55);
   tft.print("    on the");
   tft.setCursor(36,75);
   tft.print("  receiver's");
   tft.setCursor(36,95);
   tft.print("    keypad");
   tft.setTextColor(0xffff, 0x08c5);
   tft.setCursor(36,132);
   tft.print("12 34 56 78 90");
   tft.setCursor(36,160);
   tft.print("AB CD EF 01 23");
   
   tft.fillRect(25, 210, 190, 90, 0x08c5);
   tft.setTextColor(0x155b, 0x08c5);
   tft.setCursor(36,220);
   tft.print(" Verification");
   tft.setCursor(42,240);
   tft.print("   numbers");
   tft.setTextColor(0xffff, 0x08c5);

   if (thirdnum > 99){
    tft.setCursor(36,275);
    tft.printf("           %d",thirdnum);
   }
   else if (thirdnum > 9 && thirdnum < 100){
    tft.setCursor(42,275);
    tft.printf("           %d",thirdnum);
   }
   else if (thirdnum < 10){
    tft.setCursor(36,275);
    tft.printf("            %d",thirdnum);
   }

   if (secondnum > 99){
    tft.setCursor(42,275);
    tft.printf("     %d",secondnum);
   }
   else if (secondnum > 9 && secondnum < 100){
    tft.setCursor(36,275);
    tft.printf("      %d",secondnum);
   }
   else if (secondnum < 10){
    tft.setCursor(42,275);
    tft.printf("      %d",secondnum);
   }

   if (firstnum > 99){
    tft.setCursor(36,275);
    tft.printf("%d",firstnum);
   }
   else if (firstnum > 9 && firstnum < 100){
    tft.setCursor(42,275);
    tft.printf("%d",firstnum);
   }
   else if (firstnum < 10){
    tft.setCursor(36,275);
    tft.printf(" %d",firstnum);
   
   tft.setTextColor(0xffff, 0x5170);
   tft.setTextSize(1);
   tft.setCursor(0,310);
   tft.print("                                                                                                    ");
   tft.setCursor(0,310);
   tft.print("       Press any key to continue");

}

void setup() {
   tft.begin(); 
   tft.setRotation(0);

}
void loop(){
  key_setup_for_send_feature(w,q,e);
  q++;
  w++;
  e++;
  if(q > 255)
    q = 0;
  if(w > 255)
    w = 0;
  if(e > 255)
    e = 0;
  delay(50);
}
