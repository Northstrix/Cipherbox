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
#include <Adafruit_GFX.h>                                                   // include Adafruit graphics library
#include <Adafruit_ILI9341.h>                                               // include Adafruit ILI9341 TFT library
#define TFT_CS    15                                                        // TFT CS  pin is connected to ESP32 pin D15
#define TFT_RST   4                                                         // TFT RST pin is connected to ESP32 pin D4
#define TFT_DC    2                                                         // TFT DC  pin is connected to ESP32 pin D2
                                                                            // SCK (CLK) ---> ESP32 pin D18
                                                                            // MOSI(DIN) ---> ESP32 pin D23

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);

void main_menu(int curr_pos){
   tft.fillRect(30, 30, 180, 171, 0xf17f);
   
   tft.setTextColor(0xffff, 0xf17f);
   tft.setTextSize(1);
   if (curr_pos == 0){
    tft.fillRect(38, 38, 166, 12, 0xffff);
    tft.setCursor(40,40);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("Logins");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,112);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,124);
    tft.print("AES + Serpent");
    tft.setCursor(40,136);
    tft.print("Serpent");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
   }
   if (curr_pos == 1){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.fillRect(38, 50, 166, 12, 0xffff);
    tft.setTextColor(0xf17f, 0xffff);
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,112);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,124);
    tft.print("AES + Serpent");
    tft.setCursor(40,136);
    tft.print("Serpent");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
   }
   if (curr_pos == 2){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.fillRect(38, 62, 166, 12, 0xffff);
    tft.setTextColor(0xf17f, 0xffff);
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,112);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,124);
    tft.print("AES + Serpent");
    tft.setCursor(40,136);
    tft.print("Serpent");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
   }
   if (curr_pos == 3){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.fillRect(38, 74, 166, 12, 0xffff);
    tft.setTextColor(0xf17f, 0xffff);
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,88);
    tft.print("AES + Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,112);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,124);
    tft.print("AES + Serpent");
    tft.setCursor(40,136);
    tft.print("Serpent");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
   }
   if (curr_pos == 4){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.fillRect(38, 86, 166, 12, 0xffff);
    tft.setTextColor(0xf17f, 0xffff);
    tft.setCursor(40,88);
    tft.print("AES + Blowfish + Serpent");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,100);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,112);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,124);
    tft.print("AES + Serpent");
    tft.setCursor(40,136);
    tft.print("Serpent");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
   }
   if (curr_pos == 5){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Blowfish + Serpent");
    tft.fillRect(38, 98, 166, 12, 0xffff);
    tft.setTextColor(0xf17f, 0xffff);
    tft.setCursor(40,100);
    tft.print("AES + Serpent + AES");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,112);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,124);
    tft.print("AES + Serpent");
    tft.setCursor(40,136);
    tft.print("Serpent");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
   }
   if (curr_pos == 6){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent + AES");
    tft.fillRect(38, 110, 166, 12, 0xffff);
    tft.setTextColor(0xf17f, 0xffff);
    tft.setCursor(40,112);
    tft.print("Blowfish + Serpent");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,124);
    tft.print("AES + Serpent");
    tft.setCursor(40,136);
    tft.print("Serpent");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
   }
   if (curr_pos == 7){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,112);
    tft.print("Blowfish + Serpent");
    tft.fillRect(38, 122, 166, 12, 0xffff);
    tft.setTextColor(0xf17f, 0xffff);
    tft.setCursor(40,124);
    tft.print("AES + Serpent");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,136);
    tft.print("Serpent");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
   }
   if (curr_pos == 8){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,112);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,124);
    tft.print("AES + Serpent");
    tft.fillRect(38, 134, 166, 12, 0xffff);
    tft.setTextColor(0xf17f, 0xffff);
    tft.setCursor(40,136);
    tft.print("Serpent");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
   }
   if (curr_pos == 9){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,112);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,124);
    tft.print("AES + Serpent");
    tft.setCursor(40,136);
    tft.print("Serpent");
    tft.fillRect(38, 146, 166, 12, 0xffff);
    tft.setTextColor(0xf17f, 0xffff);
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
   }
   if (curr_pos == 10){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,112);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,124);
    tft.print("AES + Serpent");
    tft.setCursor(40,136);
    tft.print("Serpent");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.fillRect(38, 158, 166, 12, 0xffff);
    tft.setTextColor(0xf17f, 0xffff);
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
   }
   if (curr_pos == 11){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,112);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,124);
    tft.print("AES + Serpent");
    tft.setCursor(40,136);
    tft.print("Serpent");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.fillRect(38, 170, 166, 12, 0xffff);
    tft.setTextColor(0xf17f, 0xffff);
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,184);
    tft.print("SQL");
   }
   if (curr_pos == 12){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,112);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,124);
    tft.print("AES + Serpent");
    tft.setCursor(40,136);
    tft.print("Serpent");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.fillRect(38, 182, 166, 12, 0xffff);
    tft.setTextColor(0xf17f, 0xffff);
    tft.setCursor(40,184);
    tft.print("SQL");
   }
}

void setup() {
   tft.begin(); 
   tft.setRotation(0);
   tft.fillScreen(0x1557);
   tft.fillRect(15, 15, 210, 201, 0x08c5);
   tft.fillRect(0, 300, 240, 20, 0x08c5);
}

void loop(){
  for (int i = 0; i < 13; i++){
    main_menu(i);
    delay(1000);
  }
}
