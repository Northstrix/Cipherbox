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

void log_note_tab(){
   tft.fillRect(15, 200, 210, 80, 0x08c5);
   tft.setTextColor(0xffff, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,216);
   tft.print("1.Add");
   tft.setCursor(40,226);
   tft.print("2.Edit");
   tft.setCursor(40,236);
   tft.print("3.Delete");
   tft.setCursor(40,246);
   tft.print("4.View");
   tft.setCursor(40,256);
   tft.print("5.Show all");
}

void encr_tab(){
   tft.fillRect(15, 200, 210, 80, 0x08c5);
   tft.setTextColor(0xffff, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,216);
   tft.print("1.Encrypt");
   tft.setCursor(40,226);
   tft.print("2.Decrypt");
}

void sha512_tab(){
   tft.fillRect(15, 200, 210, 80, 0x08c5);
   tft.setTextColor(0xffff, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,216);
   tft.print("1.Hash string using SHA-512");
}

void sql_tab(){
   tft.fillRect(15, 200, 210, 80, 0x08c5);
   tft.setTextColor(0xffff, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,216);
   tft.print("1.Execute SQL query");
}

void main_menu(int curr_pos){
   tft.fillRect(30, 30, 180, 135, 0xf17f);
   
   tft.setTextColor(0xffff, 0xf17f);
   tft.setTextSize(1);
   if (curr_pos == 0){
    tft.fillRect(38, 38, 166, 12, 0xffff);
    tft.setCursor(40,40);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("Login");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,52);
    tft.print("Note");
    tft.setCursor(40,64);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,76);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,88);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent");
    tft.setCursor(40,112);
    tft.print("AES");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("SHA-512");
    tft.setCursor(40,148);
    tft.print("SQL");
    log_note_tab();
   }
   if (curr_pos == 1){
    tft.setCursor(40,40);
    tft.print("Login");
    tft.fillRect(38, 50, 166, 12, 0xffff);
    tft.setCursor(40,52);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("Note");
    tft.setCursor(40,64);
    tft.setTextColor(0xffff, 0xf17f);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,76);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,88);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent");
    tft.setCursor(40,112);
    tft.print("AES");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("SHA-512");
    tft.setCursor(40,148);
    tft.print("SQL");
    log_note_tab();
   }
   if (curr_pos == 2){
    tft.setCursor(40,40);
    tft.print("Login");
    tft.setCursor(40,52);
    tft.print("Note");
    tft.fillRect(38, 62, 166, 12, 0xffff);
    tft.setCursor(40,64);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,76);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,88);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent");
    tft.setCursor(40,112);
    tft.print("AES");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("SHA-512");
    tft.setCursor(40,148);
    tft.print("SQL");
    encr_tab();
   }
   if (curr_pos == 3){
    tft.setCursor(40,40);
    tft.print("Login");
    tft.setCursor(40,52);
    tft.print("Note");
    tft.setCursor(40,64);
    tft.print("Blowfish + AES + Serp + AES");
    tft.fillRect(38, 74, 166, 12, 0xffff);
    tft.setCursor(40,76);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("AES + Serpent + AES");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,88);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent");
    tft.setCursor(40,112);
    tft.print("AES");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("SHA-512");
    tft.setCursor(40,148);
    tft.print("SQL");
    encr_tab();
   }
   if (curr_pos == 4){
    tft.setCursor(40,40);
    tft.print("Login");
    tft.setCursor(40,52);
    tft.print("Note");
    tft.setCursor(40,64);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,76);
    tft.print("AES + Serpent + AES");
    tft.fillRect(38, 86, 166, 12, 0xffff);
    tft.setCursor(40,88);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("Blowfish + Serpent");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,100);
    tft.print("AES + Serpent");
    tft.setCursor(40,112);
    tft.print("AES");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("SHA-512");
    tft.setCursor(40,148);
    tft.print("SQL");
    encr_tab();
   }
   if (curr_pos == 5){
    tft.setCursor(40,40);
    tft.print("Login");
    tft.setCursor(40,52);
    tft.print("Note");
    tft.setCursor(40,64);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,76);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,88);
    tft.print("Blowfish + Serpent");
    tft.fillRect(38, 98, 166, 12, 0xffff);
    tft.setCursor(40,100);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("AES + Serpent");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,112);
    tft.print("AES");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("SHA-512");
    tft.setCursor(40,148);
    tft.print("SQL");
    encr_tab();
   }
   if (curr_pos == 6){
    tft.setCursor(40,40);
    tft.print("Login");
    tft.setCursor(40,52);
    tft.print("Note");
    tft.setCursor(40,64);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,76);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,88);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent");
    tft.fillRect(38, 110, 166, 12, 0xffff);
    tft.setCursor(40,112);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("AES");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("SHA-512");
    tft.setCursor(40,148);
    tft.print("SQL");
    encr_tab();
   }
   if (curr_pos == 7){
    tft.setCursor(40,40);
    tft.print("Login");
    tft.setCursor(40,52);
    tft.print("Note");
    tft.setCursor(40,64);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,76);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,88);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent");
    tft.setCursor(40,112);
    tft.print("AES");
    tft.fillRect(38, 122, 166, 12, 0xffff);
    tft.setCursor(40,124);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("Serpent");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,136);
    tft.print("SHA-512");
    tft.setCursor(40,148);
    tft.print("SQL");
    encr_tab();
   }
   if (curr_pos == 8){
    tft.setCursor(40,40);
    tft.print("Login");
    tft.setCursor(40,52);
    tft.print("Note");
    tft.setCursor(40,64);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,76);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,88);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent");
    tft.setCursor(40,112);
    tft.print("AES");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.fillRect(38, 134, 166, 12, 0xffff);
    tft.setCursor(40,136);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("SHA-512");
    tft.setTextColor(0xffff, 0xf17f);
    tft.setCursor(40,148);
    tft.print("SQL");
    sha512_tab();
   }
   if (curr_pos == 9){
    tft.setCursor(40,40);
    tft.print("Login");
    tft.setCursor(40,52);
    tft.print("Note");
    tft.setCursor(40,64);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,76);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,88);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,100);
    tft.print("AES + Serpent");
    tft.setCursor(40,112);
    tft.print("AES");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("SHA-512");
    tft.fillRect(38, 146, 166, 12, 0xffff);
    tft.setCursor(40,148);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("SQL");
    sql_tab();
   }
}

void setup() {
   tft.begin(); 
   tft.setRotation(0);
   tft.fillScreen(0x1557);
   tft.fillRect(15, 15, 210, 165, 0x08c5);
   tft.fillRect(0, 300, 240, 20, 0x08c5);
}

void loop(){
  for (int i = 0; i < 10; i++){
    main_menu(i);
    delay(1000);
  }
}
