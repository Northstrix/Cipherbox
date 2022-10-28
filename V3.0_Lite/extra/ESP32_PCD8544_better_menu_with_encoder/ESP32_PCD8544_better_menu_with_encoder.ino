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
Adafruit_PCD8544 display = Adafruit_PCD8544(18, 23, 4, 15, 2);
int contrastValue = 60;
int curr_key;
#include <EncButton2.h>
EncButton2<EB_ENC> enc0(INPUT, 26, 27);

void main_menu(int curr_pos){
   display.clearDisplay();
   display.setTextSize(1);
   display.setTextColor(BLACK, WHITE);
   if (curr_pos == 0){
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 0);
      display.println("              ");
      display.setCursor(3, 0);
      display.print("Logins");
      display.setTextColor(BLACK, WHITE);
      display.setCursor(3, 8);
      display.print("Credit cards");
      display.setCursor(3, 16);
      display.print("Notes");
      display.setCursor(3, 24);
      display.print("BL+AES+SP+AES");
      display.setCursor(3, 32);
      display.print("AES+Serp+AES");
      display.setCursor(3, 40);
      display.print("Blfsh+Serpent");
   }
   if (curr_pos == 1){
      display.setCursor(3, 0);
      display.print("Logins");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 8);
      display.println("              ");
      display.setCursor(3, 8);
      display.print("Credit cards");
      display.setCursor(3, 16);
      display.setTextColor(BLACK, WHITE);
      display.print("Notes");
      display.setCursor(3, 24);
      display.print("BL+AES+SP+AES");
      display.setCursor(3, 32);
      display.print("AES+Serp+AES");
      display.setCursor(3, 40);
      display.print("Blfsh+Serpent");
   }
   if (curr_pos == 2){
      display.setCursor(3, 0);
      display.print("Logins");
      display.setCursor(3, 8);
      display.print("Credit cards");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 16);
      display.println("              ");
      display.setCursor(3, 16);
      display.print("Notes");
      display.setCursor(3, 24);
      display.setTextColor(BLACK, WHITE);
      display.print("BL+AES+SP+AES");
      display.setCursor(3, 32);
      display.print("AES+Serp+AES");
      display.setCursor(3, 40);
      display.print("Blfsh+Serpent");
   }
   if (curr_pos == 3){
      display.setCursor(3, 0);
      display.print("Logins");
      display.setCursor(3, 8);
      display.print("Credit cards");
      display.setCursor(3, 16);
      display.print("Notes");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 24);
      display.println("              ");
      display.setCursor(3, 24);
      display.print("BL+AES+SP+AES");
      display.setCursor(3, 32);
      display.setTextColor(BLACK, WHITE);
      display.print("AES+Serp+AES");
      display.setCursor(3, 40);
      display.print("Blfsh+Serpent");
   }
   if (curr_pos == 4){
      display.setCursor(3, 0);
      display.print("Logins");
      display.setCursor(3, 8);
      display.print("Credit cards");
      display.setCursor(3, 16);
      display.print("Notes");
      display.setCursor(3, 24);
      display.print("BL+AES+SP+AES");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 32);
      display.println("              ");
      display.setCursor(3, 32);
      display.print("AES+Serp+AES");
      display.setCursor(3, 40);
      display.setTextColor(BLACK, WHITE);
      display.print("Blfsh+Serpent");
   }
   if (curr_pos == 5){
      display.setCursor(3, 0);
      display.print("Logins");
      display.setCursor(3, 8);
      display.print("Credit cards");
      display.setCursor(3, 16);
      display.print("Notes");
      display.setCursor(3, 24);
      display.print("BL+AES+SP+AES");
      display.setCursor(3, 32);
      display.print("AES+Serp+AES");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 40);
      display.println("              ");
      display.setCursor(3, 40);
      display.print("Blfsh+Serpent");
   }
   if (curr_pos == 6){
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 0);
      display.println("              ");
      display.setCursor(3, 0);
      display.print("AES+Serpent");
      display.setTextColor(BLACK, WHITE);
      display.setCursor(3, 8);
      display.print("Serpent");
      display.setCursor(3, 16);
      display.print("3DES");
      display.setCursor(3, 24);
      display.print("Hash functns");
      display.setCursor(3, 32);
      display.print("SQL");
      display.setCursor(3, 40);
      display.print("Onl strd nots");
   }
   if (curr_pos == 7){
      display.setCursor(3, 0);
      display.print("AES+Serpent");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 8);
      display.println("              ");
      display.setCursor(3, 8);
      display.print("Serpent");
      display.setCursor(3, 16);
      display.setTextColor(BLACK, WHITE);
      display.print("3DES");
      display.setCursor(3, 24);
      display.print("Hash functns");
      display.setCursor(3, 32);
      display.print("SQL");
      display.setCursor(3, 40);
      display.print("Onl strd nots");
   }
   if (curr_pos == 8){
      display.setCursor(3, 0);
      display.print("AES+Serpent");
      display.setCursor(3, 8);
      display.print("Serpent");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 16);
      display.println("              ");
      display.setCursor(3, 16);
      display.print("3DES");
      display.setCursor(3, 24);
      display.setTextColor(BLACK, WHITE);
      display.print("Hash functns");
      display.setCursor(3, 32);
      display.print("SQL");
      display.setCursor(3, 40);
      display.print("Onl strd nots");
   }
   if (curr_pos == 9){
      display.setCursor(3, 0);
      display.print("AES+Serpent");
      display.setCursor(3, 8);
      display.print("Serpent");
      display.setCursor(3, 16);
      display.print("3DES");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 24);
      display.println("              ");
      display.setCursor(3, 24);
      display.print("Hash functns");
      display.setCursor(3, 32);
      display.setTextColor(BLACK, WHITE);
      display.print("SQL");
      display.setCursor(3, 40);
      display.print("Onl strd nots");
   }
   if (curr_pos == 10){
      display.setCursor(3, 0);
      display.print("AES+Serpent");
      display.setCursor(3, 8);
      display.print("Serpent");
      display.setCursor(3, 16);
      display.print("3DES");
      display.setCursor(3, 24);
      display.print("Hash functns");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 32);
      display.println("              ");
      display.setCursor(3, 32);
      display.print("SQL");
      display.setCursor(3, 40);
      display.setTextColor(BLACK, WHITE);
      display.print("Onl strd nots");
   }
   if (curr_pos == 11){
      display.setCursor(3, 0);
      display.print("AES+Serpent");
      display.setCursor(3, 8);
      display.print("Serpent");
      display.setCursor(3, 16);
      display.print("3DES");
      display.setCursor(3, 24);
      display.print("Hash functns");
      display.setCursor(3, 32);
      display.print("SQL");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 40);
      display.println("              ");
      display.setCursor(3, 40);
      display.print("Onl strd nots");
   }
   display.display();
}

void setup() {
   display.begin();
   display.setContrast(contrastValue);
   display.clearDisplay();
   curr_key = 0;
   main_menu(curr_key);
   display.display();
}

void loop(){
  enc0.tick();
  if (enc0.left())
    curr_key--;
  if (enc0.right())
    curr_key++;
    
  if(curr_key < 0)
    curr_key = 11;
   
  if(curr_key > 11)
    curr_key = 0;

  if (enc0.turn()) {
    main_menu(curr_key);
  }
}
