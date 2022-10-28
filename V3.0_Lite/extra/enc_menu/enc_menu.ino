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
   display.setCursor(12, 0);
   display.print("Notes Menu");
   
   if (curr_pos == 0){
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 8);
      display.println("              ");
      display.setCursor(18, 8);
      display.print("Add Note");
      display.setCursor(15, 16);
      display.setTextColor(BLACK, WHITE);
      display.print("Edit Note");
      display.setCursor(9, 24);
      display.print("Delete Note");
      display.setCursor(15, 32);
      display.print("View Note");
      display.setCursor(0, 40);
      display.print("Show All Notes");
   }
   if (curr_pos == 1){
      display.setCursor(18, 8);
      display.print("Add Note");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 16);
      display.println("              ");
      display.setCursor(15, 16);
      display.print("Edit Note");
      display.setCursor(9, 24);
      display.setTextColor(BLACK, WHITE);
      display.print("Delete Note");
      display.setCursor(15, 32);
      display.print("View Note");
      display.setCursor(0, 40);
      display.print("Show All Notes");
   }
   if (curr_pos == 2){
      display.setCursor(18, 8);
      display.print("Add Note");
      display.setCursor(15, 16);
      display.print("Edit Note");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 24);
      display.println("              ");
      display.setCursor(9, 24);
      display.print("Delete Note");
      display.setCursor(15, 32);
      display.setTextColor(BLACK, WHITE);
      display.print("View Note");
      display.setCursor(0, 40);
      display.print("Show All Notes");
   }
   if (curr_pos == 3){
      display.setCursor(18, 8);
      display.print("Add Note");
      display.setCursor(15, 16);
      display.print("Edit Note");
      display.setCursor(9, 24);
      display.print("Delete Note");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 32);
      display.println("              ");
      display.setCursor(15, 32);
      display.print("View Note");
      display.setCursor(0, 40);
      display.setTextColor(BLACK, WHITE);
      display.print("Show All Notes");
   }
   if (curr_pos == 4){
      display.setCursor(18, 8);
      display.print("Add Note");
      display.setCursor(15, 16);
      display.print("Edit Note");
      display.setCursor(9, 24);
      display.print("Delete Note");
      display.setCursor(15, 32);
      display.print("View Note");
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 40);
      display.println("              ");
      display.setCursor(0, 40);
      display.print("Show All Notes");
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
    curr_key = 5;
   
  if(curr_key > 5)
    curr_key = 0;

  if (enc0.turn()) {
    main_menu(curr_key);
  }
}
