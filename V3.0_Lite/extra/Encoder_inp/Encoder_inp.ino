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

#include <EncButton2.h>
EncButton2<EB_ENC> enc0(INPUT, 26, 27);
EncButton2<EB_BTN> a_button(INPUT, 14);
EncButton2<EB_BTN> b_button(INPUT, 25);
int curr_key;
String encoder_input;

void disp_inp_panel(){
  display.setTextColor(WHITE, BLACK);
  display.drawLine(0, 0, 83, 0, BLACK);
  display.setCursor(0,1);
  display.println("              ");
  display.setCursor(2,1);
  display.setTextSize(1);
  display.print("Char' '");
  display.setCursor(47,1);
  display.println("Hex:");
  display.display();
}

void disp_input_from_enc(){
  display.setTextColor(WHITE, BLACK);
  display.setCursor(32,1);
  display.setTextSize(1);
  display.print(char(curr_key));
  display.setCursor(71,1);
  display.printf("%02x", curr_key);
  display.display();
}

void setup(void){
  curr_key = 65;
  display.begin();
  display.setContrast(contrastValue);
  display.clearDisplay();
  display.display();
  disp_inp_panel();
  display.setTextColor(WHITE, BLACK);
  display.setCursor(32,1);
  display.setTextSize(1);
  display.print("A");
  display.setCursor(71,1);
  display.printf("%02x", 65);
  display.display();
  Serial.begin(115200);
}

void loop(){
  enc0.tick();
  if (enc0.left())
    curr_key--;
  if (enc0.right())
    curr_key++;
    
  if(curr_key < 32)
    curr_key = 126;
   
  if(curr_key > 126)
    curr_key = 32;

  if (enc0.turn()) {
    disp_input_from_enc();
    Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
  }
  a_button.tick();
  if (a_button.press()){
    encoder_input += char(curr_key);
    Serial.println(encoder_input);
  }
  b_button.tick();
  if (b_button.press()){
    if(encoder_input.length() > 0)
      encoder_input.remove(encoder_input.length() -1, 1);
    Serial.println(encoder_input);
  }
}
