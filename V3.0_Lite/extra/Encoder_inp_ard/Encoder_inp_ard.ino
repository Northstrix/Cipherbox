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
#include <EncButton2.h>
EncButton2<EB_ENC> enc0(INPUT, 2, 3);
EncButton2<EB_BTN> a_button(INPUT, 5);
EncButton2<EB_BTN> b_button(INPUT, 6);
int curr_key;
String encoder_input;

void setup(void){
  curr_key = 65;
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
    Serial.println(char(curr_key));
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
