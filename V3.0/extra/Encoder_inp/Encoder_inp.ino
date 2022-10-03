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

#include <EncButton2.h>
EncButton2<EB_ENC> enc0(INPUT, 26, 27);
EncButton2<EB_BTN> a_button(INPUT, 14);
EncButton2<EB_BTN> b_button(INPUT, 25);
int curr_key;
String encoder_input;

uint16_t conv_888_cl_to_565(const char *rgb32_str_)
{
  long rgb32=strtoul(rgb32_str_, 0, 16);
  return (rgb32>>8&0xf800)|(rgb32>>5&0x07e0)|(rgb32>>3&0x001f);
}

void disp_inp_panel(){
  tft.fillScreen(conv_888_cl_to_565("00A9F9"));
  tft.fillRect(0, 0, 240, 24, conv_888_cl_to_565("25282D"));
  tft.setCursor(18, 5);
  tft.setTextSize(2);
  tft.setTextColor(conv_888_cl_to_565("EEEEEE"));
  tft.print("Char:' '   Hex:");
}

void disp_input_from_enc(){
  tft.setTextSize(2);
  tft.fillRect(90, 5, 12, 16, conv_888_cl_to_565("25282D"));
  tft.setCursor(90, 5);
  tft.setTextColor(conv_888_cl_to_565("EEEEEE"));
  tft.print(char(curr_key));
  tft.fillRect(198, 5, 24, 16, conv_888_cl_to_565("25282D"));
  tft.setCursor(198, 5);
  tft.setTextColor(conv_888_cl_to_565("EEEEEE"));
  tft.printf("%02x",curr_key);
}

void setup(void){
  tft.begin(); 
  tft.setRotation(0);
  curr_key = 65;
  disp_inp_panel();
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
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
    //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
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
  }
}
