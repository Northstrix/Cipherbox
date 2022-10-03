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
#include <EncButton2.h>
#define TFT_CS    15                                                        // TFT CS  pin is connected to ESP32 pin D15
#define TFT_RST   4                                                         // TFT RST pin is connected to ESP32 pin D4
#define TFT_DC    2                                                         // TFT DC  pin is connected to ESP32 pin D2
                                                                            // SCK (CLK) ---> ESP32 pin D18
                                                                            // MOSI(DIN) ---> ESP32 pin D23

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);
EncButton2<EB_ENC> enc0(INPUT, 26, 27);
int curr_key;

void disp_centered_text(String t_disp, int y){
   int16_t x1, y1;
   uint16_t w, h;
   tft.getTextBounds(t_disp, 240, 0, &x1, &y1, &w, &h);
   tft.setCursor(120 - (w / 2), y);
   tft.print(t_disp);
}

void onl_st_nts(int curr_pos){
  tft.setTextColor(0x899a, 0x1884);
  tft.setTextSize(1);
  if (curr_pos == 0){
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Add Note", 80);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("View Last Saved Note", 100);
    disp_centered_text("Decrypt Note", 120);
  }
  if (curr_pos == 1){
    disp_centered_text("Add Note", 80);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("View Last Saved Note", 100);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Decrypt Note", 120);
  }
  if (curr_pos == 2){
    disp_centered_text("Add Note", 80);
    disp_centered_text("View Last Saved Note", 100);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Decrypt Note", 120);
  }
}

void setup() {
   tft.begin(); 
   tft.setRotation(0);
   tft.fillScreen(0x1884);
   tft.setTextSize(2);
   tft.setTextColor(0x899a, 0x1884);
   disp_centered_text("Online-stored Notes", 30);
   curr_key = 0;
   onl_st_nts(curr_key);
}

void loop(){
  enc0.tick();
  if (enc0.left())
    curr_key--;
  if (enc0.right())
    curr_key++;
    
  if(curr_key < 0)
    curr_key = 2;
   
  if(curr_key > 2)
    curr_key = 0;

  if (enc0.turn()) {
    onl_st_nts(curr_key);
  }
}
