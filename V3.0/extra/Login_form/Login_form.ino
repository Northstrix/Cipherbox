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

#define TFT_CS 15 // TFT CS  pin is connected to ESP32 pin D15
#define TFT_RST 4 // TFT RST pin is connected to ESP32 pin D4
#define TFT_DC 2 // TFT DC  pin is connected to ESP32 pin D2
// SCK (CLK) ---> ESP32 pin D18
// MOSI(DIN) ---> ESP32 pin D23

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);

#include <EncButton2.h>

EncButton2 < EB_ENC > enc0(INPUT, 26, 27);
EncButton2 < EB_BTN > encoder_button(INPUT, 33);
EncButton2 < EB_BTN > a_button(INPUT, 14);
EncButton2 < EB_BTN > b_button(INPUT, 25);
int curr_key;
String usrn_lg;
String pass_lg;
bool un_or_p = false; // false - username, true - password
bool chng;

void log_in() {
  tft.fillScreen(0x1557);
  tft.fillRect(25, 49, 190, 220, 0x08c5);

  tft.setTextColor(0xffff, 0x08c5);
  tft.setTextSize(3);
  tft.setCursor(40, 64);
  tft.print("Cipherbox");

  tft.setTextColor(0x1557, 0x08c5);
  tft.setTextSize(1);
  tft.setCursor(40, 109);
  tft.print("Username");

  tft.setTextColor(0xffff, 0x08c5);
  tft.setTextSize(1);
  tft.setCursor(40, 126);
  tft.print("Enter your username...");

  tft.drawLine(40, 135, 200, 135, 0xffff);

  tft.setTextColor(0x1557, 0x08c5);
  tft.setTextSize(1);
  tft.setCursor(40, 159);
  tft.print("Password");

  tft.setTextColor(0xffff, 0x08c5);
  tft.setTextSize(1);
  tft.setCursor(40, 176);
  tft.print("Enter your password...");
  //tft.print("***************************");

  tft.drawLine(40, 185, 200, 185, 0xffff);

  tft.setTextColor(0x1557, 0x08c5);
  tft.setTextSize(1);
  tft.setCursor(40, 202);
  tft.print("Press the encoder button");
  tft.setCursor(40, 214);
  tft.print("to move between fields.");

  tft.setCursor(40, 237);
  tft.print("Double-click the encoder");
  tft.setCursor(40, 249);
  tft.print("button to log in.");

  tft.setTextColor(0x08c5, 0x1557);
  tft.setTextSize(2);
  tft.setCursor(14, 294);
  tft.print("Username Length:");
  tft.setCursor(206, 294);
  tft.print("0");
}

void disp_inp_panel() {
  tft.fillRect(0, 0, 240, 24, 0x2125);
  tft.setCursor(18, 5);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.print("Char:' '   Hex:");
}

void disp_input_from_enc() {
  tft.setTextSize(2);
  tft.fillRect(90, 5, 12, 16, 0x2125);
  tft.setCursor(90, 5);
  tft.setTextColor(0xffff);
  tft.print(char(curr_key));
  tft.fillRect(198, 5, 24, 16, 0x2125);
  tft.setCursor(198, 5);
  tft.setTextColor(0xffff);
  tft.printf("%02x", curr_key);
}

void disp_changes_during_login(){
    int inpl1 = usrn_lg.length();
    int inpl2 = pass_lg.length();
    if (inpl1 == 0) { // Username is empty
      tft.setTextColor(0xffff, 0x08c5);
      tft.setTextSize(1);
      tft.setCursor(40, 126);
      tft.print("                           ");
      tft.setCursor(40, 126);
      tft.print("Enter your username...");
      if (un_or_p == false) {
        tft.setTextColor(0x08c5, 0x1557);
        tft.setTextSize(2);
        tft.setCursor(206, 294);
        tft.print("  ");
        tft.setCursor(206, 294);
        tft.print("0");
      }
    } else {
      if (un_or_p == false) {
        tft.setTextColor(0xffff, 0x08c5);
        tft.setTextSize(1);
        tft.setCursor(40, 126);
        tft.print("                           ");
        String visible_usrn;
        for (int i = 0; i < inpl1; i++) {
          if (i < 27)
            visible_usrn += usrn_lg.charAt(i);
        }
        tft.setTextColor(0xffff, 0x08c5);
        tft.setTextSize(1);
        tft.setCursor(40, 126);
        tft.print(visible_usrn);
        tft.setTextColor(0x08c5, 0x1557);
        tft.setTextSize(2);
        tft.setCursor(206, 294);
        tft.print("  ");
        tft.setCursor(206, 294);
        tft.print(inpl1);
      }
    }
    if (inpl2 == 0) { // Password is empty
      tft.setTextColor(0xffff, 0x08c5);
      tft.setTextSize(1);
      tft.setCursor(40, 176);
      tft.print("                           ");
      tft.setCursor(40, 176);
      tft.print("Enter your password...");
      if (un_or_p == true) {
        tft.setTextColor(0x08c5, 0x1557);
        tft.setTextSize(2);
        tft.setCursor(206, 294);
        tft.print("  ");
        tft.setCursor(206, 294);
        tft.print("0");
      }
    } else {
      if (un_or_p == true) {
        tft.setTextColor(0xffff, 0x08c5);
        tft.setTextSize(1);
        tft.setCursor(40, 176);
        tft.print("                           ");
        String stars = "";
        for (int i = 0; i < inpl2; i++) {
          if (i < 27)
            stars += "*";
        }
        tft.setTextColor(0xffff, 0x08c5);
        tft.setTextSize(1);
        tft.setCursor(40, 176);
        tft.print(stars);
        tft.setTextColor(0x08c5, 0x1557);
        tft.setTextSize(2);
        tft.setCursor(206, 294);
        tft.print("  ");
        tft.setCursor(206, 294);
        tft.print(inpl2);
      }
    }
}

void db_location() {
  tft.fillRect(0, 311, 240, 9, 0x08c5);
  tft.setTextColor(0xffff, 0x08c5);
  tft.setTextSize(1);
  tft.setCursor(0, 312);
  tft.print("Database location: Built-in flash memory");
}

void setup() {
  tft.begin();
  tft.setRotation(0);
  log_in();
  db_location();
  curr_key = 65;
  disp_inp_panel();
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  chng = false;
  Serial.begin(115200);
}
void loop() {
  enc0.tick();
  if (enc0.left())
    curr_key--;
  if (enc0.right())
    curr_key++;

  if (curr_key < 32)
    curr_key = 126;

  if (curr_key > 126)
    curr_key = 32;

  if (enc0.turn()) {
    disp_input_from_enc();
    //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
  }
  a_button.tick();
  b_button.tick();
  encoder_button.tick();
    if (a_button.press()) {
      if (un_or_p == false)
        usrn_lg += char(curr_key);
      if (un_or_p == true)
        pass_lg += char(curr_key);
      chng = true;
    }
    if (b_button.press()) { // Backspace
      if (usrn_lg.length() > 0 && un_or_p == false) { // Username
        usrn_lg.remove(usrn_lg.length() - 1, 1);
        tft.setTextColor(0xffff, 0x08c5);
        tft.setTextSize(1);
        tft.setCursor(40, 126);
        tft.print("                           ");
      }

      if (pass_lg.length() > 0 && un_or_p == true) { // Password
        pass_lg.remove(pass_lg.length() - 1, 1);
        tft.setTextColor(0xffff, 0x08c5);
        tft.setTextSize(1);
        tft.setCursor(40, 176);
        tft.print("                           ");
      }

      tft.setTextColor(0x08c5, 0x1557);
      tft.setTextSize(2);
      tft.setCursor(206, 294);
      tft.print("  ");
      chng = true;
    }
    if (encoder_button.press()) { // Tab
      if (un_or_p == false) {
        un_or_p = true;
        tft.setTextColor(0x08c5, 0x1557);
        tft.setTextSize(2);
        tft.setCursor(14, 294);
        tft.print("                  ");
        tft.setCursor(14, 294);
        tft.print("Password Length:");
      } else if (un_or_p == true) {
        un_or_p = false;
        tft.setTextColor(0x08c5, 0x1557);
        tft.setTextSize(2);
        tft.setCursor(14, 294);
        tft.print("                  ");
        tft.setCursor(14, 294);
        tft.print("Username Length:");
      }
      chng = true;
    }
    if (chng == true){
      disp_changes_during_login();
      chng = false;
    }
    if (encoder_button.hasClicks(2)){
      Serial.print("\nLogin: ");
      Serial.println(usrn_lg);
      Serial.print("Password: ");
      Serial.println(pass_lg);
    }
}
