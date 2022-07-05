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
#include <SoftwareSerial.h>
SoftwareSerial mySerial(34, 35); // RX, TX
#include "GBUS.h"
#include "blowfish.h"
#include "sha512.h"
#include "serpent.h"
#include <Adafruit_GFX.h>                                                   // include Adafruit graphics library
#include <Adafruit_ILI9341.h>                                               // include Adafruit ILI9341 TFT library
#define TFT_CS    15                                                        // TFT CS  pin is connected to ESP32 pin D15
#define TFT_RST   4                                                         // TFT RST pin is connected to ESP32 pin D4
#define TFT_DC    2                                                         // TFT DC  pin is connected to ESP32 pin D2
                                                                            // SCK (CLK) ---> ESP32 pin D18
                                                                            // MOSI(DIN) ---> ESP32 pin D23

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);
GBUS bus(&mySerial, 3, 10);
char ch;
int pr_key;
int cur_pos;
String dbase_name;

struct myStruct {
  char x;
};

char *keys[] = {"4f18b6b1ffd81f9755b0815db942c415834a9bae3bbc838a2d6b33d2f87598fd"};// Serpent key

unsigned char Blwfsh_key[] = {
   0xd1,0xf0,0x68,0x5b,
   0x33,0xa0,0xb1,0x73,
   0xb6,0x25,0x54,0xf9,
   0xdd,0x2c,0xd3,0x1d,
   0xc1,0x93,0xb3,0x14,
   0x16,0x76,0x28,0x59
};

uint8_t key[32] = {
   0xd1,0xf0,0x68,0x5b,
   0x33,0xa0,0xb1,0x73,
   0xb6,0x25,0x54,0xf9,
   0xdd,0x2c,0xd3,0x1d,
   0xc1,0x93,0xb3,0x14,
   0x16,0x76,0x28,0x59,
   0x04,0x85,0xd4,0x24,
   0x9d,0xe0,0x2a,0x74
};

uint8_t second_key[32] = {
   0xfb,0x87,0x9c,0x11,
   0x16,0x97,0xbb,0x14,
   0x3c,0x1e,0x30,0xdb,
   0x67,0xab,0xb8,0x9b,
   0x23,0x5e,0x15,0x9a,
   0xd2,0xdd,0x7c,0x96,
   0x41,0xc9,0x25,0xd3,
   0xd0,0xe1,0x75,0xe3
};

unsigned char back_Blwfsh_key[16];

void back_Blwfsh_k(){
  for(int i = 0; i < 16; i++){
    back_Blwfsh_key[i] = Blwfsh_key[i];
  }
}

void rest_Blwfsh_k(){
  for(int i = 0; i < 16; i++){
    Blwfsh_key[i] = back_Blwfsh_key[i];
  }
}

void incr_Blwfsh_key() {
  if (Blwfsh_key[0] == 255) {
    Blwfsh_key[0] = 0;
    if (Blwfsh_key[1] == 255) {
      Blwfsh_key[1] = 0;
      if (Blwfsh_key[2] == 255) {
        Blwfsh_key[2] = 0;
        if (Blwfsh_key[3] == 255) {
          Blwfsh_key[3] = 0;
          if (Blwfsh_key[4] == 255) {
            Blwfsh_key[4] = 0;
            if (Blwfsh_key[5] == 255) {
              Blwfsh_key[5] = 0;
              if (Blwfsh_key[6] == 255) {
                Blwfsh_key[6] = 0;
                if (Blwfsh_key[7] == 255) {
                  Blwfsh_key[7] = 0;
                  if (Blwfsh_key[8] == 255) {
                    Blwfsh_key[8] = 0;
                    if (Blwfsh_key[9] == 255) {
                      Blwfsh_key[9] = 0;
                      if (Blwfsh_key[10] == 255) {
                        Blwfsh_key[10] = 0;
                        if (Blwfsh_key[11] == 255) {
                          Blwfsh_key[11] = 0;
                          if (Blwfsh_key[12] == 255) {
                            Blwfsh_key[12] = 0;
                            if (Blwfsh_key[13] == 255) {
                              Blwfsh_key[13] = 0;
                              if (Blwfsh_key[14] == 255) {
                                Blwfsh_key[14] = 0;
                                if (Blwfsh_key[15] == 255) {
                                  Blwfsh_key[15] = 0;
                                } else {
                                  Blwfsh_key[15]++;
                                }
                              } else {
                                Blwfsh_key[14]++;
                              }
                            } else {
                              Blwfsh_key[13]++;
                            }
                          } else {
                            Blwfsh_key[12]++;
                          }
                        } else {
                          Blwfsh_key[11]++;
                        }
                      } else {
                        Blwfsh_key[10]++;
                      }
                    } else {
                      Blwfsh_key[9]++;
                    }
                  } else {
                    Blwfsh_key[8]++;
                  }
                } else {
                  Blwfsh_key[7]++;
                }
              } else {
                Blwfsh_key[6]++;
              }
            } else {
              Blwfsh_key[5]++;
            }
          } else {
            Blwfsh_key[4]++;
          }
        } else {
          Blwfsh_key[3]++;
        }
      } else {
        Blwfsh_key[2]++;
      }
    } else {
      Blwfsh_key[1]++;
    }
  } else {
    Blwfsh_key[0]++;
  }
}


Blowfish blowfish;

String keyb_inp;

int getNum(char ch)
{
    int num=0;
    if(ch>='0' && ch<='9')
    {
        num=ch-0x30;
    }
    else
    {
        switch(ch)
        {
            case 'A': case 'a': num=10; break;
            case 'B': case 'b': num=11; break;
            case 'C': case 'c': num=12; break;
            case 'D': case 'd': num=13; break;
            case 'E': case 'e': num=14; break;
            case 'F': case 'f': num=15; break;
            default: num=0;
        }
    }
    return num;
}

char getChar(int num){
  char ch;
    if(num>=0 && num<=9)
    {
        ch = char(num+48);
    }
    else
    {
        switch(num)
        {
            case 10: ch='a'; break;
            case 11: ch='b'; break;
            case 12: ch='c'; break;
            case 13: ch='d'; break;
            case 14: ch='e'; break;
            case 15: ch='f'; break;
        }
    }
    return ch;
}

size_t hex2bin (void *bin, char hex[]) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  
  len = strlen (hex);
  
  if ((len & 1) != 0) {
    return 0; 
  }
  
  for (i=0; i<len; i++) {
    if (isxdigit((int)hex[i]) == 0) {
      return 0; 
    }
  }
  
  for (i=0; i<len / 2; i++) {
    sscanf (&hex[i * 2], "%2x", &x);
    p[i] = (uint8_t)x;
  } 
  return len / 2;
}

void modify_keys(char card1[], int card2[], int card3[], int card4[]){
  int str_len = keyb_inp.length() + 1;
  char input_arr[str_len];
  keyb_inp.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < 2; i++) {
      str += card1[i];
    }
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  int h_len = h.length() + 1;
  char h_array[h_len];
  h.toCharArray(h_array, h_len);
  byte res[16];
  for (int i = 0; i < 32; i += 2) {
    if (i == 0) {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i] = 0;
    } else {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i / 2] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i / 2] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i / 2] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i / 2] = 0;
    }
  }
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, i, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;
  for (i = 0; i < sizeof(keys) / sizeof(char * ); i++) {
    hex2bin(key, keys[i]);
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];
    serpent_setkey( & skey, key);
    for (j = 0; j < sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
      if ((j % 8) == 0) putchar('\n');
    }
    for (int i = 0; i < 16; i++)
      ct2.b[i] = res[i];
  }

  unsigned char tblw[16];
  /*
  Serial.println("\nBefore going through Serpent");
  for (int i = 0; i < 16; i++){
    Serial.print(int(ct2.b[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  for (int i = 0; i < 176; i++)
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
  /*
  Serial.println("\nAfter going through Serpent 176 times");
  for (int i = 0; i < 16; i++){
    Serial.print(int(ct2.b[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  for (int i = 0; i < 4; i++)
    tblw[i] = ct2.b[i];
    
  for (int i = 0; i < 711; i++)
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
  /*
  Serial.println("\nAfter going through Serpent 887 times");
  for (int i = 0; i < 16; i++){
    Serial.print(int(ct2.b[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  for (int i = 0; i < 4; i++)
    tblw[i+4] = ct2.b[i];

  for (int i = 0; i < 4; i++)
    ct2.b[i+6] ^= card2[i];

  for (int i = 0; i < 1773; i++)
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
  /*
  Serial.println("\nAfter going through Serpent 2660 times");
  for (int i = 0; i < 16; i++){
    Serial.print(int(ct2.b[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  for (int i = 0; i < 4; i++)
    tblw[i+8] = ct2.b[i];
  // Fill the last four slots in tblw with card
  for (int i = 0; i < 4; i++)
    tblw[i+12] = card3[i];
  
  /*
  Serial.println("\nBefore going through blowfish");
  for (int i = 0; i < 16; i++){
    Serial.print(int(tblw[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  for (int i = 0; i < 654; i++)
    blowfish.Decrypt(tblw, tblw, sizeof(tblw));

  int aft654[2];
  aft654[0] = int(tblw[14]);
  aft654[1] = int(tblw[5]);
  for (int i = 0; i < 1000; i++){
    blowfish.Decrypt(tblw, tblw, sizeof(tblw));
    incr_Blwfsh_key();
  }
  /*
  Serial.println("\nAfter going through blowfish 1654 times");
  for (int i = 0; i < 16; i++){
    Serial.print(int(tblw[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  std::string str1 = "";
  for (int i = 0; i < 5; i++) {
    str1 += char(250+i);
  }
    
  for (int i = 0; i < 16; i++) {
    str1 += (char)tblw[i];
  }

  for (int i = 2; i < 4; i++)
    str1 += card1[i];

  for (int i = 34; i < 60; i++)
    str1 += h_array[i];
  
  String h1 = sha512(str1).c_str();
  int h1_len = h1.length() + 1;
  //Serial.print("h1_len: ");
  //Serial.println(h1_len);
  char h1_array[h1_len];
  h1.toCharArray(h1_array, h1_len);
  byte res1[24];
  for (int i = 16; i < 64; i += 2) {
      if (h1_array[i] != 0 && h1_array[i + 1] != 0)
        res1[i / 2] = 16 * getNum(h1_array[i]) + getNum(h1_array[i + 1]);
      if (h1_array[i] != 0 && h1_array[i + 1] == 0)
        res1[i / 2] = 16 * getNum(h1_array[i]);
      if (h1_array[i] == 0 && h1_array[i + 1] != 0)
        res1[i / 2] = getNum(h1_array[i + 1]);
      if (h1_array[i] == 0 && h1_array[i + 1] == 0)
        res1[i / 2] = 0;
  }
  /*
  Serial.println("\n----------What can be used----------");
  Serial.println("\nHashed Blowfish output");
  for (int i = 3; i < 24; i++){
    if (i != 5 && i != 6 && i != 7){
      Serial.print(((int(res1[i]) + 1) * (int(h_array[80 + i]) + 1)) % 256);
      Serial.print(" ");
    }
  }
  Serial.println();
  */
  int tmp_fr_srp[16];
  for (int i = 0; i < 16; i++)
    tmp_fr_srp[i] = ct2.b[i];
  tmp_fr_srp[6] = int(res1[1]);
  // Fill the first four slots in ct2.b with card
  for (int i = 0; i < 4; i++)
    ct2.b[i] = card4[i];

  for (int i = 4; i < 16; i++)
    ct2.b[i] = tmp_fr_srp[i];
    
  for (int i = 0; i < 2000; i++)
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
  /*
  Serial.println("\nFirst three of tmp_f_s");
  for (int i = 0; i < 3; i++){
    if (i == 0)
      Serial.print(tmp_fr_srp[i] ^ aft654[1]);
    else
      Serial.print(tmp_fr_srp[i] ^ int(h_array[60+i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  /*
  Serial.println("\nResult from Serpent");
  for (int i = 2; i < 13; i++){
    Serial.print((((int(ct2.b[i]) + 1) * (int(h1_array[70 + i])) + 2)) % 256);
    Serial.print(" ");
  }
  Serial.println();
  */
  //Serial.print("\nVerifcation number: ");
  unsigned int vn = ((((int(tblw[0]) + 1) * (int(ct2.b[15]) + 2)) * 36 * (int(res1[2]) + 1) + aft654[0] + ((int(h_array[110]) + 1) * (int(h1_array[110]) + 1))) % 9981) + 13;
  //Serial.println(vn);
  /*
  Serial.println("Decomposed");
  Serial.println(int(tblw[0]));
  Serial.println(int(ct2.b[15]));
  Serial.println(int(res1[2]));
  Serial.println(int(aft654[0]));
  Serial.println();
  */
  keyb_inp = "";

  for (int i = 0; i < 10; i++){
    Blwfsh_key[i] = (unsigned char) (((int(res1[i+8]) + 1) * (int(h_array[88 + i]) + 1)) % 256);
  }

  for (int i = 0; i < 5; i++){
    second_key[i] = byte(((int(res1[i+18]) + 1) * (int(h_array[98 + i]) + 1)) % 256);
  }
  
  key[9] = byte(((int(res1[3]) + 1) * (int(h_array[84]) + 1)) % 256);
  key[12] = byte(((int(res1[4]) + 1) * (int(h_array[85]) + 1)) % 256);
  
  for (int i = 0; i < 3; i++){
    if (i == 0)
      key[i] = byte(tmp_fr_srp[i] ^ aft654[1]);
    else
      key[i] = byte(tmp_fr_srp[i] ^ int(h_array[60+i]));
  }
  
  key[5] = byte(((int(res1[i]) + 1) * (int(h_array[80 + i]) + 1)) % 256);
  
  for (int i = 2; i < 10; i++){
    second_key[i+8] = byte((((int(ct2.b[i]) + 1) * (int(h1_array[70 + i])) + 2)) % 256);
  }
  
  Blwfsh_key[10] = byte((((int(ct2.b[10]) + 1) * (int(h1_array[80])) + 2)) % 256);
  Blwfsh_key[11] = byte((((int(ct2.b[11]) + 1) * (int(h1_array[81])) + 2)) % 256);

  keyb_inp = "";
  tft.fillScreen(0x1557);
  tft.fillRect(25, 70, 190, 82, 0x08c5);
  tft.setTextColor(0x1557, 0x08c5);
  tft.setTextSize(1);
  tft.setCursor(40,85);
  tft.print("Keys derived successfully.");
  tft.setTextColor(0xffff, 0x08c5);
  tft.setTextSize(1);
  tft.setCursor(40,102);
  tft.printf("Verification number is %d", vn);
  tft.setTextColor(0x1557, 0x08c5);
  tft.setTextSize(1);
  tft.setCursor(40,119);
  tft.print("Press any key to get to the");
  tft.setCursor(40,129);
  tft.print("main menu.");
  while (!bus.gotData()){
      bus.tick();
  }
  m_menu_rect();
  main_menu(0);
  //Serial.println(dbase_name);
}

void appr_cards_and_log_in(){
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff, 0x0000);
  tft.setTextSize(1);
  tft.setCursor(0,0);
  int act = 0;
  char card1[4];
  int card2[4];
  int card3[4];
  int card4[4];
  Serial.println("Approximate the RFID card N1 to the reader");
  tft.print("Approximate RFID card N1 to the reader.");
  while (act < 90){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (act == 0)
        card1[0] = data.x;
      if (act == 1)
        card1[1] = data.x;
      if (act == 2)
        card1[2] = data.x;
      if (act == 3){
        card1[3] = data.x;
        delay(700);
        Serial.println("Approximate the RFID card N2 to the reader");
        tft.setCursor(0,10);
        tft.print("Approximate RFID card N2 to the reader.");
      }
      if (act == 4)
        card2[0] = int(data.x);
      if (act == 5)
        card2[1] = int(data.x);
      if (act == 6)
        card2[2] = int(data.x);
      if (act == 7){
        card2[3] = int(data.x);
        delay(700);
        Serial.println("Approximate the RFID card N3 to the reader");
        tft.setCursor(0,20);
        tft.println("Approximate RFID card N3 to the reader.");
      }
      if (act == 8)
        card3[0] = int(data.x);
      if (act == 9)
        card3[1] = int(data.x);
      if (act == 10)
        card3[2] = int(data.x);
      if (act == 11){
        card3[3] = int(data.x);
        delay(700);
        Serial.println("Approximate the RFID card N4 to the reader");
        tft.setCursor(0,30);
        tft.println("Approximate RFID card N4 to the reader.");
      }
      if (act == 12)
        card4[0] = int(data.x);
      if (act == 13)
        card4[1] = int(data.x);
      if (act == 14)
        card4[2] = int(data.x);
      if (act == 15){
        card4[3] = int(data.x);
        act = 100;
      }
      act ++;
    }
  }

   tft.fillScreen(0x1557);
   tft.fillRect(25, 25, 190, 220, 0x08c5);

   tft.setTextColor(0xffff, 0x08c5);
   tft.setTextSize(3);
   tft.setCursor(40,40);
   tft.print("Cipherbox");

   tft.setTextColor(0x1557, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,85);
   tft.print("Username");

   tft.setTextColor(0xffff, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,102);
   tft.print("Enter your username...");
   
   tft.drawLine(40, 111, 200, 111, 0xffff);

   tft.setTextColor(0x1557, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,135);
   tft.print("Password");

   tft.setTextColor(0xffff, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,152);
   tft.print("Enter your password...");
   
   tft.drawLine(40, 161, 200, 161, 0xffff);

   tft.setTextColor(0x1557, 0x08c5);
   tft.setTextSize(1);
   tft.setCursor(40,183);
   tft.print("Press Tab to move between");

   tft.setCursor(40,195);
   tft.print("fields.");

   tft.setCursor(40,212);
   tft.print("Press Enter to log in.");

   tft.setTextColor(0x08c5, 0x1557);
   tft.setTextSize(2);
   tft.setCursor(14,302);
   tft.print("Username Length:0");
   
  pr_key = 0;
  String usrn_lg;
  String pass_lg;
  bool un_or_p = false; // false - username, true - password
  while (act < 900){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9){
        if (un_or_p == false)
          usrn_lg += ch;
        if (un_or_p == true)
          pass_lg += ch;
      }
      else if (ch == 127) { // Backspace
        if(usrn_lg.length() > 0 && un_or_p == false){ // Username
          usrn_lg.remove(usrn_lg.length() -1, 1);
          tft.setTextColor(0xffff, 0x08c5);
          tft.setTextSize(1);
          tft.setCursor(40,102);
          tft.print("                           ");
        }
        
        if(pass_lg.length() > 0 && un_or_p == true){ // Password
          pass_lg.remove(pass_lg.length() -1, 1);
          tft.setTextColor(0xffff, 0x08c5);
          tft.setTextSize(1);
          tft.setCursor(40,152);
          tft.print("                           ");
        }

          tft.setTextColor(0x08c5, 0x1557);
          tft.setTextSize(2);
          tft.setCursor(206,302);
          tft.print("   "); 

      }
      else if (ch == 9) { // Tab
        if (un_or_p == false){
          un_or_p = true;
          tft.setTextColor(0x08c5, 0x1557);
          tft.setTextSize(2);
          tft.setCursor(14,302);
          tft.print("                  ");
          tft.setCursor(14,302);
          tft.print("Password Length:");
        }
        else if (un_or_p == true){
          un_or_p = false;
          tft.setTextColor(0x08c5, 0x1557);
          tft.setTextSize(2);
          tft.setCursor(14,302);
          tft.print("                  ");
          tft.setCursor(14,302);
          tft.print("Username Length:");
        }
      }
      int inpl1 = usrn_lg.length();
      int inpl2 = pass_lg.length();
      if(inpl1 == 0){ // Username is empty
        tft.setTextColor(0xffff, 0x08c5);
        tft.setTextSize(1);
        tft.setCursor(40,102);
        tft.print("                           ");
        tft.setCursor(40,102);
        tft.print("Enter your username...");
        if (un_or_p == false){
          tft.setTextColor(0x08c5, 0x1557);
          tft.setTextSize(2);
          tft.setCursor(206,302);
          tft.print("   ");
          tft.setCursor(206,302);
          tft.print("0"); 
        }
      }
      else{
        if (un_or_p == false){
          tft.setTextColor(0xffff, 0x08c5);
          tft.setTextSize(1);
          tft.setCursor(40,102);
          tft.print("                           ");
          String visible_usrn;
          for(int i = 0; i < inpl1; i++){
            if (i < 27)
              visible_usrn += usrn_lg.charAt(i);
          }
          tft.setTextColor(0xffff, 0x08c5);
          tft.setTextSize(1);
          tft.setCursor(40,102);
          tft.print(visible_usrn);
          tft.setTextColor(0x08c5, 0x1557);
          tft.setTextSize(2);
          tft.setCursor(206,302);
          tft.print("   ");
          tft.setCursor(206,302);
          tft.print(inpl1);
        }
      }
      if(inpl2 == 0){ // Password is empty
        tft.setTextColor(0xffff, 0x08c5);
        tft.setTextSize(1);
        tft.setCursor(40,152);
        tft.print("                           ");
        tft.setCursor(40,152);
        tft.print("Enter your password...");
        if (un_or_p == true){
          tft.setTextColor(0x08c5, 0x1557);
          tft.setTextSize(2);
          tft.setCursor(206,302);
          tft.print("   ");
          tft.setCursor(206,302);
          tft.print("0"); 
        }
      }
      else{
        if (un_or_p == true){
          tft.setTextColor(0xffff, 0x08c5);
          tft.setTextSize(1);
          tft.setCursor(40,152);
          tft.print("                           ");
          String stars = "";
          for(int i = 0; i < inpl2; i++){
            if (i < 27)
              stars += "*";
          }
          tft.setTextColor(0xffff, 0x08c5);
          tft.setTextSize(1);
          tft.setCursor(40,152);
          tft.print(stars);
          tft.setTextColor(0x08c5, 0x1557);
          tft.setTextSize(2);
          tft.setCursor(206,302);
          tft.print("   ");
          tft.setCursor(206,302);
          tft.print(inpl2);
        }
      }
      if (pr_key == 13){
        keyb_inp = pass_lg;
        der_db_name_from_str(usrn_lg);
        //Serial.println();
        //Serial.println(usrn_lg);
        //Serial.println(pass_lg);
        tft.fillScreen(0x0000);
        tft.setTextColor(0xffff, 0x0000);
        tft.setTextSize(1);
        tft.setCursor(0,0);
        tft.print("Deriving keys. Please wait for a while.");
        modify_keys(card1, card2, card3, card4);
        act  = 1000;
      }
    }
 }
}


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
   return;
}

void m_menu_rect(){
   tft.fillScreen(0x1557);
   tft.fillRect(15, 15, 210, 165, 0x08c5);
}

void der_db_name_from_str(String input){
  //Serial.println(input);
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  std::string str = "";
  if(str_len > 1){
    for(int i = 0; i<str_len-1; i++){
      str += input_arr[i];
    }
  }
  String h = sha512( str ).c_str();
  //Serial.println(h);
  int h_len = h.length() + 1;
  char h_array[h_len];
  h.toCharArray(h_array, h_len);
  byte res[12];
  for (int i = 0; i < 24; i += 2) {
    if (i == 0) {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i] = 0;
    } else {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i / 2] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i / 2] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i / 2] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i / 2] = 0;
    }
  }
  dbase_name = "";
  for(int i = 0; i < 12; i++){
    if (i == 0){
      if (res[i] != 0)
        dbase_name = char(97 + (int(res[i])%26));
      else
        dbase_name = 'a';
    }
    else{
      if (res[i] != 0)
        dbase_name += char(97 + (int(res[i])%26));
      else
        dbase_name += 'a';
    }
  }
  dbase_name += ".db";
  //Serial.println(dbase_name);
}

void setup() {
  Serial.begin(115200);
  mySerial.begin(9600);
  tft.begin(); 
  tft.setRotation(0);
  appr_cards_and_log_in();
  cur_pos = 0;
}

void loop() {
  bus.tick();
  if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
    ch = data.x;
    //Serial.println(ch);
    //Serial.println(int(ch));
    pr_key = int(ch);
    if (pr_key == 10)
      cur_pos++;
      
    if (pr_key == 11)
      cur_pos--;
      
    if (cur_pos < 0)
      cur_pos = 9;
      
    if (cur_pos > 9)
      cur_pos = 0;
    
    main_menu(cur_pos);
  }
}
