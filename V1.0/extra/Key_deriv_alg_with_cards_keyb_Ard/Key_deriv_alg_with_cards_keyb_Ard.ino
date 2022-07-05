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
GBUS bus(&mySerial, 3, 10);
char ch;
int pr_key;

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
  Serial.print("\nVerifcation number: ");
  unsigned int vn = ((((int(tblw[0]) + 1) * (int(ct2.b[15]) + 2)) * 36 * (int(res1[2]) + 1) + aft654[0] + ((int(h_array[110]) + 1) * (int(h1_array[110]) + 1))) % 9981) + 13;
  Serial.println(vn);
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
  
}

void setup() {
  Serial.begin(115200);
  mySerial.begin(9600);
  int act = 0;
  char card1[4];
  int card2[4];
  int card3[4];
  int card4[4];
  Serial.println("Approximate the RFID card N1 to the reader");
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
  Serial.println("Enter the master password");
  pr_key = 0;
  while (act < 900){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
      }
      int inpl = keyb_inp.length();
      Serial.println(keyb_inp);
      if (pr_key == 13){
        modify_keys(card1, card2, card3, card4);
        act  = 1000;
      }
    }
 }
}

void loop() {
  bus.tick();
  if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    Serial.println(int(data.x));
    Serial.println();
  }
}
