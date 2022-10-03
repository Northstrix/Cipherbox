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
#include <SoftwareSerial.h>
SoftwareSerial mySerial(34, 35); // RX, TX
#include <WiFi.h>
#include "ThingSpeak.h"
#include <SoftwareSerial.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "blowfish.h"
#include <SPI.h>
#include <FS.h>
#include "SPIFFS.h"
#include <sys/random.h>
#include "sha512.h"
#include "aes.h"
#include "serpent.h"
#include "GBUS.h"
#include "Crypto.h"
#include "DES.h"
#include <EncButton2.h>
#include <Adafruit_GFX.h>                                                   // include Adafruit graphics library
#include <Adafruit_ILI9341.h>                                               // include Adafruit ILI9341 TFT library

#define TFT_CS 15 // TFT CS  pin is connected to ESP32 pin D15
#define TFT_RST 4 // TFT RST pin is connected to ESP32 pin D4
#define TFT_DC 2  // TFT DC  pin is connected to ESP32 pin D2
                  // SCK (CLK) ---> ESP32 pin D18
                  // MOSI(DIN) ---> ESP32 pin D23

Adafruit_ILI9341 tft = Adafruit_ILI9341(TFT_CS, TFT_DC, TFT_RST);
EncButton2 < EB_ENC > enc0(INPUT, 26, 27);
EncButton2 < EB_BTN > encoder_button(INPUT, 33);
GBUS bus( & mySerial, 3, 4);
char ch;
int curr_key;
int cur_pos;
int num_of_IDs;
String dbase_name;
int count;
byte tmp_st[8];
int pass_to_serp[16];
int m;
String dec_st;
String dec_tag;
int decract;
String keyb_inp;
uint8_t back_key[32];
uint8_t back_s_key[32];
uint8_t back_serp_key[32];
unsigned char back_Blwfsh_key[16];
Blowfish blowfish;
String rec_ID;

const char* ssid = "My Wireless Network";   // Your network SSID (name) 
const char* password = "dTre7bd90mrs";   // Your network password
unsigned long myChannelNumber = 1234567; // Channel ID
const char * myWriteAPIKey = "A1B2C3D4E5F6G7H8"; // Write API Key
const char * myReadAPIKey = "K9L8M7N6O5P4Q3R2"; // Read API Key

WiFiClient  client;

// Keys (Below)

byte hmackey[] = {"JIZ7O2M92JectyqGTObEmdr682cdqh23ygx54koNH0Iux1FuX160C2T0432C6F7b39wvIZQ161mbPc9w6n5PI6Cx59JD6Vrms1Hfanq94pDQJZVtp185zz1KKP79nNmpJtOA8MwawV3tXpdL1PRlEVuuVtAcCzw9838Bk0kZff396LX78f5r2U8Ac52avx01Q8B8UEk25yO100XU5Haxlb9PDGdhzgP78W77Q76x21WfdPadq8bNzMuAjYA8uzW4DXZc89toZ542Nge59L6Xs4J9OMJYqfz9YkSvQ6ij4X3a6Z0X8rP8"};
unsigned char Blwfsh_key[] = {
0x2d,0x12,0x6b,0xf5,
0x76,0x2d,0x86,0x5a,
0xcd,0xca,0xbf,0xa9,
0x1f,0xc2,0xf9,0x68,
0xbc,0xc6,0x94,0x4d,
0x2e,0x48,0xa3,0x69
};
uint8_t key[32] = {
0x3a,0x62,0x1f,0xf8,
0xaa,0x37,0xc4,0xc9,
0xcc,0x1e,0x8a,0x10,
0xbd,0xd2,0xdb,0x7b,
0x28,0xbf,0xbc,0x2b,
0xad,0x16,0x02,0xcf,
0xc9,0xad,0x3b,0xf3,
0xdd,0xc3,0xdf,0x67
};
uint8_t serp_key[32] = {
0xc7,0x5a,0xfb,0x58,
0x34,0xea,0x9b,0xec,
0x18,0xd5,0x2c,0x91,
0xf2,0x7a,0xa8,0xed,
0x01,0xb1,0xb3,0x27,
0xef,0x2a,0x56,0xfc,
0xdb,0xa2,0x0e,0x61,
0xca,0x6c,0xaf,0xfc
};
uint8_t second_key[32] = {
0x00,0xae,0x4e,0xa4,
0x90,0xa5,0x18,0xc7,
0x97,0xe9,0xf4,0xd8,
0x2e,0xf2,0xcf,0x65,
0x2a,0x3e,0x29,0xcb,
0x58,0xbc,0x45,0x4a,
0xd8,0xae,0x9b,0x94,
0x3b,0x95,0xbd,0x8b
};
byte TDESkey[] = {
0x4b,0x7a,0xb4,0xc3,0x7e,0x2f,0xf5,0x54,
0x55,0xb1,0xff,0xcf,0x0e,0x0b,0xea,0xee,
0x40,0xcf,0xa4,0xc1,0xde,0xc5,0x10,0x27
};

// Keys (Above)

DES des;

byte TDESkey_backup[16];

void back_TDESkey(){
  for(int i = 0; i < 16; i++){
    TDESkey_backup[i] = TDESkey[i];
  }
}

void rest_TDESkey(){
  for(int i = 0; i < 16; i++){
    TDESkey[i] = TDESkey_backup[i];
  }
}

void incr_TDESkey() { // Key incrementing function
  if (TDESkey[15] == 255) {
    TDESkey[15] = 0;
    if (TDESkey[14] == 255) {
      TDESkey[14] = 0;
      if (TDESkey[13] == 255) {
        TDESkey[13] = 0;
        if (TDESkey[12] == 255) {
          TDESkey[12] = 0;
          if (TDESkey[11] == 255) {
            TDESkey[11] = 0;
            if (TDESkey[10] == 255) {
              TDESkey[10] = 0;
              if (TDESkey[9] == 255) {
                TDESkey[9] = 0;
                if (TDESkey[8] == 255) {
                  TDESkey[8] = 0;
                  if (TDESkey[7] == 255) {
                    TDESkey[7] = 0;
                    if (TDESkey[6] == 255) {
                      TDESkey[6] = 0;
                      if (TDESkey[5] == 255) {
                        TDESkey[5] = 0;
                        if (TDESkey[4] == 255) {
                          TDESkey[4] = 0;
                          if (TDESkey[3] == 255) {
                            TDESkey[3] = 0;
                            if (TDESkey[2] == 255) {
                              TDESkey[2] = 0;
                              if (TDESkey[1] == 255) {
                                TDESkey[1] = 0;
                                if (TDESkey[0] == 255) {
                                  TDESkey[0] = 0;
                                } else {
                                  TDESkey[0]++;
                                }
                              } else {
                                TDESkey[1]++;
                              }
                            } else {
                              TDESkey[2]++;
                            }
                          } else {
                            TDESkey[3]++;
                          }
                        } else {
                          TDESkey[4]++;
                        }
                      } else {
                        TDESkey[5]++;
                      }
                    } else {
                      TDESkey[6]++;
                    }
                  } else {
                    TDESkey[7]++;
                  }
                } else {
                  TDESkey[8]++;
                }
              } else {
                TDESkey[9]++;
              }
            } else {
              TDESkey[10]++;
            }
          } else {
            TDESkey[11]++;
          }
        } else {
          TDESkey[12]++;
        }
      } else {
        TDESkey[13]++;
      }
    } else {
      TDESkey[14]++;
    }
  } else {
    TDESkey[15]++;
  }
}

struct myStruct {
  char x;
  bool d;
};

int clb_m;

typedef struct struct_message {
  char l_srp[16];
  char r_srp[16];
  bool n;
}

struct_message;
struct_message myData;

const char * data = "Callback function called";
static int callback(void * data, int argc, char ** argv, char ** azColName) {
  int i;
  if (clb_m == 0) //Print in serial
    Serial.printf("%s: ", (const char * ) data);
  if (clb_m == 1) { //Print in serial
    tft.printf("%s:\n", (const char * ) data);
  }
  for (i = 0; i < argc; i++) {
    if (clb_m == 0) { //Print in serial
      Serial.printf("\n%s = %s", azColName[i], argv[i] ? argv[i] : "Empty");
      Serial.printf("\n\n");
    }
    if (clb_m == 1) { //Print in tft
      tft.printf("\n%s = %s\n", azColName[i], argv[i] ? argv[i] : "Empty");
      Serial.printf("\n\n");
    }
    if (clb_m == 2) { //Decrypt
      int ct_len = strlen(argv[i]) + 1;
      char ct_array[ct_len];
      snprintf(ct_array, ct_len, "%s", argv[i]);
      int ext = 0;
      count = 0;
      bool ch = false;
      while (ct_len > ext) {
        if (count % 2 == 1 && count != 0)
          ch = true;
        else {
          ch = false;
          incr_Blwfsh_key();
          incr_key();
          incr_serp_key();
          incr_second_key();
        }
        split_dec(ct_array, ct_len, 0 + ext, ch, true);
        ext += 32;
        count++;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
    }
    if (clb_m == 3) { //Extract IDs
      int ct_len = strlen(argv[i]) + 1;
      char ct_array[ct_len];
      snprintf(ct_array, ct_len, "%s", argv[i]);
      for (int i = 0; i < ct_len; i++) {
        dec_st += ct_array[i];
      }
      dec_st += "\n";
      num_of_IDs++;
    }
  }
  return 0;
}

void split_by_eight(char plntxt[], int k, int str_len, bool add_aes, bool out_f) {
  char plt_data[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    plt_data[i] = plntxt[i + k];
  }
  /*
  Serial.println("\nInput");
  for (int i = 0; i < 8; i++){
    Serial.print(plt_data[i]);
    Serial.print(" ");
  }
  */
  unsigned char t_encr[8];
  for (int i = 0; i < 8; i++) {
    t_encr[i] = (unsigned char) plt_data[i];
  }
  /*
  Serial.println("\nChar");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(t_encr, t_encr, sizeof(t_encr));
  char encr_for_aes[16];
  for (int i = 0; i < 8; i++) {
    encr_for_aes[i] = char(int(t_encr[i]));
  }
  /*
  Serial.println("\nEncrypted");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  for (int i = 8; i < 16; i++) {
    encr_for_aes[i] = gen_r_num();
  }
  /*
  Serial.println("\nFor AES");
  for (int i = 0; i < 16; i++){
    Serial.print(int(encr_for_aes[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  encr_AES(encr_for_aes, add_aes, out_f);
}

void encr_AES(char t_enc[], bool add_aes, bool out_f) {
  uint8_t text[16];
  for (int i = 0; i < 16; i++) {
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  aes_context ctx;
  aes_set_key( & ctx, key, key_bit[2]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for (int i = 0; i < 8; i++) {
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for (int i = 0; i < 8; i++) {
    R_half[i] = cipher_text[i + 8];
  }
  for (int i = 8; i < 16; i++) {
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  serp_enc(L_half, add_aes, out_f);
  serp_enc(R_half, add_aes, out_f);
}

void serp_enc(char res[], bool add_aes, bool out_f) {
  int tmp_s[16];
  for (int i = 0; i < 16; i++) {
    tmp_s[i] = res[i];
  }
  /*
   for (int i = 0; i < 16; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for (int i = 0; i < 16; i++) {
      ct2.b[i] = tmp_s[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    if (add_aes == false) {
      for (int i = 0; i < 16; i++) {
        if (ct2.b[i] < 16)
          Serial.print("0");
        Serial.print(ct2.b[i], HEX);
      }
    }
    if (add_aes == true)
      encr_sec_AES(ct2.b, out_f);
  }
}

void encr_sec_AES(byte t_enc[], bool out_f) {
  uint8_t text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  uint32_t second_key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, second_key, second_key_bit[2]);
  aes_encrypt_block( & ctx, cipher_text, text);
  for (i = 0; i < 16; i++) {
    if (out_f == false)
      Serial.printf("%02x", cipher_text[i]);
    if (out_f == true) {
      if (cipher_text[i] < 16)
        dec_st += 0;
      dec_st += String(cipher_text[i], HEX);
    }
  }
}

void split_dec(char ct[], int ct_len, int p, bool ch, bool add_r) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }
  if (br == false) {
    if (add_r == true) {
      uint8_t ret_text[16] = {
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
      };
      uint8_t cipher_text[16] = {
        0
      };
      for (int i = 0; i < 16; i++) {
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t second_key_bit[3] = {
        128,
        192,
        256
      };
      int i = 0;
      aes_context ctx;
      aes_set_key( & ctx, second_key, second_key_bit[2]);
      aes_decrypt_block( & ctx, ret_text, cipher_text);
      for (i = 0; i < 16; i++) {
        res[i] = (char) ret_text[i];
      }
    }
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);
      //Serial.printf ("\nkey=");

      for (j = 0; j < sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
        if ((j % 8) == 0) putchar('\n');
        //Serial.printf ("%08X ", p[j]);
      }

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
    if (ch == false) {
      for (int i = 0; i < 8; i++) {
        tmp_st[i] = char(ct2.b[i]);
      }
    }
    if (ch == true) {
      decr_AES_and_blwfsh(ct2.b);
    }
  }
}

void decr_AES_and_blwfsh(byte sh[]) {
  uint8_t ret_text[16];
  for (int i = 0; i < 8; i++) {
    ret_text[i] = tmp_st[i];
  }
  for (int i = 0; i < 8; i++) {
    ret_text[i + 8] = sh[i];
  }
  uint8_t cipher_text[16] = {
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(ret_text[i]);
    cipher_text[i] = c;
  }
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, key, key_bit[2]);
  aes_decrypt_block( & ctx, ret_text, cipher_text);
  /*
  Serial.println("\nDec by AES");
  for (int i = 0; i < 16; i++){\
    Serial.print(int(ret_text[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  unsigned char dbl[8];
  for (int i = 0; i < 8; i++) {
    dbl[i] = (unsigned char) int(ret_text[i]);
  }
  /*
  Serial.println("\nConv for blowfish");
  for (int i = 0; i < 8; i++){\
    Serial.print(dbl[i]);
    Serial.print(" ");
  }
  Serial.println();
  */
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Decrypt(dbl, dbl, sizeof(dbl));
  /*
  Serial.println("\nDecr by blowfish");
  for (int i = 0; i < 8; i++){\
    Serial.print(int(dbl[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  if (decract < 4) {
    for (int i = 0; i < 8; i++) {
      if (dbl[i] < 0x10)
        dec_tag += 0;
      dec_tag += String(dbl[i], HEX);
    }
  } else {
    for (i = 0; i < 8; ++i) {
      dec_st += (char(dbl[i]));
    }
  }
  decract++;
}

void gen_rand_ID(int n_itr) {
  for (int i = 0; i < n_itr; i++) {
    int r_numb3r = esp_random() % 95;
    if (r_numb3r != 7)
      rec_ID += char(32 + r_numb3r);
    else
      rec_ID += char(33 + r_numb3r + esp_random() % 30);
  }
}

int gen_r_num() {
  int rn = esp_random() % 256;
  return rn;
}

int db_open(const char * filename, sqlite3 ** db) {
  int rc = sqlite3_open(filename, db);
  if (rc) {
    if (clb_m == 0) //Print in serial
      Serial.printf("Can't open database: %s\n", sqlite3_errmsg( * db));
    if (clb_m == 1) //Print in tft
      tft.printf("Can't open database: %s\n", sqlite3_errmsg( * db));
    return rc;
  } else {
    if (clb_m == 0) //Print in serial
      Serial.printf("Opened database successfully\n");
    if (clb_m == 1) //Print in tft
      tft.printf("Opened database successfully\n");
  }
  return rc;
}

char * zErrMsg = 0;
int db_exec(sqlite3 * db,
  const char * sql) {
  int rc = sqlite3_exec(db, sql, callback, (void * ) data, & zErrMsg);
  if (rc != SQLITE_OK) {
    if (clb_m == 0) //Print in serial
      Serial.printf("SQL error: %s\n", zErrMsg);
    if (clb_m == 1) //Print in tft
      tft.printf("SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  } else {
    if (clb_m == 0) //Print in serial
      Serial.printf("Operation done successfully\n");
    if (clb_m == 1) //Print in serial
      tft.printf("Operation done successfully\n");
  }
  return rc;
}

void back_k() {
  for (int i = 0; i < 32; i++) {
    back_key[i] = key[i];
  }
}

void rest_k() {
  for (int i = 0; i < 32; i++) {
    key[i] = back_key[i];
  }
}

void back_serp_k() {
  for (int i = 0; i < 32; i++) {
    back_serp_key[i] = serp_key[i];
  }
}

void rest_serp_k() {
  for (int i = 0; i < 32; i++) {
    serp_key[i] = back_serp_key[i];
  }
}

void back_s_k() {
  for (int i = 0; i < 32; i++) {
    back_s_key[i] = second_key[i];
  }
}

void rest_s_k() {
  for (int i = 0; i < 32; i++) {
    second_key[i] = back_s_key[i];
  }
}

void back_Blwfsh_k() {
  for (int i = 0; i < 16; i++) {
    back_Blwfsh_key[i] = Blwfsh_key[i];
  }
}

void rest_Blwfsh_k() {
  for (int i = 0; i < 16; i++) {
    Blwfsh_key[i] = back_Blwfsh_key[i];
  }
}

void incr_key() {
  if (key[15] == 255) {
    key[15] = 0;
    if (key[14] == 255) {
      key[14] = 0;
      if (key[13] == 255) {
        key[13] = 0;
        if (key[12] == 255) {
          key[12] = 0;

          if (key[11] == 255) {
            key[11] = 0;
            if (key[10] == 255) {
              key[10] = 0;
              if (key[9] == 255) {
                key[9] = 0;
                if (key[8] == 255) {
                  key[8] = 0;

                  if (key[7] == 255) {
                    key[7] = 0;
                    if (key[6] == 255) {
                      key[6] = 0;
                      if (key[5] == 255) {
                        key[5] = 0;
                        if (key[4] == 255) {
                          key[4] = 0;

                          if (key[3] == 255) {
                            key[3] = 0;
                            if (key[2] == 255) {
                              key[2] = 0;
                              if (key[1] == 255) {
                                key[1] = 0;
                                if (key[0] == 255) {
                                  key[0] = 0;
                                } else {
                                  key[0]++;
                                }
                              } else {
                                key[1]++;
                              }
                            } else {
                              key[2]++;
                            }
                          } else {
                            key[3]++;
                          }

                        } else {
                          key[4]++;
                        }
                      } else {
                        key[5]++;
                      }
                    } else {
                      key[6]++;
                    }
                  } else {
                    key[7]++;
                  }

                } else {
                  key[8]++;
                }
              } else {
                key[9]++;
              }
            } else {
              key[10]++;
            }
          } else {
            key[11]++;
          }

        } else {
          key[12]++;
        }
      } else {
        key[13]++;
      }
    } else {
      key[14]++;
    }
  } else {
    key[15]++;
  }
}

void incr_second_key() {
  if (second_key[0] == 255) {
    second_key[0] = 0;
    if (second_key[1] == 255) {
      second_key[1] = 0;
      if (second_key[2] == 255) {
        second_key[2] = 0;
        if (second_key[3] == 255) {
          second_key[3] = 0;
          if (second_key[4] == 255) {
            second_key[4] = 0;
            if (second_key[5] == 255) {
              second_key[5] = 0;
              if (second_key[6] == 255) {
                second_key[6] = 0;
                if (second_key[7] == 255) {
                  second_key[7] = 0;
                  if (second_key[8] == 255) {
                    second_key[8] = 0;
                    if (second_key[9] == 255) {
                      second_key[9] = 0;
                      if (second_key[10] == 255) {
                        second_key[10] = 0;
                        if (second_key[11] == 255) {
                          second_key[11] = 0;
                          if (second_key[12] == 255) {
                            second_key[12] = 0;
                            if (second_key[13] == 255) {
                              second_key[13] = 0;
                              if (second_key[14] == 255) {
                                second_key[14] = 0;
                                if (second_key[15] == 255) {
                                  second_key[15] = 0;
                                } else {
                                  second_key[15]++;
                                }
                              } else {
                                second_key[14]++;
                              }
                            } else {
                              second_key[13]++;
                            }
                          } else {
                            second_key[12]++;
                          }
                        } else {
                          second_key[11]++;
                        }
                      } else {
                        second_key[10]++;
                      }
                    } else {
                      second_key[9]++;
                    }
                  } else {
                    second_key[8]++;
                  }
                } else {
                  second_key[7]++;
                }
              } else {
                second_key[6]++;
              }
            } else {
              second_key[5]++;
            }
          } else {
            second_key[4]++;
          }
        } else {
          second_key[3]++;
        }
      } else {
        second_key[2]++;
      }
    } else {
      second_key[1]++;
    }
  } else {
    second_key[0]++;
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

void incr_serp_key() {
  if (serp_key[15] == 255) {
    serp_key[15] = 0;
    if (serp_key[14] == 255) {
      serp_key[14] = 0;
      if (serp_key[13] == 255) {
        serp_key[13] = 0;
        if (serp_key[12] == 255) {
          serp_key[12] = 0;

          if (serp_key[11] == 255) {
            serp_key[11] = 0;
            if (serp_key[10] == 255) {
              serp_key[10] = 0;
              if (serp_key[9] == 255) {
                serp_key[9] = 0;
                if (serp_key[8] == 255) {
                  serp_key[8] = 0;

                  if (serp_key[7] == 255) {
                    serp_key[7] = 0;
                    if (serp_key[6] == 255) {
                      serp_key[6] = 0;
                      if (serp_key[5] == 255) {
                        serp_key[5] = 0;
                        if (serp_key[4] == 255) {
                          serp_key[4] = 0;

                          if (serp_key[3] == 255) {
                            serp_key[3] = 0;
                            if (serp_key[2] == 255) {
                              serp_key[2] = 0;
                              if (serp_key[1] == 255) {
                                serp_key[1] = 0;
                                if (serp_key[0] == 255) {
                                  serp_key[0] = 0;
                                } else {
                                  serp_key[0]++;
                                }
                              } else {
                                serp_key[1]++;
                              }
                            } else {
                              serp_key[2]++;
                            }
                          } else {
                            serp_key[3]++;
                          }

                        } else {
                          serp_key[4]++;
                        }
                      } else {
                        serp_key[5]++;
                      }
                    } else {
                      serp_key[6]++;
                    }
                  } else {
                    serp_key[7]++;
                  }

                } else {
                  serp_key[8]++;
                }
              } else {
                serp_key[9]++;
              }
            } else {
              serp_key[10]++;
            }
          } else {
            serp_key[11]++;
          }

        } else {
          serp_key[12]++;
        }
      } else {
        serp_key[13]++;
      }
    } else {
      serp_key[14]++;
    }
  } else {
    serp_key[15]++;
  }
}

int getNum(char ch) {
  int num = 0;
  if (ch >= '0' && ch <= '9') {
    num = ch - 0x30;
  } else {
    switch (ch) {
    case 'A':
    case 'a':
      num = 10;
      break;
    case 'B':
    case 'b':
      num = 11;
      break;
    case 'C':
    case 'c':
      num = 12;
      break;
    case 'D':
    case 'd':
      num = 13;
      break;
    case 'E':
    case 'e':
      num = 14;
      break;
    case 'F':
    case 'f':
      num = 15;
      break;
    default:
      num = 0;
    }
  }
  return num;
}

char getChar(int num) {
  char ch;
  if (num >= 0 && num <= 9) {
    ch = char(num + 48);
  } else {
    switch (num) {
    case 10:
      ch = 'a';
      break;
    case 11:
      ch = 'b';
      break;
    case 12:
      ch = 'c';
      break;
    case 13:
      ch = 'd';
      break;
    case 14:
      ch = 'e';
      break;
    case 15:
      ch = 'f';
      break;
    }
  }
  return ch;
}

size_t hex2bin(void * bin) {
  size_t len, i;
  int x;
  uint8_t * p = (uint8_t * ) bin;
  for (i = 0; i < 32; i++) {
    p[i] = (uint8_t) serp_key[i];
  }
  return 32;
}

void modify_keys(char card1[], int card2[], int card3[], int card4[]) {
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
  for (i = 0; i < 1; i++) {
    hex2bin(key);
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
    tblw[i + 4] = ct2.b[i];

  for (int i = 0; i < 4; i++)
    ct2.b[i + 6] ^= card2[i];

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
    tblw[i + 8] = ct2.b[i];
  // Fill the last four slots in tblw with card
  for (int i = 0; i < 4; i++)
    tblw[i + 12] = card3[i];

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
  for (int i = 0; i < 1000; i++) {
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
    str1 += char(250 + i);
  }

  for (int i = 0; i < 16; i++) {
    str1 += (char) tblw[i];
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

  for (int i = 0; i < 2000; i++) {
    incr_serp_key();
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
  }
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

  for (int i = 0; i < 8; i++) {
    Blwfsh_key[i] = (unsigned char)(((int(res1[i + 8]) + 1) * (int(h_array[88 + i]) + 1)) % 256);
  }

  for (int i = 0; i < 4; i++) {
    second_key[i] = byte(((int(res1[i + 18]) + 1) * (int(h_array[98 + i]) + 1)) % 256);
  }

  for (int i = 0; i < 3; i++) {
    key[i] = byte(tmp_fr_srp[i] ^ int(h_array[60 + i]));
  }

  key[5] = byte(((int(res1[i]) + 1) * (int(h_array[80 + i]) + 1)) % 256);

  for (int i = 2; i < 8; i++) {
    second_key[i + 8] = byte((((int(ct2.b[i]) + 1) * (int(h1_array[70 + i])) + 2)) % 256);
  }

  Blwfsh_key[11] = byte((((int(ct2.b[11]) + 1) * (int(h1_array[81])) + 2)) % 256);

  byte res12[3];
  for (int i = 104; i < 110; i += 2) {
    if (h1_array[i] != 0 && h1_array[i + 1] != 0)
      res12[i / 2] = 16 * getNum(h1_array[i]) + getNum(h1_array[i + 1]);
    if (h1_array[i] != 0 && h1_array[i + 1] == 0)
      res12[i / 2] = 16 * getNum(h1_array[i]);
    if (h1_array[i] == 0 && h1_array[i + 1] != 0)
      res12[i / 2] = getNum(h1_array[i + 1]);
    if (h1_array[i] == 0 && h1_array[i + 1] == 0)
      res12[i / 2] = 0;
  }

  String thmac;
  for (int i = 8; i < 11; i++) {
    thmac += (char((((int(ct2.b[i]) + 9) * (int(h1_array[70 + i])) + 3)) % 256));
  }
  thmac += "1f32+=c";
  thmac += char(tmp_fr_srp[0] ^ aft654[1]);
  thmac += (char(((int(res1[3]) + 1) * (int(h_array[84]) + 1)) % 256));
  thmac += (char(((int(res1[4]) + 1) * (int(h_array[85]) + 1)) % 256));
  thmac += (char(card1[1]));
  thmac += "4.[x";
  thmac += (char(card3[2]));
  thmac += char((((int(ct2.b[11]) + 1) * (int(h1_array[81])) + 2)) % 256);
  thmac += char(((int(res1[22]) + 1) * (int(h_array[102]) + 1)) % 256);
  for (int i = 8; i < 10; i++) {
    thmac += char(((int(res1[i + 8]) + 1) * (int(h_array[88 + i]) + 1)) % 256);
  }
  thmac += "FFFF";
  /*
  for (int i = 0; i < thmac.length(); i++){
    Serial.println(int(thmac.charAt(i)));
  }
  */
  int thmac_len = thmac.length() + 1;
  char thmac_array[thmac_len];
  thmac.toCharArray(thmac_array, thmac_len);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(thmac_array);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  key[9] = authCode[0];
  key[12] = authCode[1];
  Blwfsh_key[11] = authCode[2];
  for (int i = 3; i < 16; i++) {
    serp_key[i] = authCode[i];
  }
  for (int i = 0; i < 10; i++) {
    hmackey[i] = authCode[i + 16];
  }
  /*
  String res_hash;
  for (byte i=0; i < SHA256HMAC_SIZE; i++)
  {
      if (authCode[i]<0x10) { res_hash += '0'; }{
        res_hash += String(authCode[i], HEX);
      }
  }
  Serial.println(res_hash);
  for(int i = 0; i<10; i++){
      if (hmackey[i]<0x10) { Serial.print("0"); }{
        Serial.print(String(authCode[i], HEX));
      }
  }
  */
  keyb_inp = "";
  tft.fillScreen(0x1557);
  tft.fillRect(25, 70, 190, 82, 0x08c5);
  tft.setTextColor(0x1557, 0x08c5);
  tft.setTextSize(1);
  tft.setCursor(40, 85);
  tft.print("Keys derived successfully.");
  tft.setTextColor(0xffff, 0x08c5);
  tft.setTextSize(1);
  tft.setCursor(40, 102);
  tft.printf("Verification number is %d", vn);
  tft.setTextColor(0x1557, 0x08c5);
  tft.setTextSize(1);
  tft.setCursor(40, 119);
  tft.print("Press any button to get to");
  tft.setCursor(40, 129);
  tft.print("the main menu.");
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
  }
  create_logins_table();
  create_credit_cards_table();
  create_notes_table();
  m_menu_rect();
  main_menu(cur_pos);
  //Serial.println(dbase_name);
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

void disp_inp_panel_1() {
  tft.fillRect(0, 0, 240, 24, 0x1557);
  tft.setCursor(18, 5);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.print("Char:' '   Hex:");
}

void disp_input_from_enc_1() {
  tft.setTextSize(2);
  tft.fillRect(90, 5, 12, 16, 0x1557);
  tft.setCursor(90, 5);
  tft.setTextColor(0xffff);
  tft.print(char(curr_key));
  tft.fillRect(198, 5, 24, 16, 0x1557);
  tft.setCursor(198, 5);
  tft.setTextColor(0xffff);
  tft.printf("%02x", curr_key);
}

void appr_cards_and_log_in() {
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff, 0x0000);
  tft.setTextSize(1);
  tft.setCursor(0, 5);
  int act = 0;
  char card1[4];
  int card2[4];
  int card3[4];
  int card4[4];
  Serial.println("Approximate the RFID card N1 to the reader");
  tft.print("Approximate RFID card N1 to the reader.");
  while (act < 90) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == false) {
        if (act == 0)
          card1[0] = data.x;
        if (act == 1)
          card1[1] = data.x;
        if (act == 2)
          card1[2] = data.x;
        if (act == 3) {
          card1[3] = data.x;
          delay(700);
          Serial.println("Approximate the RFID card N2 to the reader");
          tft.setCursor(0, 17);
          tft.print("Approximate RFID card N2 to the reader.");
        }
        if (act == 4)
          card2[0] = int(data.x);
        if (act == 5)
          card2[1] = int(data.x);
        if (act == 6)
          card2[2] = int(data.x);
        if (act == 7) {
          card2[3] = int(data.x);
          delay(700);
          Serial.println("Approximate the RFID card N3 to the reader");
          tft.setCursor(0, 29);
          tft.println("Approximate RFID card N3 to the reader.");
        }
        if (act == 8)
          card3[0] = int(data.x);
        if (act == 9)
          card3[1] = int(data.x);
        if (act == 10)
          card3[2] = int(data.x);
        if (act == 11) {
          card3[3] = int(data.x);
          delay(700);
          Serial.println("Approximate the RFID card N4 to the reader");
          tft.setCursor(0, 41);
          tft.println("Approximate RFID card N4 to the reader.");
        }
        if (act == 12)
          card4[0] = int(data.x);
        if (act == 13)
          card4[1] = int(data.x);
        if (act == 14)
          card4[2] = int(data.x);
        if (act == 15) {
          card4[3] = int(data.x);
          act = 100;
        }
        act++;
      }
    }
  }

  disp_static_part_of_log_in();
  curr_key = 65;
  disp_inp_panel();
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  String usrn_lg;
  String pass_lg;
  bool un_or_p = false; // false - username, true - password
  bool chng = false;
  while (act < 900) {
    enc0.tick();
    if (enc0.left()) {
      curr_key--;
      if (curr_key < 32)
        curr_key = 126;
      if (curr_key > 126)
        curr_key = 32;
      disp_input_from_enc();
    }

    if (enc0.right()) {
      curr_key++;
      if (curr_key < 32)
        curr_key = 126;
      if (curr_key > 126)
        curr_key = 32;
      disp_input_from_enc();
    }
    delay(1);
    encoder_button.tick();
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
      disp_changes_during_login(usrn_lg, pass_lg, un_or_p);
    }
    if (encoder_button.hasClicks(2)) { // Enter
      keyb_inp = pass_lg;
      der_db_name_from_str(usrn_lg);
      //Serial.println();
      //Serial.println(usrn_lg);
      //Serial.println(pass_lg);
      tft.fillScreen(0x0000);
      tft.setTextColor(0xffff, 0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 5);
      tft.print("Deriving keys. Please wait for a while.");
      modify_keys(card1, card2, card3, card4);
      act = 1000;
    }
    delay(1);
    bus.tick();
    if (bus.gotData()) {
      disp_input_from_enc();
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        //Serial.println(int(ch));
        if (ch == 1) {
          if (un_or_p == false)
            usrn_lg += char(curr_key);
          if (un_or_p == true)
            pass_lg += char(curr_key);
          disp_changes_during_login(usrn_lg, pass_lg, un_or_p);
        } else if (ch == 2) { // Backspace
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
          disp_changes_during_login(usrn_lg, pass_lg, un_or_p);
        }
      }
    }
  }
}

void disp_static_part_of_log_in() {
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

void disp_changes_during_login(String usrn_lg, String pass_lg, bool un_or_p) {
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

void main_menu(int curr_pos){
   tft.setTextColor(0xffff, 0xf17f);
   tft.setTextSize(1);
   if (curr_pos == 0){
    tft.fillRect(38, 38, 166, 12, 0xffff);
    tft.setCursor(40,40);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("Logins");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 50, 166, 12, 0xf17f);
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,100);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,112);
    tft.print("AES + Serpent");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("3DES");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 194, 166, 12, 0xf17f);
    tft.setCursor(40,196);
    tft.print("Online Stored Logins");
   }
   if (curr_pos == 1){
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 38, 166, 12, 0xf17f);
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.fillRect(38, 50, 166, 12, 0xffff);
    tft.setCursor(40,52);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("Credit cards");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 62, 166, 12, 0xf17f);
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,100);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,112);
    tft.print("AES + Serpent");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("3DES");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
    tft.setCursor(40,196);
    tft.print("Online Stored Logins");
   }
   if (curr_pos == 2){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 50, 166, 12, 0xf17f);
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.fillRect(38, 62, 166, 12, 0xffff);
    tft.setCursor(40,64);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("Notes");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 74, 166, 12, 0xf17f);
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,100);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,112);
    tft.print("AES + Serpent");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("3DES");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
    tft.setCursor(40,196);
    tft.print("Online Stored Logins");
   }
   if (curr_pos == 3){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 62, 166, 12, 0xf17f);
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.fillRect(38, 74, 166, 12, 0xffff);
    tft.setCursor(40,76);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 86, 166, 12, 0xf17f);
    tft.setCursor(40,88);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,100);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,112);
    tft.print("AES + Serpent");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("3DES");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
    tft.setCursor(40,196);
    tft.print("Online Stored Logins");
   }
   if (curr_pos == 4){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 74, 166, 12, 0xf17f);
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.fillRect(38, 86, 166, 12, 0xffff);
    tft.setCursor(40,88);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("AES + Serpent + AES");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 98, 166, 12, 0xf17f);
    tft.setCursor(40,100);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,112);
    tft.print("AES + Serpent");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("3DES");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
    tft.setCursor(40,196);
    tft.print("Online Stored Logins");
   }
   if (curr_pos == 5){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 86, 166, 12, 0xf17f);
    tft.print("AES + Serpent + AES");
    tft.fillRect(38, 98, 166, 12, 0xffff);
    tft.setCursor(40,100);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("Blowfish + Serpent");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 110, 166, 12, 0xf17f);
    tft.setCursor(40,112);
    tft.print("AES + Serpent");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("3DES");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
    tft.setCursor(40,196);
    tft.print("Online Stored Logins");
   }
   if (curr_pos == 6){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Serpent + AES");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 98, 166, 12, 0xf17f);
    tft.setCursor(40,100);
    tft.print("Blowfish + Serpent");
    tft.fillRect(38, 110, 166, 12, 0xffff);
    tft.setCursor(40,112);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("AES + Serpent");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 122, 166, 12, 0xf17f);
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("3DES");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
    tft.setCursor(40,196);
    tft.print("Online Stored Logins");
   }
   if (curr_pos == 7){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,100);
    tft.print("Blowfish + Serpent");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 110, 166, 12, 0xf17f);
    tft.setCursor(40,112);
    tft.print("AES + Serpent");
    tft.fillRect(38, 122, 166, 12, 0xffff);
    tft.setCursor(40,124);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("Serpent");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 134, 166, 12, 0xf17f);
    tft.setCursor(40,136);
    tft.print("3DES");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
    tft.setCursor(40,196);
    tft.print("Online Stored Logins");
   }
   if (curr_pos == 8){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,100);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,112);
    tft.print("AES + Serpent");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 122, 166, 12, 0xf17f);
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.fillRect(38, 134, 166, 12, 0xffff);
    tft.setCursor(40,136);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("3DES");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 146, 166, 12, 0xf17f);
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
    tft.setCursor(40,196);
    tft.print("Online Stored Logins");
   }
   if (curr_pos == 9){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,100);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,112);
    tft.print("AES + Serpent");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 134, 166, 12, 0xf17f);
    tft.setCursor(40,136);
    tft.print("3DES");
    tft.fillRect(38, 146, 166, 12, 0xffff);
    tft.setCursor(40,148);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("HMAC SHA-256");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 158, 166, 12, 0xf17f);
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
    tft.setCursor(40,196);
    tft.print("Online Stored Logins");
   }
   if (curr_pos == 10){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,100);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,112);
    tft.print("AES + Serpent");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("3DES");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 146, 166, 12, 0xf17f);
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.fillRect(38, 158, 166, 12, 0xffff);
    tft.setCursor(40,160);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("SHA-512");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 170, 166, 12, 0xf17f);
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setCursor(40,184);
    tft.print("SQL");
    tft.setCursor(40,196);
    tft.print("Online Stored Logins");
   }
   if (curr_pos == 11){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,100);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,112);
    tft.print("AES + Serpent");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("3DES");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 158, 166, 12, 0xf17f);
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.fillRect(38, 170, 166, 12, 0xffff);
    tft.setCursor(40,172);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("SHA-256");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 182, 166, 12, 0xf17f);
    tft.setCursor(40,184);
    tft.print("SQL");
    tft.setCursor(40,196);
    tft.print("Online Stored Logins");
   }
   if (curr_pos == 12){
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,100);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,112);
    tft.print("AES + Serpent");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("3DES");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 170, 166, 12, 0xf17f);
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.fillRect(38, 182, 166, 12, 0xffff);
    tft.setCursor(40,184);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("SQL");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 194, 166, 12, 0xf17f);
    tft.setCursor(40,196);
    tft.print("Online Stored Logins");
   }
   if (curr_pos == 13){
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 38, 166, 12, 0xf17f);
    tft.setCursor(40,40);
    tft.print("Logins");
    tft.setCursor(40,52);
    tft.print("Credit cards");
    tft.setCursor(40,64);
    tft.print("Notes");
    tft.setCursor(40,76);
    tft.print("Blowfish + AES + Serp + AES");
    tft.setCursor(40,88);
    tft.print("AES + Serpent + AES");
    tft.setCursor(40,100);
    tft.print("Blowfish + Serpent");
    tft.setCursor(40,112);
    tft.print("AES + Serpent");
    tft.setCursor(40,124);
    tft.print("Serpent");
    tft.setCursor(40,136);
    tft.print("3DES");
    tft.setCursor(40,148);
    tft.print("HMAC SHA-256");
    tft.setCursor(40,160);
    tft.print("SHA-512");
    tft.setCursor(40,172);
    tft.print("SHA-256");
    tft.setTextColor(0xffff, 0xf17f);
    tft.fillRect(38, 182, 166, 12, 0xf17f);
    tft.setCursor(40,184);
    tft.print("SQL");
    tft.fillRect(38, 194, 166, 12, 0xffff);
    tft.setCursor(40,196);
    tft.setTextColor(0xf17f, 0xffff);
    tft.print("Online Stored Logins");
   }
}

void m_menu_rect() {
  tft.fillScreen(0x1557);
  tft.fillRect(15, 15, 210, 215, 0x08c5);
  tft.fillRect(0, 300, 240, 20, 0x08c5);
  tft.fillRect(30, 30, 180, 185, 0xf17f);
  curr_key = 0;
}

void disp_inp_at_the_bottom(String inpst) {
  tft.fillRect(0, 280, 240, 40, 0x1557);
  tft.setTextColor(0x08c5, 0x1557);
  tft.setTextSize(2);
  tft.setCursor(8, 282);
  tft.print("Input:");
  tft.setCursor(80, 282);
  tft.print("    ");
  tft.setCursor(80, 282);
  tft.print(inpst);
  tft.setCursor(8, 302);
  tft.print("A:Continue B:Cancel");
}

void der_db_name_from_str(String input) {
  //Serial.println(input);
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
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
  dbase_name = "/spiffs/";
  for (int i = 0; i < 12; i++) {
    if (res[i] != 0)
      dbase_name += char(97 + (int(res[i]) % 26));
    else
      dbase_name += 'a';
  }
  dbase_name += ".db";
  //Serial.println(dbase_name);
}

void create_logins_table() {
  exeq_sql_statement("CREATE TABLE if not exists Logins (ID CHARACTER(36), Title TEXT, Username TEXT, Password TEXT, Website Text);");
}

void create_credit_cards_table() {
  exeq_sql_statement("CREATE TABLE if not exists Credit_cards (ID CHARACTER(40), Title TEXT, Cardholder TEXT, Card_Number TEXT, Expiration_date Text, CVN Text, PIN Text, ZIP_code Text);");
}

void create_notes_table() {
  exeq_sql_statement("CREATE TABLE if not exists Notes (ID CHARACTER(34), Title TEXT, Content TEXT);");
}

void exeq_sql_statement(char sql_statmnt[]) {
  sqlite3 * db1;
  int rc;
  int str_len = dbase_name.length() + 1;
  char input_arr[str_len];
  dbase_name.toCharArray(input_arr, str_len);
  if (db_open(input_arr, & db1))
    return;

  rc = db_exec(db1, sql_statmnt);
  if (rc != SQLITE_OK) {
    sqlite3_close(db1);
    return;
  }

  sqlite3_close(db1);
}

void exeq_sql_statement_from_string(String squery) {
  int squery_len = squery.length() + 1;
  char squery_array[squery_len];
  squery.toCharArray(squery_array, squery_len);
  exeq_sql_statement(squery_array);
  return;
}

void Add_login() {
  rec_ID = "";
  gen_rand_ID(36);
  Insert_title_into_the_logins();
}

void Insert_title_into_the_logins() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the title:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the title:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      /*
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }
      */
      char hmacchar[32];
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      int p = 0;
      for (int i = 0; i < 4; i++) {
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight(hmacchar, p, 100, true, true);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight(keyb_inp_arr, p, str_len, true, true);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      //Serial.println(dec_st);
      exeq_sql_statement_from_string("INSERT INTO Logins (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
      dec_st = "";
      dec_tag = "";
      decract = 0;
      m_menu_rect();
      Insert_username_into_logins();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void Insert_username_into_logins() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the username:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the username:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      /*
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }
      */
      char hmacchar[32];
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      int p = 0;
      for (int i = 0; i < 4; i++) {
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight(hmacchar, p, 100, true, true);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight(keyb_inp_arr, p, str_len, true, true);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      //Serial.println(dec_st);
      exeq_sql_statement_from_string("UPDATE Logins set Username = '" + dec_st + "' where ID = '" + rec_ID + "';");
      dec_st = "";
      dec_tag = "";
      decract = 0;
      m_menu_rect();
      Insert_password_into_logins();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void Insert_password_into_logins() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the password:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the password:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      /*
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }
      */
      char hmacchar[32];
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      int p = 0;
      for (int i = 0; i < 4; i++) {
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight(hmacchar, p, 100, true, true);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight(keyb_inp_arr, p, str_len, true, true);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      //Serial.println(dec_st);
      exeq_sql_statement_from_string("UPDATE Logins set Password = '" + dec_st + "' where ID = '" + rec_ID + "';");
      dec_st = "";
      dec_tag = "";
      decract = 0;
      m_menu_rect();
      Insert_website_into_logins();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void Insert_website_into_logins() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the website:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the website:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      /*
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }
      */
      char hmacchar[32];
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      int p = 0;
      for (int i = 0; i < 4; i++) {
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight(hmacchar, p, 100, true, true);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight(keyb_inp_arr, p, str_len, true, true);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      //Serial.println(dec_st);
      exeq_sql_statement_from_string("UPDATE Logins set Website = '" + dec_st + "' where ID = '" + rec_ID + "';");
      dec_st = "";
      dec_tag = "";
      decract = 0;
      tft.setTextSize(1);
      tft.setCursor(0, 310);
      tft.print("                                                                                                    ");
      tft.setCursor(0, 310);
      tft.print("Press any button to return to the m menu");
      bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void Edit_login() {
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0, 2);
  tft.print("Select the record to edit and press A");
  tft.setCursor(0, 12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() - 1, 1);
    }
    dec_st = "";
    dec_tag = "";
    decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++) {
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
      dec_tag = "";
      decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    disp_inp_at_the_bottom("0");
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        keyb_inp = String(sel_rcrd);
        disp_inp_at_the_bottom(keyb_inp);
      }
      int inpl = keyb_inp.length();
      delay(1);
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          curr_key = int(ch);
          if (curr_key == 1) {
            int selected_id = keyb_inp.toInt();
            keyb_inp = "";
            disp_inp_panel_1();
            tft.fillScreen(0xfaa6);
            disp_inp_panel_1();
            curr_key = 65;
            tft.setCursor(90, 5);
            tft.print("A");
            tft.setCursor(198, 5);
            tft.printf("%02x", 65);
            tft.setTextColor(0xffff, 0xfaa6);
            tft.setTextSize(2);
            tft.fillRect(312, 0, 320, 240, 0x12ea);
            tft.setCursor(0, 29);
            tft.println("Enter new password:");
            disp_length_at_the_bottom(inpl);
            bool cont_to_next = false;
            while (cont_to_next == false) {
              bool smt_done = false;
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
                disp_input_from_enc_1();
                //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
              }

              bus.tick();
              if (bus.gotData()) {
                myStruct data;
                bus.readData(data);
                if (data.d == true) {
                  ch = data.x;
                  if (ch == 1) {
                    keyb_inp += char(curr_key);
                    //Serial.println(keyb_inp);
                    smt_done = true;
                  }

                  if (ch == 2) {
                    if (keyb_inp.length() > 0)
                      keyb_inp.remove(keyb_inp.length() - 1, 1);
                    tft.fillScreen(0xfaa6);
                    disp_inp_panel_1();
                    disp_input_from_enc_1();
                    tft.setTextColor(0xe73c, 0xfaa6);
                    tft.setTextSize(2);
                    tft.fillRect(312, 0, 320, 240, 0x12ea);
                    tft.fillRect(312, 0, 320, 240, 0x12ea);
                    tft.setCursor(0, 29);
                    tft.println("Enter new password:");
                    smt_done = true;
                  }
                }
              }
              if (smt_done == true) {
                int inpl = keyb_inp.length();
                disp_length_at_the_bottom(inpl);
                tft.setTextColor(0xe73c, 0xfaa6);
                tft.setCursor(0, 49);
                tft.println(keyb_inp);
              }
              encoder_button.tick();
              if (encoder_button.hasClicks(4)) {
                clb_m = 1;
                tft.fillScreen(0x3186);
                tft.setTextColor(0xe73c, 0x3186);
                tft.setTextSize(1);
                tft.setCursor(0, 0);
                int str_len = keyb_inp.length() + 1;
                char keyb_inp_arr[str_len];
                keyb_inp.toCharArray(keyb_inp_arr, str_len);
                SHA256HMAC hmac(hmackey, sizeof(hmackey));
                hmac.doUpdate(keyb_inp_arr);
                byte authCode[SHA256HMAC_SIZE];
                hmac.doFinal(authCode);
                /*
                String res_hash;
                for (byte i=0; i < SHA256HMAC_SIZE; i++)
                {
                    if (authCode[i]<0x10) { res_hash += 0; }{
                      res_hash += String(authCode[i], HEX);
                    }
                }
                */
                char hmacchar[32];
                for (int i = 0; i < 32; i++) {
                  hmacchar[i] = char(authCode[i]);
                }
                int p = 0;
                for (int i = 0; i < 4; i++) {
                  incr_key();
                  incr_second_key();
                  incr_Blwfsh_key();
                  incr_serp_key();
                  split_by_eight(hmacchar, p, 100, true, true);
                  p += 8;
                }
                p = 0;
                while (str_len > p + 1) {
                  incr_Blwfsh_key();
                  incr_key();
                  incr_serp_key();
                  incr_second_key();
                  split_by_eight(keyb_inp_arr, p, str_len, true, true);
                  p += 8;
                }
                rest_Blwfsh_k();
                rest_k();
                rest_serp_k();
                rest_s_k();
                //Serial.println(dec_st);
                exeq_sql_statement_from_string("UPDATE Logins set Password = '" + dec_st + "' where ID = '" + IDs[selected_id][0] + "';");
                dec_st = "";
                dec_tag = "";
                decract = 0;
                tft.setTextSize(1);
                tft.setCursor(0, 310);
                tft.print("                                                                                                    ");
                tft.setCursor(0, 310);
                tft.print("Press any key to return to the main menu");
                bool cont_to_next = false;
                while (cont_to_next == false) {
                  bus.tick();
                  if (bus.gotData()) {
                    myStruct data;
                    bus.readData(data);
                    if (data.d == true) {
                      ch = data.x;
                      if (ch == 1 || ch == 2) {
                        cont_to_next = true;
                      }
                    }
                  }
                  delay(1);
                  encoder_button.tick();
                  if (encoder_button.press())
                    cont_to_next = true;
                  delay(1);
                }
                cont_to_next = true;
                return;
              }
              if (encoder_button.hasClicks(5)) {
                keyb_inp = "";
                m_menu_rect();
                cont_to_next = true;
                return;
              }
            }
          }
          if (curr_key == 2) {
            keyb_inp = "";
            m_menu_rect();
            return;
          }
        }
      }
    }

  } else {
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0, 310);
    tft.print("                                                                                                    ");
    tft.setCursor(0, 310);
    tft.print("Press any button to return to the m menu");
    keyb_inp = "";
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          if (ch == 1 || ch == 2) {
            cont_to_next = true;
          }
        }
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
    }
    m_menu_rect();
    main_menu(cur_pos);
    return;
  }
}

void Remove_login() {
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0, 2);
  tft.print("Select the record to delete and press A");
  tft.setCursor(0, 12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() - 1, 1);
    }
    dec_st = "";
    dec_tag = "";
    decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++) {
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
      dec_tag = "";
      decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    disp_inp_at_the_bottom("0");
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        keyb_inp = String(sel_rcrd);
        disp_inp_at_the_bottom(keyb_inp);
      }
      int inpl = keyb_inp.length();
      delay(1);
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          curr_key = int(ch);
          if (curr_key == 1) {
            clb_m = 1;
            tft.fillScreen(0x3186);
            tft.setTextColor(0xe73c, 0x3186);
            tft.setTextSize(1);
            tft.setCursor(0, 0);
            exeq_sql_statement_from_string("DELETE FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            tft.setTextSize(1);
            tft.setCursor(0, 310);
            tft.print("                                                                                                    ");
            tft.setCursor(0, 310);
            tft.print("Press any button to return to the m menu");
            keyb_inp = "";
            bool cont_to_next = false;
            while (cont_to_next == false) {
              bus.tick();
              if (bus.gotData()) {
                myStruct data;
                bus.readData(data);
                if (data.d == true) {
                  ch = data.x;
                  if (ch == 1 || ch == 2) {
                    cont_to_next = true;
                  }
                }
              }
              delay(1);
              encoder_button.tick();
              if (encoder_button.press())
                cont_to_next = true;
              delay(1);
            }
            m_menu_rect();
            main_menu(cur_pos);
            return;
          }
          if (curr_key == 2) {
            keyb_inp = "";
            m_menu_rect();
            return;
          }
        }
      }
    }

  } else {
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0, 310);
    tft.print("                                                                                                    ");
    tft.setCursor(0, 310);
    tft.print("Press any button to return to the m menu");
    keyb_inp = "";
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          if (ch == 1 || ch == 2) {
            cont_to_next = true;
          }
        }
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
    }
    m_menu_rect();
    main_menu(cur_pos);
    return;
  }
}

void View_login() {
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0, 2);
  tft.print("Select the record to view and press A");
  tft.setCursor(0, 12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() - 1, 1);
    }
    dec_st = "";
    dec_tag = "";
    decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++) {
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
      dec_tag = "";
      decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    disp_inp_at_the_bottom("0");
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        keyb_inp = String(sel_rcrd);
        disp_inp_at_the_bottom(keyb_inp);
      }
      int inpl = keyb_inp.length();
      delay(1);
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          curr_key = int(ch);
          if (curr_key == 1) {
            tft.fillScreen(0x3186);
            tft.setTextColor(0xe73c, 0x3186);
            tft.setTextSize(1);
            tft.setCursor(0, 2);
            clb_m = 2;
            exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            bool title_integrity = verify_integrity();
            if (title_integrity == true)
              tft.setTextColor(0xe73c, 0x3186);
            else
              tft.setTextColor(0xf800, 0x3186);
            tft.print("Title:");
            tft.println(dec_st);
            dec_st = "";
            dec_tag = "";
            decract = 0;
            exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            bool username_integrity = verify_integrity();
            if (username_integrity == true)
              tft.setTextColor(0xe73c, 0x3186);
            else
              tft.setTextColor(0xf800, 0x3186);
            tft.print("Username:");
            tft.println(dec_st);
            dec_st = "";
            dec_tag = "";
            decract = 0;
            exeq_sql_statement_from_string("SELECT Password FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            bool password_integrity = verify_integrity();
            if (password_integrity == true)
              tft.setTextColor(0xe73c, 0x3186);
            else
              tft.setTextColor(0xf800, 0x3186);
            tft.print("Password:");
            tft.println(dec_st);
            dec_st = "";
            dec_tag = "";
            decract = 0;
            exeq_sql_statement_from_string("SELECT Website FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            bool website_integrity = verify_integrity();
            if (website_integrity == true)
              tft.setTextColor(0xe73c, 0x3186);
            else
              tft.setTextColor(0xf800, 0x3186);
            tft.print("Website:");
            tft.println(dec_st);
            tft.setTextColor(0xe73c, 0x3186);
            tft.println("----------------------------------------");
            if (title_integrity == false || username_integrity == false || password_integrity == false || website_integrity == false) {
              tft.setTextColor(0xf800, 0x3186);
              tft.println("Integrity verification failed!!!");
            }
            dec_st = "";
            dec_tag = "";
            decract = 0;
            tft.setTextColor(0xe73c, 0x3186);
            tft.setTextSize(1);
            tft.setCursor(0, 310);
            tft.print("                                                                                                    ");
            tft.setCursor(0, 310);
            tft.print("Press any button to return to the m menu");
            keyb_inp = "";
            bool cont_to_next = false;
            while (cont_to_next == false) {
              bus.tick();
              if (bus.gotData()) {
                myStruct data;
                bus.readData(data);
                if (data.d == true) {
                  ch = data.x;
                  if (ch == 1 || ch == 2) {
                    cont_to_next = true;
                  }
                }
              }
              delay(1);
              encoder_button.tick();
              if (encoder_button.press())
                cont_to_next = true;
              delay(1);
            }
            m_menu_rect();
            main_menu(cur_pos);
            return;
          }
          if (curr_key == 2) {
            keyb_inp = "";
            m_menu_rect();
            return;
          }
        }
      }
    }

  } else {
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0, 310);
    tft.print("                                                                                                    ");
    tft.setCursor(0, 310);
    tft.print("Press any button to return to the m menu");
    keyb_inp = "";
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          if (ch == 1 || ch == 2) {
            cont_to_next = true;
          }
        }
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
    }
    m_menu_rect();
    main_menu(cur_pos);
    return;
  }
}

void Show_all_logins() {
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0, 2);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    dec_st = "";
    dec_tag = "";
    decract = 0;
    for (int i = 0; i < num_of_IDs; i++) {
      Serial.print(IDs[i]);
    }
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++) {
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i] + "'");
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";
      dec_tag = "";
      decract = 0;
      exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + IDs[i] + "'");
      tft.print("Username:");
      tft.println(dec_st);
      tft.println("----------------------------------------");
      dec_st = "";
      dec_tag = "";
      decract = 0;
    }
    /*
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i] + "'");
      Serial.print("Title:");
      Serial.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + IDs[i] + "'");
      Serial.print("Username:");
      Serial.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT Password FROM Logins WHERE ID = '" + IDs[i] + "'");
      Serial.print("Password:");
      Serial.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT Website FROM Logins WHERE ID = '" + IDs[i] + "'");
      Serial.print("Website:");
      Serial.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
    }
    */
  } else {
    tft.print("Empty");
  }
  tft.setTextSize(1);
  tft.setCursor(0, 310);
  tft.print("                                                                                                    ");
  tft.setCursor(0, 310);
  tft.print("Press any button to return to the m menu");
  keyb_inp = "";
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
  }
  m_menu_rect();
  main_menu(cur_pos);
  return;
}

void Add_credit_card() {
  rec_ID = "";
  gen_rand_ID(40);
  Insert_title_into_the_credit_cards();
}

void Insert_title_into_the_credit_cards() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the title:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the title:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      /*
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }
      */
      char hmacchar[32];
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      int p = 0;
      for (int i = 0; i < 4; i++) {
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight(hmacchar, p, 100, true, true);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight(keyb_inp_arr, p, str_len, true, true);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      //Serial.println(dec_st);
      exeq_sql_statement_from_string("INSERT INTO Credit_cards (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
      dec_st = "";
      dec_tag = "";
      decract = 0;
      m_menu_rect();
      Insert_cardholder_name_into_credit_cards();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void Insert_cardholder_name_into_credit_cards() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the cardholder");
  tft.setCursor(0, 49);
  tft.println("name:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the cardholder");
          tft.setCursor(0, 49);
          tft.println("name:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 69);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      /*
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }
      */
      char hmacchar[32];
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      int p = 0;
      for (int i = 0; i < 4; i++) {
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight(hmacchar, p, 100, true, true);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight(keyb_inp_arr, p, str_len, true, true);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      //Serial.println(dec_st);
      exeq_sql_statement_from_string("UPDATE Credit_cards set Cardholder = '" + dec_st + "' where ID = '" + rec_ID + "';");
      dec_st = "";
      dec_tag = "";
      decract = 0;
      m_menu_rect();
      Insert_card_number_into_credit_cards();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void Insert_card_number_into_credit_cards() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 52;
  tft.setCursor(90, 5);
  tft.print("4");
  tft.setCursor(198, 5);
  tft.printf("%02x", 52);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter card number:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter card number:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      /*
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }
      */
      char hmacchar[32];
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      int p = 0;
      for (int i = 0; i < 4; i++) {
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight(hmacchar, p, 100, true, true);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight(keyb_inp_arr, p, str_len, true, true);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      //Serial.println(dec_st);
      exeq_sql_statement_from_string("UPDATE Credit_cards set Card_Number = '" + dec_st + "' where ID = '" + rec_ID + "';");
      dec_st = "";
      dec_tag = "";
      decract = 0;
      m_menu_rect();
      Insert_expiration_date_into_credit_cards();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void Insert_expiration_date_into_credit_cards() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 48;
  tft.setCursor(90, 5);
  tft.print("0");
  tft.setCursor(198, 5);
  tft.printf("%02x", 48);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the expiration");
  tft.setCursor(0, 49);
  tft.println("date:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the expiration");
          tft.setCursor(0, 49);
          tft.println("date:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 69);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      /*
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }
      */
      char hmacchar[32];
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      int p = 0;
      for (int i = 0; i < 4; i++) {
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight(hmacchar, p, 100, true, true);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight(keyb_inp_arr, p, str_len, true, true);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      //Serial.println(dec_st);
      exeq_sql_statement_from_string("UPDATE Credit_cards set Expiration_date = '" + dec_st + "' where ID = '" + rec_ID + "';");
      dec_st = "";
      dec_tag = "";
      decract = 0;
      m_menu_rect();
      Insert_CVN_into_credit_cards();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void Insert_CVN_into_credit_cards() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 48;
  tft.setCursor(90, 5);
  tft.print("0");
  tft.setCursor(198, 5);
  tft.printf("%02x", 48);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the CVN:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the CVN:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      /*
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }
      */
      char hmacchar[32];
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      int p = 0;
      for (int i = 0; i < 4; i++) {
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight(hmacchar, p, 100, true, true);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight(keyb_inp_arr, p, str_len, true, true);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      //Serial.println(dec_st);
      exeq_sql_statement_from_string("UPDATE Credit_cards set CVN = '" + dec_st + "' where ID = '" + rec_ID + "';");
      dec_st = "";
      dec_tag = "";
      decract = 0;
      m_menu_rect();
      Insert_PIN_into_credit_cards();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void Insert_PIN_into_credit_cards() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 48;
  tft.setCursor(90, 5);
  tft.print("0");
  tft.setCursor(198, 5);
  tft.printf("%02x", 48);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the PIN:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the PIN:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      /*
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }
      */
      char hmacchar[32];
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      int p = 0;
      for (int i = 0; i < 4; i++) {
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight(hmacchar, p, 100, true, true);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight(keyb_inp_arr, p, str_len, true, true);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      //Serial.println(dec_st);
      exeq_sql_statement_from_string("UPDATE Credit_cards set PIN = '" + dec_st + "' where ID = '" + rec_ID + "';");
      dec_st = "";
      dec_tag = "";
      decract = 0;
      m_menu_rect();
      Insert_ZIP_code_into_credit_cards();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void Insert_ZIP_code_into_credit_cards() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 48;
  tft.setCursor(90, 5);
  tft.print("0");
  tft.setCursor(198, 5);
  tft.printf("%02x", 48);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the ZIP code:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the ZIP code:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      /*
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }
      */
      char hmacchar[32];
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      int p = 0;
      for (int i = 0; i < 4; i++) {
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight(hmacchar, p, 100, true, true);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight(keyb_inp_arr, p, str_len, true, true);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      //Serial.println(dec_st);
      exeq_sql_statement_from_string("UPDATE Credit_cards set ZIP_code = '" + dec_st + "' where ID = '" + rec_ID + "';");
      dec_st = "";
      dec_tag = "";
      decract = 0;
      tft.setTextSize(1);
      tft.setCursor(0, 310);
      tft.print("                                                                                                    ");
      tft.setCursor(0, 310);
      tft.print("Press any button to return to the m menu");
      bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void Edit_credit_card() {
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0, 2);
  tft.print("Select the record to edit and press A");
  tft.setCursor(0, 12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Credit_cards");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() - 1, 1);
    }
    dec_st = "";
    dec_tag = "";
    decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++) {
      exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
      dec_tag = "";
      decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    disp_inp_at_the_bottom("0");
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        keyb_inp = String(sel_rcrd);
        disp_inp_at_the_bottom(keyb_inp);
      }
      int inpl = keyb_inp.length();
      delay(1);
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          curr_key = int(ch);
          if (curr_key == 1) {
            int selected_id = keyb_inp.toInt();
            keyb_inp = "";
            disp_inp_panel_1();
            tft.fillScreen(0xfaa6);
            disp_inp_panel_1();
            curr_key = 48;
            tft.setCursor(90, 5);
            tft.print("0");
            tft.setCursor(198, 5);
            tft.printf("%02x", 48);
            tft.setTextColor(0xffff, 0xfaa6);
            tft.setTextSize(2);
            tft.fillRect(312, 0, 320, 240, 0x12ea);
            tft.setCursor(0, 29);
            tft.println("Enter new PIN:");
            disp_length_at_the_bottom(inpl);
            bool cont_to_next = false;
            while (cont_to_next == false) {
              bool smt_done = false;
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
                disp_input_from_enc_1();
                //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
              }

              bus.tick();
              if (bus.gotData()) {
                myStruct data;
                bus.readData(data);
                if (data.d == true) {
                  ch = data.x;
                  if (ch == 1) {
                    keyb_inp += char(curr_key);
                    //Serial.println(keyb_inp);
                    smt_done = true;
                  }

                  if (ch == 2) {
                    if (keyb_inp.length() > 0)
                      keyb_inp.remove(keyb_inp.length() - 1, 1);
                    tft.fillScreen(0xfaa6);
                    disp_inp_panel_1();
                    disp_input_from_enc_1();
                    tft.setTextColor(0xe73c, 0xfaa6);
                    tft.setTextSize(2);
                    tft.fillRect(312, 0, 320, 240, 0x12ea);
                    tft.fillRect(312, 0, 320, 240, 0x12ea);
                    tft.setCursor(0, 29);
                    tft.println("Enter new PIN:");
                    smt_done = true;
                  }
                }
              }
              if (smt_done == true) {
                int inpl = keyb_inp.length();
                disp_length_at_the_bottom(inpl);
                tft.setTextColor(0xe73c, 0xfaa6);
                tft.setCursor(0, 49);
                tft.println(keyb_inp);
              }
              encoder_button.tick();
              if (encoder_button.hasClicks(4)) {
                clb_m = 1;
                tft.fillScreen(0x3186);
                tft.setTextColor(0xe73c, 0x3186);
                tft.setTextSize(1);
                tft.setCursor(0, 0);
                int str_len = keyb_inp.length() + 1;
                char keyb_inp_arr[str_len];
                keyb_inp.toCharArray(keyb_inp_arr, str_len);
                SHA256HMAC hmac(hmackey, sizeof(hmackey));
                hmac.doUpdate(keyb_inp_arr);
                byte authCode[SHA256HMAC_SIZE];
                hmac.doFinal(authCode);
                /*
                String res_hash;
                for (byte i=0; i < SHA256HMAC_SIZE; i++)
                {
                    if (authCode[i]<0x10) { res_hash += 0; }{
                      res_hash += String(authCode[i], HEX);
                    }
                }
                */
                char hmacchar[32];
                for (int i = 0; i < 32; i++) {
                  hmacchar[i] = char(authCode[i]);
                }
                int p = 0;
                for (int i = 0; i < 4; i++) {
                  incr_key();
                  incr_second_key();
                  incr_Blwfsh_key();
                  incr_serp_key();
                  split_by_eight(hmacchar, p, 100, true, true);
                  p += 8;
                }
                p = 0;
                while (str_len > p + 1) {
                  incr_Blwfsh_key();
                  incr_key();
                  incr_serp_key();
                  incr_second_key();
                  split_by_eight(keyb_inp_arr, p, str_len, true, true);
                  p += 8;
                }
                rest_Blwfsh_k();
                rest_k();
                rest_serp_k();
                rest_s_k();
                //Serial.println(dec_st);
                exeq_sql_statement_from_string("UPDATE Credit_cards set PIN = '" + dec_st + "' where ID = '" + IDs[selected_id][0] + "';");
                dec_st = "";
                dec_tag = "";
                decract = 0;
                tft.setTextSize(1);
                tft.setCursor(0, 310);
                tft.print("                                                                                                    ");
                tft.setCursor(0, 310);
                tft.print("Press any key to return to the main menu");
                bool cont_to_next = false;
                while (cont_to_next == false) {
                  bus.tick();
                  if (bus.gotData()) {
                    myStruct data;
                    bus.readData(data);
                    if (data.d == true) {
                      ch = data.x;
                      if (ch == 1 || ch == 2) {
                        cont_to_next = true;
                      }
                    }
                  }
                  delay(1);
                  encoder_button.tick();
                  if (encoder_button.press())
                    cont_to_next = true;
                  delay(1);
                }
                cont_to_next = true;
                return;
              }
              if (encoder_button.hasClicks(5)) {
                keyb_inp = "";
                m_menu_rect();
                cont_to_next = true;
                return;
              }
            }
          }
          if (curr_key == 2) {
            keyb_inp = "";
            m_menu_rect();
            return;
          }
        }
      }
    }

  } else {
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0, 310);
    tft.print("                                                                                                    ");
    tft.setCursor(0, 310);
    tft.print("Press any button to return to the m menu");
    keyb_inp = "";
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          if (ch == 1 || ch == 2) {
            cont_to_next = true;
          }
        }
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
    }
    m_menu_rect();
    main_menu(cur_pos);
    return;
  }
}

void Remove_credit_card() {
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0, 2);
  tft.print("Select the record to delete and press A");
  tft.setCursor(0, 12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Credit_cards");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() - 1, 1);
    }
    dec_st = "";
    dec_tag = "";
    decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++) {
      exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
      dec_tag = "";
      decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    disp_inp_at_the_bottom("0");
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        keyb_inp = String(sel_rcrd);
        disp_inp_at_the_bottom(keyb_inp);
      }
      int inpl = keyb_inp.length();
      delay(1);
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          curr_key = int(ch);
          if (curr_key == 1) {
            clb_m = 1;
            tft.fillScreen(0x3186);
            tft.setTextColor(0xe73c, 0x3186);
            tft.setTextSize(1);
            tft.setCursor(0, 0);
            exeq_sql_statement_from_string("DELETE FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            tft.setTextSize(1);
            tft.setCursor(0, 310);
            tft.print("                                                                                                    ");
            tft.setCursor(0, 310);
            tft.print("Press any button to return to the m menu");
            keyb_inp = "";
            bool cont_to_next = false;
            while (cont_to_next == false) {
              bus.tick();
              if (bus.gotData()) {
                myStruct data;
                bus.readData(data);
                if (data.d == true) {
                  ch = data.x;
                  if (ch == 1 || ch == 2) {
                    cont_to_next = true;
                  }
                }
              }
              delay(1);
              encoder_button.tick();
              if (encoder_button.press())
                cont_to_next = true;
              delay(1);
            }
            m_menu_rect();
            main_menu(cur_pos);
            return;
          }
          if (curr_key == 2) {
            keyb_inp = "";
            m_menu_rect();
            return;
          }
        }
      }
    }

  } else {
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0, 310);
    tft.print("                                                                                                    ");
    tft.setCursor(0, 310);
    tft.print("Press any button to return to the m menu");
    keyb_inp = "";
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          if (ch == 1 || ch == 2) {
            cont_to_next = true;
          }
        }
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
    }
    m_menu_rect();
    main_menu(cur_pos);
    return;
  }
}

void View_credit_card() {
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0, 2);
  tft.print("Select the record to view and press A");
  tft.setCursor(0, 12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Credit_cards");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() - 1, 1);
    }
    dec_st = "";
    dec_tag = "";
    decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++) {
      exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
      dec_tag = "";
      decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    disp_inp_at_the_bottom("0");
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        keyb_inp = String(sel_rcrd);
        disp_inp_at_the_bottom(keyb_inp);
      }
      int inpl = keyb_inp.length();
      delay(1);
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          curr_key = int(ch);
          if (curr_key == 1) {
            tft.fillScreen(0x3186);
            tft.setTextColor(0xe73c, 0x3186);
            tft.setTextSize(1);
            tft.setCursor(0, 2);
            clb_m = 2;
            exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            bool title_integrity = verify_integrity();
            if (title_integrity == true)
              tft.setTextColor(0xe73c, 0x3186);
            else
              tft.setTextColor(0xf800, 0x3186);
            tft.print("Title:");
            tft.println(dec_st);
            dec_st = "";
            dec_tag = "";
            decract = 0;
            exeq_sql_statement_from_string("SELECT Cardholder FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            bool cardholder_integrity = verify_integrity();
            if (cardholder_integrity == true)
              tft.setTextColor(0xe73c, 0x3186);
            else
              tft.setTextColor(0xf800, 0x3186);
            tft.print("Cardholder name:");
            tft.println(dec_st);
            dec_st = "";
            dec_tag = "";
            decract = 0;
            exeq_sql_statement_from_string("SELECT Card_Number FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            bool card_number_integrity = verify_integrity();
            if (card_number_integrity == true)
              tft.setTextColor(0xe73c, 0x3186);
            else
              tft.setTextColor(0xf800, 0x3186);
            tft.print("Card number:");
            tft.println(dec_st);
            dec_st = "";
            dec_tag = "";
            decract = 0;
            exeq_sql_statement_from_string("SELECT Expiration_date FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            bool expiration_date_integrity = verify_integrity();
            if (expiration_date_integrity == true)
              tft.setTextColor(0xe73c, 0x3186);
            else
              tft.setTextColor(0xf800, 0x3186);
            tft.print("Expiration date:");
            tft.println(dec_st);
            dec_st = "";
            dec_tag = "";
            decract = 0;
            exeq_sql_statement_from_string("SELECT CVN FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            bool cvn_integrity = verify_integrity();
            if (cvn_integrity == true)
              tft.setTextColor(0xe73c, 0x3186);
            else
              tft.setTextColor(0xf800, 0x3186);
            tft.print("CVN:");
            tft.println(dec_st);
            dec_st = "";
            dec_tag = "";
            decract = 0;
            exeq_sql_statement_from_string("SELECT PIN FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            bool pin_integrity = verify_integrity();
            if (pin_integrity == true)
              tft.setTextColor(0xe73c, 0x3186);
            else
              tft.setTextColor(0xf800, 0x3186);
            tft.print("PIN:");
            tft.println(dec_st);
            dec_st = "";
            dec_tag = "";
            decract = 0;
            exeq_sql_statement_from_string("SELECT ZIP_code FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            bool zip_code_integrity = verify_integrity();
            if (zip_code_integrity == true)
              tft.setTextColor(0xe73c, 0x3186);
            else
              tft.setTextColor(0xf800, 0x3186);
            tft.print("ZIP code:");
            tft.println(dec_st);
            tft.setTextColor(0xe73c, 0x3186);
            tft.println("----------------------------------------");
            if (title_integrity == false || cardholder_integrity == false || card_number_integrity == false || expiration_date_integrity == false || cvn_integrity == false || pin_integrity == false || zip_code_integrity == false) {
              tft.setTextColor(0xf800, 0x3186);
              tft.println("Integrity verification failed!!!");
            }
            dec_st = "";
            dec_tag = "";
            decract = 0;
            tft.setTextColor(0xe73c, 0x3186);
            tft.setTextSize(1);
            tft.setCursor(0, 310);
            tft.print("                                                                                                    ");
            tft.setCursor(0, 310);
            tft.print("Press any button to return to the m menu");
            keyb_inp = "";
            bool cont_to_next = false;
            while (cont_to_next == false) {
              bus.tick();
              if (bus.gotData()) {
                myStruct data;
                bus.readData(data);
                if (data.d == true) {
                  ch = data.x;
                  if (ch == 1 || ch == 2) {
                    cont_to_next = true;
                  }
                }
              }
              delay(1);
              encoder_button.tick();
              if (encoder_button.press())
                cont_to_next = true;
              delay(1);
            }
            m_menu_rect();
            main_menu(cur_pos);
            return;
          }
          if (curr_key == 2) {
            keyb_inp = "";
            m_menu_rect();
            return;
          }
        }
      }
    }

  } else {
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0, 310);
    tft.print("                                                                                                    ");
    tft.setCursor(0, 310);
    tft.print("Press any button to return to the m menu");
    keyb_inp = "";
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          if (ch == 1 || ch == 2) {
            cont_to_next = true;
          }
        }
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
    }
    m_menu_rect();
    main_menu(cur_pos);
    return;
  }
}

void Show_all_credit_cards() {
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0, 2);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Credit_cards");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    dec_st = "";
    dec_tag = "";
    decract = 0;
    for (int i = 0; i < num_of_IDs; i++) {
      Serial.print(IDs[i]);
    }
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++) {
      exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";
      dec_tag = "";
      decract = 0;
      exeq_sql_statement_from_string("SELECT Card_Number FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      tft.print("Card number:");
      tft.println(dec_st);
      tft.println("----------------------------------------");
      dec_st = "";
      dec_tag = "";
      decract = 0;
    }
    /*
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("Title:");
      Serial.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT Cardholder FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("Cardholder name:");
      Serial.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT Card_Number FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("Card number:");
      Serial.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT Expiration_date FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("Expiration date:");
      Serial.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT CVN FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("CVN:");
      Serial.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT PIN FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("PIN:");
      Serial.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT ZIP_code FROM Credit_cards WHERE ID = '" + IDs[i] + "'");
      Serial.print("ZIP code:");
      Serial.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
    }
    */
  } else {
    tft.print("Empty");
  }
  tft.setTextSize(1);
  tft.setCursor(0, 310);
  tft.print("                                                                                                    ");
  tft.setCursor(0, 310);
  tft.print("Press any button to return to the m menu");
  keyb_inp = "";
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
  }
  m_menu_rect();
  main_menu(cur_pos);
  return;
}

void Add_note() {
  rec_ID = "";
  gen_rand_ID(34);
  Insert_title_into_the_notes();
}

void Insert_title_into_the_notes() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the title:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the title:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      /*
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }
      */
      char hmacchar[32];
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      int p = 0;
      for (int i = 0; i < 4; i++) {
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight(hmacchar, p, 100, true, true);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight(keyb_inp_arr, p, str_len, true, true);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      //Serial.println(dec_st);
      exeq_sql_statement_from_string("INSERT INTO Notes (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
      dec_st = "";
      dec_tag = "";
      decract = 0;
      m_menu_rect();
      Insert_content_into_logins();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void Insert_content_into_logins() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the content:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the content:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      /*
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }
      */
      char hmacchar[32];
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      int p = 0;
      for (int i = 0; i < 4; i++) {
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight(hmacchar, p, 100, true, true);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight(keyb_inp_arr, p, str_len, true, true);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      //Serial.println(dec_st);
      exeq_sql_statement_from_string("UPDATE Notes set Content = '" + dec_st + "' where ID = '" + rec_ID + "';");
      dec_st = "";
      dec_tag = "";
      decract = 0;
      tft.setTextSize(1);
      tft.setCursor(0, 310);
      tft.print("                                                                                                    ");
      tft.setCursor(0, 310);
      tft.print("Press any button to return to the m menu");
      bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void Edit_note() {
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0, 2);
  tft.print("Select the record to edit and press A");
  tft.setCursor(0, 12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() - 1, 1);
    }
    dec_st = "";
    dec_tag = "";
    decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++) {
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
      dec_tag = "";
      decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    disp_inp_at_the_bottom("0");
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        keyb_inp = String(sel_rcrd);
        disp_inp_at_the_bottom(keyb_inp);
      }
      int inpl = keyb_inp.length();
      delay(1);
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          curr_key = int(ch);
          if (curr_key == 1) {
            int selected_id = keyb_inp.toInt();
            keyb_inp = "";
            disp_inp_panel_1();
            tft.fillScreen(0xfaa6);
            disp_inp_panel_1();
            curr_key = 65;
            tft.setCursor(90, 5);
            tft.print("A");
            tft.setCursor(198, 5);
            tft.printf("%02x", 65);
            tft.setTextColor(0xffff, 0xfaa6);
            tft.setTextSize(2);
            tft.fillRect(312, 0, 320, 240, 0x12ea);
            tft.setCursor(0, 29);
            tft.println("Enter new content:");
            disp_length_at_the_bottom(inpl);
            bool cont_to_next = false;
            while (cont_to_next == false) {
              bool smt_done = false;
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
                disp_input_from_enc_1();
                //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
              }

              bus.tick();
              if (bus.gotData()) {
                myStruct data;
                bus.readData(data);
                if (data.d == true) {
                  ch = data.x;
                  if (ch == 1) {
                    keyb_inp += char(curr_key);
                    //Serial.println(keyb_inp);
                    smt_done = true;
                  }

                  if (ch == 2) {
                    if (keyb_inp.length() > 0)
                      keyb_inp.remove(keyb_inp.length() - 1, 1);
                    tft.fillScreen(0xfaa6);
                    disp_inp_panel_1();
                    disp_input_from_enc_1();
                    tft.setTextColor(0xe73c, 0xfaa6);
                    tft.setTextSize(2);
                    tft.fillRect(312, 0, 320, 240, 0x12ea);
                    tft.fillRect(312, 0, 320, 240, 0x12ea);
                    tft.setCursor(0, 29);
                    tft.println("Enter new content:");
                    smt_done = true;
                  }
                }
              }
              if (smt_done == true) {
                int inpl = keyb_inp.length();
                disp_length_at_the_bottom(inpl);
                tft.setTextColor(0xe73c, 0xfaa6);
                tft.setCursor(0, 49);
                tft.println(keyb_inp);
              }
              encoder_button.tick();
              if (encoder_button.hasClicks(4)) {
                clb_m = 1;
                tft.fillScreen(0x3186);
                tft.setTextColor(0xe73c, 0x3186);
                tft.setTextSize(1);
                tft.setCursor(0, 0);
                int str_len = keyb_inp.length() + 1;
                char keyb_inp_arr[str_len];
                keyb_inp.toCharArray(keyb_inp_arr, str_len);
                SHA256HMAC hmac(hmackey, sizeof(hmackey));
                hmac.doUpdate(keyb_inp_arr);
                byte authCode[SHA256HMAC_SIZE];
                hmac.doFinal(authCode);
                /*
                String res_hash;
                for (byte i=0; i < SHA256HMAC_SIZE; i++)
                {
                    if (authCode[i]<0x10) { res_hash += 0; }{
                      res_hash += String(authCode[i], HEX);
                    }
                }
                */
                char hmacchar[32];
                for (int i = 0; i < 32; i++) {
                  hmacchar[i] = char(authCode[i]);
                }
                int p = 0;
                for (int i = 0; i < 4; i++) {
                  incr_key();
                  incr_second_key();
                  incr_Blwfsh_key();
                  incr_serp_key();
                  split_by_eight(hmacchar, p, 100, true, true);
                  p += 8;
                }
                p = 0;
                while (str_len > p + 1) {
                  incr_Blwfsh_key();
                  incr_key();
                  incr_serp_key();
                  incr_second_key();
                  split_by_eight(keyb_inp_arr, p, str_len, true, true);
                  p += 8;
                }
                rest_Blwfsh_k();
                rest_k();
                rest_serp_k();
                rest_s_k();
                //Serial.println(dec_st);
                exeq_sql_statement_from_string("UPDATE Notes set Content = '" + dec_st + "' where ID = '" + IDs[selected_id][0] + "';");
                dec_st = "";
                dec_tag = "";
                decract = 0;
                tft.setTextSize(1);
                tft.setCursor(0, 310);
                tft.print("                                                                                                    ");
                tft.setCursor(0, 310);
                tft.print("Press any key to return to the main menu");
                bool cont_to_next = false;
                while (cont_to_next == false) {
                  bus.tick();
                  if (bus.gotData()) {
                    myStruct data;
                    bus.readData(data);
                    if (data.d == true) {
                      ch = data.x;
                      if (ch == 1 || ch == 2) {
                        cont_to_next = true;
                      }
                    }
                  }
                  delay(1);
                  encoder_button.tick();
                  if (encoder_button.press())
                    cont_to_next = true;
                  delay(1);
                }
                cont_to_next = true;
                return;
              }
              if (encoder_button.hasClicks(5)) {
                keyb_inp = "";
                m_menu_rect();
                cont_to_next = true;
                return;
              }
            }
          }
          if (curr_key == 2) {
            keyb_inp = "";
            m_menu_rect();
            return;
          }
        }
      }
    }

  } else {
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0, 310);
    tft.print("                                                                                                    ");
    tft.setCursor(0, 310);
    tft.print("Press any button to return to the m menu");
    keyb_inp = "";
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          if (ch == 1 || ch == 2) {
            cont_to_next = true;
          }
        }
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
    }
    m_menu_rect();
    main_menu(cur_pos);
    return;
  }
}

void Remove_note() {
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0, 2);
  tft.print("Select the record to delete and press A");
  tft.setCursor(0, 12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() - 1, 1);
    }
    dec_st = "";
    dec_tag = "";
    decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++) {
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
      dec_tag = "";
      decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    disp_inp_at_the_bottom("0");
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        keyb_inp = String(sel_rcrd);
        disp_inp_at_the_bottom(keyb_inp);
      }
      int inpl = keyb_inp.length();
      delay(1);
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          curr_key = int(ch);
          if (curr_key == 1) {
            clb_m = 1;
            tft.fillScreen(0x3186);
            tft.setTextColor(0xe73c, 0x3186);
            tft.setTextSize(1);
            tft.setCursor(0, 0);
            exeq_sql_statement_from_string("DELETE FROM Notes WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            tft.setTextSize(1);
            tft.setCursor(0, 310);
            tft.print("                                                                                                    ");
            tft.setCursor(0, 310);
            tft.print("Press any button to return to the m menu");
            keyb_inp = "";
            bool cont_to_next = false;
            while (cont_to_next == false) {
              bus.tick();
              if (bus.gotData()) {
                myStruct data;
                bus.readData(data);
                if (data.d == true) {
                  ch = data.x;
                  if (ch == 1 || ch == 2) {
                    cont_to_next = true;
                  }
                }
              }
              delay(1);
              encoder_button.tick();
              if (encoder_button.press())
                cont_to_next = true;
              delay(1);
            }
            m_menu_rect();
            main_menu(cur_pos);
            return;
          }
          if (curr_key == 2) {
            keyb_inp = "";
            m_menu_rect();
            return;
          }
        }
      }
    }

  } else {
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0, 310);
    tft.print("                                                                                                    ");
    tft.setCursor(0, 310);
    tft.print("Press any button to return to the m menu");
    keyb_inp = "";
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          if (ch == 1 || ch == 2) {
            cont_to_next = true;
          }
        }
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
    }
    m_menu_rect();
    main_menu(cur_pos);
    return;
  }
}

void View_note() {
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0, 2);
  tft.print("Select the record to view and press A");
  tft.setCursor(0, 12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() - 1, 1);
    }
    dec_st = "";
    dec_tag = "";
    decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++) {
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";
      dec_tag = "";
      decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      tft.print("[");
      tft.print(i);
      tft.print("] ");
      tft.println(IDs[i][1]);
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
    }
    disp_inp_at_the_bottom("0");
    bool cont_to_next = false;
    int sel_rcrd = 0;
    while (cont_to_next == false) {
      enc0.tick();
      if (enc0.left())
        sel_rcrd--;
      if (enc0.right())
        sel_rcrd++;
      if (sel_rcrd > (num_of_IDs - 1))
        sel_rcrd = 0;
      if (sel_rcrd < 0)
        sel_rcrd = num_of_IDs - 1;
      if (enc0.turn()) {
        keyb_inp = String(sel_rcrd);
        disp_inp_at_the_bottom(keyb_inp);
      }
      int inpl = keyb_inp.length();
      delay(1);
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          curr_key = int(ch);
          if (curr_key == 1) {
            tft.fillScreen(0x3186);
            tft.setTextColor(0xe73c, 0x3186);
            tft.setTextSize(1);
            tft.setCursor(0, 2);
            clb_m = 2;
            exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            bool title_integrity = verify_integrity();
            if (title_integrity == true)
              tft.setTextColor(0xe73c, 0x3186);
            else
              tft.setTextColor(0xf800, 0x3186);
            tft.print("Title:");
            tft.println(dec_st);
            dec_st = "";
            dec_tag = "";
            decract = 0;
            exeq_sql_statement_from_string("SELECT Content FROM Notes WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
            bool content_integrity = verify_integrity();
            if (content_integrity == true)
              tft.setTextColor(0xe73c, 0x3186);
            else
              tft.setTextColor(0xf800, 0x3186);
            tft.print("Content:");
            tft.println(dec_st);
            dec_st = "";
            dec_tag = "";
            decract = 0;
            tft.setTextColor(0xe73c, 0x3186);
            tft.println("----------------------------------------");
            if (title_integrity == false || content_integrity == false) {
              tft.setTextColor(0xf800, 0x3186);
              tft.println("Integrity verification failed!!!");
            }
            dec_st = "";
            dec_tag = "";
            decract = 0;
            tft.setTextColor(0xe73c, 0x3186);
            tft.setTextSize(1);
            tft.setCursor(0, 310);
            tft.print("                                                                                                    ");
            tft.setCursor(0, 310);
            tft.print("Press any button to return to the m menu");
            keyb_inp = "";
            bool cont_to_next = false;
            while (cont_to_next == false) {
              bus.tick();
              if (bus.gotData()) {
                myStruct data;
                bus.readData(data);
                if (data.d == true) {
                  ch = data.x;
                  if (ch == 1 || ch == 2) {
                    cont_to_next = true;
                  }
                }
              }
              delay(1);
              encoder_button.tick();
              if (encoder_button.press())
                cont_to_next = true;
              delay(1);
            }
            m_menu_rect();
            main_menu(cur_pos);
            return;
          }
          if (curr_key == 2) {
            keyb_inp = "";
            m_menu_rect();
            return;
          }
        }
      }
    }

  } else {
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0, 310);
    tft.print("                                                                                                    ");
    tft.setCursor(0, 310);
    tft.print("Press any button to return to the m menu");
    keyb_inp = "";
    bool cont_to_next = false;
    while (cont_to_next == false) {
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        if (data.d == true) {
          ch = data.x;
          if (ch == 1 || ch == 2) {
            cont_to_next = true;
          }
        }
      }
      delay(1);
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delay(1);
    }
    m_menu_rect();
    main_menu(cur_pos);
    return;
  }
}

void Show_all_notes() {
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0, 2);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0) {
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i < dec_st.length() - 1; i++) {
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else {
        c_id++;
      }
    }
    for (int i = 0; i < num_of_IDs; i++) {
      if (IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() - 1, 1);
    }
    dec_st = "";
    dec_tag = "";
    decract = 0;
    for (int i = 0; i < num_of_IDs; i++) {
      Serial.print(IDs[i]);
    }
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++) {
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[i] + "'");
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";
      dec_tag = "";
      decract = 0;
      tft.println("----------------------------------------");
    }
    /*
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[i] + "'");
      Serial.print("Title:");
      Serial.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT Content FROM Notes WHERE ID = '" + IDs[i] + "'");
      Serial.print("Content:");
      Serial.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
    }
    */
  } else {
    tft.print("Empty");
  }
  tft.setTextSize(1);
  tft.setCursor(0, 310);
  tft.print("                                                                                                    ");
  tft.setCursor(0, 310);
  tft.print("Press any button to return to the m menu");
  keyb_inp = "";
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
  }
  m_menu_rect();
  main_menu(cur_pos);
  return;
}

void disp_length_at_the_bottom(int lofinp) {
  tft.setTextSize(1);
  tft.fillRect(0, 252, 240, 46, 0x1557);
  tft.setTextColor(0xffff);
  tft.setCursor(14, 256);
  tft.print("A:Enter character");
  tft.setCursor(14, 266);
  tft.print("B:Backspace");
  tft.setCursor(14, 276);
  tft.print("Click enc. button 4 times to continue");
  tft.setCursor(14, 286);
  tft.print("Click enc. button 5 times to cancel");
  tft.fillRect(0, 298, 240, 22, 0x1557);
  tft.setTextColor(0x08c5, 0x1557);
  tft.setTextSize(2);
  tft.setCursor(14, 302);
  tft.print("Length:");
  tft.setCursor(98, 302);
  tft.print("    ");
  tft.setCursor(98, 302);
  tft.print(lofinp);
}

void hash_str() {
  tft.fillScreen(0x49a9);
  tft.setTextColor(0xe73c, 0x49a9);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 5);
  tft.println("Enter string to hash");
  tft.fillRect(0, 298, 240, 22, 0xe73c);
  tft.setTextColor(0x49a9, 0xe73c);
  tft.setTextSize(2);
  tft.setCursor(14, 302);
  tft.print("Length:");
  while (curr_key != 27) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      curr_key = int(ch);
      if (curr_key != 127 && curr_key != 13 && curr_key != 9 && curr_key != 10 && curr_key != 11) {
        keyb_inp += ch;
      } else if (ch == 127) {
        if (keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() - 1, 1);
        tft.fillScreen(0x49a9);
        tft.setTextColor(0xe73c, 0x49a9);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0, 5);
        tft.println("Enter string to hash");
        tft.fillRect(0, 298, 240, 22, 0xe73c);
        tft.setTextColor(0x49a9, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(14, 302);
        tft.print("Length:");
      }
      int inpl = keyb_inp.length();
      tft.setTextColor(0x49a9, 0xe73c);
      tft.setCursor(98, 302);
      tft.print("    ");
      tft.setCursor(98, 302);
      tft.print(inpl);
      tft.setTextColor(0xf75b, 0x49a9);
      tft.setCursor(0, 25);
      tft.println(keyb_inp);
      if (curr_key == 13) {
        int str_len = keyb_inp.length() + 1;
        char keyb_inp_arr[str_len];
        keyb_inp.toCharArray(keyb_inp_arr, str_len);
        std::string str = "";
        if (str_len > 1) {
          for (int i = 0; i < str_len - 1; i++) {
            str += keyb_inp_arr[i];
          }
        }
        String h = sha512(str).c_str();
        //Serial.println(h);
        tft.fillScreen(0x49a9);
        tft.setTextColor(0xe73c, 0x49a9);
        tft.setCursor(0, 5);
        tft.println("Resulted hash:");
        tft.setTextColor(0xf75b, 0x49a9);
        tft.setCursor(0, 25);
        tft.println(h);
        tft.setTextSize(1);
        tft.setCursor(0, 310);
        tft.print("                                                                                                    ");
        tft.setCursor(0, 310);
        tft.print("Press any button to return to the m menu");
        keyb_inp = "";
        while (!bus.gotData()) {
          bus.tick();
        }
        m_menu_rect();
        main_menu(cur_pos);
        return;
      }
      if (curr_key == 27) {
        keyb_inp = "";
        m_menu_rect();
        main_menu(cur_pos);
        return;
      }
    }
  }
}

void exeq_sql_keyb() {
  tft.fillScreen(0x11c4);
  tft.setTextColor(0xe73c, 0x11c4);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 5);
  tft.println("Enter the SQL statem");
  tft.setCursor(0, 25);
  tft.println("ent to execute:");
  disp_length_at_the_bottom(0);
  while (curr_key != 27) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      curr_key = int(ch);
      if (curr_key != 127 && curr_key != 13 && curr_key != 9 && curr_key != 10 && curr_key != 11) {
        keyb_inp += ch;
      } else if (ch == 127) {
        if (keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() - 1, 1);
        tft.fillScreen(0x11c4);
        tft.setTextColor(0xe73c, 0x11c4);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0, 5);
        tft.println("Enter the SQL statem");
        tft.setCursor(0, 25);
        tft.println("ent to execute:");
      }
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xf75b, 0x11c4);
      tft.setCursor(0, 45);
      tft.println(keyb_inp);
      if (curr_key == 13) {
        clb_m = 1;
        tft.fillScreen(0x3186);
        tft.setTextColor(0xe73c, 0x3186);
        tft.setTextSize(1);
        tft.setCursor(0, 0);
        exeq_sql_statement_from_string(keyb_inp);
        tft.setTextSize(1);
        tft.setCursor(0, 310);
        tft.print("                                                                                                    ");
        tft.setCursor(0, 310);
        tft.print("Press any button to return to the m menu");
        keyb_inp = "";
        while (!bus.gotData()) {
          bus.tick();
        }
        m_menu_rect();
        main_menu(cur_pos);
        return;
      }
      if (curr_key == 27) {
        keyb_inp = "";
        m_menu_rect();
        main_menu(cur_pos);
        return;
      }
    }
  }
}

// Blowfish + AES + Serpent + AES (Below)

void split_by_eight_bl_aes_serp_aes(char plntxt[], int k, int str_len) {
  char plt_data[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    plt_data[i] = plntxt[i + k];
  }
  /*
  Serial.println("\nInput");
  for (int i = 0; i < 8; i++){
    Serial.print(plt_data[i]);
    Serial.print(" ");
  }
  */
  unsigned char t_encr[8];
  for (int i = 0; i < 8; i++) {
    t_encr[i] = (unsigned char) plt_data[i];
  }
  /*
  Serial.println("\nChar");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(t_encr, t_encr, sizeof(t_encr));
  char encr_for_aes[16];
  for (int i = 0; i < 8; i++) {
    encr_for_aes[i] = char(int(t_encr[i]));
  }
  /*
  Serial.println("\nEncrypted");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  for (int i = 8; i < 16; i++) {
    encr_for_aes[i] = gen_r_num();
  }
  /*
  Serial.println("\nFor AES");
  for (int i = 0; i < 16; i++){
    Serial.print(int(encr_for_aes[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  encr_AES_bl_aes_serp_aes(encr_for_aes);
}

void encr_AES_bl_aes_serp_aes(char t_enc[]) {
  uint8_t text[16];
  for (int i = 0; i < 16; i++) {
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  aes_context ctx;
  aes_set_key( & ctx, key, key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for (int i = 0; i < 8; i++) {
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for (int i = 0; i < 8; i++) {
    R_half[i] = cipher_text[i + 8];
  }
  for (int i = 8; i < 16; i++) {
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  serp_enc_bl_aes_serp_aes(L_half);
  serp_enc_bl_aes_serp_aes(R_half);
}

void serp_enc_bl_aes_serp_aes(char res[]) {
  int tmp_s[16];
  for (int i = 0; i < 16; i++) {
    tmp_s[i] = res[i];
  }
  /*
   for (int i = 0; i < 16; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for (int i = 0; i < 16; i++) {
      ct2.b[i] = tmp_s[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    encr_sec_AES_bl_aes_serp_aes(ct2.b);
  }
}

void encr_sec_AES_bl_aes_serp_aes(byte t_enc[]) {
  uint8_t text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  uint32_t second_key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, second_key, second_key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  String cphrt_to_send;
  for (i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
}

void split_dec_bl_aes_serp_aes(char ct[], int ct_len, int p, bool ch, bool add_r) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }
  if (br == false) {
    if (add_r == true) {
      uint8_t ret_text[16] = {
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
      };
      uint8_t cipher_text[16] = {
        0
      };
      for (int i = 0; i < 16; i++) {
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t second_key_bit[3] = {
        128,
        192,
        256
      };
      int i = 0;
      aes_context ctx;
      aes_set_key( & ctx, second_key, second_key_bit[m]);
      aes_decrypt_block( & ctx, ret_text, cipher_text);
      for (i = 0; i < 16; i++) {
        res[i] = (char) ret_text[i];
      }
    }
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);
      //Serial.printf ("\nkey=");

      for (j = 0; j < sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
        if ((j % 8) == 0) putchar('\n');
        //Serial.printf ("%08X ", p[j]);
      }

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
    if (ch == false) {
      for (int i = 0; i < 8; i++) {
        tmp_st[i] = char(ct2.b[i]);
      }
    }
    if (ch == true) {
      decr_AES_and_Blowfish_bl_aes_serp_aes(ct2.b);
    }
  }
}

void decr_AES_and_Blowfish_bl_aes_serp_aes(byte sh[]) {
  uint8_t ret_text[16];
  for (int i = 0; i < 8; i++) {
    ret_text[i] = tmp_st[i];
  }
  for (int i = 0; i < 8; i++) {
    ret_text[i + 8] = sh[i];
  }
  uint8_t cipher_text[16] = {
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(ret_text[i]);
    cipher_text[i] = c;
  }
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, key, key_bit[m]);
  aes_decrypt_block( & ctx, ret_text, cipher_text);
  /*
  Serial.println("\nDec by AES");
  for (int i = 0; i < 16; i++){\
    Serial.print(int(ret_text[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  unsigned char dbl[8];
  for (int i = 0; i < 8; i++) {
    dbl[i] = (unsigned char) int(ret_text[i]);
  }
  /*
  Serial.println("\nConv for blowfish");
  for (int i = 0; i < 8; i++){\
    Serial.print(dbl[i]);
    Serial.print(" ");
  }
  Serial.println();
  */
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Decrypt(dbl, dbl, sizeof(dbl));
  /*
  Serial.println("\nDecr by blowfish");
  for (int i = 0; i < 8; i++){\
    Serial.print(int(dbl[i]));
    Serial.print(" ");
  }
  Serial.println();
  */
  if (decract < 4) {
    for (int i = 0; i < 8; i++) {
      if (dbl[i] < 0x10)
        dec_tag += 0;
      dec_tag += String(dbl[i], HEX);
    }
  } else {
    for (i = 0; i < 8; ++i) {
      dec_st += (char(dbl[i]));
    }
  }
  decract++;
}

// Blowfish + AES + Serpent + AES (Above)

// AES + Serpent + AES (Below)

void split_by_eight_for_aes_serp_aes(char plntxt[], int k, int str_len) {
  char plt_data[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    plt_data[i] = plntxt[i + k];
  }
  char t_encr[16];
  for (int i = 0; i < 8; i++) {
    t_encr[i] = plt_data[i];
  }
  for (int i = 8; i < 16; i++) {
    t_encr[i] = gen_r_num();
  }
  encr_AES_for_aes_serp_aes(t_encr);
}

void encr_AES_for_aes_serp_aes(char t_enc[]) {
  uint8_t text[16];
  for (int i = 0; i < 16; i++) {
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  aes_context ctx;
  aes_set_key( & ctx, key, key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for (int i = 0; i < 8; i++) {
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for (int i = 0; i < 8; i++) {
    R_half[i] = cipher_text[i + 8];
  }
  for (int i = 8; i < 16; i++) {
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  enc_serp_for_aes_serp_aes(L_half);
  enc_serp_for_aes_serp_aes(R_half);
}

void enc_serp_for_aes_serp_aes(char res[]) {
  int tmp_s[16];
  for (int i = 0; i < 16; i++) {
    tmp_s[i] = res[i];
  }
  /*
   for (int i = 0; i < 16; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for (int i = 0; i < 16; i++) {
      ct2.b[i] = tmp_s[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    encr_sec_AES_for_aes_serp_aes(ct2.b);
  }
}

void encr_sec_AES_for_aes_serp_aes(byte t_enc[]) {
  uint8_t text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  uint32_t second_key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, second_key, second_key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  for (i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
}

void split_dec_for_aes_serp_aes(char ct[], int ct_len, int p, bool ch, bool add_r) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }
  if (br == false) {
    if (add_r == true) {
      uint8_t ret_text[16] = {
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0
      };
      uint8_t cipher_text[16] = {
        0
      };
      for (int i = 0; i < 16; i++) {
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t second_key_bit[3] = {
        128,
        192,
        256
      };
      int i = 0;
      aes_context ctx;
      aes_set_key( & ctx, second_key, second_key_bit[m]);
      aes_decrypt_block( & ctx, ret_text, cipher_text);
      for (i = 0; i < 16; i++) {
        res[i] = (char) ret_text[i];
      }
    }
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);
      //Serial.printf ("\nkey=");

      for (j = 0; j < sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
        if ((j % 8) == 0) putchar('\n');
        //Serial.printf ("%08X ", p[j]);
      }

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
    if (ch == false) {
      for (int i = 0; i < 8; i++) {
        tmp_st[i] = char(ct2.b[i]);
      }
    }
    if (ch == true) {
      decr_AES_for_aes_serp_aes(ct2.b);
    }
  }
}

void decr_AES_for_aes_serp_aes(byte sh[]) {
  uint8_t ret_text[16];
  for (int i = 0; i < 8; i++) {
    ret_text[i] = tmp_st[i];
  }
  for (int i = 0; i < 8; i++) {
    ret_text[i + 8] = sh[i];
  }
  uint8_t cipher_text[16] = {
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(ret_text[i]);
    cipher_text[i] = c;
  }
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, key, key_bit[m]);
  aes_decrypt_block( & ctx, ret_text, cipher_text);
  if (decract < 4) {
    for (int i = 0; i < 8; i++) {
      if (ret_text[i] < 0x10)
        dec_tag += 0;
      dec_tag += String(ret_text[i], HEX);
    }
  } else {
    for (i = 0; i < 8; ++i) {
      dec_st += (char(ret_text[i]));
    }
  }
  decract++;
}

// AES + Serpent + AES (Above)

// Blowfish + Serpent (Below)

void split_by_eight_for_bl_and_serp(char plntxt[], int k, int str_len) {
  char plt_data[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    plt_data[i] = plntxt[i + k];
  }
  /*
  Serial.println("\nInput");
  for (int i = 0; i < 8; i++){
    Serial.print(plt_data[i]);
    Serial.print(" ");
  }
  */
  unsigned char t_encr[8];
  for (int i = 0; i < 8; i++) {
    t_encr[i] = (unsigned char) plt_data[i];
  }
  /*
  Serial.println("\nChar");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(t_encr, t_encr, sizeof(t_encr));
  char encr_for_serp[16];
  for (int i = 0; i < 8; i++) {
    encr_for_serp[i] = char(int(t_encr[i]));
  }
  /*
  Serial.println("\nEncrypted");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  for (int i = 8; i < 16; i++) {
    encr_for_serp[i] = gen_r_num();
  }

  int tmp_s[16];
  for (int i = 0; i < 16; i++) {
    tmp_s[i] = encr_for_serp[i];
  }

  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for (int i = 0; i < 16; i++) {
      ct2.b[i] = tmp_s[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        Serial.print("0");
      Serial.print(ct2.b[i], HEX);
    }
  }
}

void split_for_dec_bl_and_serp(char ct[], int ct_len, int p) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }
  if (br == false) {
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);
      //Serial.printf ("\nkey=");

      for (j = 0; j < sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
        if ((j % 8) == 0) putchar('\n');
        //Serial.printf ("%08X ", p[j]);
      }

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);

    unsigned char dbl[8];
    for (int i = 0; i < 8; i++) {
      dbl[i] = (unsigned char) int(ct2.b[i]);
    }
    /*
    Serial.println("\nConv for blowfish");
    for (int i = 0; i < 8; i++){\
      Serial.print(dbl[i]);
      Serial.print(" ");
    }
    Serial.println();
    */
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(dbl, dbl, sizeof(dbl));
    /*
    Serial.println("\nDecr by blowfish");
    for (int i = 0; i < 8; i++){\
      Serial.print(int(dbl[i]));
      Serial.print(" ");
    }
    Serial.println();
    */
    if (decract < 4) {
      for (i = 0; i < 8; i++) {
        if (dbl[i] < 0x10)
          dec_tag += 0;
        dec_tag += String(dbl[i], HEX);
      }
    } else {
      for (i = 0; i < 8; ++i) {
        dec_st += (char(dbl[i]));
      }
    }
    decract++;
  }
}

// Blowfish + Serpent (Above)

// AES + Serpent (Below)

void split_by_eight_for_AES_serp(char plntxt[], int k, int str_len) {
  char res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    res[i] = plntxt[i + k];
  }
  for (int i = 8; i < 16; i++) {
    res[i] = gen_r_num();
  }
  /*
   for (int i = 0; i < 8; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  encr_AES_for_aes_srp(res);
}

void encr_AES_for_aes_srp(char t_enc[]) {
  uint8_t text[16];
  for (int i = 0; i < 16; i++) {
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  aes_context ctx;
  aes_set_key( & ctx, key, key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for (int i = 0; i < 8; i++) {
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for (int i = 0; i < 8; i++) {
    R_half[i] = cipher_text[i + 8];
  }
  for (int i = 8; i < 16; i++) {
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  encr_serp_for_aes_srp(L_half, false);
  encr_serp_for_aes_srp(R_half, true);
}

void encr_serp_for_aes_srp(char res[], bool snd) {
  int tmp_s[16];
  for (int i = 0; i < 16; i++) {
    tmp_s[i] = res[i];
  }
  /*
   for (int i = 0; i < 16; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for (int i = 0; i < 16; i++) {
      ct2.b[i] = tmp_s[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        Serial.print("0");
      Serial.print(ct2.b[i], HEX);
    }
  }
}

void split_dec_for_aes_serp(char ct[], int ct_len, int p, bool ch) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }
  if (br == false) {
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);
      //Serial.printf ("\nkey=");

      for (j = 0; j < sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
        if ((j % 8) == 0) putchar('\n');
        //Serial.printf ("%08X ", p[j]);
      }

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
    if (ch == false) {
      for (int i = 0; i < 8; i++) {
        tmp_st[i] = char(ct2.b[i]);
      }
    }
    if (ch == true) {
      decr_AES_for_aes_serp(ct2.b);
    }
  }
}

void decr_AES_for_aes_serp(byte sh[]) {
  uint8_t ret_text[16];
  for (int i = 0; i < 8; i++) {
    ret_text[i] = tmp_st[i];
  }
  for (int i = 0; i < 8; i++) {
    ret_text[i + 8] = sh[i];
  }
  uint8_t cipher_text[16] = {
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(ret_text[i]);
    cipher_text[i] = c;
  }
  uint32_t key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, key, key_bit[m]);
  aes_decrypt_block( & ctx, ret_text, cipher_text);
    if (decract < 4) {
      for (i = 0; i < 8; i++) {
        if (ret_text[i] < 0x10)
          dec_tag += 0;
        dec_tag += String(ret_text[i], HEX);
      }
    } else {
      for (i = 0; i < 8; ++i) {
        dec_st += (char(ret_text[i]));
      }
    }
    decract++;
}

// AES + Serpent (Above)

// Serpent (Below)

void split_by_eight_for_serp_only(char plntxt[], int k, int str_len) {
  char res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    res[i] = plntxt[i + k];
  }
  for (int i = 8; i < 16; i++) {
    res[i] = gen_r_num();
  }
  int tmp_s[16];
  for (int i = 0; i < 16; i++) {
    tmp_s[i] = res[i];
  }

  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for (int i = 0; i < 16; i++) {
      ct2.b[i] = tmp_s[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        Serial.print("0");
      Serial.print(ct2.b[i], HEX);
    }
  }
}

void split_for_dec_serp_only(char ct[], int ct_len, int p) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }
  if (br == false) {
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);
      //Serial.printf ("\nkey=");

      for (j = 0; j < sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
        if ((j % 8) == 0) putchar('\n');
        //Serial.printf ("%08X ", p[j]);
      }

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
    if (decract < 4) {
      for (i = 0; i < 8; i++) {
        if (ct2.b[i] < 0x10)
          dec_tag += 0;
        dec_tag += String(ct2.b[i], HEX);
      }
    } else {
      for (i = 0; i < 8; ++i) {
        dec_st += (char(ct2.b[i]));
      }
    }
    decract++;
  }
}

// Serpent (Above)

// 3DES (Below)

void split_by_four_for_encr_tdes(char plntxt[], int k, int str_len){
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 4; i++){
      if(i+k > str_len - 1)
      break;
      res[i] = byte(plntxt[i+k]);
  }
  for (int i = 4; i < 8; i++) {
    res[i] = gen_r_num();
  }
  encr_TDES(res);
}

void encr_TDES(byte inp_for_tdes[]){
  byte out_of_tdes[8];
  des.tripleEncrypt(out_of_tdes, inp_for_tdes, TDESkey);
  for(int i = 0; i<8; i++){
    if(out_of_tdes[i]<16)
    Serial.print("0");
    Serial.print(out_of_tdes[i],HEX);
  }
}

void decr_eight_chars_block_tdes(char ct[], int ct_len, int p){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 16; i+=2){
    if(i+p > ct_len - 1){
      br = true;
      break;
    }
    if (i == 0){
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i] = 0;
    }
    else{
    if(ct[i+p] != 0 && ct[i+p+1] != 0)
    res[i/2] = 16*getNum(ct[i+p])+getNum(ct[i+p+1]);
    if(ct[i+p] != 0 && ct[i+p+1] == 0)
    res[i/2] = 16*getNum(ct[i+p]);
    if(ct[i+p] == 0 && ct[i+p+1] != 0)
    res[i/2] = getNum(ct[i+p+1]);
    if(ct[i+p] == 0 && ct[i+p+1] == 0)
    res[i/2] = 0;
    }
  }
    if(br == false){
      byte decr_text[8];
      des.tripleDecrypt(decr_text, res, TDESkey);
    if (decract < 8) {
      for (int i = 0; i < 4; i++) {
        if (decr_text[i] < 0x10)
          dec_tag += 0;
        dec_tag += String(decr_text[i], HEX);
      }
    } else {
      for (int i = 0; i < 4; ++i) {
        dec_st += (char(decr_text[i]));
      }
    }
    decract++;
   }
}

// 3DES (Above)

bool verify_integrity() {
  int str_lentg = dec_st.length() + 1;
  char char_arraytg[str_lentg];
  dec_st.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_arraytg);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;

  for (byte i = 0; i < SHA256HMAC_SIZE; i++) {
    if (authCode[i] < 0x10) {
      res_hash += 0;
    } {
      res_hash += String(authCode[i], HEX);
    }
  }

  return dec_tag.equals(res_hash);
}

void back_keys() {
  back_k();
  back_s_k();
  back_serp_k();
  back_Blwfsh_k();
  back_TDESkey();
}

void disp_centered_text(String t_disp, int y) {
  int16_t x1, y1;
  uint16_t w, h;
  tft.getTextBounds(t_disp, 240, 0, & x1, & y1, & w, & h);
  tft.setCursor(120 - (w / 2), y);
  tft.print(t_disp);
}

void locally_stored_login_menu(int curr_pos) {
  tft.setTextColor(0x899a, 0x1884);
  tft.setTextSize(1);
  if (curr_pos == 0) {
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Add Login", 80);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Edit Login", 100);
    disp_centered_text("Delete Login", 120);
    disp_centered_text("View Login", 140);
    disp_centered_text("Show All Logins", 160);
  }
  if (curr_pos == 1) {
    disp_centered_text("Add Login", 80);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Edit Login", 100);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Delete Login", 120);
    disp_centered_text("View Login", 140);
    disp_centered_text("Show All Logins", 160);
  }
  if (curr_pos == 2) {
    disp_centered_text("Add Login", 80);
    disp_centered_text("Edit Login", 100);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Delete Login", 120);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("View Login", 140);
    disp_centered_text("Show All Logins", 160);
  }
  if (curr_pos == 3) {
    disp_centered_text("Add Login", 80);
    disp_centered_text("Edit Login", 100);
    disp_centered_text("Delete Login", 120);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("View Login", 140);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Show All Logins", 160);
  }
  if (curr_pos == 4) {
    disp_centered_text("Add Login", 80);
    disp_centered_text("Edit Login", 100);
    disp_centered_text("Delete Login", 120);
    disp_centered_text("View Login", 140);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Show All Logins", 160);
  }
}

void show_loc_st_login_menu() {
  tft.fillScreen(0x1884);
  tft.setTextSize(2);
  tft.setTextColor(0x899a, 0x1884);
  disp_centered_text("Logins Menu", 30);
  curr_key = 0;
  locally_stored_login_menu(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 4;

    if (curr_key > 4)
      curr_key = 0;

    if (enc0.turn()) {
      locally_stored_login_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 && curr_key == 0) {
          Add_login();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 1) {
          Edit_login();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 2) {
          Remove_login();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 3) {
          View_login();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 4) {
          Show_all_logins();
          cont_to_next = true;
        }

        if (ch == 2) // Get back
          cont_to_next = true;
      }

    }
  }
  m_menu_rect();
  curr_key = 0;
  main_menu(cur_pos);
}

void locally_stored_credit_cards(int curr_pos) {
  tft.setTextColor(0x899a, 0x1884);
  tft.setTextSize(1);
  if (curr_pos == 0) {
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Add Credit Card", 80);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Edit Credit Card", 100);
    disp_centered_text("Delete Credit Card", 120);
    disp_centered_text("View Credit Card", 140);
    disp_centered_text("Show All Credit Cards", 160);
  }
  if (curr_pos == 1) {
    disp_centered_text("Add Credit Card", 80);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Edit Credit Card", 100);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Delete Credit Card", 120);
    disp_centered_text("View Credit Card", 140);
    disp_centered_text("Show All Credit Cards", 160);
  }
  if (curr_pos == 2) {
    disp_centered_text("Add Credit Card", 80);
    disp_centered_text("Edit Credit Card", 100);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Delete Credit Card", 120);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("View Credit Card", 140);
    disp_centered_text("Show All Credit Cards", 160);
  }
  if (curr_pos == 3) {
    disp_centered_text("Add Credit Card", 80);
    disp_centered_text("Edit Credit Card", 100);
    disp_centered_text("Delete Credit Card", 120);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("View Credit Card", 140);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Show All Credit Cards", 160);
  }
  if (curr_pos == 4) {
    disp_centered_text("Add Credit Card", 80);
    disp_centered_text("Edit Credit Card", 100);
    disp_centered_text("Delete Credit Card", 120);
    disp_centered_text("View Credit Card", 140);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Show All Credit Cards", 160);
  }
}

void show_loc_st_credit_cards() {
  tft.fillScreen(0x1884);
  tft.setTextSize(2);
  tft.setTextColor(0x899a, 0x1884);
  disp_centered_text("Credit Cards Menu", 30);
  curr_key = 0;
  locally_stored_credit_cards(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 4;

    if (curr_key > 4)
      curr_key = 0;

    if (enc0.turn()) {
      locally_stored_credit_cards(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 && curr_key == 0) {
          Add_credit_card();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 1) {
          Edit_credit_card();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 2) {
          Remove_credit_card();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 3) {
          View_credit_card();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 4) {
          Show_all_credit_cards();
          cont_to_next = true;
        }

        if (ch == 2) // Get back
          cont_to_next = true;
      }

    }
  }
  m_menu_rect();
  curr_key = 0;
  main_menu(cur_pos);
}

void locally_stored_notes(int curr_pos) {
  tft.setTextColor(0x899a, 0x1884);
  tft.setTextSize(1);
  if (curr_pos == 0) {
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Add Note", 80);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Edit Note", 100);
    disp_centered_text("Delete Note", 120);
    disp_centered_text("View Note", 140);
    disp_centered_text("Show All Notes", 160);
  }
  if (curr_pos == 1) {
    disp_centered_text("Add Note", 80);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Edit Note", 100);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Delete Note", 120);
    disp_centered_text("View Note", 140);
    disp_centered_text("Show All Notes", 160);
  }
  if (curr_pos == 2) {
    disp_centered_text("Add Note", 80);
    disp_centered_text("Edit Note", 100);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Delete Note", 120);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("View Note", 140);
    disp_centered_text("Show All Notes", 160);
  }
  if (curr_pos == 3) {
    disp_centered_text("Add Note", 80);
    disp_centered_text("Edit Note", 100);
    disp_centered_text("Delete Note", 120);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("View Note", 140);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Show All Notes", 160);
  }
  if (curr_pos == 4) {
    disp_centered_text("Add Note", 80);
    disp_centered_text("Edit Note", 100);
    disp_centered_text("Delete Note", 120);
    disp_centered_text("View Note", 140);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Show All Notes", 160);
  }
}

void show_loc_st_notes() {
  tft.fillScreen(0x1884);
  tft.setTextSize(2);
  tft.setTextColor(0x899a, 0x1884);
  disp_centered_text("Notes Menu", 30);
  curr_key = 0;
  locally_stored_notes(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 4;

    if (curr_key > 4)
      curr_key = 0;

    if (enc0.turn()) {
      locally_stored_notes(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 && curr_key == 0) {
          Add_note();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 1) {
          Edit_note();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 2) {
          Remove_note();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 3) {
          View_note();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 4) {
          Show_all_notes();
          cont_to_next = true;
        }

        if (ch == 2) // Get back
          cont_to_next = true;
      }

    }
  }
  m_menu_rect();
  curr_key = 0;
  main_menu(cur_pos);
}

void HMAC_sha256_menu(int curr_pos){
  tft.setTextColor(0x899a, 0x1884);
  tft.setTextSize(1);
  if (curr_pos == 0){
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Compute tag for the string", 80);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Compute tag for the string from Serial", 100);
    disp_centered_text("Compute tag using RFID card as a key", 120);
    disp_centered_text("Compute tag for the string from Serial", 140);
    disp_centered_text("using RFID card as a key", 150);
  }
  if (curr_pos == 1){
    disp_centered_text("Compute tag for the string", 80);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Compute tag for the string from Serial", 100);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Compute tag using RFID card as a key", 120);
    disp_centered_text("Compute tag for the string from Serial", 140);
    disp_centered_text("using RFID card as a key", 150);
  }
  if (curr_pos == 2){
    disp_centered_text("Compute tag for the string", 80);
    disp_centered_text("Compute tag for the string from Serial", 100);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Compute tag using RFID card as a key", 120);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Compute tag for the string from Serial", 140);
    disp_centered_text("using RFID card as a key", 150);
  }
  if (curr_pos == 3){
    disp_centered_text("Compute tag for the string", 80);
    disp_centered_text("Compute tag for the string from Serial", 100);
    disp_centered_text("Compute tag using RFID card as a key", 120);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Compute tag for the string from Serial", 140);
    disp_centered_text("using RFID card as a key", 150);
  }
}

void show_HMAC_sha256_menu() {
  tft.fillScreen(0x1884);
  tft.setTextSize(2);
  tft.setTextColor(0x899a, 0x1884);
  disp_centered_text("HMAC SHA-256 Menu", 30);
  curr_key = 0;
  HMAC_sha256_menu(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 3;

    if (curr_key > 3)
      curr_key = 0;

    if (enc0.turn()) {
      HMAC_sha256_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 && curr_key == 0) {
          calc_tag_for_string_hmac_sha256();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 1) {
          calc_tag_for_string_hmac_sha256_from_ser();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 2) {
          calc_tag_for_string_hmac_sha256_rfid_key();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 3) {
          calc_tag_for_string_hmac_sha256_rfid_key_from_serial();
          cont_to_next = true;
        }

        if (ch == 2) // Get back
          cont_to_next = true;
      }

    }
  }
  m_menu_rect();
  curr_key = 0;
  main_menu(cur_pos);
}

void calc_tag_for_string_hmac_sha256() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the string:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the string:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(hmackey, sizeof(hmackey));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }

      tft.fillScreen(0x3186);
      tft.setCursor(0, 10);
      tft.setTextSize(2);
      tft.print("Computed tag:");
      tft.setCursor(0, 30);
      tft.print(res_hash);
      delay(100);
      tft.setTextSize(1);
      tft.setCursor(0, 310);
      tft.print("                                                                                                    ");
      tft.setCursor(0, 310);
      tft.print("Press any button to return to the m menu");
      bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
}

void calc_tag_for_string_hmac_sha256_from_ser(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the text you want to", 10);
  disp_centered_text("compute the tag for into", 30);
  disp_centered_text("the Serial Monitor", 50);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("Paste the text that you want to hash here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
  keyb_inp = Serial.readString();
  int str_len = keyb_inp.length() + 1;
  char keyb_inp_arr[str_len];
  keyb_inp.toCharArray(keyb_inp_arr, str_len);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(keyb_inp_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;
  for (byte i=0; i < SHA256HMAC_SIZE; i++)
  {
      if (authCode[i]<0x10) { res_hash += 0; }{
        res_hash += String(authCode[i], HEX);
      }
  }
  Serial.print("\nComputed tag: ");
  Serial.println(res_hash);
  tft.fillScreen(0x3186);
  tft.setCursor(0, 10);
  tft.setTextSize(2);
  tft.print("Computed tag:");
  tft.setCursor(0, 30);
  tft.print(res_hash);
  delay(100);
  tft.setTextSize(1);
  tft.setCursor(0, 310);
  tft.print("                                                                                                    ");
  tft.setCursor(0, 310);
  tft.print("Press any button to return to the m menu");
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
  }
  cont_to_next = true;
  return;
 }
}

void calc_tag_for_string_hmac_sha256_rfid_key() {
  tft.fillScreen(0x2145);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setCursor(0,10);
  Serial.println("Approximate the RFID card to the reader");
  tft.print("Approximate RFID card to the reader.");
  tft.setCursor(0,310);
  tft.print("Press either A or B to cancel.");
  String card_key;
  int act = 0;
  bool canc_oper = false;
  while (act < 90) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == false) {
        if (act == 0){
          if (data.x < 16)
            card_key += "0";
          card_key +=  String(data.x, HEX);
        }
        if (act == 1){
          if (data.x < 16)
            card_key += "0";
          card_key +=  String(data.x, HEX);
        }
        if (act == 2){
          if (data.x < 16)
            card_key += "0";
          card_key +=  String(data.x, HEX);
        }
        if (act == 3){
          if (data.x < 16)
            card_key += "0";
          card_key +=  String(data.x, HEX);
          act = 100;
        }
        act++;
      }
      if (data.d == true) {
          canc_oper = true;
          act = 100;
      }
    }
  }
  if (canc_oper == false)
  {
  //Serial.println(card_key);
  int card_key_len = card_key.length() + 1;
  char card_key_arr[card_key_len];
  card_key.toCharArray(card_key_arr, card_key_len);
  byte card_key_arr_b[card_key_len];
  for (int i = 0; i < card_key_len; i++){
    card_key_arr_b[i] = byte(card_key_arr[i]);
  }
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.print("Key:");
  tft.print(card_key);
  tft.setCursor(0, 49);
  tft.println("Enter the string:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.print("Key:");
          tft.print(card_key);
          tft.setCursor(0, 49);
          tft.println("Enter the string:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 69);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(card_key_arr_b, sizeof(card_key_arr_b));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }

      tft.fillScreen(0x3186);
      tft.setCursor(0, 10);
      tft.setTextSize(2);
      tft.print("Computed tag:");
      tft.setCursor(0, 30);
      tft.print(res_hash);
      delay(100);
      tft.setTextSize(1);
      tft.setCursor(0, 310);
      tft.print("                                                                                                    ");
      tft.setCursor(0, 310);
      tft.print("Press any button to return to the m menu");
      bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
  }
  else{
    keyb_inp = "";
    m_menu_rect();
    return;
  }
}

void calc_tag_for_string_hmac_sha256_rfid_key_from_serial() {
  tft.fillScreen(0x2145);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setCursor(0, 10);
  Serial.println("Approximate the RFID card to the reader");
  tft.print("Approximate RFID card to the reader.");
  tft.setCursor(0, 310);
  tft.print("Press either A or B to cancel.");
  String card_key;
  int act = 0;
  bool canc_oper = false;
  while (act < 90) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == false) {
        if (act == 0) {
          if (data.x < 16)
            card_key += "0";
          card_key += String(data.x, HEX);
        }
        if (act == 1) {
          if (data.x < 16)
            card_key += "0";
          card_key += String(data.x, HEX);
        }
        if (act == 2) {
          if (data.x < 16)
            card_key += "0";
          card_key += String(data.x, HEX);
        }
        if (act == 3) {
          if (data.x < 16)
            card_key += "0";
          card_key += String(data.x, HEX);
          act = 100;
        }
        act++;
      }
      if (data.d == true) {
        canc_oper = true;
        act = 100;
      }
    }
  }
  if (canc_oper == false) {
    //Serial.println(card_key);
    int card_key_len = card_key.length() + 1;
    char card_key_arr[card_key_len];
    card_key.toCharArray(card_key_arr, card_key_len);
    byte card_key_arr_b[card_key_len];
    bool cont_to_next = false;
    while (cont_to_next == false) {
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      disp_centered_text("Paste the text you want to", 10);
      disp_centered_text("compute the tag for into", 30);
      disp_centered_text("the Serial Monitor", 50);
      tft.setCursor(0, 310);
      tft.print("Press any button to cancel.");
      Serial.println("Paste the text that you want to hash here:");
      bool canc_op = false;
      while (!Serial.available()) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
        if (cont_to_next == true) {
          canc_op = true;
          break;
        }
      }
      if (canc_op == true)
        break;
      keyb_inp = Serial.readString();
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256HMAC hmac(card_key_arr_b, sizeof(card_key_arr_b));
      hmac.doUpdate(keyb_inp_arr);
      byte authCode[SHA256HMAC_SIZE];
      hmac.doFinal(authCode);
      String res_hash;
      for (byte i = 0; i < SHA256HMAC_SIZE; i++) {
        if (authCode[i] < 0x10) {
          res_hash += 0;
        } {
          res_hash += String(authCode[i], HEX);
        }
      }
      Serial.print("\nComputed tag: ");
      Serial.println(res_hash);
      tft.fillScreen(0x3186);
      tft.setCursor(0, 10);
      tft.setTextSize(2);
      tft.print("Computed tag:");
      tft.setCursor(0, 30);
      tft.print(res_hash);
      delay(100);
      tft.setTextSize(1);
      tft.setCursor(0, 310);
      tft.print("                                                                                                    ");
      tft.setCursor(0, 310);
      tft.print("Press any button to return to the m menu");
      bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
      cont_to_next = true;
      return;
    }

  } else {
    keyb_inp = "";
    m_menu_rect();
    return;
  }
}

void hash_using_sha512() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the string:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the string:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      std::string str = "";
      if(str_len > 1){
        for(int i = 0; i<str_len-1; i++){
          str += keyb_inp_arr[i];
        }
      }
      String h = sha512( str ).c_str();
      //Serial.println(h);
      tft.fillScreen(0x3186);
      tft.setCursor(0, 10);
      tft.setTextSize(2);
      tft.print("Resulted hash:");
      tft.setCursor(0, 30);
      tft.print(h);
      delay(100);
      tft.setTextSize(1);
      tft.setCursor(0, 310);
      tft.print("                                                                                                    ");
      tft.setCursor(0, 310);
      tft.print("Press any button to return to the m menu");
      bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
  }
}

void hash_string_with_sha256() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the string:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the string:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256 hasher;
      hasher.doUpdate(keyb_inp_arr, strlen(keyb_inp_arr));
      byte authCode[SHA256_SIZE];
      hasher.doFinal(authCode);
      
      String res_hash;
      for (byte i=0; i < SHA256HMAC_SIZE; i++)
      {
          if (authCode[i]<0x10) { res_hash += 0; }{
            res_hash += String(authCode[i], HEX);
          }
      }

      tft.fillScreen(0x3186);
      tft.setCursor(0, 10);
      tft.setTextSize(2);
      tft.print("Resulted hash:");
      tft.setCursor(0, 30);
      tft.print(res_hash);
      delay(100);
      tft.setTextSize(1);
      tft.setCursor(0, 310);
      tft.print("                                                                                                    ");
      tft.setCursor(0, 310);
      tft.print("Press any button to return to the m menu");
      bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
  }
}

void sql_menu(int curr_pos){
  tft.setTextColor(0x899a, 0x1884);
  tft.setTextSize(1);
  if (curr_pos == 0){
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Execute SQL query", 80);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Execute SQL query from Serial", 100);
  }
  if (curr_pos == 1){
    disp_centered_text("Execute SQL query", 80);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Execute SQL query from Serial", 100);
    tft.setTextColor(0x899a, 0x1884);
  }
}

void show_SQL_menu() {
  tft.fillScreen(0x1884);
  tft.setTextSize(2);
  tft.setTextColor(0x899a, 0x1884);
  disp_centered_text("SQL Menu", 30);
  curr_key = 0;
  sql_menu(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 1;

    if (curr_key > 1)
      curr_key = 0;

    if (enc0.turn()) {
      sql_menu(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 && curr_key == 0) {
          exeq_sql_query_from_enc_inp();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 1) {
          exeq_sql_query_from_enc_inp_from_ser();
          cont_to_next = true;
        }

        if (ch == 2) // Get back
          cont_to_next = true;
      }

    }
  }
  m_menu_rect();
  curr_key = 0;
  main_menu(cur_pos);
}

void exeq_sql_query_from_enc_inp() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter the SQL query:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter the SQL query:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0,0);
      exeq_sql_statement_from_string(keyb_inp);
      tft.setTextSize(1);
      tft.setCursor(0, 300);
      tft.print("                                                                                                                                                                                                        ");
      tft.setCursor(0, 310);
      tft.print("Press any button to return to the m menu");
      bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
  }
}

void exeq_sql_query_from_enc_inp_from_ser(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Enter the SQL query", 10);
  disp_centered_text("you want to execute", 30);
  disp_centered_text("into the Serial Monitor", 50);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("Enter the SQL query you want to execute here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
  keyb_inp = Serial.readString();
  clb_m = 0;
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,0);
  exeq_sql_statement_from_string(keyb_inp);
  cont_to_next = true;
  return;
 }
}

void enc_dec_options(int curr_pos){
  tft.setTextColor(0x899a, 0x1884);
  tft.setTextSize(1);
  if (curr_pos == 0){
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Encrypt String", 80);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Encrypt String from Serial", 100);
    disp_centered_text("Decrypt String", 120);
  }
  if (curr_pos == 1){
    disp_centered_text("Encrypt String", 80);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Encrypt String from Serial", 100);
    tft.setTextColor(0x899a, 0x1884);
    disp_centered_text("Decrypt String", 120);
  }
  if (curr_pos == 2){
    disp_centered_text("Encrypt String", 80);
    disp_centered_text("Encrypt String from Serial", 100);
    tft.setTextColor(0xffff, 0x1884);
    disp_centered_text("Decrypt String", 120);
  }
}

void Blfish_AES_Serp_AES_menu() {
  tft.fillScreen(0x1884);
  tft.setTextSize(2);
  tft.setTextColor(0x899a, 0x1884);
  disp_centered_text("Blfish+AES+Serp+AES", 30);
  curr_key = 0;
  enc_dec_options(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      enc_dec_options(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 && curr_key == 0) {
          encr_blwfsh_aes_serpent_aes();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 1) {
          encr_blwfsh_aes_serpent_aes_from_Serial();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 2) {
          decr_blwfsh_aes_serpent_aes();
          cont_to_next = true;
        }

        if (ch == 2) // Get back
          cont_to_next = true;
      }

    }
  }
  m_menu_rect();
  curr_key = 0;
  main_menu(cur_pos);
}

void encr_blwfsh_aes_serpent_aes() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter string to encr");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter string to encr");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    /*
    String res_hash;
    for (byte i=0; i < SHA256HMAC_SIZE; i++)
    {
        if (authCode[i]<0x10) { res_hash += 0; }{
          res_hash += String(authCode[i], HEX);
        }
    }
    Serial.print(res_hash);
    */
    char hmacchar[32];
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
    int p = 0;
    for (int i = 0; i < 4; i++){
      incr_key();
      incr_second_key();
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight_bl_aes_serp_aes(hmacchar, p, 100);
      p+=8;
    }
    p = 0;
    while(str_len > p+1){
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
      split_by_eight_bl_aes_serp_aes(char_array, p, str_len);
      p+=8;
    }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();

      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
  }
}

void encr_blwfsh_aes_serpent_aes_from_Serial(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the string you want", 10);
  disp_centered_text("to encrypt into the", 30);
  disp_centered_text("Serial Monitor", 50);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the string you want to encrypt here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
    keyb_inp = Serial.readString();
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    /*
    String res_hash;
    for (byte i=0; i < SHA256HMAC_SIZE; i++)
    {
        if (authCode[i]<0x10) { res_hash += 0; }{
          res_hash += String(authCode[i], HEX);
        }
    }
    Serial.print(res_hash);
    */
    char hmacchar[32];
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
    int p = 0;
    for (int i = 0; i < 4; i++){
      incr_key();
      incr_second_key();
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight_bl_aes_serp_aes(hmacchar, p, 100);
      p+=8;
    }
    p = 0;
    while(str_len > p+1){
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
      split_by_eight_bl_aes_serp_aes(char_array, p, str_len);
      p+=8;
    }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();
    keyb_inp = "";
    m_menu_rect();
    curr_key = 0;
    main_menu(cur_pos);
    cont_to_next = true;
    return;
 }
}

void decr_blwfsh_aes_serpent_aes(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the ciphertext", 10);
  disp_centered_text("into the Serial Monitor", 30);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the ciphertext here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
    String ct = Serial.readString();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  count = 0;
  bool ch = false;
  while(ct_len > ext){
  if(count%2 == 1 && count !=0)
    ch = true;
  else{
    ch = false;
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
  }
  split_dec_bl_aes_serp_aes(ct_array, ct_len, 0+ext, ch, true);
  ext+=32;
  count++;
  }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();
  //Serial.println("Plaintext:");
  //Serial.println(dec_st);
  bool plt_integr = verify_integrity();
  tft.setTextSize(2);
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setCursor(0,0);
  tft.println("Plaintext:");
  if (plt_integr == false)
    tft.setTextColor(0xf800, 0x3186);
  tft.setCursor(0,20);
  tft.println(dec_st);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  if (plt_integr == false){
    tft.setTextColor(0xf800, 0x3186);
    tft.setCursor(0,300);
    tft.print("                                                                                                                                                                                                                                                                                                            ");
    tft.setCursor(0,300);
    tft.print("Integrity verification failed!!!");
    tft.setTextColor(0xffff, 0x3186);
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  }
  else{
    tft.setTextColor(0xffff, 0x3186);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  }
  keyb_inp = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
        bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
    return;
 }
}

void AES_Serp_AES_menu() {
  tft.fillScreen(0x1884);
  tft.setTextSize(2);
  tft.setTextColor(0x899a, 0x1884);
  disp_centered_text("AES+Serpent+AES", 30);
  curr_key = 0;
  enc_dec_options(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      enc_dec_options(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 && curr_key == 0) {
          encr_aes_serpent_aes();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 1) {
          encr_aes_serpent_aes_from_Serial();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 2) {
          decr_aes_serpent_aes();
          cont_to_next = true;
        }

        if (ch == 2) // Get back
          cont_to_next = true;
      }

    }
  }
  m_menu_rect();
  curr_key = 0;
  main_menu(cur_pos);
}

void encr_aes_serpent_aes() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter string to encr");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter string to encr");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    /*
    String res_hash;
    for (byte i=0; i < SHA256HMAC_SIZE; i++)
    {
        if (authCode[i]<0x10) { res_hash += 0; }{
          res_hash += String(authCode[i], HEX);
        }
    }
    Serial.print(res_hash);
    */
    char hmacchar[32];
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
    int p = 0;
    for (int i = 0; i < 4; i++){
      incr_key();
      incr_second_key();
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight_for_aes_serp_aes(hmacchar, p, 100);
      p+=8;
    }
    p = 0;
    while(str_len > p+1){
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
      split_by_eight_for_aes_serp_aes(char_array, p, str_len);
      p+=8;
    }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();

      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
  }
}

void encr_aes_serpent_aes_from_Serial(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the string you want", 10);
  disp_centered_text("to encrypt into the", 30);
  disp_centered_text("Serial Monitor", 50);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the string you want to encrypt here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
    keyb_inp = Serial.readString();
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    /*
    String res_hash;
    for (byte i=0; i < SHA256HMAC_SIZE; i++)
    {
        if (authCode[i]<0x10) { res_hash += 0; }{
          res_hash += String(authCode[i], HEX);
        }
    }
    Serial.print(res_hash);
    */
    char hmacchar[32];
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
    int p = 0;
    for (int i = 0; i < 4; i++){
      incr_key();
      incr_second_key();
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight_for_aes_serp_aes(hmacchar, p, 100);
      p+=8;
    }
    p = 0;
    while(str_len > p+1){
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
      split_by_eight_for_aes_serp_aes(char_array, p, str_len);
      p+=8;
    }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();
    keyb_inp = "";
    m_menu_rect();
    curr_key = 0;
    main_menu(cur_pos);
    cont_to_next = true;
    return;
 }
}

void decr_aes_serpent_aes(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the ciphertext", 10);
  disp_centered_text("into the Serial Monitor", 30);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the ciphertext here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
    String ct = Serial.readString();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  count = 0;
  bool ch = false;
  while(ct_len > ext){
  if(count%2 == 1 && count !=0)
    ch = true;
  else{
    ch = false;
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
  }
  split_dec_for_aes_serp_aes(ct_array, ct_len, 0+ext, ch, true);
  ext+=32;
  count++;
  }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();
  //Serial.println("Plaintext:");
  //Serial.println(dec_st);
  bool plt_integr = verify_integrity();
  tft.setTextSize(2);
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setCursor(0,0);
  tft.println("Plaintext:");
  if (plt_integr == false)
    tft.setTextColor(0xf800, 0x3186);
  tft.setCursor(0,20);
  tft.println(dec_st);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  if (plt_integr == false){
    tft.setTextColor(0xf800, 0x3186);
    tft.setCursor(0,300);
    tft.print("                                                                                                                                                                                                                                                                                                            ");
    tft.setCursor(0,300);
    tft.print("Integrity verification failed!!!");
    tft.setTextColor(0xffff, 0x3186);
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  }
  else{
    tft.setTextColor(0xffff, 0x3186);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  }
  keyb_inp = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
        bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
    return;
 }
}

void Blowfish_Serpent_menu() {
  tft.fillScreen(0x1884);
  tft.setTextSize(2);
  tft.setTextColor(0x899a, 0x1884);
  disp_centered_text("Blowfish+Serpent", 30);
  curr_key = 0;
  enc_dec_options(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      enc_dec_options(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 && curr_key == 0) {
          encr_blowfish_serpent();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 1) {
          encr_blowfish_serpent_from_Serial();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 2) {
          decr_blowfish_serpent();
          cont_to_next = true;
        }

        if (ch == 2) // Get back
          cont_to_next = true;
      }

    }
  }
  m_menu_rect();
  curr_key = 0;
  main_menu(cur_pos);
}

void encr_blowfish_serpent() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter string to encr");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter string to encr");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    /*
    String res_hash;
    for (byte i=0; i < SHA256HMAC_SIZE; i++)
    {
        if (authCode[i]<0x10) { res_hash += 0; }{
          res_hash += String(authCode[i], HEX);
        }
    }
    Serial.print(res_hash);
    */
    char hmacchar[32];
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
        int p = 0;
        for (int i = 0; i < 4; i++) {
          incr_Blwfsh_key();
          incr_serp_key();
          split_by_eight_for_bl_and_serp(hmacchar, p, 100);
          p += 8;
        }
        p = 0;
        while (str_len > p + 1) {
          incr_Blwfsh_key();
          incr_serp_key();
          split_by_eight_for_bl_and_serp(char_array, p, str_len);
          p += 8;
        }
        rest_Blwfsh_k();
        rest_serp_k();

      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
  }
}

void encr_blowfish_serpent_from_Serial(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the string you want", 10);
  disp_centered_text("to encrypt into the", 30);
  disp_centered_text("Serial Monitor", 50);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the string you want to encrypt here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
    keyb_inp = Serial.readString();
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    /*
    String res_hash;
    for (byte i=0; i < SHA256HMAC_SIZE; i++)
    {
        if (authCode[i]<0x10) { res_hash += 0; }{
          res_hash += String(authCode[i], HEX);
        }
    }
    Serial.print(res_hash);
    */
    char hmacchar[32];
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
        int p = 0;
        for (int i = 0; i < 4; i++) {
          incr_Blwfsh_key();
          incr_serp_key();
          split_by_eight_for_bl_and_serp(hmacchar, p, 100);
          p += 8;
        }
        p = 0;
        while (str_len > p + 1) {
          incr_Blwfsh_key();
          incr_serp_key();
          split_by_eight_for_bl_and_serp(char_array, p, str_len);
          p += 8;
        }
        rest_Blwfsh_k();
        rest_serp_k();
    keyb_inp = "";
    m_menu_rect();
    curr_key = 0;
    main_menu(cur_pos);
    cont_to_next = true;
    return;
 }
}

void decr_blowfish_serpent(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the ciphertext", 10);
  disp_centered_text("into the Serial Monitor", 30);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the ciphertext here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
    String ct = Serial.readString();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  count = 0;
  bool ch = false;
    while (ct_len > ext) {
      incr_Blwfsh_key();
      incr_serp_key();
      split_for_dec_bl_and_serp(ct_array, ct_len, 0 + ext);
      ext += 32;
    }
    rest_Blwfsh_k();
    rest_serp_k();
  //Serial.println("Plaintext:");
  //Serial.println(dec_st);
  bool plt_integr = verify_integrity();
  tft.setTextSize(2);
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setCursor(0,0);
  tft.println("Plaintext:");
  if (plt_integr == false)
    tft.setTextColor(0xf800, 0x3186);
  tft.setCursor(0,20);
  tft.println(dec_st);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  if (plt_integr == false){
    tft.setTextColor(0xf800, 0x3186);
    tft.setCursor(0,300);
    tft.print("                                                                                                                                                                                                                                                                                                            ");
    tft.setCursor(0,300);
    tft.print("Integrity verification failed!!!");
    tft.setTextColor(0xffff, 0x3186);
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  }
  else{
    tft.setTextColor(0xffff, 0x3186);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  }
  keyb_inp = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
        bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
    return;
 }
}

void AES_Serpent_menu() {
  tft.fillScreen(0x1884);
  tft.setTextSize(2);
  tft.setTextColor(0x899a, 0x1884);
  disp_centered_text("AES+Serpent", 30);
  curr_key = 0;
  enc_dec_options(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      enc_dec_options(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 && curr_key == 0) {
          encr_aes_serpent();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 1) {
          encr_aes_serpent_from_Serial();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 2) {
          decr_aes_serpent();
          cont_to_next = true;
        }

        if (ch == 2) // Get back
          cont_to_next = true;
      }

    }
  }
  m_menu_rect();
  curr_key = 0;
  main_menu(cur_pos);
}

void encr_aes_serpent() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter string to encr");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter string to encr");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    /*
    String res_hash;
    for (byte i=0; i < SHA256HMAC_SIZE; i++)
    {
        if (authCode[i]<0x10) { res_hash += 0; }{
          res_hash += String(authCode[i], HEX);
        }
    }
    Serial.print(res_hash);
    */
    char hmacchar[32];
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
        int p = 0;
        for (int i = 0; i < 4; i++) {
          incr_key();
          incr_serp_key();
          split_by_eight_for_AES_serp(hmacchar, p, 100);
          p += 8;
        }
        p = 0;
        while (str_len > p + 1) {
          incr_key();
          incr_serp_key();
          split_by_eight_for_AES_serp(char_array, p, str_len);
          p += 8;
        }
        rest_k();
        rest_serp_k();

      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
  }
}

void encr_aes_serpent_from_Serial(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the string you want", 10);
  disp_centered_text("to encrypt into the", 30);
  disp_centered_text("Serial Monitor", 50);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the string you want to encrypt here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
    keyb_inp = Serial.readString();
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    /*
    String res_hash;
    for (byte i=0; i < SHA256HMAC_SIZE; i++)
    {
        if (authCode[i]<0x10) { res_hash += 0; }{
          res_hash += String(authCode[i], HEX);
        }
    }
    Serial.print(res_hash);
    */
    char hmacchar[32];
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
        int p = 0;
        for (int i = 0; i < 4; i++) {
          incr_key();
          incr_serp_key();
          split_by_eight_for_AES_serp(hmacchar, p, 100);
          p += 8;
        }
        p = 0;
        while (str_len > p + 1) {
          incr_key();
          incr_serp_key();
          split_by_eight_for_AES_serp(char_array, p, str_len);
          p += 8;
        }
        rest_k();
        rest_serp_k();
        
    keyb_inp = "";
    m_menu_rect();
    curr_key = 0;
    main_menu(cur_pos);
    cont_to_next = true;
    return;
 }
}

void decr_aes_serpent(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the ciphertext", 10);
  disp_centered_text("into the Serial Monitor", 30);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the ciphertext here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
    String ct = Serial.readString();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
    int ext = 0;
    count = 0;
    bool ch = false;
    while (ct_len > ext) {
      if (count % 2 == 1 && count != 0)
        ch = true;
      else {
        ch = false;
        incr_key();
        incr_serp_key();
      }
      split_dec_for_aes_serp(ct_array, ct_len, 0 + ext, ch);
      ext += 32;
      count++;
    }
    rest_k();
    rest_serp_k();
  //Serial.println("Plaintext:");
  //Serial.println(dec_st);
  bool plt_integr = verify_integrity();
  tft.setTextSize(2);
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setCursor(0,0);
  tft.println("Plaintext:");
  if (plt_integr == false)
    tft.setTextColor(0xf800, 0x3186);
  tft.setCursor(0,20);
  tft.println(dec_st);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  if (plt_integr == false){
    tft.setTextColor(0xf800, 0x3186);
    tft.setCursor(0,300);
    tft.print("                                                                                                                                                                                                                                                                                                            ");
    tft.setCursor(0,300);
    tft.print("Integrity verification failed!!!");
    tft.setTextColor(0xffff, 0x3186);
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  }
  else{
    tft.setTextColor(0xffff, 0x3186);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  }
  keyb_inp = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
        bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
    return;
 }
}

void Serpent_menu() {
  tft.fillScreen(0x1884);
  tft.setTextSize(2);
  tft.setTextColor(0x899a, 0x1884);
  disp_centered_text("Serpent", 30);
  curr_key = 0;
  enc_dec_options(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      enc_dec_options(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 && curr_key == 0) {
          encr_serpent();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 1) {
          encr_serpent_from_Serial();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 2) {
          decr_serpent();
          cont_to_next = true;
        }

        if (ch == 2) // Get back
          cont_to_next = true;
      }

    }
  }
  m_menu_rect();
  curr_key = 0;
  main_menu(cur_pos);
}

void encr_serpent() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter string to encr");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter string to encr");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    /*
    String res_hash;
    for (byte i=0; i < SHA256HMAC_SIZE; i++)
    {
        if (authCode[i]<0x10) { res_hash += 0; }{
          res_hash += String(authCode[i], HEX);
        }
    }
    Serial.print(res_hash);
    */
    char hmacchar[32];
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
        int p = 0;
        for (int i = 0; i < 4; i++) {
          incr_serp_key();
          split_by_eight_for_serp_only(hmacchar, p, 100);
          p += 8;
        }
        p = 0;
        while (str_len > p + 1) {
          incr_serp_key();
          split_by_eight_for_serp_only(char_array, p, str_len);
          p += 8;
        }
        rest_serp_k();

      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
  }
}

void encr_serpent_from_Serial(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the string you want", 10);
  disp_centered_text("to encrypt into the", 30);
  disp_centered_text("Serial Monitor", 50);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the string you want to encrypt here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
    keyb_inp = Serial.readString();
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    /*
    String res_hash;
    for (byte i=0; i < SHA256HMAC_SIZE; i++)
    {
        if (authCode[i]<0x10) { res_hash += 0; }{
          res_hash += String(authCode[i], HEX);
        }
    }
    Serial.print(res_hash);
    */
    char hmacchar[32];
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
        int p = 0;
        for (int i = 0; i < 4; i++) {
          incr_serp_key();
          split_by_eight_for_serp_only(hmacchar, p, 100);
          p += 8;
        }
        p = 0;
        while (str_len > p + 1) {
          incr_serp_key();
          split_by_eight_for_serp_only(char_array, p, str_len);
          p += 8;
        }
        rest_serp_k();
        
    keyb_inp = "";
    m_menu_rect();
    curr_key = 0;
    main_menu(cur_pos);
    cont_to_next = true;
    return;
 }
}

void decr_serpent(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the ciphertext", 10);
  disp_centered_text("into the Serial Monitor", 30);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the ciphertext here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
    String ct = Serial.readString();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
    int ext = 0;
    count = 0;
    bool ch = false;
    while (ct_len > ext) {
      incr_serp_key();
      split_for_dec_serp_only(ct_array, ct_len, 0 + ext);
      ext += 32;
    }
    rest_serp_k();
  //Serial.println("Plaintext:");
  //Serial.println(dec_st);
  bool plt_integr = verify_integrity();
  tft.setTextSize(2);
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setCursor(0,0);
  tft.println("Plaintext:");
  if (plt_integr == false)
    tft.setTextColor(0xf800, 0x3186);
  tft.setCursor(0,20);
  tft.println(dec_st);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  if (plt_integr == false){
    tft.setTextColor(0xf800, 0x3186);
    tft.setCursor(0,300);
    tft.print("                                                                                                                                                                                                                                                                                                            ");
    tft.setCursor(0,300);
    tft.print("Integrity verification failed!!!");
    tft.setTextColor(0xffff, 0x3186);
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  }
  else{
    tft.setTextColor(0xffff, 0x3186);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  }
  keyb_inp = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
        bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
    return;
 }
}

void TDES_menu() {
  tft.fillScreen(0x1884);
  tft.setTextSize(2);
  tft.setTextColor(0x899a, 0x1884);
  disp_centered_text("Triple DES", 30);
  curr_key = 0;
  enc_dec_options(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      enc_dec_options(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 && curr_key == 0) {
          encr_tdes();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 1) {
          encr_tdes_from_Serial();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 2) {
          decr_tdes();
          cont_to_next = true;
        }

        if (ch == 2) // Get back
          cont_to_next = true;
      }

    }
  }
  m_menu_rect();
  curr_key = 0;
  main_menu(cur_pos);
}

void encr_tdes() {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0, 29);
  tft.println("Enter string to encr");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x12ea);
          tft.setCursor(0, 29);
          tft.println("Enter string to encr");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    /*
    String res_hash;
    for (byte i=0; i < SHA256HMAC_SIZE; i++)
    {
        if (authCode[i]<0x10) { res_hash += 0; }{
          res_hash += String(authCode[i], HEX);
        }
    }
    Serial.print(res_hash);
    */
    char hmacchar[32];
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
        int p = 0;
        for (int i = 0; i < 8; i++) {
          split_by_four_for_encr_tdes(hmacchar, p, 100);
          incr_TDESkey();
          p += 4;
        }
        p = 0;
        while (str_len > p + 1) {
          split_by_four_for_encr_tdes(char_array, p, str_len);
          incr_TDESkey();
          p += 4;
        }
     Serial.println();
     rest_TDESkey();

      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
  }
}

void encr_tdes_from_Serial(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the string you want", 10);
  disp_centered_text("to encrypt into the", 30);
  disp_centered_text("Serial Monitor", 50);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the string you want to encrypt here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
    keyb_inp = Serial.readString();
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    /*
    String res_hash;
    for (byte i=0; i < SHA256HMAC_SIZE; i++)
    {
        if (authCode[i]<0x10) { res_hash += 0; }{
          res_hash += String(authCode[i], HEX);
        }
    }
    Serial.print(res_hash);
    */
    char hmacchar[32];
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
        int p = 0;
        for (int i = 0; i < 8; i++) {
          split_by_four_for_encr_tdes(hmacchar, p, 100);
          incr_TDESkey();
          p += 4;
        }
        p = 0;
        while (str_len > p + 1) {
          split_by_four_for_encr_tdes(char_array, p, str_len);
          incr_TDESkey();
          p += 4;
        }
     Serial.println();
     rest_TDESkey();
        
    keyb_inp = "";
    m_menu_rect();
    curr_key = 0;
    main_menu(cur_pos);
    cont_to_next = true;
    return;
 }
}

void decr_tdes(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the ciphertext", 10);
  disp_centered_text("into the Serial Monitor", 30);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the ciphertext here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
     String ct = Serial.readString();
     int ct_len = ct.length() + 1;
     char ct_array[ct_len];
     ct.toCharArray(ct_array, ct_len);
     int ext = 0;
     while( ct_len > ext){
       decr_eight_chars_block_tdes(ct_array, ct_len, 0+ext);
       ext+=16;
       incr_TDESkey();
     }
     Serial.println();
     rest_TDESkey();
  //Serial.println("Plaintext:");
  //Serial.println(dec_st);
  bool plt_integr = verify_integrity();
  tft.setTextSize(2);
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setCursor(0,0);
  tft.println("Plaintext:");
  if (plt_integr == false)
    tft.setTextColor(0xf800, 0x3186);
  tft.setCursor(0,20);
  tft.println(dec_st);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  if (plt_integr == false){
    tft.setTextColor(0xf800, 0x3186);
    tft.setCursor(0,300);
    tft.print("                                                                                                                                                                                                                                                                                                            ");
    tft.setCursor(0,300);
    tft.print("Integrity verification failed!!!");
    tft.setTextColor(0xffff, 0x3186);
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  }
  else{
    tft.setTextColor(0xffff, 0x3186);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  }
  keyb_inp = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
        bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
    return;
 }
}

// Thingspeak (Below)

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

void show_online_notes_menu() {
  tft.fillScreen(0x1884);
  tft.setTextSize(2);
  tft.setTextColor(0x899a, 0x1884);
  disp_centered_text("Online-stored Notes", 30);
  curr_key = 0;
  onl_st_nts(curr_key);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    enc0.tick();
    if (enc0.left())
      curr_key--;
    if (enc0.right())
      curr_key++;

    if (curr_key < 0)
      curr_key = 2;

    if (curr_key > 2)
      curr_key = 0;

    if (enc0.turn()) {
      onl_st_nts(curr_key);
    }
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 && curr_key == 0) {
          get_title_for_online_notes();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 1) {
          decr_onl_st_note_from_thingspeak();
          cont_to_next = true;
        }
        if (ch == 1 && curr_key == 2) {
          decr_onl_st_note_from_serial();
          cont_to_next = true;
        }

        if (ch == 2) // Get back
          cont_to_next = true;
      }

    }
  }
  m_menu_rect();
  curr_key = 0;
  main_menu(cur_pos);
}

void get_title_for_online_notes() {
  keyb_inp = "";
  bool cont_to_content = false;
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x08c5);
  tft.setCursor(0, 29);
  tft.println("Enter the title:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x08c5);
          tft.setCursor(0, 29);
          tft.println("Enter the title:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      cont_to_content = true;
      cont_to_next = true;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
  if (cont_to_content == true){
    m_menu_rect();
    get_content_for_online_notes(keyb_inp);
  }
}

void get_content_for_online_notes(String ttl_to_be_st_onl) {
  keyb_inp = "";
  tft.fillScreen(0x2145);
  disp_inp_panel_1();
  curr_key = 65;
  bool cont_to_send = false;
  tft.setCursor(90, 5);
  tft.print("A");
  tft.setCursor(198, 5);
  tft.printf("%02x", 65);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x08c5);
  tft.setCursor(0, 29);
  tft.println("Enter the content:");
  disp_length_at_the_bottom(0);
  bool cont_to_next = false;
  while (cont_to_next == false) {
    bool smt_done = false;
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
      disp_input_from_enc_1();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }

    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1) {
          keyb_inp += char(curr_key);
          //Serial.println(keyb_inp);
          smt_done = true;
        }

        if (ch == 2) {
          if (keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() - 1, 1);
          tft.fillRect(0, 48, 320, 240, 0x2145);
          disp_inp_panel_1();
          disp_input_from_enc_1();
          tft.setTextColor(0xe73c, 0x2145);
          tft.setTextSize(2);
          tft.fillRect(312, 0, 320, 240, 0x08c5);
          tft.setCursor(0, 29);
          tft.println("Enter the content:");
          smt_done = true;
        }
      }
    }
    if (smt_done == true) {
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xe73c, 0x2145);
      tft.setCursor(0, 49);
      tft.println(keyb_inp);
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      cont_to_send = true;
      cont_to_next = true;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      m_menu_rect();
      cont_to_next = true;
      return;
    }
  }
  if (cont_to_send == true){
    /*
    Serial.print("\nTitle: ");
    Serial.println(ttl_to_be_st_onl);
    Serial.print("Content: ");
    Serial.println(keyb_inp);
    */
    encr_and_send(ttl_to_be_st_onl);
    keyb_inp = "";
    m_menu_rect();
  }
}

String encr_for_onl_st;

void encr_and_send(String ttl_to_be_st_onl) {
  String ttltsnd;
  String cnttsnd;
  for (int i = 0; i < ttl_to_be_st_onl.length(); i++) {
    if (i < 16)
      ttltsnd += ttl_to_be_st_onl[i];
  }
  for (int i = 0; i < keyb_inp.length(); i++) {
    if (i < 32)
      cnttsnd += keyb_inp[i];
  }
  keyb_inp = "";

  int str_len0 = ttltsnd.length() + 1;
  char char_array0[str_len0];
  ttltsnd.toCharArray(char_array0, str_len0);
  int p = 0;
  while (str_len0 > p + 1) {
    incr_Blwfsh_key();
    incr_serp_key();
    split_by_eight_for_bl_and_serp_for_onl_n(char_array0, p, str_len0);
    p += 8;
  }
  rest_Blwfsh_k();
  rest_serp_k();
  /*
  Serial.println("\nTitle");
  Serial.println(encr_for_onl_st);
  */
  String encr_t = encr_for_onl_st;
  encr_for_onl_st ="";
  
  String tbehashed = ttltsnd + cnttsnd;
  int str_len = tbehashed.length() + 1;
  char char_array[str_len];
  tbehashed.toCharArray(char_array, str_len);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_array);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  /*
  String res_hash;
  for (byte i=0; i < SHA256HMAC_SIZE; i++)
  {
      if (authCode[i]<0x10) { res_hash += 0; }{
        res_hash += String(authCode[i], HEX);
      }
  }
  Serial.print(res_hash);
  */
  char hmacchar[32];
  for (int i = 0; i < 32; i++) {
    hmacchar[i] = char(authCode[i]);
  }
  p = 0;
  for (int i = 0; i < 2; i++) {
    incr_Blwfsh_key();
    incr_serp_key();
    split_by_eight_for_bl_and_serp_for_onl_n(hmacchar, p, 100);
    p += 8;
  }
  int str_len1 = cnttsnd.length() + 1;
  char char_array1[str_len1];
  cnttsnd.toCharArray(char_array1, str_len1);
  p = 0;
  while (str_len1 > p + 1) {
    incr_Blwfsh_key();
    incr_serp_key();
    split_by_eight_for_bl_and_serp_for_onl_n(char_array1, p, str_len1);
    p += 8;
  }
  rest_Blwfsh_k();
  rest_serp_k();
  /*
  Serial.println("\nContent");
  Serial.println(encr_for_onl_st);
  */
  bool upd_ch = true;
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,310);
  tft.println("Hold the encoder button to cancel.");
  tft.setCursor(0,5);
  tft.println("Attempting to connect to the network");
  tft.setCursor(0,15);
  tft.println("If it takes too long to connect,");
  tft.setCursor(0,25);
  tft.println("hold the encoder button and try again.");
  if(WiFi.status() != WL_CONNECTED){
    while(WiFi.status() != WL_CONNECTED){
      encoder_button.tick();
      if (encoder_button.isPress() || encoder_button.isHolded() || encoder_button.isHold()){
        upd_ch = false;
        break;
      }
      delay(10);
      WiFi.begin(ssid, password);
      tft.print(".");
      delay(2000);
    }
  }
  if (upd_ch == true){
    tft.fillScreen(0x3186);
    tft.setCursor(0,5);
    tft.println("Connected to the network!");
    tft.println("Updating the channel...");
    
    ThingSpeak.setField(1, encr_t);
    ThingSpeak.setField(2, encr_for_onl_st);
    
    int x = ThingSpeak.writeFields(myChannelNumber, myWriteAPIKey);

    if(x == 200){
      tft.println("Channel updated successfully");
    }
    else{
      tft.setTextColor(0xf800, 0x3186);
      tft.print("Something went wrong.\nError code ");
      tft.println(String(x));
    }
    tft.setTextColor(0xe73c, 0x3186);
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
    
    bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
    return;
    }
    else
      return;
}

void decr_onl_st_note_from_thingspeak(){
 bool cont_to_next = false;
 while (cont_to_next == false){
    bool upd_ch = true;
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,310);
  tft.println("Hold the encoder button to cancel.");
  tft.setCursor(0,5);
  tft.println("Attempting to connect to the network");
  tft.setCursor(0,15);
  tft.println("If it takes too long to connect,");
  tft.setCursor(0,25);
  tft.println("hold the encoder button and try again.");
  if(WiFi.status() != WL_CONNECTED){
    while(WiFi.status() != WL_CONNECTED){
      encoder_button.tick();
      if (encoder_button.isPress() || encoder_button.isHolded() || encoder_button.isHold()){
        upd_ch = false;
        break;
      }
      delay(10);
      WiFi.begin(ssid, password);
      tft.print(".");
      delay(2000);
    }
  }
  if (upd_ch == true){
    tft.fillScreen(0x3186);
    tft.setCursor(0,5);
    tft.println("Connected to the network!");
    tft.setCursor(0,15);
    tft.println("Reading the channel...");
    tft.setCursor(0,25);
    tft.println("It might take a while.");
  String ct1 = ThingSpeak.readStringField(myChannelNumber, 1, myReadAPIKey);
  delay(10);
  String ct2 = ThingSpeak.readStringField(myChannelNumber, 2, myReadAPIKey);
  int x = ThingSpeak.getLastReadStatus();
  int ct_len1 = ct1.length() + 1;
  char ct_array1[ct_len1];
  ct1.toCharArray(ct_array1, ct_len1);
  int ct_len2 = ct2.length() + 1;
  char ct_array2[ct_len2];
  ct2.toCharArray(ct_array2, ct_len2);
  /*
  Serial.print("Title: ");
  Serial.println(ct1);
  Serial.print("Content: ");
  Serial.println(ct2);
  */
  dec_st = "";
  dec_tag = "";
  decract = 10;
  int ext = 0;
  while (ct_len1 > ext) {
    incr_Blwfsh_key();
    incr_serp_key();
    split_for_dec_bl_and_serp_for_onl_n(ct_array1, ct_len1, 0 + ext);
    ext += 32;
  }
  rest_Blwfsh_k();
  rest_serp_k();
  String dec_title = dec_st;
  dec_st = "";
  dec_tag = "";
  decract = 0;
  ext = 0;
  while (ct_len2 > ext) {
    incr_Blwfsh_key();
    incr_serp_key();
    split_for_dec_bl_and_serp_for_onl_n(ct_array2, ct_len2, 0 + ext);
    ext += 32;
  }
  rest_Blwfsh_k();
  rest_serp_k();
  /*
  Serial.print("Decrypted title: ");
  Serial.println(dec_title);
  Serial.print("Decrypted content: ");
  Serial.println(dec_st);
  */
  /*
  Serial.print("Decrypted tag: ");
  Serial.println(dec_tag);
  */
  String ttltsnd;
  String cnttsnd;
  for (int i = 0; i < dec_title.length(); i++) {
    if (i < 16 && dec_title[i] != 0)
      ttltsnd += dec_title[i];
  }
  for (int i = 0; i < dec_st.length(); i++) {
    if (i < 32 && dec_st[i] != 0)
      cnttsnd += dec_st[i];
  }
  /*
  for (int i = 0; i < ttltsnd.length(); i++) {
    if (i < 16)
      Serial.println(int(ttltsnd[i]));
  }
  for (int i = 0; i < cnttsnd.length(); i++) {
    if (i < 32)
      Serial.println(int(cnttsnd[i]));
  }
  */
  String tbehashed = ttltsnd + cnttsnd;
  int str_len = tbehashed.length() + 1;
  char char_array[str_len];
  tbehashed.toCharArray(char_array, str_len);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_array);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  
  String res_hash;
  for (byte i=0; i < 16; i++)
  {
      if (authCode[i]<0x10) { res_hash += 0; }{
        res_hash += String(authCode[i], HEX);
      }
  }
  /*
  Serial.print("Computed tag: ");
  Serial.println(res_hash);
  */
  tft.fillScreen(0x3186);
  tft.setTextSize(2);
  tft.setTextColor(0xffff, 0x3186);
  if (dec_tag.equals(res_hash) == false)
    tft.setTextColor(0xf800, 0x3186);
  tft.setCursor(0,0);
  tft.println("Title:");
  tft.setCursor(0,20);
  tft.println(dec_title);
  tft.setCursor(0,40);
  tft.println("Content:");
  tft.setCursor(0,60);
  tft.println(dec_st);
  tft.setTextSize(1);
  tft.setCursor(0,250);
  if(x == 200){
      tft.println("Channel read successfully");
    }
    else{
      tft.setTextColor(0xf800, 0x3186);
      tft.print("Something went wrong.\nError code ");
      tft.println(String(x));
    }
  if (dec_tag.equals(res_hash) == false){
    tft.setCursor(0,295);
    tft.println("Integrity verification failed!!!");
  }
  tft.setTextColor(0xe73c, 0x3186);
  tft.setCursor(0,310);
  tft.print("Press any key to return to the main menu");
  dec_st = "";
  dec_tag = "";
  decract = 0;
  bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
  return;
  
  }
  else
    return;
 }
}

void decr_onl_st_note_from_serial(){
 bool cont_to_next = false;
 while (cont_to_next == false){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the encrypted title", 10);
  disp_centered_text("into the Serial Monitor", 30);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the encrypted title here:");
  bool canc_op = false;
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
  String ct1 = Serial.readString();
  int ct_len1 = ct1.length() + 1;
  char ct_array1[ct_len1];
  ct1.toCharArray(ct_array1, ct_len1);

  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  disp_centered_text("Paste the encrypted content", 10);
  disp_centered_text("into the Serial Monitor", 30);
  tft.setCursor(0,310);
  tft.print("Press any button to cancel.");
  Serial.println("\nPaste the encrypted content here:");
  while (!Serial.available()) {
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      if (data.d == true) {
        ch = data.x;
        if (ch == 1 || ch == 2) {
          cont_to_next = true;
        }
      }
    }
    delay(1);
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delay(1);
    if (cont_to_next == true){
      canc_op = true;
      break;
    }
  }
  if (canc_op == true)
    break;
  String ct2 = Serial.readString();
  int ct_len2 = ct2.length() + 1;
  char ct_array2[ct_len2];
  ct2.toCharArray(ct_array2, ct_len2);
  /*
  Serial.print("Title: ");
  Serial.println(ct1);
  Serial.print("Content: ");
  Serial.println(ct2);
  */
  dec_st = "";
  dec_tag = "";
  decract = 10;
  int ext = 0;
  while (ct_len1 > ext) {
    incr_Blwfsh_key();
    incr_serp_key();
    split_for_dec_bl_and_serp_for_onl_n(ct_array1, ct_len1, 0 + ext);
    ext += 32;
  }
  rest_Blwfsh_k();
  rest_serp_k();
  String dec_title = dec_st;
  dec_st = "";
  dec_tag = "";
  decract = 0;
  ext = 0;
  while (ct_len2 > ext) {
    incr_Blwfsh_key();
    incr_serp_key();
    split_for_dec_bl_and_serp_for_onl_n(ct_array2, ct_len2, 0 + ext);
    ext += 32;
  }
  rest_Blwfsh_k();
  rest_serp_k();
  /*
  Serial.print("Decrypted title: ");
  Serial.println(dec_title);
  Serial.print("Decrypted content: ");
  Serial.println(dec_st);
  */
  /*
  Serial.print("Decrypted tag: ");
  Serial.println(dec_tag);
  */
  String ttltsnd;
  String cnttsnd;
  for (int i = 0; i < dec_title.length(); i++) {
    if (i < 16 && dec_title[i] != 0)
      ttltsnd += dec_title[i];
  }
  for (int i = 0; i < dec_st.length(); i++) {
    if (i < 32 && dec_st[i] != 0)
      cnttsnd += dec_st[i];
  }
  /*
  for (int i = 0; i < ttltsnd.length(); i++) {
    if (i < 16)
      Serial.println(int(ttltsnd[i]));
  }
  for (int i = 0; i < cnttsnd.length(); i++) {
    if (i < 32)
      Serial.println(int(cnttsnd[i]));
  }
  */
  String tbehashed = ttltsnd + cnttsnd;
  int str_len = tbehashed.length() + 1;
  char char_array[str_len];
  tbehashed.toCharArray(char_array, str_len);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_array);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  
  String res_hash;
  for (byte i=0; i < 16; i++)
  {
      if (authCode[i]<0x10) { res_hash += 0; }{
        res_hash += String(authCode[i], HEX);
      }
  }
  /*
  Serial.print("Computed tag: ");
  Serial.println(res_hash);
  */
  tft.fillScreen(0x3186);
  tft.setTextSize(2);
  tft.setTextColor(0xffff, 0x3186);
  if (dec_tag.equals(res_hash) == false)
    tft.setTextColor(0xf800, 0x3186);
  tft.setCursor(0,0);
  tft.println("Title:");
  tft.setCursor(0,20);
  tft.println(dec_title);
  tft.setCursor(0,40);
  tft.println("Content:");
  tft.setCursor(0,60);
  tft.println(dec_st);
  tft.setTextSize(1);
  if (dec_tag.equals(res_hash) == false){
    tft.setCursor(0,295);
    tft.println("Integrity verification failed!!!");
  }
  tft.setTextColor(0xe73c, 0x3186);
  tft.setCursor(0,310);
  tft.print("Press any key to return to the main menu");
  dec_st = "";
  dec_tag = "";
  decract = 0;
  bool cont_to_next = false;
      while (cont_to_next == false) {
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          if (data.d == true) {
            ch = data.x;
            if (ch == 1 || ch == 2) {
              cont_to_next = true;
            }
          }
        }
        delay(1);
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delay(1);
      }
  return;
  
 }
}

void split_by_eight_for_bl_and_serp_for_onl_n(char plntxt[], int k, int str_len) {
  char plt_data[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    plt_data[i] = plntxt[i + k];
  }
  /*
  Serial.println("\nInput");
  for (int i = 0; i < 8; i++){
    Serial.print(plt_data[i]);
    Serial.print(" ");
  }
  */
  unsigned char t_encr[8];
  for (int i = 0; i < 8; i++) {
    t_encr[i] = (unsigned char) plt_data[i];
  }
  /*
  Serial.println("\nChar");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(t_encr, t_encr, sizeof(t_encr));
  char encr_for_serp[16];
  for (int i = 0; i < 8; i++) {
    encr_for_serp[i] = char(int(t_encr[i]));
  }
  /*
  Serial.println("\nEncrypted");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  for (int i = 8; i < 16; i++) {
    encr_for_serp[i] = gen_r_num();
  }

  int tmp_s[16];
  for (int i = 0; i < 16; i++) {
    tmp_s[i] = encr_for_serp[i];
  }

  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for (int i = 0; i < 16; i++) {
      ct2.b[i] = tmp_s[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    for (int i = 0; i < 16; i++) {
        if (ct2.b[i] < 16)
          encr_for_onl_st += "0";
        encr_for_onl_st +=  String(ct2.b[i], HEX);
    }
  }
}

void split_for_dec_bl_and_serp_for_onl_n(char ct[], int ct_len, int p) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }
  if (br == false) {
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);
      //Serial.printf ("\nkey=");

      for (j = 0; j < sizeof(skey) / sizeof(serpent_subkey_t) * 4; j++) {
        if ((j % 8) == 0) putchar('\n');
        //Serial.printf ("%08X ", p[j]);
      }

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);

    unsigned char dbl[8];
    for (int i = 0; i < 8; i++) {
      dbl[i] = (unsigned char) int(ct2.b[i]);
    }
    /*
    Serial.println("\nConv for blowfish");
    for (int i = 0; i < 8; i++){\
      Serial.print(dbl[i]);
      Serial.print(" ");
    }
    Serial.println();
    */
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(dbl, dbl, sizeof(dbl));
    /*
    Serial.println("\nDecr by blowfish");
    for (int i = 0; i < 8; i++){\
      Serial.print(int(dbl[i]));
      Serial.print(" ");
    }
    Serial.println();
    */
    if (decract < 2) {
      for (i = 0; i < 8; i++) {
        if (dbl[i] < 0x10)
          dec_tag += 0;
        dec_tag += String(dbl[i], HEX);
      }
    } else {
      for (i = 0; i < 8; ++i) {
        dec_st += (char(dbl[i]));
      }
    }
    decract++;
  }
}

// Thingspeak (Above)

void setup() {
  Serial.begin(115200);
  mySerial.begin(9600);
  m = 2; // Set AES to 256 bit
  cur_pos = 0;
  tft.begin();
  tft.setRotation(0);
  if (SPIFFS.begin(true)) {} else {
    Serial.println("An Error has occurred while mounting SPIFFS");
    return;
  }
  // list SPIFFS contents
  File root = SPIFFS.open("/");
  if (!root) {
    Serial.println("- failed to open directory");
    return;
  }
  if (!root.isDirectory()) {
    Serial.println(" - not a directory");
    return;
  }
  /*
  File file = root.openNextFile();
  while (file) {
      if (file.isDirectory()) {
          Serial.print("  DIR : ");
          Serial.println(file.name());
      } else {
          Serial.print("  FILE: ");
          Serial.print(file.name());
          Serial.print("\tSIZE: ");
          Serial.println(file.size());
      }
      file = root.openNextFile();
  }
  */
  sqlite3_initialize();
  WiFi.mode(WIFI_STA);
  ThingSpeak.begin(client);

  appr_cards_and_log_in();
}

void loop() {
  back_keys();
  delay(1);
  enc0.tick();
  if (enc0.left())
    curr_key--;
  if (enc0.right())
    curr_key++;

  if (curr_key < 0)
    curr_key = 13;

  if (curr_key > 13)
    curr_key = 0;

  if (enc0.turn()) {
    main_menu(curr_key);
  }

  bus.tick();
  if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    if (data.d == true) {
      ch = data.x;
      if (ch == 1 && curr_key == 0)
        show_loc_st_login_menu();

      if (ch == 1 && curr_key == 1)
        show_loc_st_credit_cards();

      if (ch == 1 && curr_key == 2)
        show_loc_st_notes();

      if (ch == 1 && curr_key == 3)
        Blfish_AES_Serp_AES_menu();

      if (ch == 1 && curr_key == 4)
        AES_Serp_AES_menu();

      if (ch == 1 && curr_key == 5)
        Blowfish_Serpent_menu();

      if (ch == 1 && curr_key == 6)
        AES_Serpent_menu();

      if (ch == 1 && curr_key == 7)
        Serpent_menu();

      if (ch == 1 && curr_key == 8)
        TDES_menu();
        
      if (ch == 1 && curr_key == 9)
        show_HMAC_sha256_menu();
      
      if (ch == 1 && curr_key == 10)
        hash_using_sha512();

      if (ch == 1 && curr_key == 11)
        hash_string_with_sha256();

      if (ch == 1 && curr_key == 12)
        show_SQL_menu();

     if (ch == 1 && curr_key == 13)
        show_online_notes_menu();
    }
  }
  delay(1);
}
