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
#include "Crypto.h"
#include "DES.h"
#include <EncButton2.h>
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_PCD8544.h>
#include "cboxicon.h"

Adafruit_PCD8544 nokia5110lcd = Adafruit_PCD8544(18, 23, 4, 15, 2);
int contrastValue = 60; // Contrast 

EncButton2 <EB_ENC> enc0(INPUT, 26, 27);
EncButton2 <EB_BTN> encoder_button(INPUT, 33);
EncButton2 <EB_BTN> a_button(INPUT, 14);
EncButton2 <EB_BTN> b_button(INPUT, 25);

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
int clb_m;

const char* ssid = "My Wireless Network";   // Your network SSID (name) 
const char* password = "dTre7bd90mrs";   // Your network password
unsigned long myChannelNumber = 1234567; // Channel ID
const char * myWriteAPIKey = "A1B2C3D4E5F6G7H8"; // Write API Key
const char * myReadAPIKey = "K9L8M7N6O5P4Q3R2"; // Read API Key

WiFiClient  client;

// Keys (Below)

String kderalgs = "tFAE7t2S09Wy9g464tzEUhOpYNBhEy";
int numofkincr = 6129;
byte hmackey[] = {"wKtBPS6245ZJFf66bsf844jy2Cfn5IhAb5R2w5sHSbYmV8k8Saia0W6vs4WMjeg4DM55g96Tm3kRLelBo1CwfMh92qizK9tVpWp9I2YOYDE38j9UU1yeT8ctvE6MLTTU5iF0BtPjFER6PbWcltXbEz0Isl0bub0i0o7qqaz1wyf7RQ3CcSp42sn2u85Cc9ZoCHXkwD8j44ns11bhKzzS69pwoRtSon3Z23U10Rs2LAa5TXYuOwf1QC"};
unsigned char Blwfsh_key[] = {
0xc7,0x5e,0x0b,0xa7,
0xd8,0xa9,0x1a,0xe2,
0xc6,0xe1,0xb4,0xe2,
0x58,0xa0,0xaa,0x3e,
0xf9,0x01,0x5f,0x43,
0xdd,0x3f,0xc5,0x85
};
uint8_t key[32] = {
0xdd,0xcf,0xdb,0xc1,
0xff,0x51,0x63,0x50,
0xf0,0x8e,0x85,0x56,
0xf2,0x37,0xc3,0xeb,
0xa7,0x2a,0x0b,0x04,
0x9f,0x59,0x9b,0xa1,
0x8a,0xe8,0x76,0xea,
0x5f,0xec,0xec,0xd2
};
uint8_t serp_key[32] = {
0x69,0xad,0xb6,0xf4,
0x04,0x88,0xf9,0xa6,
0x63,0xb0,0xdb,0x9b,
0x9c,0x1c,0xf7,0x0d,
0xbf,0xa7,0xd5,0x06,
0x6c,0xf8,0x10,0xca,
0x6c,0x9e,0xfb,0x0b,
0xce,0xe1,0xac,0xdc
};
uint8_t second_key[32] = {
0xdd,0xd4,0xba,0xa3,
0x02,0x3d,0xa8,0x70,
0xdc,0x6b,0xee,0x8a,
0xbb,0xd4,0xa6,0xee,
0xc2,0x52,0xc3,0x8a,
0xe9,0xad,0xdf,0xcf,
0xec,0x9d,0xe0,0xed,
0x4b,0x3b,0xc1,0x6a
};
byte TDESkey[] = {
0xb5,0x5a,0x63,0x0a,0x2c,0x35,0x3c,0xea,
0x74,0xe4,0xa1,0x46,0x05,0xe8,0xc3,0xb9,
0xb4,0xd3,0x6a,0x1f,0xc2,0xe0,0x3e,0xd0
};

// Keys (Above)

DES des;

byte TDESkey_backup[16];

void display_cipherbox_icon() {
  nokia5110lcd.clearDisplay();
  for (int i = 0; i < 84; i++) {
    for (int j = 0; j < 10; j++) {
      if (cbicon[i][j] == false)
        nokia5110lcd.drawPixel(i, j, BLACK);
    }
  }
  for (int i = 0; i < 3; i++) {
    nokia5110lcd.drawPixel(13, 10 + i, BLACK);
    nokia5110lcd.drawPixel(14, 10 + i, BLACK);
  }
  nokia5110lcd.display();
}

void back_TDESkey() {
  for (int i = 0; i < 16; i++) {
    TDESkey_backup[i] = TDESkey[i];
  }
}

void rest_TDESkey() {
  for (int i = 0; i < 16; i++) {
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

const char * data = "Callback function called";
static int callback(void * data, int argc, char ** argv, char ** azColName) {
  int i;
  if (clb_m == 0) //Print in serial
    Serial.printf("%s: ", (const char * ) data);
  if (clb_m == 1) { //Print on display
    nokia5110lcd.printf("%s:\n", (const char * ) data);
  }
  for (i = 0; i < argc; i++) {
    if (clb_m == 0) { //Print in serial
      Serial.printf("\n%s = %s", azColName[i], argv[i] ? argv[i] : "Empty");
      Serial.printf("\n\n");
    }
    if (clb_m == 1) { //Print in tft
      nokia5110lcd.printf("\n%s = %s\n", azColName[i], argv[i] ? argv[i] : "Empty");
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
      nokia5110lcd.printf("Can't open db: %s\n", sqlite3_errmsg( * db));
    return rc;
  } else {
    if (clb_m == 0) //Print in serial
      Serial.printf("Opened database successfully\n");
    if (clb_m == 1) //Print in tft
      nokia5110lcd.printf("Opd db success");
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
      nokia5110lcd.printf("SQL error: %s\n", zErrMsg);
    sqlite3_free(zErrMsg);
  } else {
    if (clb_m == 0) //Print in serial
      Serial.printf("Operation done successfully\n");
    if (clb_m == 1) //Print in serial
      nokia5110lcd.printf("Op don success");
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

void modify_keys() {
  keyb_inp += kderalgs;
  int str_len = keyb_inp.length() + 1;
  char input_arr[str_len];
  keyb_inp.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
  }
  //Serial.println(h);
  int h_len = h.length() + 1;
  char h_array[h_len];
  h.toCharArray(h_array, h_len);
  byte res[64];
  for (int i = 0; i < 128; i += 2) {
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
  for (int i = 0; i < 13; i++) {
    hmackey[i] = res[i];
  }
  TDESkey[9] = res[13];
  for (int i = 0; i < 9; i++) {
    Blwfsh_key[i] = (unsigned char) res[i + 14];
  }
  for (int i = 0; i < 3; i++) {
    TDESkey[i] = (unsigned char) res[i + 23];
  }
  for (int i = 0; i < 10; i++) {
    hmackey[i] = int(res[i + 26]);
  }
  for (int i = 0; i < 10; i++) {
    key[i] = int(res[i + 36]);
  }
  for (int i = 0; i < 9; i++) {
    serp_key[i] = int(res[i + 46]);
  }
  for (int i = 0; i < 8; i++) {
    second_key[i] = int(res[i + 55]);
  }
  int vn = ((res[62] + 1) * (res[62] + 3)) % 9987;
  keyb_inp = "";
  nokia5110lcd.clearDisplay();
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.setCursor(6, 0);
  nokia5110lcd.print("Keys derived");
  nokia5110lcd.setCursor(6, 9);
  nokia5110lcd.println("successfully");
  nokia5110lcd.setCursor(6, 23);
  nokia5110lcd.println("Verification");
  nokia5110lcd.setCursor(24, 32);
  nokia5110lcd.println("number");

  if (vn > 999) {
    nokia5110lcd.setCursor(30, 41);
    nokia5110lcd.println(vn);
  }
  if (vn > 99 && vn < 1000) {
    nokia5110lcd.setCursor(33, 41);
    nokia5110lcd.println(vn);
  }
  if (vn > 9 && vn < 100) {
    nokia5110lcd.setCursor(36, 41);
    nokia5110lcd.println(vn);
  }
  if (vn < 10) {
    nokia5110lcd.setCursor(39, 41);
    nokia5110lcd.println(vn);
  }
  nokia5110lcd.display();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    encoder_button.tick();
    if (encoder_button.press())
      cont_to_next = true;
    delayMicroseconds(400);
    a_button.tick();
    if (a_button.press())
      cont_to_next = true;
    delayMicroseconds(400);
    b_button.tick();
    if (b_button.press())
      cont_to_next = true;
    delayMicroseconds(400);
  }
  create_logins_table();
  create_credit_cards_table();
  create_notes_table();
  main_menu(cur_pos);
  //Serial.println(dbase_name);
}

void disp_inp_panel() {
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.drawLine(0, 0, 83, 0, BLACK);
  nokia5110lcd.setCursor(0, 1);
  nokia5110lcd.println("              ");
  nokia5110lcd.setCursor(2, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("Char' '");
  nokia5110lcd.setCursor(47, 1);
  nokia5110lcd.println("Hex:");
  nokia5110lcd.display();
}

void disp_input_from_enc() {
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print(char(curr_key));
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", curr_key);
  nokia5110lcd.display();
}

void disp_inp_panel_1() {
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.drawLine(0, 0, 83, 0, BLACK);
  nokia5110lcd.setCursor(0, 1);
  nokia5110lcd.println("              ");
  nokia5110lcd.setCursor(2, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("Char' '");
  nokia5110lcd.setCursor(47, 1);
  nokia5110lcd.println("Hex:");
  nokia5110lcd.display();
}

void disp_input_from_enc_1() {
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print(char(curr_key));
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", curr_key);
  nokia5110lcd.display();
}

void log_in() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter username");
  nokia5110lcd.display();
  int act = 100;
  curr_key = 65;
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(2)) { // Enter
      log_in_password();
      act = 1000;
    }
    delay(1);

  }
}

void log_in_password() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter password");
  nokia5110lcd.display();
  int act = 100;
  curr_key = 65;
  String usrn_lg = keyb_inp;
  keyb_inp = "";
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      int plnt = keyb_inp.length();
      String stars = "";
      for (int i = 0; i < plnt; i++) {
        stars += "*";
      }
      nokia5110lcd.print(stars);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      int plnt = keyb_inp.length();
      String stars = "";
      for (int i = 0; i < plnt; i++) {
        if (i < 27)
          stars += "*";
      }
      nokia5110lcd.print(stars);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(2)) { // Enter
      der_db_name_from_str(usrn_lg);
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setTextSize(1);
      nokia5110lcd.setCursor(3, 0);
      nokia5110lcd.print("Deriving keys");
      nokia5110lcd.setCursor(9, 12);
      nokia5110lcd.println("Please wait");
      nokia5110lcd.setCursor(9, 21);
      nokia5110lcd.println("for a while");
      nokia5110lcd.display();
      modify_keys();
      act = 1000;
    }
    delay(1);

  }
}

void main_menu(int curr_pos) {
  nokia5110lcd.clearDisplay();
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  if (curr_pos == 0) {
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("Logins");
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Credit cards");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("Notes");
    nokia5110lcd.setCursor(3, 24);
    nokia5110lcd.print("BL+AES+SP+AES");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.print("AES+Serp+AES");
    nokia5110lcd.setCursor(3, 40);
    nokia5110lcd.print("Blfsh+Serpent");
  }
  if (curr_pos == 1) {
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("Logins");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 8);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Credit cards");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Notes");
    nokia5110lcd.setCursor(3, 24);
    nokia5110lcd.print("BL+AES+SP+AES");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.print("AES+Serp+AES");
    nokia5110lcd.setCursor(3, 40);
    nokia5110lcd.print("Blfsh+Serpent");
  }
  if (curr_pos == 2) {
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("Logins");
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Credit cards");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("Notes");
    nokia5110lcd.setCursor(3, 24);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("BL+AES+SP+AES");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.print("AES+Serp+AES");
    nokia5110lcd.setCursor(3, 40);
    nokia5110lcd.print("Blfsh+Serpent");
  }
  if (curr_pos == 3) {
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("Logins");
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Credit cards");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("Notes");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 24);
    nokia5110lcd.print("BL+AES+SP+AES");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("AES+Serp+AES");
    nokia5110lcd.setCursor(3, 40);
    nokia5110lcd.print("Blfsh+Serpent");
  }
  if (curr_pos == 4) {
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("Logins");
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Credit cards");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("Notes");
    nokia5110lcd.setCursor(3, 24);
    nokia5110lcd.print("BL+AES+SP+AES");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.print("AES+Serp+AES");
    nokia5110lcd.setCursor(3, 40);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Blfsh+Serpent");
  }
  if (curr_pos == 5) {
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("Logins");
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Credit cards");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("Notes");
    nokia5110lcd.setCursor(3, 24);
    nokia5110lcd.print("BL+AES+SP+AES");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.print("AES+Serp+AES");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 40);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 40);
    nokia5110lcd.print("Blfsh+Serpent");
  }
  if (curr_pos == 6) {
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("AES+Serpent");
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Serpent");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("3DES");
    nokia5110lcd.setCursor(3, 24);
    nokia5110lcd.print("Hash functns");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.print("SQL");
    nokia5110lcd.setCursor(3, 40);
    nokia5110lcd.print("Onl strd nots");
  }
  if (curr_pos == 7) {
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("AES+Serpent");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 8);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Serpent");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("3DES");
    nokia5110lcd.setCursor(3, 24);
    nokia5110lcd.print("Hash functns");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.print("SQL");
    nokia5110lcd.setCursor(3, 40);
    nokia5110lcd.print("Onl strd nots");
  }
  if (curr_pos == 8) {
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("AES+Serpent");
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Serpent");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("3DES");
    nokia5110lcd.setCursor(3, 24);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Hash functns");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.print("SQL");
    nokia5110lcd.setCursor(3, 40);
    nokia5110lcd.print("Onl strd nots");
  }
  if (curr_pos == 9) {
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("AES+Serpent");
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Serpent");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("3DES");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 24);
    nokia5110lcd.print("Hash functns");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("SQL");
    nokia5110lcd.setCursor(3, 40);
    nokia5110lcd.print("Onl strd nots");
  }
  if (curr_pos == 10) {
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("AES+Serpent");
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Serpent");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("3DES");
    nokia5110lcd.setCursor(3, 24);
    nokia5110lcd.print("Hash functns");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.print("SQL");
    nokia5110lcd.setCursor(3, 40);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Onl strd nots");
  }
  if (curr_pos == 11) {
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("AES+Serpent");
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Serpent");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("3DES");
    nokia5110lcd.setCursor(3, 24);
    nokia5110lcd.print("Hash functns");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.print("SQL");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 40);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 40);
    nokia5110lcd.print("Onl strd nots");
  }
  nokia5110lcd.display();
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
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter title");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
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
      Insert_username_into_logins();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void Insert_username_into_logins() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter username");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
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
      Insert_password_into_logins();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void Insert_password_into_logins() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter password");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
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
      Insert_website_into_logins();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void Insert_website_into_logins() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter website");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
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
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 40);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("Press any bttn");
      nokia5110lcd.setCursor(9, 40);
      nokia5110lcd.println("to continue");
      nokia5110lcd.display();
      bool cont_to_next = false;
      while (cont_to_next == false) {
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
        a_button.tick();
        if (a_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
        b_button.tick();
        if (b_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
      }
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void Edit_login() {
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
    //Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      /*
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
      */
    }
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(6, 0);
    nokia5110lcd.print("Edit login");
    nokia5110lcd.setCursor(0, 9);
    nokia5110lcd.print("Login 1/");
    nokia5110lcd.print(String(num_of_IDs));
    nokia5110lcd.setCursor(0, 18);
    nokia5110lcd.print(IDs[0][1]);
    nokia5110lcd.display();
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
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setTextColor(BLACK, WHITE);
        nokia5110lcd.setCursor(6, 0);
        nokia5110lcd.print("Edit login");
        nokia5110lcd.setCursor(0, 9);
        nokia5110lcd.print("Login " + String(sel_rcrd + 1) + "/" + String(num_of_IDs));
        nokia5110lcd.setCursor(0, 18);
        nokia5110lcd.print(IDs[sel_rcrd][1]);
        nokia5110lcd.display();
      }
      int inpl = keyb_inp.length();
      delayMicroseconds(400);
      a_button.tick();
      int curr_key1 = 0;
      if (a_button.press())
        curr_key1 = 1;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        curr_key1 = 2;
      delayMicroseconds(400);
      if (curr_key1 == 1) {
        nokia5110lcd.clearDisplay();
        disp_inp_panel();
        nokia5110lcd.setTextColor(WHITE, BLACK);
        nokia5110lcd.setCursor(32, 1);
        nokia5110lcd.setTextSize(1);
        nokia5110lcd.print("A");
        nokia5110lcd.setCursor(71, 1);
        nokia5110lcd.printf("%02x", 65);
        nokia5110lcd.setTextColor(BLACK, WHITE);
        nokia5110lcd.setCursor(0, 10);
        nokia5110lcd.print("Enter new pwrd");
        nokia5110lcd.display();
        bool cont_to_next1 = false;
        curr_key = 65;
        keyb_inp = "";
        while (cont_to_next1 == false) {
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

          if (curr_key < 32)
            curr_key = 126;

          if (curr_key > 126)
            curr_key = 32;

          if (enc0.turn()) {
            disp_input_from_enc();
            //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
          }
          a_button.tick();
          if (a_button.press()) {
            keyb_inp += char(curr_key);
            //Serial.println(keyb_inp);
            nokia5110lcd.setTextColor(BLACK, WHITE);
            nokia5110lcd.setCursor(0, 20);
            nokia5110lcd.print(keyb_inp);
            nokia5110lcd.display();
          }
          b_button.tick();
          if (b_button.press()) {
            if (keyb_inp.length() > 0)
              keyb_inp.remove(keyb_inp.length() - 1, 1);
            //Serial.println(keyb_inp);
            nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
            nokia5110lcd.setTextColor(BLACK, WHITE);
            nokia5110lcd.setCursor(0, 20);
            nokia5110lcd.print(keyb_inp);
            nokia5110lcd.display();
          }
          encoder_button.tick();
          if (encoder_button.hasClicks(4)) {
            clb_m = 1;
            nokia5110lcd.clearDisplay();
            nokia5110lcd.setTextColor(BLACK, WHITE);
            nokia5110lcd.setCursor(0, 0);
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
            exeq_sql_statement_from_string("UPDATE Logins set Password = '" + dec_st + "' where ID = '" + IDs[sel_rcrd][0] + "';");
            dec_st = "";
            dec_tag = "";
            decract = 0;
            cont_to_next1 = true;
            return;
          }
          if (encoder_button.hasClicks(5)) {
            keyb_inp = "";
            cont_to_next = true;
            return;
          }
        }
      }
      if (curr_key1 == 2) {
        keyb_inp = "";
        return;
      }
    }

  } else {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.println("Empty");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(9, 40);
    nokia5110lcd.println("to continue");
    nokia5110lcd.display();
    keyb_inp = "";
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
    }
    main_menu(cur_pos);
    return;
  }
}

void Remove_login() {
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
    //Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      /*
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
      */
    }
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(6, 0);
    nokia5110lcd.print("Delete login");
    nokia5110lcd.setCursor(0, 9);
    nokia5110lcd.print("Login 1/");
    nokia5110lcd.print(String(num_of_IDs));
    nokia5110lcd.setCursor(0, 18);
    nokia5110lcd.print(IDs[0][1]);
    nokia5110lcd.display();
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
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setTextColor(BLACK, WHITE);
        nokia5110lcd.setCursor(6, 0);
        nokia5110lcd.print("Delete login");
        nokia5110lcd.setCursor(0, 9);
        nokia5110lcd.print("Login " + String(sel_rcrd + 1) + "/" + String(num_of_IDs));
        nokia5110lcd.setCursor(0, 18);
        nokia5110lcd.print(IDs[sel_rcrd][1]);
        nokia5110lcd.display();
      }
      int inpl = keyb_inp.length();
      delayMicroseconds(400);
      a_button.tick();
      int curr_key = 0;
      if (a_button.press())
        curr_key = 1;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        curr_key = 2;
      delayMicroseconds(400);
      if (curr_key == 1) {
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        exeq_sql_statement_from_string("DELETE FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.display();
        dec_st = "";
        dec_tag = "";
        decract = 0;
        keyb_inp = "";
        cont_to_next = true;
        main_menu(cur_pos);
        return;
      }
      if (curr_key == 2) {
        keyb_inp = "";
        return;
      }
    }

  } else {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.println("Empty");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(9, 40);
    nokia5110lcd.println("to continue");
    nokia5110lcd.display();
    keyb_inp = "";
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
    }
    main_menu(cur_pos);
    return;
  }
}

void View_login() {
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
    //Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      /*
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
      */
    }
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Login 1/");
    nokia5110lcd.print(String(num_of_IDs));
    nokia5110lcd.setCursor(0, 9);
    nokia5110lcd.print(IDs[0][1]);
    nokia5110lcd.display();
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
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.setTextColor(BLACK, WHITE);
        nokia5110lcd.print("Login " + String(sel_rcrd + 1) + "/" + String(num_of_IDs));
        nokia5110lcd.setCursor(0, 9);
        nokia5110lcd.print(IDs[sel_rcrd][1]);
        nokia5110lcd.display();
      }
      int inpl = keyb_inp.length();
      delayMicroseconds(400);
      a_button.tick();
      int curr_key = 0;
      if (a_button.press())
        curr_key = 1;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        curr_key = 2;
      delayMicroseconds(400);
      if (curr_key == 1) {
        clb_m = 2;
        exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.println("Title");
        nokia5110lcd.setCursor(0, 8);
        nokia5110lcd.println(dec_st);
        nokia5110lcd.display();
        bool title_integrity = verify_integrity();
        if (title_integrity == false) {
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("Integrity veri");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("fication faild");
          nokia5110lcd.display();
        }
        bool cont_to_next1 = false;
        while (cont_to_next1 == false) {
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next1 = true;
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press())
            cont_to_next1 = true;
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press())
            cont_to_next1 = true;
          delayMicroseconds(400);
        }
        dec_st = "";
        dec_tag = "";
        decract = 0;
        exeq_sql_statement_from_string("SELECT Website FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.println("Website");
        nokia5110lcd.setCursor(0, 8);
        nokia5110lcd.println(dec_st);
        nokia5110lcd.display();
        bool website_integrity = verify_integrity();
        if (website_integrity == false) {
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("Integrity veri");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("fication faild");
          nokia5110lcd.display();
        }
        bool cont_to_next2 = false;
        while (cont_to_next2 == false) {
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next2 = true;
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press())
            cont_to_next2 = true;
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press())
            cont_to_next2 = true;
          delayMicroseconds(400);
        }
        dec_st = "";
        dec_tag = "";
        decract = 0;
        exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.println("Username");
        nokia5110lcd.setCursor(0, 8);
        nokia5110lcd.println(dec_st);
        nokia5110lcd.display();
        bool username_integrity = verify_integrity();
        if (username_integrity == false) {
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("Integrity veri");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("fication faild");
          nokia5110lcd.display();
        }
        bool cont_to_next3 = false;
        while (cont_to_next3 == false) {
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next3 = true;
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press())
            cont_to_next3 = true;
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press())
            cont_to_next3 = true;
          delayMicroseconds(400);
        }
        dec_st = "";
        dec_tag = "";
        decract = 0;
        exeq_sql_statement_from_string("SELECT Password FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.println("Password");
        nokia5110lcd.setCursor(0, 8);
        nokia5110lcd.println(dec_st);
        nokia5110lcd.display();
        bool password_integrity = verify_integrity();
        if (password_integrity == false) {
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("Integrity veri");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("fication faild");
          nokia5110lcd.display();
        }
        dec_st = "";
        dec_tag = "";
        decract = 0;
        keyb_inp = "";
        bool cont_to_next4 = false;
        while (cont_to_next4 == false) {
          encoder_button.tick();
          if (encoder_button.press()) {
            cont_to_next4 = true;
            cont_to_next = true;
          }
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press()) {
            cont_to_next4 = true;
            cont_to_next = true;
          }
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press()) {
            cont_to_next = true;
            cont_to_next = true;
          }
          delayMicroseconds(400);
        }
        main_menu(cur_pos);
        return;
      }
      if (curr_key == 2) {
        keyb_inp = "";
        return;
      }
    }

  } else {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.println("Empty");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(9, 40);
    nokia5110lcd.println("to continue");
    nokia5110lcd.display();
    keyb_inp = "";
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
    }
    main_menu(cur_pos);
    return;
  }
}

void Add_credit_card() {
  rec_ID = "";
  gen_rand_ID(40);
  Insert_title_into_the_credit_cards();
}

void Insert_title_into_the_credit_cards() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter title");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
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
      Insert_cardholder_name_into_credit_cards();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void Insert_cardholder_name_into_credit_cards() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Ent Cardh Name");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
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
      Insert_card_number_into_credit_cards();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void Insert_card_number_into_credit_cards() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("4");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 52);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter Card Num");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 52;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
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
      Insert_expiration_date_into_credit_cards();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void Insert_expiration_date_into_credit_cards() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("0");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 48);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Ent expir date");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 48;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
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
      Insert_CVN_into_credit_cards();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void Insert_CVN_into_credit_cards() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("0");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 48);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter the CVN");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 48;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
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
      Insert_PIN_into_credit_cards();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void Insert_PIN_into_credit_cards() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("0");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 48);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter the PIN");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 48;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
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
      Insert_ZIP_code_into_credit_cards();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void Insert_ZIP_code_into_credit_cards() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("0");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 48);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter ZIP Code");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 48;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
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
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 40);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("Press any bttn");
      nokia5110lcd.setCursor(9, 40);
      nokia5110lcd.println("to continue");
      nokia5110lcd.display();
      bool cont_to_next = false;
      while (cont_to_next == false) {
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
        a_button.tick();
        if (a_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
        b_button.tick();
        if (b_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
      }
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void Edit_credit_card() {
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
    //Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      /*
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
      */
    }
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(6, 0);
    nokia5110lcd.print("Edit card");
    nokia5110lcd.setCursor(0, 9);
    nokia5110lcd.print("Card 1/");
    nokia5110lcd.print(String(num_of_IDs));
    nokia5110lcd.setCursor(0, 18);
    nokia5110lcd.print(IDs[0][1]);
    nokia5110lcd.display();
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
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setTextColor(BLACK, WHITE);
        nokia5110lcd.setCursor(6, 0);
        nokia5110lcd.print("Edit card");
        nokia5110lcd.setCursor(0, 9);
        nokia5110lcd.print("Card " + String(sel_rcrd + 1) + "/" + String(num_of_IDs));
        nokia5110lcd.setCursor(0, 18);
        nokia5110lcd.print(IDs[sel_rcrd][1]);
        nokia5110lcd.display();
      }
      int inpl = keyb_inp.length();
      delayMicroseconds(400);
      a_button.tick();
      int curr_key1 = 0;
      if (a_button.press())
        curr_key1 = 1;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        curr_key1 = 2;
      delayMicroseconds(400);
      if (curr_key1 == 1) {
        nokia5110lcd.clearDisplay();
        disp_inp_panel();
        nokia5110lcd.setTextColor(WHITE, BLACK);
        nokia5110lcd.setCursor(32, 1);
        nokia5110lcd.setTextSize(1);
        nokia5110lcd.print("A");
        nokia5110lcd.setCursor(71, 1);
        nokia5110lcd.printf("%02x", 65);
        nokia5110lcd.setTextColor(BLACK, WHITE);
        nokia5110lcd.setCursor(0, 10);
        nokia5110lcd.print("Enter new PIN");
        nokia5110lcd.display();
        bool cont_to_next1 = false;
        curr_key = 65;
        keyb_inp = "";
        while (cont_to_next1 == false) {
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

          if (curr_key < 32)
            curr_key = 126;

          if (curr_key > 126)
            curr_key = 32;

          if (enc0.turn()) {
            disp_input_from_enc();
            //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
          }
          a_button.tick();
          if (a_button.press()) {
            keyb_inp += char(curr_key);
            //Serial.println(keyb_inp);
            nokia5110lcd.setTextColor(BLACK, WHITE);
            nokia5110lcd.setCursor(0, 20);
            nokia5110lcd.print(keyb_inp);
            nokia5110lcd.display();
          }
          b_button.tick();
          if (b_button.press()) {
            if (keyb_inp.length() > 0)
              keyb_inp.remove(keyb_inp.length() - 1, 1);
            //Serial.println(keyb_inp);
            nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
            nokia5110lcd.setTextColor(BLACK, WHITE);
            nokia5110lcd.setCursor(0, 20);
            nokia5110lcd.print(keyb_inp);
            nokia5110lcd.display();
          }
          encoder_button.tick();
          if (encoder_button.hasClicks(4)) {
            clb_m = 1;
            nokia5110lcd.clearDisplay();
            nokia5110lcd.setTextColor(BLACK, WHITE);
            nokia5110lcd.setCursor(0, 0);
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
            exeq_sql_statement_from_string("UPDATE Credit_cards set PIN = '" + dec_st + "' where ID = '" + IDs[sel_rcrd][0] + "';");
            dec_st = "";
            dec_tag = "";
            decract = 0;
            cont_to_next1 = true;
            return;
          }
          if (encoder_button.hasClicks(5)) {
            keyb_inp = "";
            cont_to_next = true;
            return;
          }
        }
      }
      if (curr_key1 == 2) {
        keyb_inp = "";
        return;
      }
    }

  } else {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.println("Empty");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(9, 40);
    nokia5110lcd.println("to continue");
    nokia5110lcd.display();
    keyb_inp = "";
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
    }
    main_menu(cur_pos);
    return;
  }
}

void Remove_credit_card() {
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
    //Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      /*
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
      */
    }
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(6, 0);
    nokia5110lcd.print("Delete card");
    nokia5110lcd.setCursor(0, 9);
    nokia5110lcd.print("Card 1/");
    nokia5110lcd.print(String(num_of_IDs));
    nokia5110lcd.setCursor(0, 18);
    nokia5110lcd.print(IDs[0][1]);
    nokia5110lcd.display();
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
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setTextColor(BLACK, WHITE);
        nokia5110lcd.setCursor(6, 0);
        nokia5110lcd.print("Delete card");
        nokia5110lcd.setCursor(0, 9);
        nokia5110lcd.print("Card " + String(sel_rcrd + 1) + "/" + String(num_of_IDs));
        nokia5110lcd.setCursor(0, 18);
        nokia5110lcd.print(IDs[sel_rcrd][1]);
        nokia5110lcd.display();
      }
      int inpl = keyb_inp.length();
      delayMicroseconds(400);
      a_button.tick();
      int curr_key = 0;
      if (a_button.press())
        curr_key = 1;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        curr_key = 2;
      delayMicroseconds(400);
      if (curr_key == 1) {
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        exeq_sql_statement_from_string("DELETE FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.display();
        dec_st = "";
        dec_tag = "";
        decract = 0;
        keyb_inp = "";
        cont_to_next = true;
        main_menu(cur_pos);
        return;
      }
      if (curr_key == 2) {
        keyb_inp = "";
        return;
      }
    }

  } else {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.println("Empty");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(9, 40);
    nokia5110lcd.println("to continue");
    nokia5110lcd.display();
    keyb_inp = "";
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
    }
    main_menu(cur_pos);
    return;
  }
}

void View_credit_card() {
  clb_m = 3;
  keyb_inp = "";
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
    //Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      /*
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
      */
    }
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Card 1/");
    nokia5110lcd.print(String(num_of_IDs));
    nokia5110lcd.setCursor(0, 9);
    nokia5110lcd.print(IDs[0][1]);
    nokia5110lcd.display();
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
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.setTextColor(BLACK, WHITE);
        nokia5110lcd.print("Card " + String(sel_rcrd + 1) + "/" + String(num_of_IDs));
        nokia5110lcd.setCursor(0, 9);
        nokia5110lcd.print(IDs[sel_rcrd][1]);
        nokia5110lcd.display();
      }
      int inpl = keyb_inp.length();
      delayMicroseconds(400);
      a_button.tick();
      int curr_key = 0;
      if (a_button.press())
        curr_key = 1;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        curr_key = 2;
      delayMicroseconds(400);
      if (curr_key == 1) {
        clb_m = 2;
        exeq_sql_statement_from_string("SELECT Title FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.println("Title");
        nokia5110lcd.setCursor(0, 8);
        nokia5110lcd.println(dec_st);
        nokia5110lcd.display();
        bool title_integrity = verify_integrity();
        if (title_integrity == false) {
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("Integrity veri");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("fication faild");
          nokia5110lcd.display();
        }
        bool cont_to_next1 = false;
        while (cont_to_next1 == false) {
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next1 = true;
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press())
            cont_to_next1 = true;
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press())
            cont_to_next1 = true;
          delayMicroseconds(400);
        }
        dec_st = "";
        dec_tag = "";
        decract = 0;
        exeq_sql_statement_from_string("SELECT Cardholder FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.println("Cardholder");
        nokia5110lcd.setCursor(0, 8);
        nokia5110lcd.println(dec_st);
        nokia5110lcd.display();
        bool cardhname_integrity = verify_integrity();
        if (cardhname_integrity == false) {
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("Integrity veri");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("fication faild");
          nokia5110lcd.display();
        }
        bool cont_to_next2 = false;
        while (cont_to_next2 == false) {
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next2 = true;
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press())
            cont_to_next2 = true;
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press())
            cont_to_next2 = true;
          delayMicroseconds(400);
        }
        dec_st = "";
        dec_tag = "";
        decract = 0;
        exeq_sql_statement_from_string("SELECT Card_Number FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.println("Card number");
        nokia5110lcd.setCursor(0, 8);
        nokia5110lcd.println(dec_st);
        nokia5110lcd.display();
        bool cardnumber_integrity = verify_integrity();
        if (cardnumber_integrity == false) {
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("Integrity veri");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("fication faild");
          nokia5110lcd.display();
        }
        bool cont_to_next3 = false;
        while (cont_to_next3 == false) {
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next3 = true;
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press())
            cont_to_next3 = true;
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press())
            cont_to_next3 = true;
          delayMicroseconds(400);
        }
        dec_st = "";
        dec_tag = "";
        decract = 0;
        exeq_sql_statement_from_string("SELECT Expiration_date FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.println("Expirtion date");
        nokia5110lcd.setCursor(0, 8);
        nokia5110lcd.println(dec_st);
        nokia5110lcd.display();
        bool expd_integrity = verify_integrity();
        if (expd_integrity == false) {
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("Integrity veri");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("fication faild");
          nokia5110lcd.display();
        }
        dec_st = "";
        dec_tag = "";
        decract = 0;
        bool cont_to_next4 = false;
        while (cont_to_next4 == false) {
          encoder_button.tick();
          if (encoder_button.press()) {
            cont_to_next4 = true;
            cont_to_next = true;
          }
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press()) {
            cont_to_next4 = true;
            cont_to_next = true;
          }
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press()) {
            cont_to_next = true;
            cont_to_next = true;
          }
          delayMicroseconds(400);
        }

        dec_st = "";
        dec_tag = "";
        decract = 0;
        exeq_sql_statement_from_string("SELECT CVN FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.println("CVN");
        nokia5110lcd.setCursor(0, 8);
        nokia5110lcd.println(dec_st);
        nokia5110lcd.display();
        bool cvn_integrity = verify_integrity();
        if (cvn_integrity == false) {
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("Integrity veri");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("fication faild");
          nokia5110lcd.display();
        }
        bool cont_to_next5 = false;
        while (cont_to_next5 == false) {
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next5 = true;
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press())
            cont_to_next5 = true;
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press())
            cont_to_next5 = true;
          delayMicroseconds(400);
        }

        dec_st = "";
        dec_tag = "";
        decract = 0;
        exeq_sql_statement_from_string("SELECT PIN FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.println("PIN");
        nokia5110lcd.setCursor(0, 8);
        nokia5110lcd.println(dec_st);
        nokia5110lcd.display();
        bool pin_integrity = verify_integrity();
        if (pin_integrity == false) {
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("Integrity veri");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("fication faild");
          nokia5110lcd.display();
        }
        bool cont_to_next6 = false;
        while (cont_to_next6 == false) {
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next6 = true;
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press())
            cont_to_next6 = true;
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press())
            cont_to_next6 = true;
          delayMicroseconds(400);
        }

        dec_st = "";
        dec_tag = "";
        decract = 0;
        exeq_sql_statement_from_string("SELECT ZIP_code FROM Credit_cards WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.println("ZIP Code");
        nokia5110lcd.setCursor(0, 8);
        nokia5110lcd.println(dec_st);
        nokia5110lcd.display();
        bool zipcode_integrity = verify_integrity();
        if (zipcode_integrity == false) {
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("Integrity veri");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("fication faild");
          nokia5110lcd.display();
        }
        keyb_inp = "";
        dec_st = "";
        dec_tag = "";
        decract = 0;
        bool cont_to_next7 = false;
        while (cont_to_next7 == false) {
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next7 = true;
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press())
            cont_to_next7 = true;
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press())
            cont_to_next7 = true;
          delayMicroseconds(400);
        }

        main_menu(cur_pos);
        return;
      }
      if (curr_key == 2) {
        keyb_inp = "";
        return;
      }
    }

  } else {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.println("Empty");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(9, 40);
    nokia5110lcd.println("to continue");
    nokia5110lcd.display();
    keyb_inp = "";
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
    }
    main_menu(cur_pos);
    return;
  }
}

void Add_note() {
  rec_ID = "";
  gen_rand_ID(34);
  Insert_title_into_the_notes();
}

void Insert_title_into_the_notes() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter title");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
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
      Insert_content_into_logins();
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void Insert_content_into_logins() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter content");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
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
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 40);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("Press any bttn");
      nokia5110lcd.setCursor(9, 40);
      nokia5110lcd.println("to continue");
      nokia5110lcd.display();
      bool cont_to_next = false;
      while (cont_to_next == false) {
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
        a_button.tick();
        if (a_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
        b_button.tick();
        if (b_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
      }
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void Edit_note() {
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
    //Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      /*
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
      */
    }
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(6, 0);
    nokia5110lcd.print("Edit note");
    nokia5110lcd.setCursor(0, 9);
    nokia5110lcd.print("Note 1/");
    nokia5110lcd.print(String(num_of_IDs));
    nokia5110lcd.setCursor(0, 18);
    nokia5110lcd.print(IDs[0][1]);
    nokia5110lcd.display();
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
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setTextColor(BLACK, WHITE);
        nokia5110lcd.setCursor(6, 0);
        nokia5110lcd.print("Edit note");
        nokia5110lcd.setCursor(0, 9);
        nokia5110lcd.print("Note " + String(sel_rcrd + 1) + "/" + String(num_of_IDs));
        nokia5110lcd.setCursor(0, 18);
        nokia5110lcd.print(IDs[sel_rcrd][1]);
        nokia5110lcd.display();
      }
      int inpl = keyb_inp.length();
      delayMicroseconds(400);
      a_button.tick();
      int curr_key1 = 0;
      if (a_button.press())
        curr_key1 = 1;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        curr_key1 = 2;
      delayMicroseconds(400);
      if (curr_key1 == 1) {
        nokia5110lcd.clearDisplay();
        disp_inp_panel();
        nokia5110lcd.setTextColor(WHITE, BLACK);
        nokia5110lcd.setCursor(32, 1);
        nokia5110lcd.setTextSize(1);
        nokia5110lcd.print("A");
        nokia5110lcd.setCursor(71, 1);
        nokia5110lcd.printf("%02x", 65);
        nokia5110lcd.setTextColor(BLACK, WHITE);
        nokia5110lcd.setCursor(0, 10);
        nokia5110lcd.print("Enter new cont");
        nokia5110lcd.display();
        bool cont_to_next1 = false;
        curr_key = 65;
        keyb_inp = "";
        while (cont_to_next1 == false) {
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

          if (curr_key < 32)
            curr_key = 126;

          if (curr_key > 126)
            curr_key = 32;

          if (enc0.turn()) {
            disp_input_from_enc();
            //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
          }
          a_button.tick();
          if (a_button.press()) {
            keyb_inp += char(curr_key);
            //Serial.println(keyb_inp);
            nokia5110lcd.setTextColor(BLACK, WHITE);
            nokia5110lcd.setCursor(0, 20);
            nokia5110lcd.print(keyb_inp);
            nokia5110lcd.display();
          }
          b_button.tick();
          if (b_button.press()) {
            if (keyb_inp.length() > 0)
              keyb_inp.remove(keyb_inp.length() - 1, 1);
            //Serial.println(keyb_inp);
            nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
            nokia5110lcd.setTextColor(BLACK, WHITE);
            nokia5110lcd.setCursor(0, 20);
            nokia5110lcd.print(keyb_inp);
            nokia5110lcd.display();
          }
          encoder_button.tick();
          if (encoder_button.hasClicks(4)) {
            clb_m = 1;
            nokia5110lcd.clearDisplay();
            nokia5110lcd.setTextColor(BLACK, WHITE);
            nokia5110lcd.setCursor(0, 0);
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
            exeq_sql_statement_from_string("UPDATE Notes set Content = '" + dec_st + "' where ID = '" + IDs[sel_rcrd][0] + "';");
            dec_st = "";
            dec_tag = "";
            decract = 0;
            cont_to_next1 = true;
            return;
          }
          if (encoder_button.hasClicks(5)) {
            keyb_inp = "";
            cont_to_next = true;
            return;
          }
        }
      }
      if (curr_key1 == 2) {
        keyb_inp = "";
        cont_to_next = true;
        return;
      }
    }

  } else {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.println("Empty");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(9, 40);
    nokia5110lcd.println("to continue");
    nokia5110lcd.display();
    keyb_inp = "";
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
    }
    main_menu(cur_pos);
    return;
  }
}

void Remove_note() {
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
    //Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      /*
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
      */
    }
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(6, 0);
    nokia5110lcd.print("Delete Note");
    nokia5110lcd.setCursor(0, 9);
    nokia5110lcd.print("Note 1/");
    nokia5110lcd.print(String(num_of_IDs));
    nokia5110lcd.setCursor(0, 18);
    nokia5110lcd.print(IDs[0][1]);
    nokia5110lcd.display();
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
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setTextColor(BLACK, WHITE);
        nokia5110lcd.setCursor(6, 0);
        nokia5110lcd.print("Delete Note");
        nokia5110lcd.setCursor(0, 9);
        nokia5110lcd.print("Note " + String(sel_rcrd + 1) + "/" + String(num_of_IDs));
        nokia5110lcd.setCursor(0, 18);
        nokia5110lcd.print(IDs[sel_rcrd][1]);
        nokia5110lcd.display();
      }
      int inpl = keyb_inp.length();
      delayMicroseconds(400);
      a_button.tick();
      int curr_key = 0;
      if (a_button.press())
        curr_key = 1;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        curr_key = 2;
      delayMicroseconds(400);
      if (curr_key == 1) {
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        exeq_sql_statement_from_string("DELETE FROM Notes WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.display();
        dec_st = "";
        dec_tag = "";
        decract = 0;
        keyb_inp = "";
        cont_to_next = true;
        main_menu(cur_pos);
        return;
      }
      if (curr_key == 2) {
        keyb_inp = "";
        return;
      }
    }

  } else {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.println("Empty");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(9, 40);
    nokia5110lcd.println("to continue");
    nokia5110lcd.display();
    keyb_inp = "";
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
    }
    main_menu(cur_pos);
    return;
  }
}

void View_note() {
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
    //Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++) {
      //Serial.println(IDs[i][0]);
      //Serial.println(IDs[i][1]);
      /*
      Serial.print("[");
      Serial.print(i);
      Serial.print("] ");
      Serial.println(IDs[i][1]);
      */
    }
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Note 1/");
    nokia5110lcd.print(String(num_of_IDs));
    nokia5110lcd.setCursor(0, 9);
    nokia5110lcd.print(IDs[0][1]);
    nokia5110lcd.display();
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
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.setTextColor(BLACK, WHITE);
        nokia5110lcd.print("Note " + String(sel_rcrd + 1) + "/" + String(num_of_IDs));
        nokia5110lcd.setCursor(0, 9);
        nokia5110lcd.print(IDs[sel_rcrd][1]);
        nokia5110lcd.display();
      }
      int inpl = keyb_inp.length();
      delayMicroseconds(400);
      a_button.tick();
      int curr_key = 0;
      if (a_button.press())
        curr_key = 1;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        curr_key = 2;
      delayMicroseconds(400);
      if (curr_key == 1) {
        clb_m = 2;
        exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.println("Title");
        nokia5110lcd.setCursor(0, 8);
        nokia5110lcd.println(dec_st);
        nokia5110lcd.display();
        bool title_integrity = verify_integrity();
        if (title_integrity == false) {
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("Integrity veri");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("fication faild");
          nokia5110lcd.display();
        }
        bool cont_to_next1 = false;
        while (cont_to_next1 == false) {
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next1 = true;
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press())
            cont_to_next1 = true;
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press())
            cont_to_next1 = true;
          delayMicroseconds(400);
        }
        dec_st = "";
        dec_tag = "";
        decract = 0;
        exeq_sql_statement_from_string("SELECT Content FROM Notes WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 0);
        nokia5110lcd.println("Content");
        nokia5110lcd.setCursor(0, 8);
        nokia5110lcd.println(dec_st);
        nokia5110lcd.display();
        bool content_integrity = verify_integrity();
        if (content_integrity == false) {
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("              ");
          nokia5110lcd.setCursor(0, 32);
          nokia5110lcd.println("Integrity veri");
          nokia5110lcd.setCursor(0, 41);
          nokia5110lcd.println("fication faild");
          nokia5110lcd.display();
        }

        dec_st = "";
        dec_tag = "";
        decract = 0;
        keyb_inp = "";
        bool cont_to_next4 = false;
        while (cont_to_next4 == false) {
          encoder_button.tick();
          if (encoder_button.press()) {
            cont_to_next4 = true;
            cont_to_next = true;
          }
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press()) {
            cont_to_next4 = true;
            cont_to_next = true;
          }
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press()) {
            cont_to_next = true;
            cont_to_next = true;
          }
          delayMicroseconds(400);
        }
        main_menu(cur_pos);
        return;
      }
      if (curr_key == 2) {
        keyb_inp = "";
        return;
      }
    }

  } else {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.println("Empty");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(9, 40);
    nokia5110lcd.println("to continue");
    nokia5110lcd.display();
    keyb_inp = "";
    bool cont_to_next5 = false;
    while (cont_to_next5 == false) {
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        cont_to_next5 = true;
      delayMicroseconds(400);
    }
    main_menu(cur_pos);
    return;
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
  for (int i = 0; i < 16; i++) {
    if (cipher_text[i] < 16)
      Serial.print("0");
    Serial.print(cipher_text[i], HEX);
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
  for (int i = 0; i < 16; i++) {
    if (cipher_text[i] < 16)
      Serial.print("0");
    Serial.print(cipher_text[i], HEX);
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

void split_by_four_for_encr_tdes(char plntxt[], int k, int str_len) {
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 4; i++) {
    if (i + k > str_len - 1)
      break;
    res[i] = byte(plntxt[i + k]);
  }
  for (int i = 4; i < 8; i++) {
    res[i] = gen_r_num();
  }
  encr_TDES(res);
}

void encr_TDES(byte inp_for_tdes[]) {
  byte out_of_tdes[8];
  des.tripleEncrypt(out_of_tdes, inp_for_tdes, TDESkey);
  for (int i = 0; i < 8; i++) {
    if (out_of_tdes[i] < 16)
      Serial.print("0");
    Serial.print(out_of_tdes[i], HEX);
  }
}

void decr_eight_chars_block_tdes(char ct[], int ct_len, int p) {
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
  for (int i = 0; i < 16; i += 2) {
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

void locally_stored_login_menu(int curr_pos) {
  nokia5110lcd.clearDisplay();
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(9, 0);
  nokia5110lcd.print("Logins Menu");

  if (curr_pos == 0) {
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 8);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(15, 8);
    nokia5110lcd.print("Add Login");
    nokia5110lcd.setCursor(12, 16);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Edit Login");
    nokia5110lcd.setCursor(6, 24);
    nokia5110lcd.print("Delete Login");
    nokia5110lcd.setCursor(12, 32);
    nokia5110lcd.print("View Login");
  }
  if (curr_pos == 1) {
    nokia5110lcd.setCursor(15, 8);
    nokia5110lcd.print("Add Login");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(12, 16);
    nokia5110lcd.print("Edit Login");
    nokia5110lcd.setCursor(6, 24);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Delete Login");
    nokia5110lcd.setCursor(12, 32);
    nokia5110lcd.print("View Login");
  }
  if (curr_pos == 2) {
    nokia5110lcd.setCursor(15, 8);
    nokia5110lcd.print("Add Login");
    nokia5110lcd.setCursor(12, 16);
    nokia5110lcd.print("Edit Login");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(6, 24);
    nokia5110lcd.print("Delete Login");
    nokia5110lcd.setCursor(12, 32);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("View Login");
  }
  if (curr_pos == 3) {
    nokia5110lcd.setCursor(15, 8);
    nokia5110lcd.print("Add Login");
    nokia5110lcd.setCursor(12, 16);
    nokia5110lcd.print("Edit Login");
    nokia5110lcd.setCursor(6, 24);
    nokia5110lcd.print("Delete Login");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(12, 32);
    nokia5110lcd.print("View Login");
    nokia5110lcd.setCursor(0, 40);
  }
  nokia5110lcd.display();
}

void show_loc_st_login_menu() {
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
      curr_key = 3;

    if (curr_key > 3)
      curr_key = 0;

    if (enc0.turn()) {
      locally_stored_login_menu(curr_key);
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delayMicroseconds(400);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

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

    if (ch == 2) // Get back
      cont_to_next = true;
    delayMicroseconds(400);
  }
  curr_key = 0;
  main_menu(cur_pos);
}

void locally_stored_credit_cards(int curr_pos) {
  nokia5110lcd.clearDisplay();
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(6, 0);
  nokia5110lcd.print("Credit Cards");

  if (curr_pos == 0) {
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 8);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Add Cred Card");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Edit Crd Card");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.print("Delete Cr Card");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.print("View Crd Card");
  }
  if (curr_pos == 1) {
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Add Cred Card");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("Edit Crd Card");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Delete Cr Card");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.print("View Crd Card");
  }
  if (curr_pos == 2) {
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Add Cred Card");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("Edit Crd Card");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.print("Delete Cr Card");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("View Crd Card");
  }
  if (curr_pos == 3) {
    nokia5110lcd.setCursor(3, 8);
    nokia5110lcd.print("Add Cred Card");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("Edit Crd Card");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.print("Delete Cr Card");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(3, 32);
    nokia5110lcd.print("View Crd Card");
  }
  nokia5110lcd.display();
}

void show_loc_st_credit_cards() {
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
      curr_key = 3;

    if (curr_key > 3)
      curr_key = 0;

    if (enc0.turn()) {
      locally_stored_credit_cards(curr_key);
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delayMicroseconds(400);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;
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

    if (ch == 2) // Get back
      cont_to_next = true;
    delayMicroseconds(400);
  }
  curr_key = 0;
  main_menu(cur_pos);
}

void locally_stored_notes(int curr_pos) {
  nokia5110lcd.clearDisplay();
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(12, 0);
  nokia5110lcd.print("Notes Menu");

  if (curr_pos == 0) {
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 8);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(18, 8);
    nokia5110lcd.print("Add Note");
    nokia5110lcd.setCursor(15, 16);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Edit Note");
    nokia5110lcd.setCursor(9, 24);
    nokia5110lcd.print("Delete Note");
    nokia5110lcd.setCursor(15, 32);
    nokia5110lcd.print("View Note");
  }
  if (curr_pos == 1) {
    nokia5110lcd.setCursor(18, 8);
    nokia5110lcd.print("Add Note");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(15, 16);
    nokia5110lcd.print("Edit Note");
    nokia5110lcd.setCursor(9, 24);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Delete Note");
    nokia5110lcd.setCursor(15, 32);
    nokia5110lcd.print("View Note");
  }
  if (curr_pos == 2) {
    nokia5110lcd.setCursor(18, 8);
    nokia5110lcd.print("Add Note");
    nokia5110lcd.setCursor(15, 16);
    nokia5110lcd.print("Edit Note");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(9, 24);
    nokia5110lcd.print("Delete Note");
    nokia5110lcd.setCursor(15, 32);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("View Note");
  }
  if (curr_pos == 3) {
    nokia5110lcd.setCursor(18, 8);
    nokia5110lcd.print("Add Note");
    nokia5110lcd.setCursor(15, 16);
    nokia5110lcd.print("Edit Note");
    nokia5110lcd.setCursor(9, 24);
    nokia5110lcd.print("Delete Note");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(15, 32);
    nokia5110lcd.print("View Note");
  }
  nokia5110lcd.display();
}

void show_loc_st_notes() {
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
      curr_key = 3;

    if (curr_key > 3)
      curr_key = 0;

    if (enc0.turn()) {
      locally_stored_notes(curr_key);
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delayMicroseconds(400);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;
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

    if (ch == 2) // Get back
      cont_to_next = true;
    delayMicroseconds(400);
  }
  curr_key = 0;
  main_menu(cur_pos);
}

void enc_dec_options(int curr_pos, int shft, String hdr) {
  nokia5110lcd.clearDisplay();
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(shft, 0);
  nokia5110lcd.print(hdr);

  if (curr_pos == 0) {
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(21, 16);
    nokia5110lcd.print("Encrypt");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("En from Serial");
    nokia5110lcd.setCursor(21, 32);
    nokia5110lcd.print("Decrypt");
  }
  if (curr_pos == 1) {
    nokia5110lcd.setCursor(21, 16);
    nokia5110lcd.print("Encrypt");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.print("En from Serial");
    nokia5110lcd.setCursor(21, 32);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Decrypt");
  }
  if (curr_pos == 2) {
    nokia5110lcd.setCursor(21, 16);
    nokia5110lcd.print("Encrypt");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.print("En from Serial");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(21, 32);
    nokia5110lcd.print("Decrypt");
  }
  nokia5110lcd.display();
}

void Blfish_AES_Serp_AES_menu() {
  curr_key = 0;
  enc_dec_options(curr_key, 3, "BL+AES+SP+AES");
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
      enc_dec_options(curr_key, 3, "BL+AES+SP+AES");
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delayMicroseconds(400);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

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

    delayMicroseconds(400);
  }
  curr_key = 0;
  main_menu(cur_pos);
}

void encr_blwfsh_aes_serpent_aes() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter string");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
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
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      delay(20);
      Serial.println("\nCiphertext:");
      int p = 0;
      for (int i = 0; i < 4; i++) {
        delay(20);
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight_bl_aes_serp_aes(hmacchar, p, 100);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        delay(20);
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight_bl_aes_serp_aes(char_array, p, str_len);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      delay(20);
      keyb_inp = "";
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void encr_blwfsh_aes_serpent_aes_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the plaintext to the Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
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
    for (int i = 0; i < 32; i++) {
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
    int p = 0;
    for (int i = 0; i < 4; i++) {
      incr_key();
      incr_second_key();
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight_bl_aes_serp_aes(hmacchar, p, 100);
      p += 8;
    }
    p = 0;
    while (str_len > p + 1) {
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
      split_by_eight_bl_aes_serp_aes(char_array, p, str_len);
      p += 8;
    }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();
    keyb_inp = "";

    curr_key = 0;
    main_menu(cur_pos);
    cont_to_next = true;
    return;
  }
}

void decr_blwfsh_aes_serpent_aes() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the ciphertext to the Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
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
      delay(20);
      if (count % 2 == 1 && count != 0)
        ch = true;
      else {
        ch = false;
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
      }
      split_dec_bl_aes_serp_aes(ct_array, ct_len, 0 + ext, ch, true);
      ext += 32;
      count++;
    }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();
    //Serial.println("Plaintext:");
    //Serial.println(dec_st);
    bool plt_integr = verify_integrity();
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Plaintext");
    nokia5110lcd.setCursor(0, 8);
    nokia5110lcd.println(dec_st);
    nokia5110lcd.display();
    if (plt_integr == false) {
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("Integrity veri");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("fication faild");
      nokia5110lcd.display();
    }
    bool cont_to_next = false;
    while (cont_to_next == false) {
      encoder_button.tick();
      if (encoder_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
    }
    keyb_inp = "";
    dec_st = "";
    dec_tag = "";
    decract = 0;
    return;
  }
}

void AES_Serp_AES_menu() {
  curr_key = 0;
  enc_dec_options(curr_key, 0, "AES+Serpnt+AES");
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
      enc_dec_options(curr_key, 0, "AES+Serpnt+AES");
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delayMicroseconds(400);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

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

    delayMicroseconds(400);
  }
  curr_key = 0;
  main_menu(cur_pos);
}

void encr_aes_serpent_aes() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter string");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
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
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      delay(20);
      Serial.println("\nCiphertext:");
      int p = 0;
      for (int i = 0; i < 4; i++) {
        delay(20);
        incr_key();
        incr_second_key();
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight_for_aes_serp_aes(hmacchar, p, 100);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        delay(20);
        incr_Blwfsh_key();
        incr_key();
        incr_serp_key();
        incr_second_key();
        split_by_eight_for_aes_serp_aes(char_array, p, str_len);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_k();
      rest_serp_k();
      rest_s_k();
      delay(20);
      keyb_inp = "";

      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void encr_aes_serpent_aes_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the plaintext to the Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
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
    for (int i = 0; i < 32; i++) {
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
    int p = 0;
    for (int i = 0; i < 4; i++) {
      incr_key();
      incr_second_key();
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight_for_aes_serp_aes(hmacchar, p, 100);
      p += 8;
    }
    p = 0;
    while (str_len > p + 1) {
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
      split_by_eight_for_aes_serp_aes(char_array, p, str_len);
      p += 8;
    }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();
    keyb_inp = "";

    curr_key = 0;
    main_menu(cur_pos);
    cont_to_next = true;
    return;
  }
}

void decr_aes_serpent_aes() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the ciphertext to the Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
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
        incr_second_key();
      }
      split_dec_for_aes_serp_aes(ct_array, ct_len, 0 + ext, ch, true);
      ext += 32;
      count++;
    }
    rest_k();
    rest_serp_k();
    rest_s_k();
    //Serial.println("Plaintext:");
    //Serial.println(dec_st);
    bool plt_integr = verify_integrity();
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Plaintext");
    nokia5110lcd.setCursor(0, 8);
    nokia5110lcd.println(dec_st);
    nokia5110lcd.display();
    if (plt_integr == false) {
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("Integrity veri");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("fication faild");
      nokia5110lcd.display();
    }
    bool cont_to_next = false;
    while (cont_to_next == false) {
      encoder_button.tick();
      if (encoder_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
    }
    keyb_inp = "";
    dec_st = "";
    dec_tag = "";
    decract = 0;
    return;
  }
}

void Blowfish_Serpent_menu() {
  curr_key = 0;
  enc_dec_options(curr_key, 0, "Blwfish+Serpnt");
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
      enc_dec_options(curr_key, 0, "Blwfish+Serpnt");
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delayMicroseconds(400);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

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

    delayMicroseconds(400);
  }
  curr_key = 0;
  main_menu(cur_pos);
}

void encr_blowfish_serpent() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter string");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
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
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      delay(20);
      Serial.println("\nCiphertext:");
      int p = 0;
      for (int i = 0; i < 4; i++) {
        delay(20);
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight_for_bl_and_serp(hmacchar, p, 100);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        delay(20);
        incr_Blwfsh_key();
        incr_serp_key();
        split_by_eight_for_bl_and_serp(char_array, p, str_len);
        p += 8;
      }
      rest_Blwfsh_k();
      rest_serp_k();
      delay(20);
      keyb_inp = "";

      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void encr_blowfish_serpent_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the plaintext to the Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
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
    for (int i = 0; i < 32; i++) {
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

    curr_key = 0;
    main_menu(cur_pos);
    cont_to_next = true;
    return;
  }
}

void decr_blowfish_serpent() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the ciphertext to the Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
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
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Plaintext");
    nokia5110lcd.setCursor(0, 8);
    nokia5110lcd.println(dec_st);
    nokia5110lcd.display();
    if (plt_integr == false) {
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("Integrity veri");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("fication faild");
      nokia5110lcd.display();
    }
    bool cont_to_next = false;
    while (cont_to_next == false) {
      encoder_button.tick();
      if (encoder_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
    }
    keyb_inp = "";
    dec_st = "";
    dec_tag = "";
    decract = 0;
    return;
  }
}

void AES_Serpent_menu() {
  curr_key = 0;
  enc_dec_options(curr_key, 9, "AES+Serpent");
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
      enc_dec_options(curr_key, 9, "AES+Serpent");
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delayMicroseconds(400);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

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

    delayMicroseconds(400);
  }
  curr_key = 0;
  main_menu(cur_pos);
}

void encr_aes_serpent() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter string");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
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
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      delay(20);
      Serial.println("\nCiphertext:");
      int p = 0;
      for (int i = 0; i < 4; i++) {
        delay(20);
        incr_key();
        incr_serp_key();
        split_by_eight_for_AES_serp(hmacchar, p, 100);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        delay(20);
        incr_key();
        incr_serp_key();
        split_by_eight_for_AES_serp(char_array, p, str_len);
        p += 8;
      }
      rest_k();
      rest_serp_k();
      delay(20);
      keyb_inp = "";

      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void encr_aes_serpent_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the plaintext to the Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
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
    for (int i = 0; i < 32; i++) {
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

    curr_key = 0;
    main_menu(cur_pos);
    cont_to_next = true;
    return;
  }
}

void decr_aes_serpent() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the ciphertext to the Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
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
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Plaintext");
    nokia5110lcd.setCursor(0, 8);
    nokia5110lcd.println(dec_st);
    nokia5110lcd.display();
    if (plt_integr == false) {
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("Integrity veri");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("fication faild");
      nokia5110lcd.display();
    }
    bool cont_to_next = false;
    while (cont_to_next == false) {
      encoder_button.tick();
      if (encoder_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
    }
    keyb_inp = "";
    dec_st = "";
    dec_tag = "";
    decract = 0;
    return;
  }
}

void Serpent_menu() {
  curr_key = 0;
  enc_dec_options(curr_key, 21, "Serpent");
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
      enc_dec_options(curr_key, 21, "Serpent");
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delayMicroseconds(400);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

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

    delayMicroseconds(400);
  }
  curr_key = 0;
  main_menu(cur_pos);
}

void encr_serpent() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter string");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
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
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      delay(20);
      Serial.println("\nCiphertext:");
      int p = 0;
      for (int i = 0; i < 4; i++) {
        delay(20);
        incr_serp_key();
        split_by_eight_for_serp_only(hmacchar, p, 100);
        p += 8;
      }
      p = 0;
      while (str_len > p + 1) {
        delay(20);
        incr_serp_key();
        split_by_eight_for_serp_only(char_array, p, str_len);
        p += 8;
      }
      rest_serp_k();
      delay(20);
      keyb_inp = "";
      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void encr_serpent_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the plaintext to the Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
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
    for (int i = 0; i < 32; i++) {
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

    curr_key = 0;
    main_menu(cur_pos);
    cont_to_next = true;
    return;
  }
}

void decr_serpent() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the ciphertext to the Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
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
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Plaintext");
    nokia5110lcd.setCursor(0, 8);
    nokia5110lcd.println(dec_st);
    nokia5110lcd.display();
    if (plt_integr == false) {
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("Integrity veri");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("fication faild");
      nokia5110lcd.display();
    }
    bool cont_to_next = false;
    while (cont_to_next == false) {
      encoder_button.tick();
      if (encoder_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
    }
    keyb_inp = "";
    dec_st = "";
    dec_tag = "";
    decract = 0;
    return;
  }
}

void TDES_menu() {
  curr_key = 0;
  enc_dec_options(curr_key, 12, "Triple DES");
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
      enc_dec_options(curr_key, 12, "Triple DES");
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delayMicroseconds(400);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

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

    delayMicroseconds(400);
  }
  curr_key = 0;
  main_menu(cur_pos);
}

void encr_tdes() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter string");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
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
      for (int i = 0; i < 32; i++) {
        hmacchar[i] = char(authCode[i]);
      }
      delay(20);
      Serial.println("\nCiphertext:");
      int p = 0;
      for (int i = 0; i < 8; i++) {
        delay(20);
        split_by_four_for_encr_tdes(hmacchar, p, 100);
        incr_TDESkey();
        p += 4;
      }
      p = 0;
      while (str_len > p + 1) {
        delay(20);
        split_by_four_for_encr_tdes(char_array, p, str_len);
        incr_TDESkey();
        p += 4;
      }
      Serial.println();
      rest_TDESkey();
      delay(20);
      keyb_inp = "";

      curr_key = 0;
      main_menu(cur_pos);
      cont_to_next = true;
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void encr_tdes_from_Serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the plaintext to the Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the string you want to encrypt here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
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
    for (int i = 0; i < 32; i++) {
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

    curr_key = 0;
    main_menu(cur_pos);
    cont_to_next = true;
    return;
  }
}

void decr_tdes() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the ciphertext to the Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the ciphertext here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
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
    while (ct_len > ext) {
      decr_eight_chars_block_tdes(ct_array, ct_len, 0 + ext);
      ext += 16;
      incr_TDESkey();
    }
    rest_TDESkey();
    //Serial.println("Plaintext:");
    //Serial.println(dec_st);
    bool plt_integr = verify_integrity();
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextSize(1);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Plaintext");
    nokia5110lcd.setCursor(0, 8);
    nokia5110lcd.println(dec_st);
    nokia5110lcd.display();
    if (plt_integr == false) {
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("Integrity veri");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("fication faild");
      nokia5110lcd.display();
    }
    bool cont_to_next = false;
    while (cont_to_next == false) {
      encoder_button.tick();
      if (encoder_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        cont_to_next = true;
      }
      delayMicroseconds(400);
    }
    keyb_inp = "";
    dec_st = "";
    dec_tag = "";
    decract = 0;
    return;
  }
}

// Hash functions (Below)

void hash_functions_menu(int curr_pos) {
  nokia5110lcd.clearDisplay();
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 0);
  nokia5110lcd.print("Hash Functions");

  if (curr_pos == 0) {
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(21, 16);
    nokia5110lcd.print("SHA-256");
    nokia5110lcd.setCursor(21, 24);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("SHA-512");
  }
  if (curr_pos == 1) {
    nokia5110lcd.setCursor(21, 16);
    nokia5110lcd.print("SHA-256");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(21, 24);
    nokia5110lcd.print("SHA-512");

  }

  nokia5110lcd.display();
}

void show_hfunc_m() {
  curr_key = 0;
  hash_functions_menu(curr_key);
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
      hash_functions_menu(curr_key);
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delayMicroseconds(400);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;
    if (ch == 1 && curr_key == 0) {
      hash_str_sha256();
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 1) {
      hash_str_sha512();
      cont_to_next = true;
    }

    if (ch == 2) // Get back
      cont_to_next = true;
    delayMicroseconds(400);
  }
  curr_key = 0;
  main_menu(cur_pos);
}

void hash_str_sha256() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter string");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      int str_len = keyb_inp.length() + 1;
      char keyb_inp_arr[str_len];
      keyb_inp.toCharArray(keyb_inp_arr, str_len);
      SHA256 hasher;
      hasher.doUpdate(keyb_inp_arr, strlen(keyb_inp_arr));
      byte authCode[SHA256_SIZE];
      hasher.doFinal(authCode);

      String res_hash;
      for (byte i = 0; i < SHA256HMAC_SIZE; i++) {
        if (authCode[i] < 0x10) {
          res_hash += 0;
        } {
          res_hash += String(authCode[i], HEX);
        }
      }
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(3, 0);
      nokia5110lcd.println("Resulted hash");
      nokia5110lcd.setCursor(0, 8);
      nokia5110lcd.println(res_hash);
      nokia5110lcd.display();
      bool cont_to_next = false;
      while (cont_to_next == false) {
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
        a_button.tick();
        if (a_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
        b_button.tick();
        if (b_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
      }
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void hash_str_sha512() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter string");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
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
      int str_len1 = h.length() + 1;
      char keyb_inp_arr1[str_len1];
      h.toCharArray(keyb_inp_arr1, str_len1);
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(3, 0);
      nokia5110lcd.println("Resulted hash");
      nokia5110lcd.setCursor(0, 8);
      nokia5110lcd.println(h);
      nokia5110lcd.display();
      bool cont_to_next = false;
      while (cont_to_next == false) {
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
        a_button.tick();
        if (a_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
        b_button.tick();
        if (b_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
      }

      nokia5110lcd.clearDisplay();
      nokia5110lcd.setCursor(0, 0);
      for (int i = 70; i < 128; i++) {
        nokia5110lcd.print(keyb_inp_arr1[i]);
      }
      nokia5110lcd.display();

      bool cont_to_next2 = false;
      while (cont_to_next2 == false) {
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next2 = true;
        delayMicroseconds(400);
        a_button.tick();
        if (a_button.press())
          cont_to_next2 = true;
        delayMicroseconds(400);
        b_button.tick();
        if (b_button.press())
          cont_to_next2 = true;
        delayMicroseconds(400);
      }
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

// Hash functions (Above)

// SQL (Below)

void sql_src_menu(int curr_pos) {
  nokia5110lcd.clearDisplay();
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(33, 0);
  nokia5110lcd.print("SQL");

  if (curr_pos == 0) {
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.print("Exec SQL query");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Exec SQL queryfrom S Monitor");
  }
  if (curr_pos == 1) {
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.print("Exec SQL query");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.println("                            ");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.print("Exec SQL queryfrom S Monitor");

  }

  nokia5110lcd.display();
}

void show_sql_m() {
  curr_key = 0;
  sql_src_menu(curr_key);
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
      sql_src_menu(curr_key);
    }
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delayMicroseconds(400);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;
    if (ch == 1 && curr_key == 0) {
      exeq_sql_q_enc();
      cont_to_next = true;
    }
    if (ch == 1 && curr_key == 1) {
      exeq_sql_query_from_ser();
      cont_to_next = true;
    }

    if (ch == 2) // Get back
      cont_to_next = true;
    delayMicroseconds(400);
  }
  curr_key = 0;
  main_menu(cur_pos);
}

void exeq_sql_q_enc() {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Entr SQL query");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      clb_m = 1;
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
      exeq_sql_statement_from_string(keyb_inp);
      nokia5110lcd.display();
      bool cont_to_next2 = false;
      while (cont_to_next2 == false) {
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next2 = true;
        delayMicroseconds(400);
        a_button.tick();
        if (a_button.press())
          cont_to_next2 = true;
        delayMicroseconds(400);
        b_button.tick();
        if (b_button.press())
          cont_to_next2 = true;
        delayMicroseconds(400);
      }
      return;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }
  }
}

void exeq_sql_query_from_ser() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("Enter the SQL");
    nokia5110lcd.setCursor(0, 8);
    nokia5110lcd.print("query you want");
    nokia5110lcd.setCursor(3, 16);
    nokia5110lcd.print("to execute to");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.print("Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("Enter the SQL query you want to execute here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
        break;
      }
    }
    if (canc_op == true) {
      curr_key = 0;
      main_menu(cur_pos);
      break;
    }
    keyb_inp = Serial.readString();
    clb_m = 0;
    nokia5110lcd.clearDisplay();
    nokia5110lcd.display();
    exeq_sql_statement_from_string(keyb_inp);
    curr_key = 0;
    main_menu(cur_pos);
    cont_to_next = true;
    return;
  }
}

// SQL (Above)

// Thingspeak (Below)

void onl_st_nts(int curr_pos) {
  nokia5110lcd.clearDisplay();
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 0);
  nokia5110lcd.print("Onl strd notes");

  if (curr_pos == 0) {
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(18, 16);
    nokia5110lcd.print("Add Note");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Last Savd Note");
    nokia5110lcd.setCursor(6, 32);
    nokia5110lcd.print("Decrypt Note");
  }
  if (curr_pos == 1) {
    nokia5110lcd.setCursor(18, 16);
    nokia5110lcd.print("Add Note");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.print("Last Savd Note");
    nokia5110lcd.setCursor(6, 32);
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.print("Decrypt Note");
  }
  if (curr_pos == 2) {
    nokia5110lcd.setCursor(18, 16);
    nokia5110lcd.print("Add Note");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.print("Last Savd Note");
    nokia5110lcd.setTextColor(WHITE, BLACK);
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(6, 32);
    nokia5110lcd.print("Decrypt Note");
  }
  nokia5110lcd.display();
}

void online_stored_notes_menu() {
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
    a_button.tick();
    int ch = 0;
    if (a_button.press() == true)
      ch = 1;

    delayMicroseconds(400);
    b_button.tick();
    if (b_button.press() == true)
      ch = 2;

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

    delayMicroseconds(400);
  }
  curr_key = 0;
  main_menu(cur_pos);
}

bool upd_ch;

void get_title_for_online_notes() {

  upd_ch = true;
  nokia5110lcd.clearDisplay();
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(3, 0);
  nokia5110lcd.print("Connecting to");
  nokia5110lcd.setCursor(9, 8);
  nokia5110lcd.print("the network");
  nokia5110lcd.setCursor(0, 16);
  nokia5110lcd.print("If it taks too");
  nokia5110lcd.setCursor(0, 24);
  nokia5110lcd.print("long, hold the");
  nokia5110lcd.setCursor(0, 32);
  nokia5110lcd.print("encoder button");
  nokia5110lcd.setCursor(0, 40);
  nokia5110lcd.print("and try again.");
  nokia5110lcd.display();
  if (WiFi.status() != WL_CONNECTED) {
    while (WiFi.status() != WL_CONNECTED) {
      WiFi.begin(ssid, password);
      delay(1900);
      encoder_button.tick();
      if (encoder_button.isPress() || encoder_button.isHolded() || encoder_button.isHold()) {
        upd_ch = false;
        break;
      }
      delay(400);
    }
  }

  if (upd_ch == false) {
    cur_pos = 0;
    main_menu(cur_pos);
    return;
  }

  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter title");
  nokia5110lcd.display();
  bool cont_to_next = false;
  curr_key = 65;
  keyb_inp = "";
  bool cont_to_content = false;
  while (cont_to_next == false) {
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

    if (enc0.turn()) {
      disp_input_from_enc();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }
    a_button.tick();
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      cont_to_content = true;
      cont_to_next = true;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }

    if (cont_to_content == true) {
      get_content_for_online_notes(keyb_inp);
    }
  }
}

void get_content_for_online_notes(String ttl_to_be_st_onl) {
  nokia5110lcd.clearDisplay();
  disp_inp_panel();
  nokia5110lcd.setTextColor(WHITE, BLACK);
  nokia5110lcd.setCursor(32, 1);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.print("A");
  nokia5110lcd.setCursor(71, 1);
  nokia5110lcd.printf("%02x", 65);
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setCursor(0, 10);
  nokia5110lcd.print("Enter content");
  nokia5110lcd.display();
  bool cont_to_next = false;
  bool cont_to_send = false;
  curr_key = 65;
  keyb_inp = "";
  while (cont_to_next == false) {
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

    if (enc0.turn()) {
      disp_input_from_enc();
      //Serial.printf("Char:'%c'  Hex:%02x\n", curr_key, curr_key);
    }
    a_button.tick();
    if (a_button.press()) {
      keyb_inp += char(curr_key);
      //Serial.println(keyb_inp);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    b_button.tick();
    if (b_button.press()) {
      if (keyb_inp.length() > 0)
        keyb_inp.remove(keyb_inp.length() - 1, 1);
      //Serial.println(keyb_inp);
      nokia5110lcd.fillRect(0, 20, 84, 28, WHITE);
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print(keyb_inp);
      nokia5110lcd.display();
    }
    encoder_button.tick();
    if (encoder_button.hasClicks(4)) {
      cont_to_send = true;
      cont_to_next = true;
    }
    if (encoder_button.hasClicks(5)) {
      keyb_inp = "";
      cont_to_next = true;
      return;
    }

    if (cont_to_send == true) {
      /*
      Serial.print("\nTitle: ");
      Serial.println(ttl_to_be_st_onl);
      Serial.print("Content: ");
      Serial.println(keyb_inp);
      */
      encr_and_send(ttl_to_be_st_onl);
      keyb_inp = "";

    }
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
  encr_for_onl_st = "";

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

  if (upd_ch == true) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(12, 0);
    nokia5110lcd.print("Connected!");
    nokia5110lcd.setCursor(6, 12);
    nokia5110lcd.print("Updating the");
    nokia5110lcd.setCursor(21, 20);
    nokia5110lcd.print("channel");
    nokia5110lcd.display();

    ThingSpeak.setField(1, encr_t);
    ThingSpeak.setField(2, encr_for_onl_st);

    int x = ThingSpeak.writeFields(myChannelNumber, myWriteAPIKey);

    if (x == 200) {
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
      nokia5110lcd.print("Channel updatd");
      nokia5110lcd.setCursor(6, 8);
      nokia5110lcd.print("successfully");
      nokia5110lcd.display();
    } else {
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
      nokia5110lcd.print("Something went");
      nokia5110lcd.setCursor(0, 8);
      nokia5110lcd.print("wrong:");
      nokia5110lcd.print(String(x));
      nokia5110lcd.display();
    }
    delay(1500);
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(0, 40);
    nokia5110lcd.println("              ");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(9, 40);
    nokia5110lcd.println("to continue");
    nokia5110lcd.display();

    bool cont_to_next = false;
    while (cont_to_next == false) {
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press())
        cont_to_next = true;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        cont_to_next = true;
      delayMicroseconds(400);
    }
    return;
  } else
    return;
}

void decr_onl_st_note_from_thingspeak() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    upd_ch = true;
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(3, 0);
    nokia5110lcd.print("Connecting to");
    nokia5110lcd.setCursor(9, 8);
    nokia5110lcd.print("the network");
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.print("If it taks too");
    nokia5110lcd.setCursor(0, 24);
    nokia5110lcd.print("long, hold the");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.print("encoder button");
    nokia5110lcd.setCursor(0, 40);
    nokia5110lcd.print("and try again.");
    nokia5110lcd.display();
    if (WiFi.status() != WL_CONNECTED) {
      while (WiFi.status() != WL_CONNECTED) {
        WiFi.begin(ssid, password);
        delay(1900);
        encoder_button.tick();
        if (encoder_button.isPress() || encoder_button.isHolded() || encoder_button.isHold()) {
          upd_ch = false;
          break;
        }
        delay(400);
      }
    }
    if (upd_ch == true) {
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(12, 0);
      nokia5110lcd.print("Connected!");
      nokia5110lcd.setCursor(9, 12);
      nokia5110lcd.print("Reading the");
      nokia5110lcd.setCursor(21, 20);
      nokia5110lcd.print("channel");
      nokia5110lcd.setCursor(3, 32);
      nokia5110lcd.print("It might take");
      nokia5110lcd.setCursor(21, 40);
      nokia5110lcd.print("a while");
      nokia5110lcd.display();
      String ct1 = ThingSpeak.readStringField(myChannelNumber, 1, myReadAPIKey);
      delay(250);
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
      for (byte i = 0; i < 16; i++) {
        if (authCode[i] < 0x10) {
          res_hash += 0;
        } {
          res_hash += String(authCode[i], HEX);
        }
      }
      /*
      Serial.print("Computed tag: ");
      Serial.println(res_hash);
      */
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setTextColor(BLACK, WHITE);
      nokia5110lcd.setCursor(0, 0);
      nokia5110lcd.print("Title:");
      nokia5110lcd.print(dec_title);
      nokia5110lcd.setCursor(0, 20);
      nokia5110lcd.print("Content:");
      nokia5110lcd.print(dec_st);
      nokia5110lcd.display();
      /*
      if(x == 200){
          tft.println("Channel read successfully");
        }
        else{
          tft.setTextColor(0xf800, 0x3186);
          tft.print("Something went wrong.\nError code ");
          tft.println(String(x));
        }
      */
      if (dec_tag.equals(res_hash) == false) {
        bool cont_to_next1 = false;
        while (cont_to_next1 == false) {
          encoder_button.tick();
          if (encoder_button.press())
            cont_to_next1 = true;
          delayMicroseconds(400);
          a_button.tick();
          if (a_button.press())
            cont_to_next1 = true;
          delayMicroseconds(400);
          b_button.tick();
          if (b_button.press())
            cont_to_next1 = true;
          delayMicroseconds(400);
        }
        nokia5110lcd.clearDisplay();
        nokia5110lcd.setCursor(0, 32);
        nokia5110lcd.println("              ");
        nokia5110lcd.setCursor(0, 41);
        nokia5110lcd.println("              ");
        nokia5110lcd.setCursor(0, 32);
        nokia5110lcd.println("Integrity veri");
        nokia5110lcd.setCursor(0, 41);
        nokia5110lcd.println("fication faild");
        nokia5110lcd.display();
      }
      dec_st = "";
      dec_tag = "";
      decract = 0;
      bool cont_to_next = false;
      while (cont_to_next == false) {
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
        a_button.tick();
        if (a_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
        b_button.tick();
        if (b_button.press())
          cont_to_next = true;
        delayMicroseconds(400);
      }
      return;

    } else
      return;
  }
}

void decr_onl_st_note_from_serial() {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the encr");
    nokia5110lcd.setCursor(6, 8);
    nokia5110lcd.print("title to the");
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.print("Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the encrypted title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
        break;
      }
    }
    if (canc_op == true)
      break;
    String ct1 = Serial.readString();
    int ct_len1 = ct1.length() + 1;
    char ct_array1[ct_len1];
    ct1.toCharArray(ct_array1, ct_len1);
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Paste the encr");
    nokia5110lcd.setCursor(0, 8);
    nokia5110lcd.print("content to the");
    nokia5110lcd.setCursor(0, 16);
    nokia5110lcd.print("Serial Monitor");
    nokia5110lcd.setCursor(0, 32);
    nokia5110lcd.println("Press any bttn");
    nokia5110lcd.setCursor(15, 40);
    nokia5110lcd.println("to cancel");
    nokia5110lcd.display();
    Serial.println("\nPaste the encrypted content here:");
    while (!Serial.available()) {
      encoder_button.tick();
      if (encoder_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press()) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true) {
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
    for (byte i = 0; i < 16; i++) {
      if (authCode[i] < 0x10) {
        res_hash += 0;
      } {
        res_hash += String(authCode[i], HEX);
      }
    }
    /*
    Serial.print("Computed tag: ");
    Serial.println(res_hash);
    */
    nokia5110lcd.clearDisplay();
    nokia5110lcd.setTextColor(BLACK, WHITE);
    nokia5110lcd.setCursor(0, 0);
    nokia5110lcd.print("Title:");
    nokia5110lcd.print(dec_title);
    nokia5110lcd.setCursor(0, 20);
    nokia5110lcd.print("Content:");
    nokia5110lcd.print(dec_st);
    nokia5110lcd.display();
    /*
    if(x == 200){
        tft.println("Channel read successfully");
      }
      else{
        tft.setTextColor(0xf800, 0x3186);
        tft.print("Something went wrong.\nError code ");
        tft.println(String(x));
      }
    */
    if (dec_tag.equals(res_hash) == false) {
      bool cont_to_next1 = false;
      while (cont_to_next1 == false) {
        encoder_button.tick();
        if (encoder_button.press())
          cont_to_next1 = true;
        delayMicroseconds(400);
        a_button.tick();
        if (a_button.press())
          cont_to_next1 = true;
        delayMicroseconds(400);
        b_button.tick();
        if (b_button.press())
          cont_to_next1 = true;
        delayMicroseconds(400);
      }
      nokia5110lcd.clearDisplay();
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("              ");
      nokia5110lcd.setCursor(0, 32);
      nokia5110lcd.println("Integrity veri");
      nokia5110lcd.setCursor(0, 41);
      nokia5110lcd.println("fication faild");
      nokia5110lcd.display();
    }
    dec_st = "";
    dec_tag = "";
    decract = 0;
    bool cont_to_next = false;
    while (cont_to_next == false) {
      encoder_button.tick();
      if (encoder_button.press())
        cont_to_next = true;
      delayMicroseconds(400);
      a_button.tick();
      if (a_button.press())
        cont_to_next = true;
      delayMicroseconds(400);
      b_button.tick();
      if (b_button.press())
        cont_to_next = true;
      delayMicroseconds(400);
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
      encr_for_onl_st += String(ct2.b[i], HEX);
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
  nokia5110lcd.begin();
  nokia5110lcd.setContrast(contrastValue);
  display_cipherbox_icon();
  nokia5110lcd.setTextColor(BLACK, WHITE);
  nokia5110lcd.setTextSize(1);
  nokia5110lcd.setCursor(0, 13);
  nokia5110lcd.print("Cipherbox V3.0");
  nokia5110lcd.setCursor(30, 22);
  nokia5110lcd.println("Lite");
  nokia5110lcd.display();
  m = 2; // Set AES to 256 bit
  cur_pos = 0;
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
  nokia5110lcd.setCursor(6, 33);
  nokia5110lcd.println("Double-click");
  nokia5110lcd.setCursor(0, 41);
  nokia5110lcd.println("encoder button");
  nokia5110lcd.display();
  while (!encoder_button.hasClicks(2)) {
    encoder_button.tick();
    delay(1);
  }
  log_in();
}

void loop() {
  back_keys();
  delayMicroseconds(400);
  enc0.tick();
  if (enc0.left())
    curr_key--;
  if (enc0.right())
    curr_key++;

  if (curr_key < 0)
    curr_key = 11;

  if (curr_key > 11)
    curr_key = 0;

  if (enc0.turn()) {
    main_menu(curr_key);
  }

  delayMicroseconds(400);

  a_button.tick();
  bool ch = false;
  if (a_button.press() == true)
    ch = true;

  if (ch == true && curr_key == 0)
    show_loc_st_login_menu();

  if (ch == true && curr_key == 1)
    show_loc_st_credit_cards();

  if (ch == true && curr_key == 2)
    show_loc_st_notes();

  if (ch == true && curr_key == 3)
    Blfish_AES_Serp_AES_menu();

  if (ch == true && curr_key == 4)
    AES_Serp_AES_menu();

  if (ch == true && curr_key == 5)
    Blowfish_Serpent_menu();

  if (ch == true && curr_key == 6)
    AES_Serpent_menu();

  if (ch == true && curr_key == 7)
    Serpent_menu();

  if (ch == true && curr_key == 8)
    TDES_menu();

  if (ch == true && curr_key == 9)
    show_hfunc_m();

  if (ch == true && curr_key == 10)
    show_sql_m();

  if (ch == true && curr_key == 11)
    online_stored_notes_menu();

}
