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
https://github.com/intrbiz/arduino-crypto
https://github.com/Chris--A/Keypad
https://github.com/platisd/nokia-5110-lcd-library
*/
#include <SoftwareSerial.h>
SoftwareSerial mySerial(34, 35); // RX, TX
#include <esp_now.h>
#include <WiFi.h>
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
int num_of_IDs;
String dbase_name;
int count;
byte tmp_st[8];
char temp_st_for_pp[16];
int m;
int n;
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
bool send_setup;

uint8_t broadcastAddress[] = {0x5C, 0xCF, 0x7F, 0xFD, 0x85, 0x1D}; // Receiver's MAC address

byte hmackey_for_session_key[] = {"73KkjhYSsKw2WorCJ55d7Lxp62Hk5mvYvFZz9w8mik1o8qgbss4Ro1DdRknqy501XYk0ciL7WkBpUhZg85jlU4ZCz31329t8N9yn77a4S2ujs3QR9qClpk25f9LOXNydkGwV35Y7Thn6jz3ALcHO2tuh4Auy6408Y0bFgPBa3o6B18U98x4iAqERs18yU497sxDiyn8Ilxdnz6BeYtQYLaf3la0Ekwb226Mwn4n4EKdaTCr16oT650J9ZkcdF2X6j0ZVeTTMY1Ys2mVA7p"};
uint8_t projection_key[32] = {
0xbf,0xec,0xff,0x39,
0xdc,0xa4,0xa0,0x6b,
0xb9,0x4a,0xdb,0xf4,
0x12,0x8e,0x79,0x24,
0x05,0x60,0xc7,0x7e,
0xdb,0xba,0x27,0x12,
0x79,0xdb,0xe5,0xab,
0xa0,0xc0,0x7e,0x41
};
uint8_t proj_serp_key[32] = {
0x40,0x62,0xbc,0xa1,
0xdf,0xa1,0x05,0x09,
0xcf,0x04,0xda,0xc5,
0x7d,0xcf,0xc5,0x9d,
0x4f,0x0b,0x67,0x03,
0x00,0x80,0x27,0xd0,
0xe6,0x83,0x28,0xdb,
0xdd,0xf2,0xdd,0x8a
};
byte hmackey[] = {"eZ3SBzRa43tj40S1mMubKT0tD0x7OEM4flKryHqobk1SlgKgpcdHs3b16s2vs9tuZIcSb8P8eSAB71zgTd7d3eux4nFnWU1rJ4w32Jz12d54rfiqskAlBP3415557C14NDWwG9JRoRoJW22To2ra9gTbiQv2Cc6n0TS87B8w16RbbC7pq8wowBgfYdRLtw3297EExo2s3yXs953J83g31yVV8bWv1NuYWY38u87f267B6ENa763F3t5o5uCdJW4puOu"};
unsigned char Blwfsh_key[] = {
0xaa,0x6f,0x0f,0xc0,
0xa3,0xe7,0x62,0x1e,
0x3d,0x97,0xe0,0x2d,
0x62,0x4e,0xfe,0x7e,
0x6e,0xcf,0x07,0x29,
0x4d,0x10,0xec,0xe3
};
uint8_t key[32] = {
0x7f,0xed,0xdd,0xac,
0xbf,0x00,0xcf,0xe7,
0xfc,0xd5,0x3d,0xbf,
0xdc,0x99,0xda,0xf0,
0xc9,0x51,0xff,0x62,
0xc2,0x55,0x7c,0x97,
0xbf,0x9c,0xb0,0xff,
0x2e,0x76,0x1f,0x0f
};
uint8_t serp_key[32] = {
0xbc,0xdf,0x7a,0x8b,
0xba,0x98,0x9d,0xeb,
0xd5,0xf5,0xc4,0xcc,
0x4b,0xd8,0xa7,0xce,
0xfc,0x1a,0xf9,0x34,
0xc9,0x8f,0xd0,0x08,
0x8c,0xfc,0xa5,0x7c,
0x4b,0x23,0x8f,0x6f
};
uint8_t second_key[32] = {
0xee,0x45,0xa3,0xb3,
0x8f,0x91,0xca,0x6a,
0x6c,0xa6,0x1a,0x4a,
0x9f,0xf1,0x13,0x44,
0x28,0xb1,0xee,0xb5,
0x8a,0xef,0x2c,0x6b,
0xa6,0x97,0xa4,0xee,
0x85,0xe8,0xff,0x9b
};

struct myStruct {
  char x;
};

int clb_m;

typedef struct struct_message {
  char l_srp[16];
  char r_srp[16];
  bool n;
} struct_message;

struct_message myData;

esp_now_peer_info_t peerInfo;

void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  Serial.print("\r\nLast Packet Send Status:\t");
  Serial.println(status == ESP_NOW_SEND_SUCCESS ? "Delivery Success" : "Delivery Fail");
}

const char* data = "Callback function called";
static int callback(void *data, int argc, char **argv, char **azColName) {
   int i;
   if (clb_m == 0) //Print in serial
    Serial.printf("%s: ", (const char*)data);
   if (clb_m == 1){ //Print in serial
    tft.printf("%s:\n", (const char*)data);
   }
   for (i = 0; i<argc; i++){
       if (clb_m == 0){ //Print in serial
        Serial.printf("\n%s = %s", azColName[i], argv[i] ? argv[i] : "Empty");
        Serial.printf("\n\n");
       }
       if (clb_m == 1){ //Print in tft
        tft.printf("\n%s = %s\n", azColName[i], argv[i] ? argv[i] : "Empty");
        Serial.printf("\n\n");
       }
       if (clb_m == 2){ //Decrypt
        int ct_len = strlen(argv[i]) + 1;
        char ct_array[ct_len];
        snprintf(ct_array, ct_len, "%s", argv[i]);
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
        split_dec(ct_array, ct_len, 0+ext, ch, true);
        ext+=32;
        count++;
        }
        rest_Blwfsh_k();
        rest_k();
        rest_serp_k();
        rest_s_k();
       }
       if (clb_m == 3){ //Extract IDs
        int ct_len = strlen(argv[i]) + 1;
        char ct_array[ct_len];
        snprintf(ct_array, ct_len, "%s", argv[i]);
        for (int i = 0; i<ct_len; i++){
          dec_st += ct_array[i];
        }
        dec_st += "\n";
        num_of_IDs++;
       }
   }
   return 0;
}

void split_by_eight(char plntxt[], int k, int str_len, bool add_aes, bool out_f){
  char plt_data[] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      plt_data[i] = plntxt[i+k];
  }
  /*
  Serial.println("\nInput");
  for (int i = 0; i < 8; i++){
    Serial.print(plt_data[i]);
    Serial.print(" ");
  }
  */
  unsigned char t_encr[8];
  for(int i = 0; i < 8; i++){
      t_encr[i] = (unsigned char)plt_data[i];
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
  for(int i = 0; i < 8; i++){
      encr_for_aes[i] = char(int(t_encr[i]));
  }
  /*
  Serial.println("\nEncrypted");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  for(int i = 8; i < 16; i++){
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

void encr_AES(char t_enc[], bool add_aes, bool out_f){
  uint8_t text[16];
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  aes_context ctx;
  aes_set_key(&ctx, key, key_bit[2]);
  aes_encrypt_block(&ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for(int i = 0; i<8; i++){
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for(int i = 0; i<8; i++){
    R_half[i] = cipher_text[i+8];
  }
  for(int i = 8; i<16; i++){
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  serp_enc(L_half, add_aes, out_f);
  serp_enc(R_half, add_aes, out_f);
}

void serp_enc(char res[], bool add_aes, bool out_f){
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
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
  uint32_t *p;
  
  for (b=0; b<1; b++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
  if(add_aes == false){
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
    }
  }
  if(add_aes == true)
  encr_sec_AES(ct2.b, out_f);
  }
}

void encr_sec_AES(byte t_enc[], bool out_f){
  uint8_t text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t second_key_bit[3] = {128, 192, 256};
  int i = 0;
  aes_context ctx;
  aes_set_key(&ctx, second_key, second_key_bit[2]);
  aes_encrypt_block(&ctx, cipher_text, text);
  for (i = 0; i < 16; i++) {
    if (out_f == false)
      Serial.printf("%02x", cipher_text[i]);
    if (out_f == true){
      if (cipher_text[i] < 16)
        dec_st += 0;
      dec_st +=  String(cipher_text[i], HEX);
    }
  }
}

void split_dec(char ct[], int ct_len, int p, bool ch, bool add_r){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
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
      if(add_r == true){
      uint8_t ret_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t second_key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, second_key, second_key_bit[2]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 16; i++) {
        res[i] = (char)ret_text[i];
      }
      }
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<1; i++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
    if (ch == false){
    for (int i=0; i<8; i++) {
      tmp_st[i] = char(ct2.b[i]);
    }
    }
    if (ch == true){
      decr_AES_and_blwfsh(ct2.b);
    }
  }
}

void decr_AES_and_blwfsh(byte sh[]){
  uint8_t ret_text[16];
  for(int i = 0; i<8; i++){
    ret_text[i] = tmp_st[i];
  }
  for(int i = 0; i<8; i++){
    ret_text[i+8] = sh[i];
  }
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(ret_text[i]);
        cipher_text[i] = c;
      }
      uint32_t key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, key, key_bit[2]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      /*
      Serial.println("\nDec by AES");
      for (int i = 0; i < 16; i++){\
        Serial.print(int(ret_text[i]));
        Serial.print(" ");
      }
      Serial.println();
      */
      unsigned char dbl[8];
      for (int i = 0; i < 8; i++){
        dbl[i] = (unsigned char)int(ret_text[i]);
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
      if (decract < 4){
        for (int i = 0; i < 8; i++){
          if (dbl[i]<0x10)
            dec_tag += 0;
          dec_tag += String(dbl[i], HEX);
        }
      }
      else{
        for (i = 0; i < 8; ++i) {
          dec_st += (char(dbl[i]));
        }
      }
      decract ++;
}

void gen_rand_ID(int n_itr){
  for (int i = 0; i<n_itr; i++){
    int r_numb3r = esp_random()%95;
    if (r_numb3r != 7)
      rec_ID += char(32 + r_numb3r);
    else
      rec_ID += char(33 + r_numb3r + esp_random()%30);
  }
}

int gen_r_num(){
  int rn = esp_random()%256;
  return rn;
}

int db_open(const char *filename, sqlite3 **db) {
   int rc = sqlite3_open(filename, db);
   if (rc) {
       if (clb_m == 0) //Print in serial
        Serial.printf("Can't open database: %s\n", sqlite3_errmsg(*db));
       if (clb_m == 1) //Print in tft
        tft.printf("Can't open database: %s\n", sqlite3_errmsg(*db));
       return rc;
   } else {
       if (clb_m == 0) //Print in serial
        Serial.printf("Opened database successfully\n");
       if (clb_m == 1) //Print in tft
        tft.printf("Opened database successfully\n");
   }
   return rc;
}

char *zErrMsg = 0;
int db_exec(sqlite3 *db, const char *sql) {
   int rc = sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg);
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

void back_k(){
  for(int i = 0; i<32; i++){
    back_key[i] = key[i];
  }
}

void rest_k(){
  for(int i = 0; i<32; i++){
    key[i] = back_key[i];
  }
}

void back_serp_k(){
  for(int i = 0; i<32; i++){
    back_serp_key[i] = serp_key[i];
  }
}

void rest_serp_k(){
  for(int i = 0; i<32; i++){
    serp_key[i] = back_serp_key[i];
  }
}

void back_s_k(){
  for(int i = 0; i<32; i++){
    back_s_key[i] = second_key[i];
  }
}

void rest_s_k(){
  for(int i = 0; i<32; i++){
    second_key[i] = back_s_key[i];
  }
}

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

void incr_projection_key() {
  if (projection_key[0] == 255) {
    projection_key[0] = 0;
    if (projection_key[1] == 255) {
      projection_key[1] = 0;
      if (projection_key[2] == 255) {
        projection_key[2] = 0;
        if (projection_key[3] == 255) {
          projection_key[3] = 0;

          if (projection_key[4] == 255) {
            projection_key[4] = 0;
            if (projection_key[5] == 255) {
              projection_key[5] = 0;
              if (projection_key[6] == 255) {
                projection_key[6] = 0;
                if (projection_key[7] == 255) {
                  projection_key[7] = 0;

                  if (projection_key[8] == 255) {
                    projection_key[8] = 0;
                    if (projection_key[9] == 255) {
                      projection_key[9] = 0;
                      if (projection_key[10] == 255) {
                        projection_key[10] = 0;
                        if (projection_key[11] == 255) {
                          projection_key[11] = 0;

                          if (projection_key[12] == 255) {
                            projection_key[12] = 0;
                            if (projection_key[13] == 255) {
                              projection_key[13] = 0;
                              if (projection_key[14] == 255) {
                                projection_key[14] = 0;
                                if (projection_key[15] == 255) {
                                  projection_key[15] = 0;
                                } else {
                                  projection_key[15]++;
                                }
                              } else {
                                projection_key[14]++;
                              }
                            } else {
                              projection_key[13]++;
                            }
                          } else {
                            projection_key[12]++;
                          }

                        } else {
                          projection_key[11]++;
                        }
                      } else {
                        projection_key[10]++;
                      }
                    } else {
                      projection_key[9]++;
                    }
                  } else {
                    projection_key[8]++;
                  }

                } else {
                  projection_key[7]++;
                }
              } else {
                projection_key[6]++;
              }
            } else {
              projection_key[5]++;
            }
          } else {
            projection_key[4]++;
          }

        } else {
          projection_key[3]++;
        }
      } else {
        projection_key[2]++;
      }
    } else {
      projection_key[1]++;
    }
  } else {
    projection_key[0]++;
  }
}

void incr_proj_serp_key() {
  if (proj_serp_key[15] == 255) {
    proj_serp_key[15] = 0;
    if (proj_serp_key[14] == 255) {
      proj_serp_key[14] = 0;
      if (proj_serp_key[13] == 255) {
        proj_serp_key[13] = 0;
        if (proj_serp_key[12] == 255) {
          proj_serp_key[12] = 0;

          if (proj_serp_key[11] == 255) {
            proj_serp_key[11] = 0;
            if (proj_serp_key[10] == 255) {
              proj_serp_key[10] = 0;
              if (proj_serp_key[9] == 255) {
                proj_serp_key[9] = 0;
                if (proj_serp_key[8] == 255) {
                  proj_serp_key[8] = 0;

                  if (proj_serp_key[7] == 255) {
                    proj_serp_key[7] = 0;
                    if (proj_serp_key[6] == 255) {
                      proj_serp_key[6] = 0;
                      if (proj_serp_key[5] == 255) {
                        proj_serp_key[5] = 0;
                        if (proj_serp_key[4] == 255) {
                          proj_serp_key[4] = 0;

                          if (proj_serp_key[3] == 255) {
                            proj_serp_key[3] = 0;
                            if (proj_serp_key[2] == 255) {
                              proj_serp_key[2] = 0;
                              if (proj_serp_key[1] == 255) {
                                proj_serp_key[1] = 0;
                                if (proj_serp_key[0] == 255) {
                                  proj_serp_key[0] = 0;
                                } else {
                                  proj_serp_key[0]++;
                                }
                              } else {
                                proj_serp_key[1]++;
                              }
                            } else {
                              proj_serp_key[2]++;
                            }
                          } else {
                            proj_serp_key[3]++;
                          }

                        } else {
                          proj_serp_key[4]++;
                        }
                      } else {
                        proj_serp_key[5]++;
                      }
                    } else {
                      proj_serp_key[6]++;
                    }
                  } else {
                    proj_serp_key[7]++;
                  }

                } else {
                  proj_serp_key[8]++;
                }
              } else {
                proj_serp_key[9]++;
              }
            } else {
              proj_serp_key[10]++;
            }
          } else {
            proj_serp_key[11]++;
          }

        } else {
          proj_serp_key[12]++;
        }
      } else {
        proj_serp_key[13]++;
      }
    } else {
      proj_serp_key[14]++;
    }
  } else {
    proj_serp_key[15]++;
  }
}

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

size_t hex2bin (void *bin) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  for (i=0; i < 32; i++) {
    p[i] = (uint8_t)serp_key[i];
  }
  return 32;
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
    
  for (int i = 0; i < 2000; i++){
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

  for (int i = 0; i < 8; i++){
    Blwfsh_key[i] = (unsigned char) (((int(res1[i+8]) + 1) * (int(h_array[88 + i]) + 1)) % 256);
  }

  for (int i = 0; i < 4; i++){
    second_key[i] = byte(((int(res1[i+18]) + 1) * (int(h_array[98 + i]) + 1)) % 256);
  }
  
  for (int i = 0; i < 3; i++){
    key[i] = byte(tmp_fr_srp[i] ^ int(h_array[60+i]));
  }
  
  key[5] = byte(((int(res1[i]) + 1) * (int(h_array[80 + i]) + 1)) % 256);
  
  for (int i = 2; i < 8; i++){
    second_key[i+8] = byte((((int(ct2.b[i]) + 1) * (int(h1_array[70 + i])) + 2)) % 256);
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
  for(int i = 8; i < 11; i++){
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
  for (int i = 8; i<10; i++){
    thmac += char(((int(res1[i+8]) + 1) * (int(h_array[88 + i]) + 1)) % 256);
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
  for (int i = 3; i < 16; i++){
    serp_key[i] = authCode[i];
  }
  for (int i = 0; i < 10; i++){
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
  create_login_table();
  create_notes_table();
  m_menu_rect(); main_menu(cur_pos); but_panl();
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
   tft.setCursor(40,236);
   tft.print("3.Encr string from Serial");
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
    tft.print("AES (Vulnerable to CPA!!!)");
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
    tft.print("AES (Vulnerable to CPA!!!)");
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
    tft.print("AES (Vulnerable to CPA!!!)");
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
    tft.print("AES (Vulnerable to CPA!!!)");
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
    tft.print("AES (Vulnerable to CPA!!!)");
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
    tft.print("AES (Vulnerable to CPA!!!)");
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
    tft.print("AES (Vulnerable to CPA!!!)");
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
    tft.print("AES (Vulnerable to CPA!!!)");
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
    tft.print("AES (Vulnerable to CPA!!!)");
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
    tft.print("AES (Vulnerable to CPA!!!)");
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

void disp_inp_at_the_bottom(String inpst){
   tft.fillRect(0, 280, 240, 40, 0x1557);
   tft.setTextColor(0x08c5, 0x1557);
   tft.setTextSize(2);
   tft.setCursor(8,282);
   tft.print("Input:");
   tft.setCursor(80,282);
   tft.print("    "); 
   tft.setCursor(80,282);
   tft.print(inpst);
   tft.setCursor(8,302);
   tft.print("Press Esc to cancel."); 
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
  dbase_name = "/spiffs/";
  for(int i = 0; i < 12; i++){
      if (res[i] != 0)
        dbase_name += char(97 + (int(res[i])%26));
      else
        dbase_name += 'a';
  }
  dbase_name += ".db";
  //Serial.println(dbase_name);
}

void create_login_table(){
   exeq_sql_statement("CREATE TABLE if not exists Logins (ID CHARACTER(36), Title TEXT, Username TEXT, Password TEXT, Website Text);");
}

void create_notes_table(){
   exeq_sql_statement("CREATE TABLE if not exists Notes (ID CHARACTER(34), Title TEXT, Content TEXT);");
}

void exeq_sql_statement(char sql_statmnt[]){
   sqlite3 *db1;
   int rc;
   int str_len = dbase_name.length() + 1;
   char input_arr[str_len];
   dbase_name.toCharArray(input_arr, str_len);
   if (db_open(input_arr, &db1))
       return;

   rc = db_exec(db1, sql_statmnt);
   if (rc != SQLITE_OK) {
       sqlite3_close(db1);
       return;
   }

   sqlite3_close(db1);
}

void exeq_sql_statement_from_string(String squery){
   int squery_len = squery.length() + 1;
   char squery_array[squery_len];
   squery.toCharArray(squery_array, squery_len);
   exeq_sql_statement(squery_array);
   return;
}

void Add_login(){
  rec_ID = "";
  gen_rand_ID(36);
  Insert_title_into_the_logins();
}

void Insert_title_into_the_logins(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the title:");
  disp_length_at_the_bottom(0);
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x2145);
        tft.setTextColor(0xe73c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the title:");
      }
  int inpl = keyb_inp.length();
  disp_length_at_the_bottom(inpl);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
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
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    int p = 0;
    for (int i = 0; i < 4; i++){
      incr_key();
      incr_second_key();
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight(hmacchar, p, 100, true, true);
      p+=8;
    }
    p = 0;
    while(str_len > p+1){
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("INSERT INTO Logins (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    dec_st = "";   dec_tag = "";   decract = 0;
   m_menu_rect(); main_menu(cur_pos); but_panl();
    Insert_username_into_logins();
    return;
    }
  if (pr_key == 27){
     keyb_inp = "";
    m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void Insert_username_into_logins(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the username:");
  disp_length_at_the_bottom(0);
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x2145);
        tft.setTextColor(0xe73c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the username:");
      }
  int inpl = keyb_inp.length();
  disp_length_at_the_bottom(inpl);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
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
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    int p = 0;
    for (int i = 0; i < 4; i++){
      incr_key();
      incr_second_key();
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight(hmacchar, p, 100, true, true);
      p+=8;
    }
    p = 0;
    while(str_len > p+1){
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Logins set Username = '" + dec_st + "' where ID = '" + rec_ID + "';");
    dec_st = "";   dec_tag = "";   decract = 0;
   m_menu_rect(); main_menu(cur_pos); but_panl();
    Insert_password_into_logins();
    return;
    }
  if (pr_key == 27){
     keyb_inp = "";
    m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void Insert_password_into_logins(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the password:");
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x2145);
        tft.setTextColor(0xe73c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the password:");
      }
  int inpl = keyb_inp.length();
  disp_length_at_the_bottom(inpl);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
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
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    int p = 0;
    for (int i = 0; i < 4; i++){
      incr_key();
      incr_second_key();
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight(hmacchar, p, 100, true, true);
      p+=8;
    }
    p = 0;
    while(str_len > p+1){
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Logins set Password = '" + dec_st + "' where ID = '" + rec_ID + "';");
    dec_st = "";   dec_tag = "";   decract = 0;
   m_menu_rect(); main_menu(cur_pos); but_panl();
    Insert_website_into_logins();
    return;
    }
  if (pr_key == 27){
     keyb_inp = "";
    m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void Insert_website_into_logins(){
  keyb_inp = "";
  tft.fillScreen(0x2145);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the website:");
  disp_length_at_the_bottom(0);
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x2145);
        tft.setTextColor(0xe73c, 0x2145);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the website:");
      }
  int inpl = keyb_inp.length();
  disp_length_at_the_bottom(inpl);
  tft.setTextColor(0xe73c, 0x2145);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
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
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    int p = 0;
    for (int i = 0; i < 4; i++){
      incr_key();
      incr_second_key();
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight(hmacchar, p, 100, true, true);
      p+=8;
    }
    p = 0;
    while(str_len > p+1){
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Logins set Website = '" + dec_st + "' where ID = '" + rec_ID + "';");
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
   m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
    }
  if (pr_key == 27){
     keyb_inp = "";
    m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void Edit_login(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the recrd to edit and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";   dec_tag = "";   decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";   dec_tag = "";   decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
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
    disp_inp_at_the_bottom("");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
        }
    int inpl = keyb_inp.length();
    disp_inp_at_the_bottom(keyb_inp);
    if (pr_key == 13){
      int selected_id = keyb_inp.toInt();
      keyb_inp = "";
      tft.fillScreen(0xfaa6);
      tft.setTextColor(0xffff, 0xfaa6);
      tft.setTextSize(2);
      tft.fillRect(312, 0, 320, 240, 0x12ea);
      tft.setCursor(0,5);
      tft.println("Enter new password:");
      disp_length_at_the_bottom(inpl);
      while (pr_key != 27){
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
          ch = data.x;
          pr_key = int(ch);
          if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
            keyb_inp += ch;
          }
          else if (ch == 127) {
            if(keyb_inp.length() > 0)
              keyb_inp.remove(keyb_inp.length() -1, 1);
            tft.fillScreen(0xfaa6);
            tft.setTextColor(0xffff, 0xfaa6);
            tft.setTextSize(2);
            tft.setCursor(0,5);
            tft.println("Enter new password:");
      }
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xffff, 0xfaa6);
      tft.setCursor(0,25);
      tft.println(keyb_inp);
      if (pr_key == 13){
        clb_m = 1;
        dec_st = "";   dec_tag = "";   decract = 0;
        tft.fillScreen(0x3186);
        tft.setTextColor(0xffff, 0x3186);
        tft.setTextSize(1);
        tft.setCursor(0,0);
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
        for (int i = 0; i < 32; i++){
          hmacchar[i] = char(authCode[i]);
        }
        int p = 0;
        for (int i = 0; i < 4; i++){
          incr_key();
          incr_second_key();
          incr_Blwfsh_key();
          incr_serp_key();
          split_by_eight(hmacchar, p, 100, true, true);
          p+=8;
        }
        p = 0;
        while(str_len > p+1){
          incr_Blwfsh_key();
          incr_key();
          incr_serp_key();
          incr_second_key();
          split_by_eight(keyb_inp_arr, p, str_len, true, true);
          p+=8;
        }
        rest_Blwfsh_k();
        rest_k();
        rest_serp_k();
        rest_s_k();
        //Serial.println(dec_st);
        exeq_sql_statement_from_string("UPDATE Logins set Password = '" + dec_st + "' where ID = '" + IDs[selected_id][0] + "';");
        dec_st = "";   dec_tag = "";   decract = 0;
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
        keyb_inp = "";
        while (!bus.gotData()){
          bus.tick();
        }
       m_menu_rect(); main_menu(cur_pos); but_panl();
        return;
      }
      if (pr_key == 27){
         keyb_inp = "";
       m_menu_rect(); main_menu(cur_pos); but_panl();
        return;
      }
    }
 }
      }
    if (pr_key == 27){
      keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
   } 
  }
 
  }
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
   m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
}

void Remove_login(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the rec to delete and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";   dec_tag = "";   decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";   dec_tag = "";   decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
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
    disp_inp_at_the_bottom("");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
        }
    int inpl = keyb_inp.length();
    disp_inp_at_the_bottom(keyb_inp);
    if (pr_key == 13){
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0,0);
      exeq_sql_statement_from_string("DELETE FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
      keyb_inp = "";
      while (!bus.gotData()){
        bus.tick();
      }
     m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
      }
    if (pr_key == 27){
      keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
   } 
  }
 
  }
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
   m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
}

void View_login(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the recrd to view and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";   dec_tag = "";   decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";   dec_tag = "";   decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
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
    disp_inp_at_the_bottom("");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
        }
    int inpl = keyb_inp.length();
    disp_inp_at_the_bottom(keyb_inp);
    if (pr_key == 13){
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0,2);
      clb_m = 2;
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      bool title_integrity = verify_integrity();
      if (title_integrity == true)
        tft.setTextColor(0xe73c, 0x3186);
      else
        tft.setTextColor(0xf800, 0x3186);
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      bool username_integrity = verify_integrity();
      if (username_integrity == true)
        tft.setTextColor(0xe73c, 0x3186);
      else
        tft.setTextColor(0xf800, 0x3186);
      tft.print("Username:");
      tft.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT Password FROM Logins WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      bool password_integrity = verify_integrity();
      if (password_integrity == true)
        tft.setTextColor(0xe73c, 0x3186);
      else
        tft.setTextColor(0xf800, 0x3186);
      tft.print("Password:");
      tft.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
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
      if (title_integrity == false || username_integrity == false || password_integrity == false || website_integrity == false){
        tft.setTextColor(0xf800, 0x3186);
        tft.println("Integrity verification failed!!!");
      }
      dec_st = "";   dec_tag = "";   decract = 0;
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
      keyb_inp = "";
      while (!bus.gotData()){
        bus.tick();
      }
     m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
      }
    if (pr_key == 27){
      keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
   } 
  }
 
  }
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
   m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
}

void Show_all_logins(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Logins");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() -1, 1);
    }
    dec_st = "";   dec_tag = "";   decract = 0;
    for (int i = 0; i < num_of_IDs; i++){
      Serial.print(IDs[i]);
    }
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Logins WHERE ID = '" + IDs[i] + "'");
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT Username FROM Logins WHERE ID = '" + IDs[i] + "'");
      tft.print("Username:");
      tft.println(dec_st);
      tft.println("----------------------------------------");
      dec_st = "";   dec_tag = "";   decract = 0;
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
  }
  else{
    tft.print("Empty");
  }
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  keyb_inp = "";
  while (!bus.gotData()){
    bus.tick();
  }
 m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
}

void Add_note(){
  rec_ID = "";
  gen_rand_ID(34);
  Insert_title_into_the_notes();
}

void Insert_title_into_the_notes(){
  keyb_inp = "";
  tft.fillScreen(0x4a49);
  tft.setTextColor(0x8606, 0x4a49);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the title:");
  disp_length_at_the_bottom(0);
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x4a49);
        tft.setTextColor(0x8606, 0x4a49);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the title:");
      }
  int inpl = keyb_inp.length();
  disp_length_at_the_bottom(inpl);
  tft.setTextColor(0x8606, 0x4a49);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
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
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    int p = 0;
    for (int i = 0; i < 4; i++){
      incr_key();
      incr_second_key();
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight(hmacchar, p, 100, true, true);
      p+=8;
    }
    p = 0;
    while(str_len > p+1){
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("INSERT INTO Notes (ID, Title) VALUES( '" + rec_ID + "','" + dec_st + "');");
    dec_st = "";   dec_tag = "";   decract = 0;
   m_menu_rect(); main_menu(cur_pos); but_panl();
    Insert_content_into_the_notes();
    return;
    }
  if (pr_key == 27){
     keyb_inp = "";
    m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void Insert_content_into_the_notes(){
  keyb_inp = "";
  tft.fillScreen(0x4a49);
  tft.setTextColor(0x8606, 0x4a49);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the note:");
  disp_length_at_the_bottom(0);
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x4a49);
        tft.setTextColor(0x8606, 0x4a49);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the note:");
      }
  int inpl = keyb_inp.length();
  disp_length_at_the_bottom(inpl);
  tft.setTextColor(0x8606, 0x4a49);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
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
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    int p = 0;
    for (int i = 0; i < 4; i++){
      incr_key();
      incr_second_key();
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight(hmacchar, p, 100, true, true);
      p+=8;
    }
    p = 0;
    while(str_len > p+1){
      incr_Blwfsh_key();
      incr_key();
      incr_serp_key();
      incr_second_key();
      split_by_eight(keyb_inp_arr, p, str_len, true, true);
      p+=8;
    }
    rest_Blwfsh_k();
    rest_k();
    rest_serp_k();
    rest_s_k();
    //Serial.println(dec_st);
    exeq_sql_statement_from_string("UPDATE Notes set Content = '" + dec_st + "' where ID = '" + rec_ID + "';");
    dec_st = "";   dec_tag = "";   decract = 0;
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
   m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
    }
  if (pr_key == 27){
     keyb_inp = "";
    m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void Edit_note(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the recrd to edit and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";   dec_tag = "";   decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";   dec_tag = "";   decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
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
    disp_inp_at_the_bottom("");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
        }
    int inpl = keyb_inp.length();
    disp_inp_at_the_bottom(keyb_inp);
    if (pr_key == 13){
      int selected_id = keyb_inp.toInt();
      keyb_inp = "";
      tft.fillScreen(0xfaa6);
      tft.setTextColor(0xffff, 0xfaa6);
      tft.setTextSize(2);
      tft.setCursor(0,5);
      tft.println("Enter the new note:");
      disp_length_at_the_bottom(0);
      while (pr_key != 27){
        bus.tick();
        if (bus.gotData()) {
          myStruct data;
          bus.readData(data);
          // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
          ch = data.x;
          pr_key = int(ch);
          if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
            keyb_inp += ch;
          }
          else if (ch == 127) {
            if(keyb_inp.length() > 0)
              keyb_inp.remove(keyb_inp.length() -1, 1);
            tft.fillScreen(0xfaa6);
            tft.setTextColor(0xffff, 0xfaa6);
            tft.setTextSize(2);
            tft.setCursor(0,5);
            tft.println("Enter the new note:");
      }
      int inpl = keyb_inp.length();
      disp_length_at_the_bottom(inpl);
      tft.setTextColor(0xffff, 0xfaa6);
      tft.setCursor(0,25);
      tft.println(keyb_inp);
      if (pr_key == 13){
        clb_m = 1;
        dec_st = "";   dec_tag = "";   decract = 0;
        tft.fillScreen(0x3186);
        tft.setTextColor(0xe73c, 0x3186);
        tft.setTextSize(1);
        tft.setCursor(0,0);
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
        for (int i = 0; i < 32; i++){
          hmacchar[i] = char(authCode[i]);
        }
        int p = 0;
        for (int i = 0; i < 4; i++){
          incr_key();
          incr_second_key();
          incr_Blwfsh_key();
          incr_serp_key();
          split_by_eight(hmacchar, p, 100, true, true);
          p+=8;
        }
        p = 0;
        while(str_len > p+1){
          incr_Blwfsh_key();
          incr_key();
          incr_serp_key();
          incr_second_key();
          split_by_eight(keyb_inp_arr, p, str_len, true, true);
          p+=8;
        }
        rest_Blwfsh_k();
        rest_k();
        rest_serp_k();
        rest_s_k();
        //Serial.println(dec_st);
        exeq_sql_statement_from_string("UPDATE Notes set Content = '" + dec_st + "' where ID = '" + IDs[selected_id][0] + "';");
        dec_st = "";   dec_tag = "";   decract = 0;
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
        keyb_inp = "";
        while (!bus.gotData()){
          bus.tick();
        }
       m_menu_rect(); main_menu(cur_pos); but_panl();
        return;
      }
      if (pr_key == 27){
         keyb_inp = "";
       m_menu_rect(); main_menu(cur_pos); but_panl();
        return;
      }
    }
 }
      }
    if (pr_key == 27){
      keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
   } 
  }
 
  }
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
   m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
}

void Remove_note(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the rec to delete and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";   dec_tag = "";   decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";   dec_tag = "";   decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
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
    disp_inp_at_the_bottom("");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
        }
    int inpl = keyb_inp.length();
    disp_inp_at_the_bottom(keyb_inp);
    tft.print(keyb_inp);
    if (pr_key == 13){
      clb_m = 1;
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0,0);
      exeq_sql_statement_from_string("DELETE FROM Notes WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
      keyb_inp = "";
      while (!bus.gotData()){
        bus.tick();
      }
     m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
      }
    if (pr_key == 27){
      keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
   } 
  }
 
  }
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
   m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
}

void View_note(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  tft.print("Select the recrd to view and press Enter");
  tft.setCursor(0,12);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs][2];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id][0] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i][0].length() > 0)
        IDs[i][0].remove(IDs[i][0].length() -1, 1);
    }
    dec_st = "";   dec_tag = "";   decract = 0;
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[i][0] + "'");
      IDs[i][1] = dec_st;
      dec_st = "";   dec_tag = "";   decract = 0;
    }
    clb_m = 0;
    Serial.println("\nStored records:");
    for (int i = 0; i < num_of_IDs; i++){
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
    disp_inp_at_the_bottom("");
    while (pr_key != 27){
      bus.tick();
      if (bus.gotData()) {
        myStruct data;
        bus.readData(data);
        // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
        ch = data.x;
        pr_key = int(ch);
        if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11 && keyb_inp.length() < 4){
          keyb_inp += ch;
        }
        else if (ch == 127) {
          if(keyb_inp.length() > 0)
            keyb_inp.remove(keyb_inp.length() -1, 1);
        }
    int inpl = keyb_inp.length();
    disp_inp_at_the_bottom(keyb_inp);
    if (pr_key == 13){
      tft.fillScreen(0x3186);
      tft.setTextColor(0xe73c, 0x3186);
      tft.setTextSize(1);
      tft.setCursor(0,2);
      clb_m = 2;
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      bool title_integrity = verify_integrity();
      if (title_integrity == true)
        tft.setTextColor(0xe73c, 0x3186);
      else
        tft.setTextColor(0xf800, 0x3186);
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      exeq_sql_statement_from_string("SELECT Content FROM Notes WHERE ID = '" + IDs[keyb_inp.toInt()][0] + "'");
      bool note_integrity = verify_integrity();
      if (note_integrity == true)
        tft.setTextColor(0xe73c, 0x3186);
      else
        tft.setTextColor(0xf800, 0x3186);
      tft.print("Note:");
      tft.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      tft.setTextColor(0xe73c, 0x3186);
      tft.println("----------------------------------------");
      if (title_integrity == false || note_integrity == false){
        tft.setTextColor(0xf800, 0x3186);
        tft.println("Integrity verification failed!!!");
      }
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
      keyb_inp = "";
      while (!bus.gotData()){
        bus.tick();
      }
     m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
      }
    if (pr_key == 27){
      keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
   } 
  }
 
  }
  else{
    tft.print("Empty");
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
   m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
}

void Show_all_notes(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,2);
  clb_m = 3;
  num_of_IDs = 0;
  exeq_sql_statement_from_string("Select ID FROM Notes");
  if (num_of_IDs != 0){
    String IDs[num_of_IDs];
    //Serial.println(dec_st);
    //Serial.println(num_of_IDs);
    int c_id = 0;
    for (int i = 0; i< dec_st.length()-1; i++){
      if (dec_st.charAt(i) != '\n')
        IDs[c_id] += dec_st.charAt(i);
      else{
        c_id++;
      }
    }
    for (int i = 0; i<num_of_IDs; i++){
      if(IDs[i].length() > 0)
        IDs[i].remove(IDs[i].length() -1, 1);
    }
    dec_st = "";   dec_tag = "";   decract = 0;
    for (int i = 0; i < num_of_IDs; i++){
      Serial.print(IDs[i]);
    }
    clb_m = 2;
    for (int i = 0; i < num_of_IDs; i++){
      exeq_sql_statement_from_string("SELECT Title FROM Notes WHERE ID = '" + IDs[i] + "'");
      tft.print("Title:");
      tft.println(dec_st);
      dec_st = "";   dec_tag = "";   decract = 0;
      tft.println("----------------------------------------");
      dec_st = "";   dec_tag = "";   decract = 0;
    }
    clb_m = 0;
  }
  else{
    tft.print("Empty");
  }
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
  keyb_inp = "";
  while (!bus.gotData()){
    bus.tick();
  }
 m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
}

void disp_length_at_the_bottom(int lofinp){
   tft.fillRect(0, 298, 240, 22, 0x1557);
   tft.setTextColor(0x08c5, 0x1557);
   tft.setTextSize(2);
   tft.setCursor(14,302);
   tft.print("Length:");
   tft.setCursor(98,302);
   tft.print("    "); 
   tft.setCursor(98,302);
   tft.print(lofinp); 
}

void hash_str(){
  tft.fillScreen(0x49a9);
  tft.setTextColor(0xe73c, 0x49a9);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter string to hash");
  tft.fillRect(0, 298, 240, 22, 0xe73c);
  tft.setTextColor(0x49a9, 0xe73c);
  tft.setTextSize(2);
  tft.setCursor(14,302);
  tft.print("Length:");
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x49a9);
        tft.setTextColor(0xe73c, 0x49a9);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter string to hash");
        tft.fillRect(0, 298, 240, 22, 0xe73c);
        tft.setTextColor(0x49a9, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(14,302);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x49a9, 0xe73c);
  tft.setCursor(98,302);
  tft.print("    "); 
  tft.setCursor(98,302);
  tft.print(inpl); 
  tft.setTextColor(0xf75b, 0x49a9);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
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
    tft.fillScreen(0x49a9);
    tft.setTextColor(0xe73c, 0x49a9);
    tft.setCursor(0,5);
    tft.println("Resulted hash:");
    tft.setTextColor(0xf75b, 0x49a9);
    tft.setCursor(0,25);
    tft.println(h);
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
  if (pr_key == 27){
     keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void exeq_sql_keyb(){
  tft.fillScreen(0x11c4);
  tft.setTextColor(0xe73c, 0x11c4);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter the SQL statem");
  tft.setCursor(0,25);
  tft.println("ent to execute:");
  disp_length_at_the_bottom(0);
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x11c4);
        tft.setTextColor(0xe73c, 0x11c4);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter the SQL statem");
        tft.setCursor(0,25);
        tft.println("ent to execute:");
      }
  int inpl = keyb_inp.length();
  disp_length_at_the_bottom(inpl);
  tft.setTextColor(0xf75b, 0x11c4);
  tft.setCursor(0,45);
  tft.println(keyb_inp);
  if (pr_key == 13){
    clb_m = 1;
    tft.fillScreen(0x3186);
    tft.setTextColor(0xe73c, 0x3186);
    tft.setTextSize(1);
    tft.setCursor(0,0);
    exeq_sql_statement_from_string(keyb_inp);
    tft.setTextSize(1);
    tft.setCursor(0,310);
    tft.print("                                                                                                    ");
    tft.setCursor(0,310);
    tft.print("Press any key to return to the main menu");
    keyb_inp = "";
    while (!bus.gotData()){
      bus.tick();
    }
    m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
  if (pr_key == 27){
     keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void proj_pass(String input){
      int str_len = input.length() + 1;
      char char_array[str_len];
      input.toCharArray(char_array, str_len);
      int p = 0;
      while( str_len > p+1){
        split_by_eight_for_pass_proj(char_array, p, str_len);
        p+=8;
      }
    keyb_inp = "";
    m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
}

void split_by_eight_for_pass_proj(char plntxt[], int k, int str_len){
  char res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      res[i] = plntxt[i+k];
  }
  for (int i = 8; i < 16; i++){
      res[i] = gen_r_num();
  }
  /*
   for (int i = 0; i < 8; i++){
     Serial.print(res[i]);
  }
  Serial.println();
  */
  encr_AES_for_pp(res);
}

void encr_AES_for_pp(char t_enc[]){
  uint8_t text[16];
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  aes_context ctx;
  aes_set_key(&ctx, projection_key, key_bit[2]);
  aes_encrypt_block(&ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for(int i = 0; i<8; i++){
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for(int i = 0; i<8; i++){
    R_half[i] = cipher_text[i+8];
  }
  for(int i = 8; i<16; i++){
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  serp_for_pp(L_half, false);
  serp_for_pp(R_half, true);
}

void serp_for_pp(char res[], bool snd){
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
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
  uint32_t *p;
  
  for (b=0; b<1; b++) {
    hex2binproj(key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
    }
    if (snd == false){
     for(int i = 0; i <16; i++){
      temp_st_for_pp[i] = ct2.b[i];
     }
    }
    if (snd == true){
     for(int i = 0; i <16; i++){
      myData.l_srp[i] = temp_st_for_pp[i];
      myData.r_srp[i] = ct2.b[i];
     }
     myData.n = n;
     esp_now_send(broadcastAddress, (uint8_t *) &myData, sizeof(myData));
     incr_projection_key();
     incr_proj_serp_key();
     incr_proj_serp_key();
     n = true;
     delayMicroseconds(240);
    }
  }
}

size_t hex2binproj (void *bin) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  for (i=0; i < 32; i++) {
    p[i] = (uint8_t)proj_serp_key[i];
  }
  return 32;
}

// Blowfish + AES + Serpent + AES (Below)

void encr_blwfsh_aes_serpent_aes(){
  tft.fillScreen(0x8813);
  tft.setTextColor(0xe73c, 0x8813);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter string to encr");
  disp_length_at_the_bottom(0);
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x8813);
        tft.setTextColor(0xe73c, 0x8813);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter string to encr");
      }
  int inpl = keyb_inp.length();
  disp_length_at_the_bottom(inpl);
  tft.setTextColor(0xf75b, 0x8813);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
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
    m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
  if (pr_key == 27){
     keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void decr_blwfsh_aes_serpent_aes(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,5);
  tft.print("Paste the ciphertext into the Serial");
  tft.setCursor(0,15);
  tft.print("Monitor.");
  tft.setCursor(5,302);
  tft.print("Press Esc to cancel.");
  dec_st = "";   dec_tag = "";   decract = 0;
  String ct;
  Serial.println("\nPaste the ciphertext here:");
  while (!Serial.available()) {
    bus.tick();
   if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
    ch = data.x;
    pr_key = int(ch);
    if (pr_key == 27){
      keyb_inp = "";
      dec_st = "";   dec_tag = "";   decract = 0;
      m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
   }  
  }
  ct = Serial.readString();
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
  dec_st = "";   dec_tag = "";   decract = 0;
  while (!bus.gotData()){
    bus.tick();
  }
  m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
 }
}

void split_by_eight_bl_aes_serp_aes(char plntxt[], int k, int str_len){
  char plt_data[] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      plt_data[i] = plntxt[i+k];
  }
  /*
  Serial.println("\nInput");
  for (int i = 0; i < 8; i++){
    Serial.print(plt_data[i]);
    Serial.print(" ");
  }
  */
  unsigned char t_encr[8];
  for(int i = 0; i < 8; i++){
      t_encr[i] = (unsigned char)plt_data[i];
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
  for(int i = 0; i < 8; i++){
      encr_for_aes[i] = char(int(t_encr[i]));
  }
  /*
  Serial.println("\nEncrypted");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  for(int i = 8; i < 16; i++){
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

void encr_AES_bl_aes_serp_aes(char t_enc[]){
  uint8_t text[16];
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  aes_context ctx;
  aes_set_key(&ctx, key, key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for(int i = 0; i<8; i++){
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for(int i = 0; i<8; i++){
    R_half[i] = cipher_text[i+8];
  }
  for(int i = 8; i<16; i++){
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  serp_enc_bl_aes_serp_aes(L_half);
  serp_enc_bl_aes_serp_aes(R_half);
}

void serp_enc_bl_aes_serp_aes(char res[]){
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
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
  uint32_t *p;
  
  for (b=0; b<1; b++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
  encr_sec_AES_bl_aes_serp_aes(ct2.b);
  }
}

void encr_sec_AES_bl_aes_serp_aes(byte t_enc[]){
  uint8_t text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t second_key_bit[3] = {128, 192, 256};
  int i = 0;
  aes_context ctx;
  aes_set_key(&ctx, second_key, second_key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  String cphrt_to_send;
  for (i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
}

void split_dec_bl_aes_serp_aes(char ct[], int ct_len, int p, bool ch, bool add_r){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
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
      if(add_r == true){
      uint8_t ret_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t second_key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, second_key, second_key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 16; i++) {
        res[i] = (char)ret_text[i];
      }
      }
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<1; i++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
    if (ch == false){
    for (int i=0; i<8; i++) {
      tmp_st[i] = char(ct2.b[i]);
    }
    }
    if (ch == true){
      decr_AES_and_Blowfish_bl_aes_serp_aes(ct2.b);
    }
  }
}

void decr_AES_and_Blowfish_bl_aes_serp_aes(byte sh[]){
  uint8_t ret_text[16];
  for(int i = 0; i<8; i++){
    ret_text[i] = tmp_st[i];
  }
  for(int i = 0; i<8; i++){
    ret_text[i+8] = sh[i];
  }
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(ret_text[i]);
        cipher_text[i] = c;
      }
      uint32_t key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, key, key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      /*
      Serial.println("\nDec by AES");
      for (int i = 0; i < 16; i++){\
        Serial.print(int(ret_text[i]));
        Serial.print(" ");
      }
      Serial.println();
      */
      unsigned char dbl[8];
      for (int i = 0; i < 8; i++){
        dbl[i] = (unsigned char)int(ret_text[i]);
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
      if (decract < 4){
        for (int i = 0; i < 8; i++){
          if (dbl[i]<0x10)
            dec_tag += 0;
          dec_tag += String(dbl[i], HEX);
        }
      }
      else{
        for (i = 0; i < 8; ++i) {
          dec_st += (char(dbl[i]));
        }
      }
      decract ++;
}

// Blowfish + AES + Serpent + AES (Above)

// AES + Serpent + AES (Below)

void encr_aes_serpent_aes(){
  tft.fillScreen(0x8813);
  tft.setTextColor(0xe73c, 0x8813);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter string to encr");
  disp_length_at_the_bottom(0);
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x8813);
        tft.setTextColor(0xe73c, 0x8813);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter string to encr");
      }
  int inpl = keyb_inp.length();
  disp_length_at_the_bottom(inpl);
  tft.setTextColor(0xf75b, 0x8813);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    String res_hash;
    char hmacchar[32];
    for (int i = 0; i < 32; i++){
      hmacchar[i] = char(authCode[i]);
    }
    Serial.println("\nCiphertext:");
    int p = 0;
    for (int i = 0; i < 4; i++){
      incr_key();
      incr_second_key();
      incr_serp_key();
      split_by_eight_for_aes_serp_aes(hmacchar, p, 100);
      p+=8;
    }
    p = 0;
    while(str_len > p+1){
      incr_key();
      incr_serp_key();
      incr_second_key();
      split_by_eight_for_aes_serp_aes(char_array, p, str_len);
      p+=8;
    }
    rest_k();
    rest_serp_k();
    rest_s_k();
    keyb_inp = "";
    m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
  if (pr_key == 27){
     keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void decr_aes_serpent_aes(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,5);
  tft.print("Paste the ciphertext into the Serial");
  tft.setCursor(0,15);
  tft.print("Monitor.");
  tft.setCursor(5,302);
  tft.print("Press Esc to cancel.");
  dec_st = "";   dec_tag = "";   decract = 0;
  String ct;
  Serial.println("\nPaste the ciphertext here:");
  while (!Serial.available()) {
    bus.tick();
   if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
    ch = data.x;
    pr_key = int(ch);
    if (pr_key == 27){
      keyb_inp = "";
      dec_st = "";   dec_tag = "";   decract = 0;
      m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
   }  
  }
  ct = Serial.readString();
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
      incr_key();
      incr_serp_key();
      incr_second_key();
  }
  split_dec_for_aes_serp_aes(ct_array, ct_len, 0+ext, ch, true);
  ext+=32;
  count++;
  }
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
  dec_st = "";   dec_tag = "";   decract = 0;
  while (!bus.gotData()){
    bus.tick();
  }
  m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
 }
}

void split_by_eight_for_aes_serp_aes(char plntxt[], int k, int str_len){
  char plt_data[] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
        break;
      plt_data[i] = plntxt[i+k];
  }
  char t_encr[16];
  for(int i = 0; i<8; i++){
      t_encr[i] = plt_data[i];
  }
  for(int i = 8; i<16; i++){
      t_encr[i] = gen_r_num();
  }
  encr_AES_for_aes_serp_aes(t_encr);
}

void encr_AES_for_aes_serp_aes(char t_enc[]){
  uint8_t text[16];
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  aes_context ctx;
  aes_set_key(&ctx, key, key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for(int i = 0; i<8; i++){
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for(int i = 0; i<8; i++){
    R_half[i] = cipher_text[i+8];
  }
  for(int i = 8; i<16; i++){
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  enc_serp_for_aes_serp_aes(L_half);
  enc_serp_for_aes_serp_aes(R_half);
}

void enc_serp_for_aes_serp_aes(char res[]){
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
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
  uint32_t *p;
  
  for (b=0; b<1; b++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
  encr_sec_AES_for_aes_serp_aes(ct2.b);
  }
}

void encr_sec_AES_for_aes_serp_aes(byte t_enc[]){
  uint8_t text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t second_key_bit[3] = {128, 192, 256};
  int i = 0;
  aes_context ctx;
  aes_set_key(&ctx, second_key, second_key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  for (i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
}

void split_dec_for_aes_serp_aes(char ct[], int ct_len, int p, bool ch, bool add_r){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
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
      if(add_r == true){
      uint8_t ret_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t second_key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, second_key, second_key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 16; i++) {
        res[i] = (char)ret_text[i];
      }
      }
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<1; i++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
    if (ch == false){
    for (int i=0; i<8; i++) {
      tmp_st[i] = char(ct2.b[i]);
    }
    }
    if (ch == true){
      decr_AES_for_aes_serp_aes(ct2.b);
    }
  }
}

void decr_AES_for_aes_serp_aes(byte sh[]){
  uint8_t ret_text[16];
  for(int i = 0; i<8; i++){
    ret_text[i] = tmp_st[i];
  }
  for(int i = 0; i<8; i++){
    ret_text[i+8] = sh[i];
  }
  uint8_t cipher_text[16] = {0};
  for(int i = 0; i<16; i++){
    int c = int(ret_text[i]);
    cipher_text[i] = c;
  }
  uint32_t key_bit[3] = {128, 192, 256};
  int i = 0;
  aes_context ctx;
  aes_set_key(&ctx, key, key_bit[m]);
  aes_decrypt_block(&ctx, ret_text, cipher_text);
  if (decract < 4){
    for (int i = 0; i < 8; i++){
      if (ret_text[i]<0x10)
        dec_tag += 0;
      dec_tag += String(ret_text[i], HEX);
    }
  }
  else{
    for (i = 0; i < 8; ++i) {
      dec_st += (char(ret_text[i]));
    }
  }
  decract ++;
}

// AES + Serpent + AES (Above)

// Blowfish + Serpent (Below)

void encr_Blowfish_Serpent(){
  tft.fillScreen(0x8813);
  tft.setTextColor(0xe73c, 0x8813);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter string to encr");
  disp_length_at_the_bottom(0);
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x8813);
        tft.setTextColor(0xe73c, 0x8813);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter string to encr");
      }
  int inpl = keyb_inp.length();
  disp_length_at_the_bottom(inpl);
  tft.setTextColor(0xf75b, 0x8813);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    String res_hash;
    /*
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
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight_for_bl_and_serp(hmacchar, p, 100);
      p+=8;
  }
    p = 0;
    while(str_len > p+1){
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight_for_bl_and_serp(char_array, p, str_len);
      p+=8;
    }
    rest_Blwfsh_k();
    rest_serp_k();
    keyb_inp = "";
    m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
  if (pr_key == 27){
     keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void decr_Blowfish_Serpent(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,5);
  tft.print("Paste the ciphertext into the Serial");
  tft.setCursor(0,15);
  tft.print("Monitor.");
  tft.setCursor(5,302);
  tft.print("Press Esc to cancel.");
  dec_st = "";   dec_tag = "";   decract = 0;
  String ct;
  Serial.println("\nPaste the ciphertext here:");
  while (!Serial.available()) {
    bus.tick();
   if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
    ch = data.x;
    pr_key = int(ch);
    if (pr_key == 27){
      keyb_inp = "";
      dec_st = "";   dec_tag = "";   decract = 0;
      m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
   }  
  }
  ct = Serial.readString();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  count = 0;
  bool ch = false;
  while(ct_len > ext){
      incr_Blwfsh_key();
      incr_serp_key();
      split_for_dec_bl_and_serp(ct_array, ct_len, 0+ext);
      ext+=32;
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
  dec_st = "";   dec_tag = "";   decract = 0;
  while (!bus.gotData()){
    bus.tick();
  }
  m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
 }
}

void split_by_eight_for_bl_and_serp(char plntxt[], int k, int str_len){
  char plt_data[] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      plt_data[i] = plntxt[i+k];
  }
  /*
  Serial.println("\nInput");
  for (int i = 0; i < 8; i++){
    Serial.print(plt_data[i]);
    Serial.print(" ");
  }
  */
  unsigned char t_encr[8];
  for(int i = 0; i < 8; i++){
      t_encr[i] = (unsigned char)plt_data[i];
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
  for(int i = 0; i < 8; i++){
      encr_for_serp[i] = char(int(t_encr[i]));
  }
  /*
  Serial.println("\nEncrypted");
  for (int i = 0; i < 8; i++){
    Serial.print(t_encr[i]);
    Serial.print(" ");
  }
  */
  for(int i = 8; i < 16; i++){
      encr_for_serp[i] = gen_r_num();
  }
  
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
      tmp_s[i] = encr_for_serp[i];
  }

  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t *p;
  
  for (b=0; b<1; b++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
    }
  }
}

void split_for_dec_bl_and_serp(char ct[], int ct_len, int p){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
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
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<1; i++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);

      unsigned char dbl[8];
      for (int i = 0; i < 8; i++){
        dbl[i] = (unsigned char)int(ct2.b[i]);
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
      if (decract < 4){
        for (i = 0; i < 8; i++){
          if (dbl[i]<0x10)
            dec_tag += 0;
          dec_tag += String(dbl[i], HEX);
        }
      }
      else{
        for (i = 0; i < 8; ++i) {
          dec_st += (char(dbl[i]));
        }
      }
      decract ++;
  }
}

// Blowfish + Serpent (Above)

// AES + Serpent (Below)

void encr_AES_Serpent(){
  tft.fillScreen(0x8813);
  tft.setTextColor(0xe73c, 0x8813);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter string to encr");
  disp_length_at_the_bottom(0);
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x8813);
        tft.setTextColor(0xe73c, 0x8813);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter string to encr");
      }
  int inpl = keyb_inp.length();
  disp_length_at_the_bottom(inpl);
  tft.setTextColor(0xf75b, 0x8813);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    int p = 0;
    Serial.println("\nCiphertext:");
    while(str_len > p+1){
      incr_key();
      incr_serp_key();
      split_by_eight_for_AES_serp(char_array, p, str_len);
      p+=8;
    }
    rest_k();
    rest_serp_k();
    keyb_inp = "";
    m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
  if (pr_key == 27){
     keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void decr_AES_Serpent(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,5);
  tft.print("Paste the ciphertext into the Serial");
  tft.setCursor(0,15);
  tft.print("Monitor.");
  tft.setCursor(5,302);
  tft.print("Press Esc to cancel.");
  dec_st = "";   dec_tag = "";   decract = 0;
  String ct;
  Serial.println("\nPaste the ciphertext here:");
  while (!Serial.available()) {
    bus.tick();
   if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
    ch = data.x;
    pr_key = int(ch);
    if (pr_key == 27){
      keyb_inp = "";
      dec_st = "";   dec_tag = "";   decract = 0;
      m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
   }  
  }
  ct = Serial.readString();
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
      incr_key();
      incr_serp_key();
    }
    split_dec_for_aes_serp(ct_array, ct_len, 0+ext, ch);
    ext+=32;
    count++;
  }
    rest_k();
    rest_serp_k();
  //Serial.println("Plaintext:");
  //Serial.println(dec_st);
  tft.setTextSize(2);
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setCursor(0,0);
  tft.println("Plaintext:");
  tft.setCursor(0,20);
  tft.println(dec_st);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,310);
  tft.print("                                                                                                    ");
  tft.setCursor(0,310);
  tft.print("Press any key to return to the main menu");
  keyb_inp = "";
  dec_st = "";   dec_tag = "";   decract = 0;
  while (!bus.gotData()){
    bus.tick();
  }
  m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
 }
}

void split_by_eight_for_AES_serp(char plntxt[], int k, int str_len){
  char res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
      if(i+k > str_len - 1)
      break;
      res[i] = plntxt[i+k];
  }
  for (int i = 8; i < 16; i++){
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

void encr_AES_for_aes_srp(char t_enc[]){
  uint8_t text[16];
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  aes_context ctx;
  aes_set_key(&ctx, key, key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  /*
  for (int i = 0; i < 16; i++) {
    Serial.printf("%02x", cipher_text[i]);
  }
  */
  char L_half[16];
  for(int i = 0; i<8; i++){
    L_half[i] = cipher_text[i];
  }
  char R_half[16];
  for(int i = 0; i<8; i++){
    R_half[i] = cipher_text[i+8];
  }
  for(int i = 8; i<16; i++){
    L_half[i] = gen_r_num();
    R_half[i] = gen_r_num();
  }
  encr_serp_for_aes_srp(L_half, false);
  encr_serp_for_aes_srp(R_half, true);
}

void encr_serp_for_aes_srp(char res[], bool snd){
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
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
  uint32_t *p;
  
  for (b=0; b<1; b++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
    }
  }
}

void split_dec_for_aes_serp(char ct[], int ct_len, int p, bool ch){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
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
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i<1; i++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
    if (ch == false){
    for (int i=0; i<8; i++) {
      tmp_st[i] = char(ct2.b[i]);
    }
    }
    if (ch == true){
      decr_AES_for_aes_serp(ct2.b);
    }
  }
}

void decr_AES_for_aes_serp(byte sh[]){
  uint8_t ret_text[16];
  for(int i = 0; i<8; i++){
    ret_text[i] = tmp_st[i];
  }
  for(int i = 0; i<8; i++){
    ret_text[i+8] = sh[i];
  }
  uint8_t cipher_text[16] = {0};
  for(int i = 0; i<16; i++){
    int c = int(ret_text[i]);
    cipher_text[i] = c;
  }
  uint32_t key_bit[3] = {128, 192, 256};
  int i = 0;
  aes_context ctx;
  aes_set_key(&ctx, key, key_bit[m]);
  aes_decrypt_block(&ctx, ret_text, cipher_text);
  for (i = 0; i < 8; i++) {
    dec_st += (char(ret_text[i]));
  }
}

// AES + Serpent (Above)

// AES (Below)

void encr_AES_only(){
  tft.fillScreen(0x8813);
  tft.setTextColor(0xe73c, 0x8813);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter string to encr");
  disp_length_at_the_bottom(0);
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x8813);
        tft.setTextColor(0xe73c, 0x8813);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter string to encr");
      }
  int inpl = keyb_inp.length();
  disp_length_at_the_bottom(inpl);
  tft.setTextColor(0xf75b, 0x8813);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    int p = 0;
    Serial.println("\nCiphertext:");
    while(str_len > p+1){
      incr_key();
      split_by_sixteen_for_AES_only(char_array, p, str_len);
      p+=16;
    }
    rest_k();
    keyb_inp = "";
    m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
  if (pr_key == 27){
     keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void decr_AES_only(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,5);
  tft.print("Paste the ciphertext into the Serial");
  tft.setCursor(0,15);
  tft.print("Monitor.");
  tft.setCursor(5,302);
  tft.print("Press Esc to cancel.");
  dec_st = "";   dec_tag = "";   decract = 0;
  String ct;
  Serial.println("\nPaste the ciphertext here:");
  while (!Serial.available()) {
    bus.tick();
   if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
    ch = data.x;
    pr_key = int(ch);
    if (pr_key == 27){
      keyb_inp = "";
      dec_st = "";   dec_tag = "";   decract = 0;
      m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
   }  
  }
  ct = Serial.readString();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  count = 0;
  bool ch = false;
  while(ct_len > ext){
    incr_key();
    split_dec_for_AES_only(ct_array, ct_len, 0+ext);
    ext+=32;
  }
    rest_k();
  //Serial.println("Plaintext:");
  //Serial.println(dec_st);
  tft.setTextSize(2);
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setCursor(0,0);
  tft.println("Plaintext:");
  tft.setCursor(0,20);
  tft.println(dec_st);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,310);
  tft.print("                                                                                                    ");
  tft.setCursor(0,310);
  tft.print("Press any key to return to the main menu");
  keyb_inp = "";
  dec_st = "";   dec_tag = "";   decract = 0;
  while (!bus.gotData()){
    bus.tick();
  }
  m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
 }
}

void split_by_sixteen_for_AES_only(char plntxt[], int k, int str_len){
  char res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 16; i++){
      if(i+k > str_len - 1)
      break;
      res[i] = plntxt[i+k];
  }
  encr_AES_only(res);
}

void encr_AES_only(char t_enc[]){
  uint8_t text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for(int i = 0; i<16; i++){
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint32_t key_bit[3] = {128, 192, 256};
  int i = 0;
  aes_context ctx;
  aes_set_key(&ctx, key, key_bit[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
  for (i = 0; i < 16; ++i) {
    Serial.printf("%02x", cipher_text[i]);
  }
}

void split_dec_for_AES_only(char ct[], int ct_len, int p){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
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
      uint8_t ret_text[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      uint8_t cipher_text[16] = {0};
      for(int i = 0; i<16; i++){
        int c = int(res[i]);
        cipher_text[i] = c;
      }
      uint32_t key_bit[3] = {128, 192, 256};
      int i = 0;
      aes_context ctx;
      aes_set_key(&ctx, key, key_bit[m]);
      aes_decrypt_block(&ctx, ret_text, cipher_text);
      for (i = 0; i < 16; i++) {
        dec_st += (char(ret_text[i]));
      }
   }
}

// AES (Above)

// Serpent (Below)

void encr_Serpent_only(){
  tft.fillScreen(0x8813);
  tft.setTextColor(0xe73c, 0x8813);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter string to encr");
  disp_length_at_the_bottom(0);
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x8813);
        tft.setTextColor(0xe73c, 0x8813);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter string to encr");
      }
  int inpl = keyb_inp.length();
  disp_length_at_the_bottom(inpl);
  tft.setTextColor(0xf75b, 0x8813);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    int str_len = keyb_inp.length() + 1;
    char char_array[str_len];
    keyb_inp.toCharArray(char_array, str_len);
    int p = 0;
    Serial.println("\nCiphertext:");
    while(str_len > p+1){
        incr_serp_key();
        split_by_eight_for_serp_only(char_array, p, str_len);
        p+=8;
    }
    rest_serp_k();
    keyb_inp = "";
    m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
  if (pr_key == 27){
     keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void decr_Serpent_only(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,5);
  tft.print("Paste the ciphertext into the Serial");
  tft.setCursor(0,15);
  tft.print("Monitor.");
  tft.setCursor(5,302);
  tft.print("Press Esc to cancel.");
  dec_st = "";   dec_tag = "";   decract = 0;
  String ct;
  Serial.println("\nPaste the ciphertext here:");
  while (!Serial.available()) {
    bus.tick();
   if (bus.gotData()) {
    myStruct data;
    bus.readData(data);
    // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
    ch = data.x;
    pr_key = int(ch);
    if (pr_key == 27){
      keyb_inp = "";
      dec_st = "";   dec_tag = "";   decract = 0;
      m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
   }  
  }
  ct = Serial.readString();
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  count = 0;
  bool ch = false;
  while(ct_len > ext){
        incr_serp_key();
        split_for_dec_serp_only(ct_array, ct_len, 0+ext);
        ext+=32;
  }
    rest_serp_k();
  //Serial.println("Plaintext:");
  //Serial.println(dec_st);
  tft.setTextSize(2);
  tft.fillScreen(0x3186);
  tft.setTextColor(0xffff, 0x3186);
  tft.setCursor(0,0);
  tft.println("Plaintext:");
  tft.setCursor(0,20);
  tft.println(dec_st);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(0,310);
  tft.print("                                                                                                    ");
  tft.setCursor(0,310);
  tft.print("Press any key to return to the main menu");
  keyb_inp = "";
  dec_st = "";   dec_tag = "";   decract = 0;
  while (!bus.gotData()){
    bus.tick();
  }
  m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
 }
}

void split_by_eight_for_serp_only(char plntxt[], int k, int str_len){
  char res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 8; i++){
    if(i+k > str_len - 1)
      break;
    res[i] = plntxt[i+k];
  }
  for (int i = 8; i < 16; i++){
    res[i] = gen_r_num();
  }
  int tmp_s[16];
  for(int i = 0; i < 16; i++){
      tmp_s[i] = res[i];
  }

  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t *p;
  
  for (b=0; b<1; b++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");
    /*
    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      Serial.printf ("%08X ", p[j]);
    }
    */
    for(int i = 0; i < 16; i++){
        ct2.b[i] = tmp_s[i];
    }
  serpent_encrypt (ct2.b, &skey, SERPENT_ENCRYPT);
    for (int i=0; i<16; i++) {
      if(ct2.b[i]<16)
        Serial.print("0");
      Serial.print(ct2.b[i],HEX);
  }
  }
}

void split_for_dec_serp_only(char ct[], int ct_len, int p){
  int br = false;
  byte res[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (int i = 0; i < 32; i+=2){
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
      uint8_t ct1[32], pt1[32], key[64];
      int plen, clen, i, j;
      serpent_key skey;
      serpent_blk ct2;
      uint32_t *p;
  
  for (i=0; i < 1; i++) {
    hex2bin (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = res[i];
    /*
    Serial.printf ("\n\n");
    for(int i = 0; i<16; i++){
    Serial.printf("%x", ct2.b[i]);
    Serial.printf(" ");
    */
    }
    //Serial.printf("\n");
    serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);
    for (int i=0; i<8; i++) {
      dec_st += char(ct2.b[i]);
    }
  }
}

// Serpent (Above)

void send_to_receiver(){
  if (send_setup == false)
    key_setup_for_send_feature();
  send_str();
}

size_t hex2bin_for_der (void *bin) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  for (i=0; i < 32; i++) {
    p[i] = (uint8_t)proj_serp_key[i];
  }
  return 32;
}

void key_setup_for_send_feature(){
   tft.fillScreen(0x5170);
   tft.setTextSize(2);
   tft.fillRect(25, 20, 190, 170, 0x08c5);
   tft.setTextColor(0x155b, 0x08c5);
   tft.setCursor(42,35);
   tft.print("Type this key");
   tft.setCursor(36,55);
   tft.print("    on the");
   tft.setCursor(36,75);
   tft.print("  receiver's");
   tft.setCursor(36,95);
   tft.print("    keypad");

  int rnd_len = 64 + esp_random()%75;
  char rnd_input[rnd_len];
  for(int i = 0; i < rnd_len; i++){
    rnd_input[i] = char(gen_r_num());
  }
  
  int rnd_key_len = 50 + esp_random()%40;
  byte rnd_key[rnd_key_len];
  for(int i = 0; i < rnd_key_len; i++){
    rnd_key[i] = byte(gen_r_num());
  }
  
  SHA256HMAC hmac(rnd_key, sizeof(rnd_key));
  hmac.doUpdate(rnd_input);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String to_kda;
  for (byte i=10; i < 20; i++)
  {
      if (authCode[i]<0x10) { to_kda += '0'; }
      to_kda += String(authCode[i], HEX);
      to_kda += ' ';
  }
  to_kda.remove(to_kda.length() -1, 1);
  for (int i = 0; i < to_kda.length(); i++){
    if (to_kda.charAt(i) == 'a')
      to_kda[i] = 'A';
    if (to_kda.charAt(i) == 'b')
      to_kda[i] = 'B';
    if (to_kda.charAt(i) == 'c')
      to_kda[i] = 'C';
    if (to_kda.charAt(i) == 'd')
      to_kda[i] = 'D';
    if (to_kda.charAt(i) == 'e')
      to_kda[i] = 'E';
    if (to_kda.charAt(i) == 'f')
      to_kda[i] = 'F';
  }
   
   tft.setTextColor(0xffff, 0x08c5);
   tft.setCursor(36,132);
   for (int i = 0; i < 14; i++){
     tft.print(to_kda.charAt(i));
   }
   tft.setCursor(36,160);
   for (int i = 0; i < 14; i++){
     tft.print(to_kda.charAt(i + 15));
   }
   
   derive_session_keys(to_kda);
}

void derive_session_keys(String inp_to_kder){
  inp_to_kder += "FFE";
  SHA256HMAC hmac(hmackey_for_session_key, sizeof(hmackey_for_session_key));
  int str_len = inp_to_kder.length() + 1;
  char input_arr[str_len];
  inp_to_kder.toCharArray(input_arr, str_len);
  hmac.doUpdate(input_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  for(int i = 0; i < 4; i++){
    proj_serp_key[i] = authCode[16 + i];
  }
  for(int i = 0; i < 4; i++){
    projection_key[i] = authCode[20 + i];
  }
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, i, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t *p;
  
  for (i=0; i < 1; i++) {
    hex2bin_for_der (key);
  
    // set key
    memset (&skey, 0, sizeof (skey));
    p=(uint32_t*)&skey.x[0][0];
    
    serpent_setkey (&skey, key);
    //Serial.printf ("\nkey=");

    for (j=0; j<sizeof(skey)/sizeof(serpent_subkey_t)*4; j++) {
      if ((j % 8)==0) putchar('\n');
      //Serial.printf ("%08X ", p[j]);
    }

    for(int i = 0; i <16; i++)
      ct2.b[i] = authCode[i];
    }
    //Serial.printf("\n");
    for (int i = 0; i < 1000; i++)
      serpent_encrypt (ct2.b, &skey, SERPENT_DECRYPT);

    for(int i = 0; i < 6; i++){
      proj_serp_key[i + 7] = ct2.b[i];
    }
    for(int i = 0; i < 6; i++){
      projection_key[i + 8] = ct2.b[8 + i];
    }
    /*
    for(int i = 0; i < 32; i++){
      Serial.println(proj_serp_key[i]);
    }
    for(int i = 0; i < 32; i++){
      Serial.println(projection_key[i]);
    }
  */
   int firstnum = int(ct2.b[7]);
   int secondnum = int(ct2.b[6]);
   int thirdnum = int(ct2.b[15]);
   tft.fillRect(25, 210, 190, 90, 0x08c5);
   tft.setTextColor(0x155b, 0x08c5);
   tft.setCursor(36,220);
   tft.print(" Verification");
   tft.setCursor(42,240);
   tft.print("   numbers");
   tft.setTextColor(0xffff, 0x08c5);

   if (thirdnum > 99){
    tft.setCursor(36,275);
    tft.printf("           %d",thirdnum);
   }
   else if (thirdnum > 9 && thirdnum < 100){
    tft.setCursor(42,275);
    tft.printf("           %d",thirdnum);
   }
   else if (thirdnum < 10){
    tft.setCursor(36,275);
    tft.printf("            %d",thirdnum);
   }

   if (secondnum > 99){
    tft.setCursor(42,275);
    tft.printf("     %d",secondnum);
   }
   else if (secondnum > 9 && secondnum < 100){
    tft.setCursor(36,275);
    tft.printf("      %d",secondnum);
   }
   else if (secondnum < 10){
    tft.setCursor(42,275);
    tft.printf("      %d",secondnum);
   }

   if (firstnum > 99){
    tft.setCursor(36,275);
    tft.printf("%d",firstnum);
   }
   else if (firstnum > 9 && firstnum < 100){
    tft.setCursor(42,275);
    tft.printf("%d",firstnum);
   }
   else if (firstnum < 10){
    tft.setCursor(36,275);
    tft.printf(" %d",firstnum);
   }
   
   tft.setTextColor(0xffff, 0x5170);
   tft.setTextSize(1);
   tft.setCursor(0,310);
   tft.print("                                                                                                    ");
   tft.setCursor(0,310);
   tft.print("       Press any key to continue");
   send_setup = true;
   while (!bus.gotData()){
     bus.tick();
   }
}

void send_str(){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(2);
  tft.fillRect(312, 0, 320, 240, 0x12ea);
  tft.setCursor(0,5);
  tft.println("Enter string to send");
  tft.fillRect(0, 298, 240, 22, 0xe73c);
  tft.setTextColor(0x3186, 0xe73c);
  tft.setTextSize(2);
  tft.setCursor(14,302);
  tft.print("Length:");
  while (pr_key != 27){
    bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
      if(pr_key != 127 && pr_key != 13 && pr_key != 9 && pr_key != 10 && pr_key != 11){
        keyb_inp += ch;
      }
      else if (ch == 127) {
        if(keyb_inp.length() > 0)
          keyb_inp.remove(keyb_inp.length() -1, 1);
        tft.fillScreen(0x3186);
        tft.setTextColor(0xe73c, 0x3186);
        tft.setTextSize(2);
        tft.fillRect(312, 0, 320, 240, 0x12ea);
        tft.setCursor(0,5);
        tft.println("Enter string to send");
        tft.fillRect(0, 298, 240, 22, 0xe73c);
        tft.setTextColor(0x3186, 0xe73c);
        tft.setTextSize(2);
        tft.setCursor(14,302);
        tft.print("Length:");
      }
  int inpl = keyb_inp.length();
  tft.setTextColor(0x3186, 0xe73c);
  tft.setCursor(98,302);
  tft.print("    "); 
  tft.setCursor(98,302);
  tft.print(inpl); 
  tft.setTextColor(0xf75b, 0x3186);
  tft.setCursor(0,25);
  tft.println(keyb_inp);
  if (pr_key == 13){
    proj_pass(keyb_inp);
    m_menu_rect(); main_menu(cur_pos); but_panl();
    return;
  }
  if (pr_key == 27){
     keyb_inp = "";
     m_menu_rect(); main_menu(cur_pos); but_panl();
     return;
  }
  }
 }
}

void but_panl(){
   tft.fillRect(0, 300, 240, 20, 0x08c5);
   tft.setTextColor(0x1557, 0x08c5);
   tft.setTextSize(2);
   tft.setCursor(6,302);
   tft.print("AES:    Tab to send");
   tft.setCursor(54,302);
   if (m == 2)
    tft.print(256);
   if (m == 1)
    tft.print(192);
   if (m == 0)
    tft.print(128);
}

void encr_bl_aes_serp_aes_from_ser(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(5,5);
  tft.println("Paste the plaintext into the Serial");
  tft.setCursor(5,17);
  tft.println("Monitor");
  tft.setCursor(5,302);
  tft.print("Press Esc to cancel.");
  Serial.println("Paste the text that you want to encrypt here.");
  String input;
  while (!Serial.available()) {
        bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
     if (pr_key == 27){
      keyb_inp = "";
      m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
    }
  }
  input = Serial.readString();
  int str_len = input.length() + 1;
  char char_array[str_len];
  input.toCharArray(char_array, str_len);
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
  m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
 }
}

void encr_aes_serp_aes_from_ser(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(5,5);
  tft.println("Paste the plaintext into the Serial");
  tft.setCursor(5,17);
  tft.println("Monitor");
  tft.setCursor(5,302);
  tft.print("Press Esc to cancel.");
  Serial.println("Paste the text that you want to encrypt here.");
  String input;
  while (!Serial.available()) {
        bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
     if (pr_key == 27){
      keyb_inp = "";
      m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
    }
  }
  input = Serial.readString();
  int str_len = input.length() + 1;
  char char_array[str_len];
  input.toCharArray(char_array, str_len);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_array);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;
  char hmacchar[32];
  for (int i = 0; i < 32; i++){
    hmacchar[i] = char(authCode[i]);
  }
  Serial.println("\nCiphertext:");
  int p = 0;
  for (int i = 0; i < 4; i++){
    incr_key();
    incr_second_key();
    incr_serp_key();
    split_by_eight_for_aes_serp_aes(hmacchar, p, 100);
    p+=8;
  }
  p = 0;
  while(str_len > p+1){
    incr_key();
    incr_serp_key();
    incr_second_key();
    split_by_eight_for_aes_serp_aes(char_array, p, str_len);
    p+=8;
  }
  rest_k();
  rest_serp_k();
  rest_s_k();
  m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
 }
}

void encr_blowfish_serpent_from_ser(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(5,5);
  tft.println("Paste the plaintext into the Serial");
  tft.setCursor(5,17);
  tft.println("Monitor");
  tft.setCursor(5,302);
  tft.print("Press Esc to cancel.");
  Serial.println("Paste the text that you want to encrypt here.");
  String input;
  while (!Serial.available()) {
        bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
     if (pr_key == 27){
      keyb_inp = "";
      m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
    }
  }
  input = Serial.readString();
    int str_len = input.length() + 1;
    char char_array[str_len];
    input.toCharArray(char_array, str_len);
    SHA256HMAC hmac(hmackey, sizeof(hmackey));
    hmac.doUpdate(char_array);
    byte authCode[SHA256HMAC_SIZE];
    hmac.doFinal(authCode);
    String res_hash;
    /*
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
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight_for_bl_and_serp(hmacchar, p, 100);
      p+=8;
    }
    p = 0;
    while(str_len > p+1){
      incr_Blwfsh_key();
      incr_serp_key();
      split_by_eight_for_bl_and_serp(char_array, p, str_len);
      p+=8;
    }
    rest_Blwfsh_k();
    rest_serp_k();
  m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
 }
}

void encr_aes_serpent_from_ser(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(5,5);
  tft.println("Paste the plaintext into the Serial");
  tft.setCursor(5,17);
  tft.println("Monitor");
  tft.setCursor(5,302);
  tft.print("Press Esc to cancel.");
  Serial.println("Paste the text that you want to encrypt here.");
  String input;
  while (!Serial.available()) {
        bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
     if (pr_key == 27){
      keyb_inp = "";
      m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
    }
  }
  input = Serial.readString();
    int str_len = input.length() + 1;
    char char_array[str_len];
    input.toCharArray(char_array, str_len);
    int p = 0;
    Serial.println("\nCiphertext:");
    while(str_len > p+1){
      incr_key();
      incr_serp_key();
      split_by_eight_for_AES_serp(char_array, p, str_len);
      p+=8;
    }
    rest_k();
    rest_serp_k();
  m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
 }
}

void encr_aes_only_from_ser(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(5,5);
  tft.println("Paste the plaintext into the Serial");
  tft.setCursor(5,17);
  tft.println("Monitor");
  tft.setCursor(5,302);
  tft.print("Press Esc to cancel.");
  Serial.println("Paste the text that you want to encrypt here.");
  String input;
  while (!Serial.available()) {
        bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
     if (pr_key == 27){
      keyb_inp = "";
      m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
    }
  }
  input = Serial.readString();
    int str_len = input.length() + 1;
    char char_array[str_len];
    input.toCharArray(char_array, str_len);
    int p = 0;
    Serial.println("\nCiphertext:");
    while(str_len > p+1){
      incr_key();
      split_by_sixteen_for_AES_only(char_array, p, str_len);
      p+=16;
    }
    rest_k();
  m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
 }
}

void encr_serpent_only_from_ser(){
 while (pr_key != 27){
  tft.fillScreen(0x3186);
  tft.setTextColor(0xe73c, 0x3186);
  tft.setTextSize(1);
  tft.setCursor(5,5);
  tft.println("Paste the plaintext into the Serial");
  tft.setCursor(5,17);
  tft.println("Monitor");
  tft.setCursor(5,302);
  tft.print("Press Esc to cancel.");
  Serial.println("Paste the text that you want to encrypt here.");
  String input;
  while (!Serial.available()) {
        bus.tick();
    if (bus.gotData()) {
      myStruct data;
      bus.readData(data);
      // 11 - Up arrow; 10 - Down arrow; 13 - Enter; 27 - Escape; 9 - Tab.
      ch = data.x;
      pr_key = int(ch);
     if (pr_key == 27){
      keyb_inp = "";
      m_menu_rect(); main_menu(cur_pos); but_panl();
      return;
    }
    }
  }
  input = Serial.readString();
    int str_len = input.length() + 1;
    char char_array[str_len];
    input.toCharArray(char_array, str_len);
    int p = 0;
    Serial.println("\nCiphertext:");
    while(str_len > p+1){
        incr_serp_key();
        split_by_eight_for_serp_only(char_array, p, str_len);
        p+=8;
    }
    rest_serp_k();
  m_menu_rect(); main_menu(cur_pos); but_panl();
  return;
 }
}

bool verify_integrity(){
  int str_lentg = dec_st.length() + 1;
  char char_arraytg[str_lentg];
  dec_st.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_arraytg);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;
  
  for (byte i=0; i < SHA256HMAC_SIZE; i++)
  {
      if (authCode[i]<0x10) { res_hash += 0; }{
        res_hash += String(authCode[i], HEX);
      }
  }

  return dec_tag.equals(res_hash);
}

void setup() {
  Serial.begin(115200);
  mySerial.begin(9600);
  m = 2; // Set AES to 256 bit
  cur_pos = 0;
  send_setup = false;
  n = false;
  tft.begin(); 
  tft.setRotation(0);
    if (SPIFFS.begin(true)) {
  }
  else{
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
  // Set device as a Wi-Fi Station
  WiFi.mode(WIFI_STA);
  // Init ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }

  // Once ESPNow is successfully Init, we will register for Send CB to
  // get the status of Trasnmitted packet
  esp_now_register_send_cb(OnDataSent);
  
  // Register peer
  memcpy(peerInfo.peer_addr, broadcastAddress, 6);
  peerInfo.channel = 0;  
  peerInfo.encrypt = false;

  
  // Add peer        
  if (esp_now_add_peer(&peerInfo) == ESP_OK){

  }
  else{
    Serial.println("Failed to add peer");
    return;
  }
  appr_cards_and_log_in();
}

void loop() {
  n = false;
  back_k();
  back_s_k();
  back_serp_k();
  back_Blwfsh_k();
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

    if (cur_pos == 0 && pr_key == 49) // Login.1
      Add_login();
    if (cur_pos == 0 && pr_key == 50) // Login.2
      Edit_login();
    if (cur_pos == 0 && pr_key == 51) // Login.3
      Remove_login();
    if (cur_pos == 0 && pr_key == 52) // Login.4
      View_login();
    if (cur_pos == 0 && pr_key == 53) // Login.5
      Show_all_logins();

    if (cur_pos == 1 && pr_key == 49) // Note.1
      Add_note();
    if (cur_pos == 1 && pr_key == 50) // Note.2
      Edit_note();
    if (cur_pos == 1 && pr_key == 51) // Note.3
      Remove_note();
    if (cur_pos == 1 && pr_key == 52) // Note.4
      View_note();
    if (cur_pos == 1 && pr_key == 53) // Note.5
      Show_all_notes();
    
    if (cur_pos == 2 && pr_key == 49) // Blowfish + AES + Serpent + AES.1
      encr_blwfsh_aes_serpent_aes();

    if (cur_pos == 2 && pr_key == 50) // Blowfish + AES + Serpent + AES.2
      decr_blwfsh_aes_serpent_aes();

    if (cur_pos == 2 && pr_key == 51) // Blowfish + AES + Serpent + AES.3
      encr_bl_aes_serp_aes_from_ser();

    if (cur_pos == 3 && pr_key == 49) // AES + Serpent + AES.1
      encr_aes_serpent_aes();

    if (cur_pos == 3 && pr_key == 50) // AES + Serpent + AES.2
      decr_aes_serpent_aes();

    if (cur_pos == 3 && pr_key == 51) // AES + Serpent + AES.3
      encr_aes_serp_aes_from_ser();

    if (cur_pos == 4 && pr_key == 49) // Blowfish + Serpent.1
      encr_Blowfish_Serpent();

    if (cur_pos == 4 && pr_key == 50) // Blowfish + Serpent.2
      decr_Blowfish_Serpent();

    if (cur_pos == 4 && pr_key == 51) // Blowfish + Serpent.3
      encr_blowfish_serpent_from_ser();

    if (cur_pos == 5 && pr_key == 49) // AES + Serpent.1
      encr_AES_Serpent();

    if (cur_pos == 5 && pr_key == 50) // AES + Serpent.2
      decr_AES_Serpent();

    if (cur_pos == 5 && pr_key == 51) // AES + Serpent.3
      encr_aes_serpent_from_ser();

    if (cur_pos == 6 && pr_key == 49) // AES.1
      encr_AES_only();

    if (cur_pos == 6 && pr_key == 50) // AES.2
      decr_AES_only();

    if (cur_pos == 6 && pr_key == 51) // AES.3
      encr_aes_only_from_ser();

    if (cur_pos == 7 && pr_key == 49) // Serpent.1
      encr_Serpent_only();

    if (cur_pos == 7 && pr_key == 50) // Serpent.2
      decr_Serpent_only();

    if (cur_pos == 7 && pr_key == 51) // Serpent.3
      encr_serpent_only_from_ser();

    if (cur_pos == 8 && pr_key == 49) // SHA-512.1
      hash_str();

    if (cur_pos == 9 && pr_key == 49) // SQL.1
      exeq_sql_keyb();

    if (pr_key == 9) // Send
      send_to_receiver();

    if (pr_key == 21) // Right Arrow
      m++;

    if (pr_key == 8) // Left Arrow
      m--;

    if (m > 2)
      m = 0;
    if (m < 0)
      m = 2;
      
    main_menu(cur_pos);
    but_panl();
  }
}
