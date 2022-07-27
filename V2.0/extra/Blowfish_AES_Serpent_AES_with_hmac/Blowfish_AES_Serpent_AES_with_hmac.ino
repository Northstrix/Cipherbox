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
#include "aes.h"
#include "serpent.h"
#include <sys/random.h>
#include "blowfish.h"
#include "Crypto.h"
char ch;
int count;
byte tmp_st[8];
int m;
String dec_st;
String dec_tag;
int decract;
uint8_t back_key[32];
uint8_t back_s_key[32];
unsigned char back_Blwfsh_key[16];
uint8_t back_serp_key[32];
Blowfish blowfish;

byte hmackey[] = {"1234"};

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

uint8_t serp_key[32] = {
   0xd1,0xf0,0x68,0x5b,
   0x33,0xa0,0xb1,0x73,
   0xb6,0x25,0x54,0xf9,
   0xdd,0x2c,0xd3,0x1d,
   0xc1,0x93,0xb3,0x14,
   0x16,0x76,0x28,0x59,
   0x04,0x85,0xd4,0x24,
   0x9d,0xe0,0x2a,0x74
};

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

void incr_key() {
  if (key[0] == 255) {
    key[0] = 0;
    if (key[1] == 255) {
      key[1] = 0;
      if (key[2] == 255) {
        key[2] = 0;
        if (key[3] == 255) {
          key[3] = 0;

          if (key[4] == 255) {
            key[4] = 0;
            if (key[5] == 255) {
              key[5] = 0;
              if (key[6] == 255) {
                key[6] = 0;
                if (key[7] == 255) {
                  key[7] = 0;

                  if (key[8] == 255) {
                    key[8] = 0;
                    if (key[9] == 255) {
                      key[9] = 0;
                      if (key[10] == 255) {
                        key[10] = 0;
                        if (key[11] == 255) {
                          key[11] = 0;

                          if (key[12] == 255) {
                            key[12] = 0;
                            if (key[13] == 255) {
                              key[13] = 0;
                              if (key[14] == 255) {
                                key[14] = 0;
                                if (key[15] == 255) {
                                  key[15] = 0;
                                } else {
                                  key[15]++;
                                }
                              } else {
                                key[14]++;
                              }
                            } else {
                              key[13]++;
                            }
                          } else {
                            key[12]++;
                          }

                        } else {
                          key[11]++;
                        }
                      } else {
                        key[10]++;
                      }
                    } else {
                      key[9]++;
                    }
                  } else {
                    key[8]++;
                  }

                } else {
                  key[7]++;
                }
              } else {
                key[6]++;
              }
            } else {
              key[5]++;
            }
          } else {
            key[4]++;
          }

        } else {
          key[3]++;
        }
      } else {
        key[2]++;
      }
    } else {
      key[1]++;
    }
  } else {
    key[0]++;
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

int gen_r_num(){
  int rn = esp_random()%256;
  return rn;
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
  for (int i = 0; i < 16; ++i) {
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
  for (i = 0; i < 16; ++i) {
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
      for (i = 0; i < 16; ++i) {
        res[i] = (char)ret_text[i];
      }
      }
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
      /*
      for (i = 0; i < 8; ++i) {
        Serial.printf("%02x", dbl[i]);
      }
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

void dec_BL_AES_Serp_AES_from_serial(){
  dec_st = "";
  dec_tag = "";
  decract = 0;
  String ct;
  Serial.println("Paste the ciphertext:");
  while (!Serial.available()) {}
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
      incr_second_key();
      incr_Blwfsh_key();
      incr_serp_key();
  }
  split_dec_bl_aes_serp_aes(ct_array, ct_len, 0+ext, ch, true);
  ext+=32;
  count++;
  }
  rest_k();
  rest_s_k();
  rest_Blwfsh_k();
  rest_serp_k();
  Serial.println("Decrypted tag:");
  Serial.println(dec_tag);
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
  Serial.println("Calculated tag:");
  Serial.println(res_hash);
  Serial.println("Decrypted text:");
  Serial.println(dec_st);
  dec_st = "";
}

void enc_BL_AES_Serp_AES_from_serial(){
  Serial.println("Paste the text to encrypt:");
  String inp_str;
  while (!Serial.available()) {}
  inp_str = Serial.readString();
  int str_len = inp_str.length() + 1;
  char char_array[str_len];
  inp_str.toCharArray(char_array, str_len);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_array);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;
  /*
  for (byte i=0; i < SHA256HMAC_SIZE; i++)
  {
      if (authCode[i]<0x10) { res_hash += '0'; }{
        res_hash += String(authCode[i], HEX);
      }
  }
  */
  char hmacchar[32];
  for (int i = 0; i < 32; i++){
    hmacchar[i] = char(authCode[i]);
  }
  Serial.println("Ciphertext:");
  int p = 0;
  for (int i = 0; i < 4; i++){
    incr_key();
    incr_second_key();
    incr_Blwfsh_key();
    incr_serp_key();
    split_by_eight_bl_aes_serp_aes(hmacchar, p, 100);
    p+=8;
  }
  //Serial.print(res_hash);
  p = 0;
  while(str_len > p+1){
    incr_key();
    incr_second_key();
    incr_Blwfsh_key();
    incr_serp_key();
    split_by_eight_bl_aes_serp_aes(char_array, p, str_len);
    p+=8;
  }
  rest_k();
  rest_s_k();
  rest_Blwfsh_k();
  rest_serp_k();
  Serial.println("");
}

void setup() {
  Serial.begin(115200);
  m = 2;
}

void loop() {
  back_k();
  back_s_k();
  back_Blwfsh_k();
  back_serp_k();
  Serial.println();
  Serial.println("What do you want to do?");
  Serial.println("1.Encrypt record");
  Serial.println("2.Decrypt record");
  while (!Serial.available()) {}
  int x = Serial.parseInt();
  if(x == 1){
    enc_BL_AES_Serp_AES_from_serial();
  }
  if(x == 2){
    dec_BL_AES_Serp_AES_from_serial();
   }
}
