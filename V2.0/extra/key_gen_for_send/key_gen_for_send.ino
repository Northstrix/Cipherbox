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
#include "Crypto.h"
#include "serpent.h"

byte hmackey_for_session_key[] = {"1234"};

uint8_t projection_key[32] = {
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00
};

uint8_t proj_serp_key[32] = {
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00,
0x00,0x00,0x00,0x00
};

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

size_t hex2bin_for_der (void *bin) {
  size_t len, i;
  int x;
  uint8_t *p=(uint8_t*)bin;
  for (i=0; i < 32; i++) {
    p[i] = (uint8_t)proj_serp_key[i];
  }
  return 32;
}

int gen_r_num(){
  int rn = esp_random()%256;
  return rn;
}

void generate_random_session_key(){
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
  Serial.println(to_kda);
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
    
    for(int i = 0; i < 32; i++){
      Serial.println(proj_serp_key[i]);
    }
    for(int i = 0; i < 32; i++){
      Serial.println(projection_key[i]);
    }

    Serial.println("Verification numbers");
    Serial.println(ct2.b[7]);
    Serial.println(ct2.b[6]);
    Serial.println(ct2.b[15]);
}

void setup()
{
  Serial.begin(115200);
}


void loop()
{
  generate_random_session_key();
  delay(500);
}
