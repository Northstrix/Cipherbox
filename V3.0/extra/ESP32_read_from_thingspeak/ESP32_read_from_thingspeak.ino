/*
Cipherbox
Distributed under the MIT License
© Copyright Maxim Bortnikov 2022
For more information please visit
https://github.com/Northstrix/Cipherbox
https://sourceforge.net/projects/mcu-cipherbox
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
#include <WiFi.h>
#include "ThingSpeak.h"

const char* ssid = "My Wireless Network";   // Your network SSID (name) 
const char* password = "dTre7bd90mrs";   // Your network password

WiFiClient  client;

unsigned long myChannelNumber = 1234567; // Channel ID
const char * myReadAPIKey = "K9L8M7N6O5P4Q3R2"; // Read API Key

void setup() {
  Serial.begin(115200); //Initialize serial

  WiFi.mode(WIFI_STA);

  ThingSpeak.begin(client); // Initialize ThingSpeak
}

void loop() {
  // Connect or reconnect to WiFi
  if (WiFi.status() != WL_CONNECTED) {
    Serial.print("Attempting to connect");
    while (WiFi.status() != WL_CONNECTED) {
      WiFi.begin(ssid, password);
      delay(5000);
    }
    Serial.println("\nConnected.");
  }

  String ttl = ThingSpeak.readStringField(myChannelNumber, 1, myReadAPIKey);
  String cnt = ThingSpeak.readStringField(myChannelNumber, 2, myReadAPIKey);
  int x = ThingSpeak.getLastReadStatus();
    Serial.print("Title: ");
    Serial.println(ttl);
    Serial.print("Content: ");
    Serial.println(cnt);
  if (x == 200) {
    Serial.println("Data read successfully.");
  }
  else {
    Serial.println("Something went wrong. HTTP error code " + String(x));
  }
  delay(5000);
}
