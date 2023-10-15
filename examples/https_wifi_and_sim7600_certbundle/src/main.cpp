/**
 * Example of how to use certificate bundle on the SSL client,
 * and how to change the base client in runtime, to use it with PlatformIO.
 */

// * TinyGsm definitions before include library
#define TINY_GSM_MODEM_SIM7600
#define TINY_GSM_RX_BUFFER 1024
#define TINY_GSM_DEBUG     Serial

#include "SSLClientESP32.h"
#include "TinyGSM.h"
#include <Arduino.h>
#include <WiFi.h>

/* ---------------------------------------------------------------------------------------------- */
/*                                           Definitions                                          */
/* ---------------------------------------------------------------------------------------------- */
// * Wifi
#define WIFI_SSID "my ssid"
#define WIFI_PASS "my pass"

// * TinyGSM
#define MODEM_UART Serial1
#define MODEM_APN  "internet"
/* ---------------------------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------------------------- */
/*                                      Objects and variables                                     */
/* ---------------------------------------------------------------------------------------------- */
// * SIM7600 modem
TinyGsm modem(MODEM_UART);

// * Clients
WiFiClient client_wifi;
TinyGsmClient client_modem(modem);

// * Secure client object, initialized with Wifi client
SSLClientESP32 ssl(&client_wifi);

// * Certificate bundle with 41 most used root certificates
extern const uint8_t ca_cert_bundle_start[] asm("_binary_data_crt_x509_crt_bundle_bin_start");
extern const uint8_t ca_cert_bundle_end[] asm("_binary_data_crt_x509_crt_bundle_bin_end");
/* ---------------------------------------------------------------------------------------------- */

/* ---------------------------------------------------------------------------------------------- */
/*                                            Functions                                           */
/* ---------------------------------------------------------------------------------------------- */
void usbRead();
void testGET(const char* host, uint16_t port, const char* resource = nullptr);
/* ---------------------------------------------------------------------------------------------- */

void setup() {
  // Initialize ESP32
  Serial.begin(115200);

  // Probably need to change pins, like this:
  // MODEM_UART.begin(115200, SERIAL_8N1, rx, tx);
  MODEM_UART.begin(115200);

  // Set certificate bundle to SSL client
  ssl.setCACertBundle(ca_cert_bundle_start);

  // Habilitar Wifi
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  // Enable PSRAM
  psramInit();

  // Initialize SIM7600G-H
  log_i("Initializing modem...");
  modem.restart();
}

void loop() {
  // Read from user input on serial monitor
  usbRead();
}

// PIN usbRead()
/* ---------------------------------------------------------------------------------------------- */
void usbRead() {
  if (Serial.available()) {
    char c = Serial.read();

    if (c == '\r' || c == '\n')
      log_i("-> \\%c", c == '\r' ? 'r' : 'n');
    else
      log_i("-> %c", c);

    switch (c) {
      // Connect SIM7600G-H to the network
      case '0':
      {
        log_i("Connecting to network...");

        if (!modem.waitForNetwork()) {
          log_e("Failed to connect to network");
          return;
        }

        // Conectar al MODEM_APN
        if (!modem.gprsConnect(MODEM_APN)) {
          log_e("Failed to connect to MODEM_APN");
          return;
        }

        log_i("Modem connected!");
      } break;

      case '1':
      {
        testGET("vsh.pp.ua", 443, "/TinyGSM/logo.txt");
      } break;

      case '2':
      {
        testGET("api.my-ip.io", 443, "/ip.json");
      } break;

      case '3':
      {
        testGET("ifconfig.me", 443, "/ip");
      } break;

      case '4':
      {
        testGET("www.howsmyssl.com", 443, "/a/check");
      } break;

      case '8':
      {
        log_i("Setting WiFi client");
        ssl.setClient(&client_wifi);
      } break;

      case '9':
      {
        log_i("Setting Modem client");
        ssl.setClient(&client_modem);
      } break;
    }
  }
}
/* ---------------------------------------------------------------------------------------------- */

// PIN testGET()
/* ---------------------------------------------------------------------------------------------- */
void testGET(const char* host, uint16_t port, const char* resource) {
  if (!ssl.connect(host, port)) {
    log_e("Failed to connect to server");
    return;
  }

  // GET request
  log_i("Performing HTTPS GET request...");
  ssl.printf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\n",
             resource == nullptr ? "/" : resource,
             host);

  // Wait a little to receive some data
  uint32_t start = millis();
  while (ssl.connected() && !ssl.available() && ((millis() - start) < 10000L)) {
    delay(10);
  }

  log_d("Server response:");

  while (ssl.available()) {
    char c = ssl.read();
    Serial.print(c);
  }

  Serial.println();
  log_d("End of server response");

  // Cerrar conexión
  ssl.stop();
  log_w("Server disconnected");
}
/* ---------------------------------------------------------------------------------------------- */