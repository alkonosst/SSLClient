<h1 align="center">
  <a><img src=".img/ssl.png" alt="Logo" width="400"></a>
  <br>
  SSLClientESP32
</h1>

<p align="center">
  <b>A library to add a secure connection to a Client object</b>
</p>

---

## Table of contents <!-- omit in toc -->
- [Description](#description)
- [Usage](#usage)
  - [Adding library to platformio.ini (PlatformIO)](#adding-library-to-platformioini-platformio)
  - [Using WiFi and Root Certificate to client](#using-wifi-and-root-certificate-to-client)
  - [Using SIM7600G-H and Certificate Bundle](#using-sim7600g-h-and-certificate-bundle)
  - [Changing the base client in runtime](#changing-the-base-client-in-runtime)
- [Credits](#credits)

---

## Description
The **SSLClientESP32** library allows establishing a secure connection using SSL/TLS. Has been designed
for ESP32. Allows you to give a secure connection to any object derived from `Client`, such as
[WiFiClient](https://github.com/espressif/arduino-esp32/tree/master/libraries/WiFi) and [TinyGsmClient](https://github.com/vshymanskyy/TinyGSM). Offers to be able to attach a [Certificate Bundle](https://github.com/espressif/arduino-esp32/blob/master/libraries/WiFiClientSecure/README.md#using-a-bundle-of-root-certificate-authority-certificates) to the client, reducing the
number of certificates entered manually into the firmware and increasing the possibility of
establish a secure connection to most servers.

## Usage
Here are some basic examples...

### Adding library to platformio.ini (PlatformIO)
```ini
; Most recent changes
lib_deps =
  https://github.com/alkonosst/SSLClientESP32.git

; Release vx.y.z
lib_deps =
  https://github.com/alkonosst/SSLClientESP32.git#v2.0.0
```

### Using WiFi and Root Certificate to client
```cpp
#include <WiFi.h>
#include "SSLClientESP32.h"

// Create clients
WiFiClient base_client;
SSLClientESP32 ssl_client(&base_client);

// Root Certificate ISRG Root X1
const char* isrg_root_ca = "-----BEGIN CERTIFICATE-----\n"
                           "...\n"
                           "-----END CERTIFICATE-----\n";

void setup() {
  // Attach certificate
  ssl_client.setCACert(isrg_root_ca);

  // Enable WiFi
  WiFi.begin(WIFI_SSID, WIFI_PASS);
}

void foo() {
  if (!ssl_client.connect(SERVER, 443)) {
    // Connection failed
  } else {
    // Connection successful
  }
}
```

### Using SIM7600G-H and Certificate Bundle
**platformio.ini**
```ini
; File must exist in ./data/crt/
; You can use the file in /examples/https_wifi_and_sim7600_certbundle/data/crt/x509_crt_bundle.bin of this repo
board_build.embed_files = data/crt/x509_crt_bundle.bin
```

**main.cpp**
```cpp
#include <WiFi.h>
#include "TinyGSM.h"
#include "SSLClientESP32.h"

// Modem SIM7600G-H
TinyGsm modem(Serial1);

// Create clients
TinyGsmClient base_client(modem);
SSLClientESP32 ssl_client(&base_client);

// Declaration of binary file
extern const uint8_t ca_cert_bundle_start[] asm("_binary_data_crt_x509_crt_bundle_bin_start");
extern const uint8_t ca_cert_bundle_end[] asm("_binary_data_crt_x509_crt_bundle_bin_end");

void setup() {
  // Attach certificate bundle
  ssl_client.setCACertBundle(ca_cert_bundle_start);

  // Enable and connect modem...
}

void foo() {
  if (!ssl_client.connect(SERVER, 443)) {
    // Connection failed
  } else {
    // Connection successful
  }
}
```

### Changing the base client in runtime
```cpp
#include <WiFi.h>
#include "TinyGSM.h"
#include "SSLClientESP32.h"

// Modem SIM7600G-H
TinyGsm modem(Serial1);

// Create clients
WiFiClient base_client_1, base_client_2;
TinyGsmClient base_client_3(modem);
SSLClientESP32 ssl_client(&base_client_1);

void setup() {
  // Attach certificate...

  // Enable WiFi...

  // Enable and connect modem...
}

void foo(uint8_t client) {
  switch(client) {
    case 1: ssl_client.setClient(&base_client_1); break;
    case 2: ssl_client.setClient(&base_client_2); break;
    case 3: ssl_client.setClient(&base_client_3); break;
  }
}
```

## Credits
Huge thanks to [govorox](https://github.com/govorox) to provide the base code of this library :raised_hands: