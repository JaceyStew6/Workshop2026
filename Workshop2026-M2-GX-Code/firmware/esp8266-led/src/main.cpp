// Voyant bicolore (vert / rouge) piloté par la passerelle face-gate, via le WiFi du hotspot du PC Hôte.
//   Câblage (LED bicolore 3 broches, cathode commune) : GPIO5 (D1) -> 220 ohms -> anode verte
//                                                       GPIO4 (D2) -> 220 ohms -> anode rouge ; cathode -> GND
//   Éteinte par défaut ; allumée uniquement sur ordre du serveur (voir include/led_logic.h).
#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WiFi.h>
#include <WiFiClient.h>

#include "led_logic.h"
#include "secrets.h"

#ifndef PIN_LED_GREEN
#define PIN_LED_GREEN 5
#endif
#ifndef PIN_LED_RED
#define PIN_LED_RED 4
#endif

static const uint32_t kPollEveryMs = 1000;
static const uint16_t kHttpTimeoutMs = 1200;

static LedLogic logic;
static WiFiClient wifi;
static uint32_t lastPoll = 0;

static void drive(uint32_t now) {
  const LedOutputs o = logic.outputs(now);
  digitalWrite(PIN_LED_GREEN, o.green ? HIGH : LOW);
  digitalWrite(PIN_LED_RED, o.red ? HIGH : LOW);
}

static void poll() {
  if (WiFi.status() != WL_CONNECTED) return;  // pas de réponse valide : l'échec sûr éteindra la LED
  HTTPClient http;
  http.setTimeout(kHttpTimeoutMs);
  if (!http.begin(wifi, GATE_HOST, GATE_PORT, "/gate/device/led")) return;
  http.addHeader("X-Device-Token", DEVICE_TOKEN);
  const int code = http.GET();
  if (code == HTTP_CODE_OK) {
    StaticJsonDocument<192> doc;
    if (deserializeJson(doc, http.getString()) == DeserializationError::Ok && doc["seq"].is<uint32_t>()) {
      logic.on_answer(doc["seq"].as<uint32_t>(), parse_pattern(doc["pattern"] | "off"),
                      doc["remaining_ms"] | 0u, millis());
    }
  } else {
    Serial.printf("poll HTTP %d\n", code);
  }
  http.end();
}

void setup() {
  pinMode(PIN_LED_GREEN, OUTPUT);
  pinMode(PIN_LED_RED, OUTPUT);
  digitalWrite(PIN_LED_GREEN, LOW);  // éteinte par défaut, y compris pendant la connexion WiFi
  digitalWrite(PIN_LED_RED, LOW);
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.printf("\nconnexion a %s...\n", WIFI_SSID);
}

void loop() {
  const uint32_t now = millis();
  if (now - lastPoll >= kPollEveryMs) {
    lastPoll = now;
    poll();
  }
  drive(millis());
  delay(10);
}
