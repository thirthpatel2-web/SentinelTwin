/*
 * sentineltwin_esp32.ino
 * -----------------------
 * Publishes REAL sensor readings from an ESP32 + DHT22 into SentinelTwin
 * over MQTT, on the topic/JSON shape mqtt_bridge.py expects, and accepts
 * fault-injection commands so the hardware evaluation campaign
 * (tools/hw_campaign.py) can run scripted faults with ground-truth
 * timestamps on the physical device.
 *
 * Each message carries:
 *   seq   - monotonically increasing counter (transport provenance)
 *   pub   - publisher fingerprint (firmware id)
 *   mac   - optional HMAC-SHA256 over the exact JSON sent (set DEVICE_KEY_HEX)
 *
 * Optional second DHT22 on GPIO 5 publishes as its own device
 * (<DEVICE_ID>-REF, a humidity_sensor) so the zone has a physical
 * reference sensor for the drift-vs-tampering consensus.
 *
 * Wiring:
 *   DHT22 #1 VCC->3V3, GND->GND, DATA->GPIO4 (10k pull-up to 3V3)
 *   DHT22 #2 (optional reference) DATA->GPIO5 (10k pull-up to 3V3)
 *
 * Libraries (Arduino Library Manager):
 *   "DHT sensor library" by Adafruit, "PubSubClient" by Nick O'Leary
 * Board: ESP32 Dev Module. mbedtls ships with the ESP32 core.
 *
 * Fault commands (JSON on sentineltwin/<DEVICE_ID>/cmd):
 *   {"fault":"NONE"}                     clear
 *   {"fault":"SPIKE"}                    one channel jumps +-35..60
 *   {"fault":"STUCK"}                    temperature frozen at its current value
 *   {"fault":"DROPOUT","p":0.75}         skip publishing with probability p
 *   {"fault":"DRIFT","rate":0.06}        temperature offset grows by rate degC per reading
 *   {"fault":"RAMP","rate":0.06}         same arithmetic, but labelled as a compromised-firmware attack
 *   {"fault":"FLOOD","n":40}             burst n messages per interval
 *   {"fault":"WIFI_OFF","s":40}          drop Wi-Fi for s seconds (real network failure)
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include <DHT.h>
#include "mbedtls/md.h"

// ---- EDIT THESE ----
const char* WIFI_SSID      = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD  = "YOUR_WIFI_PASSWORD";
const char* MQTT_BROKER    = "192.168.1.50";   // machine running SentinelTwin / mosquitto
const int   MQTT_PORT      = 1883;
const char* DEVICE_ID      = "REAL-TEMP-01";
const char* DEVICE_ZONE    = "Zone-Live";
const char* DEVICE_KEY_HEX = "";               // 64 hex chars to enable HMAC; must match SENTINELTWIN_DEVICE_KEYS
const bool  HAS_REFERENCE  = false;            // true if a second DHT22 is wired to GPIO 5
// ---------------------

#define DHT_PIN      4
#define DHT_REF_PIN  5
#define DHT_TYPE     DHT22

DHT dht(DHT_PIN, DHT_TYPE);
DHT dhtRef(DHT_REF_PIN, DHT_TYPE);
WiFiClient espClient;
PubSubClient mqtt(espClient);

const unsigned long PUBLISH_INTERVAL_MS = 2000;
unsigned long lastPublish = 0;
unsigned long seqMain = 0, seqRef = 0;
bool sentIdentityMain = false, sentIdentityRef = false;

// fault state (driven by the cmd topic)
String fault = "NONE";
float faultRate = 0.06, faultP = 0.75, offset = 0, stuckValue = NAN;
int floodN = 40;
unsigned long wifiOffUntil = 0;
uint8_t key[32];
bool useMac = false;

int hexNibble(char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; }

void signAndPublish(const char* topic, char* body, size_t cap) {
  if (useMac) {
    unsigned char out[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&ctx, key, sizeof(key));
    mbedtls_md_hmac_update(&ctx, (const unsigned char*)body, strlen(body));
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
    size_t n = strlen(body);
    if (n + 76 < cap) {
      body[n - 1] = '\0';                          // drop the closing brace
      char* p = body + strlen(body);
      p += sprintf(p, ",\"mac\":\"");
      for (int i = 0; i < 32; i++) p += sprintf(p, "%02x", out[i]);
      sprintf(p, "\"}");
    }
  }
  mqtt.publish(topic, body);
}

void onCommand(char* topic, byte* payload, unsigned int len) {
  String s; for (unsigned int i = 0; i < len; i++) s += (char)payload[i];
  int f = s.indexOf("\"fault\":\"");
  if (f < 0) return;
  fault = s.substring(f + 9, s.indexOf('"', f + 9));
  auto num = [&](const char* k, float d) {
    int i = s.indexOf(String("\"") + k + "\":");
    return i < 0 ? d : s.substring(i + strlen(k) + 3).toFloat();
  };
  faultRate = num("rate", 0.06); faultP = num("p", 0.75); floodN = (int)num("n", 40);
  offset = 0; stuckValue = NAN;
  if (fault == "WIFI_OFF") { wifiOffUntil = millis() + (unsigned long)(num("s", 40) * 1000); WiFi.disconnect(true); }
  Serial.printf("CMD fault=%s\n", fault.c_str());
}

void connectWiFi() {
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print("."); }
  Serial.println(" connected.");
}

void connectMQTT() {
  mqtt.setServer(MQTT_BROKER, MQTT_PORT);
  mqtt.setCallback(onCommand);
  mqtt.setBufferSize(512);
  while (!mqtt.connected()) {
    Serial.print("Connecting to MQTT broker...");
    if (mqtt.connect(DEVICE_ID)) {
      char t[64]; snprintf(t, sizeof(t), "sentineltwin/%s/cmd", DEVICE_ID);
      mqtt.subscribe(t);
      Serial.println(" connected.");
    } else {
      Serial.printf(" failed, rc=%d retrying in 2s\n", mqtt.state());
      delay(2000);
    }
  }
}

// WiFi RSSI (-90..-30 dBm) -> SentinelTwin's 0..100 signal_strength scale
float rssiToSignalStrength(long rssi) {
  float pct = (rssi + 90.0) * (100.0 / 60.0);
  return pct < 0 ? 0 : pct > 100 ? 100 : pct;
}

void setup() {
  Serial.begin(115200);
  dht.begin();
  if (HAS_REFERENCE) dhtRef.begin();
  useMac = strlen(DEVICE_KEY_HEX) == 64;
  for (int i = 0; useMac && i < 32; i++) key[i] = hexNibble(DEVICE_KEY_HEX[2 * i]) * 16 + hexNibble(DEVICE_KEY_HEX[2 * i + 1]);
  randomSeed(esp_random());
  connectWiFi();
  connectMQTT();
}

void publishMain(float temperature, float humidity, float signal) {
  char topic[64], body[400];
  snprintf(topic, sizeof(topic), "sentineltwin/%s/telemetry", DEVICE_ID);
  seqMain++;
  snprintf(body, sizeof(body),
    "{%s\"seq\":%lu,\"pub\":\"%s-fw\",\"temperature\":%.2f,\"humidity_ambient\":%.2f,"
    "\"battery\":100.0,\"signal_strength\":%.1f,\"packet_loss\":0.0}",
    sentIdentityMain ? "" : (String("\"device_type\":\"temp_sensor\",\"zone\":\"") + DEVICE_ZONE + "\",").c_str(),
    seqMain, DEVICE_ID, temperature, humidity, signal);
  sentIdentityMain = true;
  signAndPublish(topic, body, sizeof(body));
  Serial.println(body);
}

void loop() {
  if (wifiOffUntil) {
    if (millis() < wifiOffUntil) return;            // real link outage in progress
    wifiOffUntil = 0; fault = "NONE"; connectWiFi();
  }
  if (!mqtt.connected()) connectMQTT();
  mqtt.loop();

  unsigned long now = millis();
  if (now - lastPublish < PUBLISH_INTERVAL_MS) return;
  lastPublish = now;

  float temperature = dht.readTemperature();
  float humidity = dht.readHumidity();
  if (isnan(temperature) || isnan(humidity)) { Serial.println("DHT22 read failed, skipping."); return; }
  float signal = rssiToSignalStrength(WiFi.RSSI());

  if (fault == "SPIKE") temperature += (random(2) ? 1 : -1) * (35 + random(26));
  else if (fault == "STUCK") { if (isnan(stuckValue)) stuckValue = temperature; temperature = stuckValue; }
  else if (fault == "DROPOUT" && random(1000) < faultP * 1000) return;
  else if (fault == "DRIFT" || fault == "RAMP") { offset += faultRate; temperature += offset; }

  int copies = fault == "FLOOD" ? floodN : 1;
  for (int i = 0; i < copies; i++) publishMain(temperature, humidity, signal);

  if (HAS_REFERENCE) {
    float rt = dhtRef.readTemperature(), rh = dhtRef.readHumidity();
    if (!isnan(rt) && !isnan(rh)) {
      char topic[64], body[400];
      snprintf(topic, sizeof(topic), "sentineltwin/%s-REF/telemetry", DEVICE_ID);
      seqRef++;
      snprintf(body, sizeof(body),
        "{%s\"seq\":%lu,\"pub\":\"%s-REF-fw\",\"humidity\":%.2f,\"temperature_ambient\":%.2f,"
        "\"battery\":100.0,\"signal_strength\":%.1f,\"packet_loss\":0.0}",
        sentIdentityRef ? "" : (String("\"device_type\":\"humidity_sensor\",\"zone\":\"") + DEVICE_ZONE + "\",").c_str(),
        seqRef, DEVICE_ID, rh, rt, signal);
      sentIdentityRef = true;
      signAndPublish(topic, body, sizeof(body));
    }
  }
}
