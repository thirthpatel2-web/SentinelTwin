/*
 * sentineltwin_esp32.ino
 * -----------------------
 * Publishes REAL sensor readings from an ESP32 + DHT22 into SentinelTwin
 * over MQTT, on the exact same topic/JSON shape mqtt_bridge.py expects.
 * Once this is running, the device shows up on the SentinelTwin
 * dashboard tagged "LIVE HARDWARE" and goes through the identical
 * detect -> diagnose -> recover -> verify pipeline as the simulated
 * devices - including automatic failover to a simulated standby
 * (BKP-TEMP-*) if this real device drops off the network.
 *
 * Wiring:
 *   DHT22 VCC  -> 3V3
 *   DHT22 GND  -> GND
 *   DHT22 DATA -> GPIO4 (with a 10k pull-up resistor to 3V3)
 *
 * Libraries needed (Arduino Library Manager):
 *   - "DHT sensor library" by Adafruit
 *   - "PubSubClient" by Nick O'Leary
 *
 * Board: ESP32 Dev Module
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include <DHT.h>

// ---- EDIT THESE ----
const char* WIFI_SSID     = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";
const char* MQTT_BROKER   = "192.168.1.50";   // IP of the machine running SentinelTwin / mosquitto
const int   MQTT_PORT     = 1883;
const char* DEVICE_ID     = "REAL-TEMP-01";   // shows up as this ID on the dashboard
const char* DEVICE_ZONE   = "Zone-Live";
// ---------------------

#define DHT_PIN  4
#define DHT_TYPE DHT22

DHT dht(DHT_PIN, DHT_TYPE);
WiFiClient espClient;
PubSubClient mqtt(espClient);

const unsigned long PUBLISH_INTERVAL_MS = 2000;
unsigned long lastPublish = 0;
bool firstMessageSent = false;

void connectWiFi() {
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(400);
    Serial.print(".");
  }
  Serial.println(" connected.");
}

void connectMQTT() {
  mqtt.setServer(MQTT_BROKER, MQTT_PORT);
  while (!mqtt.connected()) {
    Serial.print("Connecting to MQTT broker...");
    if (mqtt.connect(DEVICE_ID)) {
      Serial.println(" connected.");
    } else {
      Serial.print(" failed, rc=");
      Serial.print(mqtt.state());
      Serial.println(" retrying in 2s");
      delay(2000);
    }
  }
}

// Maps WiFi RSSI (typically -90..-30 dBm) onto SentinelTwin's 0..100
// signal_strength scale, so NETWORK_FAILURE diagnosis behaves the same
// way it does for the simulated fleet.
float rssiToSignalStrength(long rssi) {
  float pct = (rssi + 90.0) * (100.0 / 60.0);
  if (pct < 0) pct = 0;
  if (pct > 100) pct = 100;
  return pct;
}

void setup() {
  Serial.begin(115200);
  dht.begin();
  connectWiFi();
  connectMQTT();
}

void loop() {
  if (!mqtt.connected()) connectMQTT();
  mqtt.loop();

  unsigned long now = millis();
  if (now - lastPublish < PUBLISH_INTERVAL_MS) return;
  lastPublish = now;

  float temperature = dht.readTemperature();
  float humidity     = dht.readHumidity();
  if (isnan(temperature) || isnan(humidity)) {
    Serial.println("DHT22 read failed, skipping this tick.");
    return;
  }

  float signalStrength = rssiToSignalStrength(WiFi.RSSI());
  // Rough battery estimate placeholder - replace with a real ADC read
  // (e.g. analogRead(35) through a voltage divider) if running on battery.
  float battery = 100.0;

  char payload[256];
  if (!firstMessageSent) {
    // device_type + zone only need to be sent once - the bridge registers
    // the device on first message and ignores these fields afterward.
    snprintf(payload, sizeof(payload),
      "{\"device_type\":\"temp_sensor\",\"zone\":\"%s\",\"temperature\":%.2f,"
      "\"humidity_ambient\":%.2f,\"battery\":%.1f,\"signal_strength\":%.1f}",
      DEVICE_ZONE, temperature, humidity, battery, signalStrength);
    firstMessageSent = true;
  } else {
    snprintf(payload, sizeof(payload),
      "{\"temperature\":%.2f,\"humidity_ambient\":%.2f,\"battery\":%.1f,\"signal_strength\":%.1f}",
      temperature, humidity, battery, signalStrength);
  }

  char topic[64];
  snprintf(topic, sizeof(topic), "sentineltwin/%s/telemetry", DEVICE_ID);
  mqtt.publish(topic, payload);

  Serial.print("Published: ");
  Serial.println(payload);
}
