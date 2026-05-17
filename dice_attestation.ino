#include <SHA256.h>

const int FIRMWARE_SIZE = 1024;
const char EXPECTED_HASH[] = "0B0CBC8B68CE583E094C745EA0BE49749777914475D3D41109564FA3A3C60092";

SHA256 sha256;

void setup() {
  Serial.begin(9600);
  while (!Serial) {
    delay(10);
  }
  
  delay(2000);
  
  Serial.println("========================================");
 Serial.println("DICE Boot Attestation - Tier 1 HACKED");
  Serial.println("Constrained Device Security");
  Serial.println("========================================");
  Serial.println("");
  
  performAttestation();
}

void loop() {
}

void performAttestation() {
  Serial.println("[Step 1] Reading firmware from memory...");
  
  uint8_t* firmwareStart = (uint8_t*)0x0000;
  
  Serial.println("[Step 2] Calculating SHA-256 hash...");
  
  sha256.reset();
  
  for (int i = 0; i < FIRMWARE_SIZE; i++) {
    uint8_t byte = pgm_read_byte_near(firmwareStart + i);
    sha256.update(&byte, 1);
  }
  
  uint8_t hash[32];
  sha256.finalize(hash, 32);
  
  Serial.print("Firmware Hash: ");
  char hashString[65];
  for (int i = 0; i < 32; i++) {
    sprintf(&hashString[i*2], "%02X", hash[i]);
  }
  hashString[64] = '\0';
  Serial.println(hashString);
  Serial.println("");
  
  Serial.println("[Step 3] Verifying integrity...");
  
  if (strlen(EXPECTED_HASH) < 10) {
    Serial.println("STATUS: BASELINE - First attestation");
    Serial.println("This hash should be recorded as trusted baseline");
  } else {
    if (strcmp(hashString, EXPECTED_HASH) == 0) {
      Serial.println("STATUS: TRUSTED");
      Serial.println("Firmware integrity verified");
      Serial.println("Device authorized for network access");
    } else {
      Serial.println("STATUS: COMPROMISED");
      Serial.println("Firmware has been modified!");
      Serial.println("Device denied network access");
    }
  }
  
  Serial.println("");
  Serial.println("========================================");
  Serial.println("Attestation Complete");
  Serial.println("========================================");
}