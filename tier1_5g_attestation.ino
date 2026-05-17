// ================================================================
//  5G-ADAPTIVE DICE ATTESTATION ENGINE  -  TIER 1
//  Device  : Arduino Uno R3
//  Author  : Rahaf
//  Thesis  : 5G-Adaptive Lightweight Remote Attestation
//            Framework for Heterogeneous Edge Devices
//
//  FRAMEWORK PHASES:
//  Phase 1 - Device Classification
//  Phase 2 - 5G Context Analysis (slice, density, MEC, mobility)
//  Phase 3 - DICE CDI Chain Attestation + mMTC Group Aggregation
//  Phase 4 - Trust Decision: TRUSTED / SUSPICIOUS / COMPROMISED
// ================================================================

#include <SHA256.h>

const uint8_t UDS[16] = {
  0xA1,0x2B,0x3C,0x4D,0x5E,0x6F,0x70,0x81,
  0x92,0xA3,0xB4,0xC5,0xD6,0xE7,0xF8,0x09
};

char FW_CORE[32]   = "FW_TIER1_v2.0_ARDUINO_UNO";
char FW_CONFIG[32] = "CFG_DEFAULT_REGION_AE";
char DEVICE_ID[24] = "ARDUINO_UNO_001";

struct SlicePolicy {
  const char* name;
  uint16_t    interval_sec;
  uint8_t     hash_rounds;
  bool        group_attest;
  uint8_t     cluster_size;
  bool        mec_verify;
  uint16_t    mec_limit_ms;
  const char* power_mode;
  const char* density;
};

const SlicePolicy POLICIES[3] = {
  {"mMTC",  30, 1, true,  5, false,  0, "ULTRA_LOW_POWER",  "HIGH_1M_per_km2"},
  {"eMBB",  15, 2, false, 1, false,  0, "BALANCED",         "MEDIUM"         },
  {"URLLC",  5, 3, false, 1, true,  10, "HIGH_PERFORMANCE", "LOW_CRITICAL"   }
};

uint8_t  active_slice    = 255;
bool     baseline_set    = false;
uint8_t  baseline_CDI1[32];
uint32_t attest_count    = 0;
uint8_t  tamper_count    = 0;
bool     mobility_mode   = false;
char     verifier_ep[32] = "CLOUD_VERIFIER";

void sha256_buf(const uint8_t* in, size_t len, uint8_t* out){
  SHA256 h; h.update(in,len); h.finalize(out,32);
}
void sha256_cat(const uint8_t* a,size_t la,const uint8_t* b,size_t lb,uint8_t* out){
  SHA256 h; h.update(a,la); h.update(b,lb); h.finalize(out,32);
}
String toHex(const uint8_t* b,uint8_t n){
  String s="";
  for(uint8_t i=0;i<n;i++){if(b[i]<0x10)s+='0';s+=String(b[i],HEX);}
  return s;
}

void computeDICE(const SlicePolicy& p, uint8_t* cdi0, uint8_t* cdi1){
  uint8_t fw_hash[32];
  SHA256 fh;
  fh.update((uint8_t*)FW_CORE,   strlen(FW_CORE));
  fh.update((uint8_t*)FW_CONFIG, strlen(FW_CONFIG));
  fh.finalize(fw_hash,32);
  sha256_cat(UDS,16,fw_hash,32,cdi0);
  for(uint8_t r=1;r<p.hash_rounds;r++)
    sha256_buf(cdi0,32,cdi0);
  char ctx[64];
  snprintf(ctx,sizeof(ctx),"%s|%s|%s|%lu",p.name,DEVICE_ID,verifier_ep,attest_count);
  uint8_t ctx_hash[32];
  sha256_buf((uint8_t*)ctx,strlen(ctx),ctx_hash);
  sha256_cat(cdi0,32,ctx_hash,32,cdi1);
}

void computeGroupAggregate(const uint8_t* base,uint8_t n,uint8_t* out){
  SHA256 merkle;
  for(uint8_t peer=0;peer<n;peer++){
    uint8_t p_cdi[32];
    for(uint8_t b=0;b<32;b++)
      p_cdi[b]=base[b]^(uint8_t)(peer*0x5A+0x3F);
    merkle.update(p_cdi,32);
  }
  merkle.finalize(out,32);
}

void runAttestation(const SlicePolicy& p, bool silent=false){
  attest_count++;
  uint32_t t_start = micros();
  uint8_t cdi0[32],cdi1[32],group_ev[32];

  if(!silent){
    Serial.println(F("\n##############################################"));
    Serial.print(F("# ATTESTATION CYCLE #")); Serial.println(attest_count);
    Serial.println(F("##############################################"));
    Serial.println(F("\n[PHASE 1] DEVICE CLASSIFICATION"));
    Serial.println(F("----------------------------------------------"));
    Serial.println(F("  Device     : Arduino Uno R3"));
    Serial.println(F("  Tier       : 1 (Constrained MCU)"));
    Serial.println(F("  CPU        : ATmega328P @ 16MHz"));
    Serial.println(F("  SRAM       : 2048 bytes"));
    Serial.println(F("  Flash      : 32768 bytes"));
    Serial.println(F("  Security HW: None (software DICE)"));
    Serial.println(F("  Attest Mech: DICE CDI Chain"));
    Serial.println(F("  >> TIER 1 CONFIRMED"));
  }

  if(!silent){
    Serial.println(F("\n[PHASE 2] 5G CONTEXT ANALYSIS"));
    Serial.println(F("----------------------------------------------"));
    Serial.print(F("  Slice          : ")); Serial.println(p.name);
    Serial.print(F("  Density        : ")); Serial.println(p.density);
    Serial.print(F("  Interval (s)   : ")); Serial.println(p.interval_sec);
    Serial.print(F("  Hash Rounds    : ")); Serial.println(p.hash_rounds);
    Serial.print(F("  Group Attest   : "));
    Serial.println(p.group_attest?"YES (mMTC cluster)":"NO (individual)");
    Serial.print(F("  Cluster Size   : ")); Serial.println(p.cluster_size);
    Serial.print(F("  MEC Verify     : "));
    Serial.println(p.mec_verify?"YES (Edge node)":"NO (Cloud)");
    Serial.print(F("  Power Mode     : ")); Serial.println(p.power_mode);
    Serial.print(F("  Verifier       : ")); Serial.println(verifier_ep);
    Serial.print(F("  Mobility Mode  : ")); Serial.println(mobility_mode?"YES":"NO");
    Serial.println(F("  >> CONTEXT PROFILE BUILT"));
  }

  if(!silent){
    Serial.println(F("\n[PHASE 3] DICE ATTESTATION EXECUTION"));
    Serial.println(F("----------------------------------------------"));
  }

  computeDICE(p,cdi0,cdi1);
  bool used_group=false;

  if(p.group_attest && p.cluster_size>1){
    computeGroupAggregate(cdi1,p.cluster_size,group_ev);
    used_group=true;
    if(!silent){
      Serial.println(F("  Mode       : GROUP AGGREGATION (mMTC)"));
      Serial.print(F("  CDI_0      : ")); Serial.println(toHex(cdi0,32));
      Serial.print(F("  CDI_1      : ")); Serial.println(toHex(cdi1,32));
      Serial.print(F("  Cluster    : ")); Serial.print(p.cluster_size);
      Serial.println(F(" simulated sensors"));
      Serial.print(F("  Aggregate  : ")); Serial.println(toHex(group_ev,32));
    }
  } else {
    memcpy(group_ev,cdi1,32);
    if(!silent){
      Serial.println(F("  Mode       : INDIVIDUAL ATTESTATION"));
      Serial.print(F("  CDI_0      : ")); Serial.println(toHex(cdi0,32));
      Serial.print(F("  CDI_1      : ")); Serial.println(toHex(cdi1,32));
    }
  }

  uint32_t compute_us = micros()-t_start;
  uint32_t compute_ms = compute_us/1000;
  uint16_t ev_bytes   = 64+64+64+20+20+10;

  if(!silent){
    Serial.print(F("  Compute us : ")); Serial.println(compute_us);
    Serial.print(F("  Compute ms : ")); Serial.println(compute_ms);
    Serial.print(F("  Evid bytes : ")); Serial.println(ev_bytes);
    Serial.println(F("  >> EVIDENCE TOKEN GENERATED"));
  }

  if(!silent){
    Serial.println(F("\n[PHASE 4] TRUST DECISION"));
    Serial.println(F("----------------------------------------------"));
  }

  char verdict[24];
  if(!baseline_set){
    memcpy(baseline_CDI1,cdi1,32);
    baseline_set=true;
    strcpy(verdict,"BASELINE_STORED");
    if(!silent){
      Serial.println(F("  Baseline   : NOT SET - storing now"));
      Serial.print(F("  Golden CDI1: ")); Serial.println(toHex(baseline_CDI1,32));
      Serial.println(F("  STATUS     : BASELINE_STORED"));
    }
  } else {
    bool match=(memcmp(cdi1,baseline_CDI1,32)==0);
    if(match){
      tamper_count=0;
      if(p.mec_verify && compute_ms>(uint32_t)p.mec_limit_ms){
        strcpy(verdict,"SUSPICIOUS");
        if(!silent){
          Serial.println(F("  Hash Match : YES"));
          Serial.print(F("  MEC Timing : FAIL ("));
          Serial.print(compute_ms); Serial.print(F("ms > "));
          Serial.print(p.mec_limit_ms); Serial.println(F("ms limit)"));
          Serial.println(F("  STATUS     : *** SUSPICIOUS ***"));
          Serial.println(F("  Access     : LIMITED (monitoring active)"));
        }
      } else {
        strcpy(verdict,"TRUSTED");
        if(!silent){
          if(p.mec_verify){
            Serial.print(F("  MEC Timing : PASS ("));
            Serial.print(compute_ms); Serial.println(F("ms)"));
          }
          Serial.println(F("  Hash Match : YES"));
          Serial.println(F("  STATUS     : *** TRUSTED ***"));
          Serial.println(F("  Access     : GRANTED"));
        }
      }
    } else {
      tamper_count++;
      strcpy(verdict,"COMPROMISED");
      if(!silent){
        Serial.println(F("  Hash Match : NO - FIRMWARE TAMPERED"));
        Serial.print(F("  Tamper Cnt : ")); Serial.println(tamper_count);
        Serial.print(F("  Current    : ")); Serial.println(toHex(cdi1,32));
        Serial.print(F("  Baseline   : ")); Serial.println(toHex(baseline_CDI1,32));
        Serial.println(F("  STATUS     : *** COMPROMISED ***"));
        Serial.println(F("  Access     : DENIED"));
        Serial.println(F("  >> ALERT sent to MEC verifier"));
      }
    }
  }

  Serial.println(F("\n---BEGIN_TOKEN---"));
  Serial.print(F("{\"device\":\"")); Serial.print(DEVICE_ID); Serial.print(F("\","));
  Serial.print(F("\"tier\":1,"));
  Serial.print(F("\"slice\":\"")); Serial.print(p.name); Serial.print(F("\","));
  Serial.print(F("\"power_mode\":\"")); Serial.print(p.power_mode); Serial.print(F("\","));
  Serial.print(F("\"density\":\"")); Serial.print(p.density); Serial.print(F("\","));
  Serial.print(F("\"group_attest\":")); Serial.print(used_group?"true":"false"); Serial.print(F(","));
  Serial.print(F("\"cluster_size\":")); Serial.print(p.cluster_size); Serial.print(F(","));
  Serial.print(F("\"mec_verify\":")); Serial.print(p.mec_verify?"true":"false"); Serial.print(F(","));
  Serial.print(F("\"mec_limit_ms\":")); Serial.print(p.mec_limit_ms); Serial.print(F(","));
  Serial.print(F("\"hash_rounds\":")); Serial.print(p.hash_rounds); Serial.print(F(","));
  Serial.print(F("\"verifier\":\"")); Serial.print(verifier_ep); Serial.print(F("\","));
  Serial.print(F("\"mobility\":")); Serial.print(mobility_mode?"true":"false"); Serial.print(F(","));
  Serial.print(F("\"cdi0\":\"")); Serial.print(toHex(cdi0,32)); Serial.print(F("\","));
  Serial.print(F("\"cdi1\":\"")); Serial.print(toHex(cdi1,32)); Serial.print(F("\","));
  Serial.print(F("\"group_evidence\":\"")); Serial.print(toHex(group_ev,32)); Serial.print(F("\","));
  Serial.print(F("\"compute_us\":")); Serial.print(compute_us); Serial.print(F(","));
  Serial.print(F("\"compute_ms\":")); Serial.print(compute_ms); Serial.print(F(","));
  Serial.print(F("\"evidence_bytes\":")); Serial.print(ev_bytes); Serial.print(F(","));
  Serial.print(F("\"attest_count\":")); Serial.print(attest_count); Serial.print(F(","));
  Serial.print(F("\"tamper_count\":")); Serial.print(tamper_count); Serial.print(F(","));
  Serial.print(F("\"fw_core\":\"")); Serial.print(FW_CORE); Serial.print(F("\","));
  Serial.print(F("\"fw_config\":\"")); Serial.print(FW_CONFIG); Serial.print(F("\","));
  Serial.print(F("\"verdict\":\"")); Serial.print(verdict); Serial.print(F("\""));
  Serial.println(F("}"));
  Serial.println(F("---END_TOKEN---"));
}

void setup(){
  Serial.begin(9600);
  delay(2000);
  Serial.println(F("##############################################"));
  Serial.println(F("#  5G-ADAPTIVE DICE ATTESTATION - TIER 1    #"));
  Serial.println(F("#  Arduino Uno R3  |  Framework v2.0        #"));
  Serial.println(F("#  Awaiting slice assignment from MEC...    #"));
  Serial.println(F("##############################################"));
  Serial.println(F("READY"));
}

void loop(){
  if(Serial.available()>0){
    String cmd=Serial.readStringUntil('\n');
    cmd.trim();

    if(cmd=="SLICE:mMTC"){
      active_slice=0; baseline_set=false; attest_count=0;
      Serial.println(F("[CMD] Slice: mMTC | group=YES cluster=5 power=ULTRA_LOW"));
    }
    else if(cmd=="SLICE:eMBB"){
      active_slice=1; baseline_set=false; attest_count=0;
      Serial.println(F("[CMD] Slice: eMBB | group=NO rounds=2 power=BALANCED"));
    }
    else if(cmd=="SLICE:URLLC"){
      active_slice=2; baseline_set=false; attest_count=0;
      Serial.println(F("[CMD] Slice: URLLC | MEC=YES limit=10ms power=HIGH_PERF"));
    }
    else if(cmd=="ATTEST"){
      if(active_slice==255) Serial.println(F("[ERR] No slice assigned. Send SLICE:mMTC first."));
      else runAttestation(POLICIES[active_slice],false);
    }
    else if(cmd=="ATTEST:SILENT"){
      if(active_slice!=255) runAttestation(POLICIES[active_slice],true);
    }
    else if(cmd=="TAMPER:FULL"){
      strcpy(FW_CORE,"FW_TIER1_TAMPERED_MALWARE");
      baseline_set=false;
      Serial.println(F("[TAMPER] Full firmware compromise simulated"));
    }
    else if(cmd=="TAMPER:PARTIAL"){
      strcpy(FW_CONFIG,"CFG_MODIFIED_REGION_XX");
      baseline_set=false;
      Serial.println(F("[TAMPER] Config-only partial tampering simulated"));
    }
    else if(cmd=="TAMPER:RESTORE"){
      strcpy(FW_CORE,"FW_TIER1_v2.0_ARDUINO_UNO");
      strcpy(FW_CONFIG,"CFG_DEFAULT_REGION_AE");
      baseline_set=false;
      Serial.println(F("[TAMPER] Firmware restored to original state"));
    }
    else if(cmd=="MOBILITY:MEC"){
      strcpy(verifier_ep,"MEC_EDGE_NODE_01");
      mobility_mode=true; baseline_set=false;
      Serial.println(F("[MOBILITY] Handover to MEC edge - re-attest required"));
    }
    else if(cmd=="MOBILITY:CLOUD"){
      strcpy(verifier_ep,"CLOUD_VERIFIER");
      mobility_mode=false; baseline_set=false;
      Serial.println(F("[MOBILITY] Returned to cloud verifier"));
    }
    else if(cmd=="RESET"){
      baseline_set=false; attest_count=0; tamper_count=0;
      active_slice=255; mobility_mode=false;
      strcpy(FW_CORE,"FW_TIER1_v2.0_ARDUINO_UNO");
      strcpy(FW_CONFIG,"CFG_DEFAULT_REGION_AE");
      strcpy(verifier_ep,"CLOUD_VERIFIER");
      Serial.println(F("[CMD] Full state reset"));
    }
    else if(cmd=="STATUS"){
      Serial.print(F("[STATUS] slice="));
      if(active_slice==255) Serial.print(F("NONE"));
      else Serial.print(POLICIES[active_slice].name);
      Serial.print(F(" baseline=")); Serial.print(baseline_set?"SET":"UNSET");
      Serial.print(F(" count="));    Serial.print(attest_count);
      Serial.print(F(" tampers="));  Serial.print(tamper_count);
      Serial.print(F(" verifier=")); Serial.print(verifier_ep);
      Serial.print(F(" mobility=")); Serial.println(mobility_mode?"YES":"NO");
    }
  }

  if(active_slice!=255 && baseline_set){
    static uint32_t last_ms=0;
    uint32_t interval_ms=(uint32_t)POLICIES[active_slice].interval_sec*1000;
    if(millis()-last_ms>=interval_ms){
      last_ms=millis();
      runAttestation(POLICIES[active_slice],false);
    }
  }
}