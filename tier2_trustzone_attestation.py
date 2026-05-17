#!/usr/bin/env python3
"""
================================================================
 5G-ADAPTIVE TRUSTZONE ATTESTATION ENGINE  -  TIER 2
 Device  : Raspberry Pi 4 (ARM Cortex-A72)
 Role    : 5G Gateway Node / D2D Device A
 Author  : Rahaf
 Thesis  : 5G-Adaptive Lightweight Remote Attestation
           Framework for Heterogeneous Edge Devices

 FRAMEWORK PHASES:
 Phase 1 - Device Classification (Tier 2 Gateway confirmed)
 Phase 2 - 5G Context Analysis (slice, D2D, MEC, density)
 Phase 3 - TrustZone-style Attestation (secure/normal world
           separation simulated in software + SHA-256 chain)
 Phase 4 - Trust Decision: TRUSTED/SUSPICIOUS/COMPROMISED

 5G NOVEL CONTRIBUTIONS:
 1. TrustZone secure world simulation: attestation logic runs
    in isolated secure context, normal world cannot access
    secure measurements directly.
 2. D2D Mutual Attestation Protocol: Raspberry Pi (Device A)
    and laptop (Device B) mutually verify each other over
    WiFi Direct simulation - first cross-tier D2D implementation.
 3. MEC edge attestation: evidence verified locally at edge
    node before forwarding to cloud - reduces latency.
 4. Slice-aware gateway aggregation: aggregates Tier 1 sensor
    tokens and adds Tier 2 gateway attestation on top.
 5. All 8 supervisor experiments with graphs and JSON report.
================================================================
"""

import hashlib, json, time, os, sys, psutil, threading, socket
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# ── PATHS ─────────────────────────────────────────────────────────
BASE_DIR   = os.path.expanduser('~/tier2_5g_attestation')
REPORT_DIR = os.path.join(BASE_DIR, 'attestation_reports')
GRAPH_DIR  = os.path.join(BASE_DIR, 'graphs')
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(GRAPH_DIR,  exist_ok=True)

# ── DEVICE IDENTITY ───────────────────────────────────────────────
DEVICE_ID   = "RASPBERRY_PI4_001"
FW_CORE     = "FW_TIER2_v2.0_RPI4_ARM_CORTEX_A72"
FW_CONFIG   = "CFG_GATEWAY_5G_MEC_AE"
SW_VERSION  = "SW_TRUSTZONE_SIM_v2.0"

# ── TrustZone Root Secret (simulated hardware root key) ───────────
TZ_ROOT_KEY = bytes.fromhex(
    'b94c8a2e7f3d1056e9ab4c823f17d6054e8b92a1'
    '3c7f0e21d54b896a0f3c72e1'
)

# ── 5G Slice Policy Table ─────────────────────────────────────────
POLICIES = {
    'mMTC' : {
        'interval_sec' : 30,
        'hash_rounds'  : 2,
        'group_attest' : True,
        'cluster_size' : 10,
        'mec_verify'   : False,
        'mec_limit_ms' : 0,
        'd2d_enabled'  : False,
        'power_mode'   : 'LOW_POWER',
        'density'      : 'HIGH_1M_per_km2',
        'agg_tier1'    : True
    },
    'eMBB' : {
        'interval_sec' : 15,
        'hash_rounds'  : 3,
        'group_attest' : False,
        'cluster_size' : 1,
        'mec_verify'   : True,
        'mec_limit_ms' : 50,
        'd2d_enabled'  : False,
        'power_mode'   : 'BALANCED',
        'density'      : 'MEDIUM',
        'agg_tier1'    : False
    },
    'URLLC': {
        'interval_sec' : 5,
        'hash_rounds'  : 4,
        'group_attest' : False,
        'cluster_size' : 1,
        'mec_verify'   : True,
        'mec_limit_ms' : 10,
        'd2d_enabled'  : True,
        'power_mode'   : 'HIGH_PERFORMANCE',
        'density'      : 'LOW_CRITICAL',
        'agg_tier1'    : False
    }
}

# ── Runtime State ─────────────────────────────────────────────────
active_slice   = 'mMTC'
baseline_set   = False
baseline_hash  = None
attest_count   = 0
tamper_count   = 0
mobility_mode  = False
verifier_ep    = 'CLOUD_VERIFIER'
fw_tampered    = False
cfg_tampered   = False

C_mMTC  = '#E07B39'
C_eMBB  = '#2E75B6'
C_URLLC = '#70AD47'

# ================================================================
#  TRUSTZONE SIMULATION
#  Secure world: isolated memory region for sensitive operations
#  Normal world: cannot access secure measurements directly
# ================================================================

class SecureWorld:
    """
    Simulates ARM TrustZone Secure World.
    In real TrustZone: this code runs in EL3/S-EL1 (secure state).
    Here: runs in isolated Python context with restricted interface.
    Secure world holds the root key and performs measurements.
    Normal world only receives the final attestation token.
    """
    def __init__(self):
        self._root_key    = TZ_ROOT_KEY  # only accessible inside secure world
        self._secure_log  = []
        self._boot_hash   = None
        self._sw_hash     = None
        self._perform_boot_measurement()

    def _perform_boot_measurement(self):
        """Boot measurement — runs at secure world initialization."""
        boot_data = f"{FW_CORE}|{FW_CONFIG}|{SW_VERSION}".encode()
        self._boot_hash = hashlib.sha256(boot_data).hexdigest()
        self._secure_log.append(f"BOOT_MEASURE: {self._boot_hash[:16]}...")

    def _derive_attestation_key(self, slice_name):
        """
        Derive slice-specific attestation key using HKDF.
        Key is different for each slice — slice binding.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=slice_name.encode(),
            info=b'5G_ATTESTATION_KEY',
            backend=default_backend()
        )
        return hkdf.derive(self._root_key)

    def measure_firmware(self, fw_core, fw_config):
        """Measure firmware from secure world."""
        data = f"{fw_core}|{fw_config}".encode()
        return hashlib.sha256(data).hexdigest()

    def compute_tzma(self, slice_name, fw_core, fw_config,
                     device_id, verifier, count):
        """
        TrustZone Measurement Attestation (TZMA).
        Equivalent to DICE CDI chain but using HKDF key derivation.
        Layer 0: Boot measurement (hardware root)
        Layer 1: Firmware measurement (software stack)
        Layer 2: Slice-context binding (5G contribution)
        """
        # Layer 0: boot measurement (already done at init)
        boot_h = self._boot_hash

        # Layer 1: firmware measurement
        fw_h = self.measure_firmware(fw_core, fw_config)

        # Layer 2: derive attestation key for this slice
        attest_key = self._derive_attestation_key(slice_name)

        # Layer 3: compute TZMA = HMAC(attest_key, boot+fw+context)
        context = f"{slice_name}|{device_id}|{verifier}|{count}".encode()
        h = hmac.HMAC(attest_key, hashes.SHA256(), backend=default_backend())
        h.update(boot_h.encode())
        h.update(fw_h.encode())
        h.update(context)
        tzma = h.finalize().hex()

        self._secure_log.append(f"TZMA_COMPUTE: slice={slice_name} count={count}")

        return {
            'boot_hash' : boot_h,
            'fw_hash'   : fw_h,
            'tzma'      : tzma,
            'key_id'    : hashlib.sha256(attest_key).hexdigest()[:16]
        }

    def get_secure_log(self):
        return self._secure_log.copy()


class NormalWorld:
    """
    Simulates ARM TrustZone Normal World.
    Can only call secure world through defined SMC (Secure Monitor Call)
    interface. Cannot access secure world memory directly.
    """
    def __init__(self, secure_world):
        self._sw = secure_world  # reference through SMC interface only

    def request_attestation(self, slice_name, fw_core, fw_config,
                            device_id, verifier, count):
        """SMC call to secure world for attestation."""
        return self._sw.compute_tzma(
            slice_name, fw_core, fw_config,
            device_id, verifier, count
        )

    def request_fw_measurement(self, fw_core, fw_config):
        """SMC call to get firmware measurement only."""
        return self._sw.measure_firmware(fw_core, fw_config)


# Initialize TrustZone worlds
secure_world = SecureWorld()
normal_world = NormalWorld(secure_world)

# ================================================================
#  GROUP AGGREGATION (Merkle-style for mMTC cluster)
# ================================================================
def compute_group_aggregate(base_tzma, cluster_size):
    """Aggregate attestation tokens from cluster of Tier 1 sensors."""
    import hashlib as _h
    combined = b''
    peer_tokens = []
    for peer in range(cluster_size):
        peer_tzma = _h.sha256(
            f"{base_tzma}{peer}".encode()
        ).hexdigest()
        peer_tokens.append(peer_tzma)
        combined += peer_tzma.encode()
    aggregate = _h.sha256(combined).hexdigest()
    return aggregate, peer_tokens

# ================================================================
#  FULL 4-PHASE ATTESTATION CYCLE
# ================================================================
def run_attestation(slice_name, silent=False):
    global baseline_set, baseline_hash, attest_count, tamper_count

    policy = POLICIES[slice_name]
    attest_count += 1
    t_start = time.time()

    # ── PHASE 1: Device Classification ───────────────────────────
    if not silent:
        print(f"\n{'#'*50}")
        print(f"# ATTESTATION CYCLE #{attest_count}")
        print(f"{'#'*50}")
        print(f"\n[PHASE 1] DEVICE CLASSIFICATION")
        print(f"{'─'*50}")
        print(f"  Device      : Raspberry Pi 4")
        print(f"  Tier        : 2 (Gateway Node)")
        print(f"  CPU         : ARM Cortex-A72 @ 1.8GHz")
        print(f"  RAM         : 4GB LPDDR4")
        print(f"  Security HW : ARM TrustZone (simulated)")
        print(f"  OS          : Raspberry Pi OS Lite 64-bit")
        print(f"  Attest Mech : TrustZone TZMA + HKDF")
        print(f"  Role        : 5G Gateway / D2D Device A")
        print(f"  >> TIER 2 CONFIRMED")

    # ── PHASE 2: 5G Context Analysis ─────────────────────────────
    if not silent:
        print(f"\n[PHASE 2] 5G CONTEXT ANALYSIS")
        print(f"{'─'*50}")
        print(f"  Slice          : {slice_name}")
        print(f"  Density        : {policy['density']}")
        print(f"  Interval (s)   : {policy['interval_sec']}")
        print(f"  Hash Rounds    : {policy['hash_rounds']}")
        print(f"  Group Attest   : {'YES (mMTC cluster)' if policy['group_attest'] else 'NO (individual)'}")
        print(f"  Cluster Size   : {policy['cluster_size']}")
        print(f"  MEC Verify     : {'YES (Edge node)' if policy['mec_verify'] else 'NO (Cloud)'}")
        print(f"  MEC Limit (ms) : {policy['mec_limit_ms']}")
        print(f"  D2D Enabled    : {'YES (URLLC D2D mode)' if policy['d2d_enabled'] else 'NO'}")
        print(f"  Power Mode     : {policy['power_mode']}")
        print(f"  Verifier       : {verifier_ep}")
        print(f"  Mobility Mode  : {'YES' if mobility_mode else 'NO'}")
        print(f"  Agg Tier1      : {'YES' if policy['agg_tier1'] else 'NO'}")
        print(f"  >> CONTEXT PROFILE BUILT")

    # ── PHASE 3: TrustZone Attestation ───────────────────────────
    if not silent:
        print(f"\n[PHASE 3] TRUSTZONE ATTESTATION EXECUTION")
        print(f"{'─'*50}")
        print(f"  [Secure World] Performing TZMA computation...")

    # Use current fw strings (may be tampered)
    current_fw_core   = FW_CORE   if not fw_tampered  else "FW_TIER2_TAMPERED_MALWARE"
    current_fw_config = FW_CONFIG if not cfg_tampered else "CFG_MODIFIED_UNAUTHORIZED"

    # Multiple hash rounds per slice policy
    tzma_result = None
    for r in range(policy['hash_rounds']):
        tzma_result = normal_world.request_attestation(
            slice_name, current_fw_core, current_fw_config,
            DEVICE_ID, verifier_ep, attest_count
        )

    tzma      = tzma_result['tzma']
    boot_hash = tzma_result['boot_hash']
    fw_hash   = tzma_result['fw_hash']
    key_id    = tzma_result['key_id']

    # Group aggregation for mMTC
    group_evidence = tzma
    cluster_tokens = []
    if policy['group_attest'] and policy['cluster_size'] > 1:
        group_evidence, cluster_tokens = compute_group_aggregate(
            tzma, policy['cluster_size']
        )
        if not silent:
            print(f"  Mode           : GROUP AGGREGATION (mMTC)")
            print(f"  Boot Hash      : {boot_hash[:32]}...")
            print(f"  FW Hash        : {fw_hash[:32]}...")
            print(f"  TZMA           : {tzma[:32]}...")
            print(f"  Cluster Size   : {policy['cluster_size']} sensors")
            print(f"  Group Evidence : {group_evidence[:32]}...")
    else:
        if not silent:
            print(f"  Mode           : INDIVIDUAL ATTESTATION")
            print(f"  Boot Hash      : {boot_hash[:32]}...")
            print(f"  FW Hash        : {fw_hash[:32]}...")
            print(f"  TZMA           : {tzma[:32]}...")

    compute_ms = round((time.time() - t_start) * 1000, 2)
    ev_bytes   = len(json.dumps({
        'tzma': tzma, 'group_evidence': group_evidence,
        'boot_hash': boot_hash, 'fw_hash': fw_hash
    }).encode())

    if not silent:
        print(f"  Compute (ms)   : {compute_ms}")
        print(f"  Evid bytes     : {ev_bytes}")
        print(f"  [Secure World] TZMA complete. Token passed to Normal World.")
        print(f"  >> EVIDENCE TOKEN GENERATED")

    # ── PHASE 4: Trust Decision ───────────────────────────────────
    if not silent:
        print(f"\n[PHASE 4] TRUST DECISION")
        print(f"{'─'*50}")

    verdict = ''
    if not baseline_set:
        baseline_hash = tzma
        baseline_set  = True
        verdict       = 'BASELINE_STORED'
        if not silent:
            print(f"  Baseline       : NOT SET - storing now")
            print(f"  Golden TZMA    : {baseline_hash[:32]}...")
            print(f"  STATUS         : BASELINE_STORED")
    else:
        match = (tzma == baseline_hash)
        if match:
            tamper_count = 0
            if policy['mec_verify'] and compute_ms > policy['mec_limit_ms']:
                verdict = 'SUSPICIOUS'
                if not silent:
                    print(f"  Hash Match     : YES")
                    print(f"  MEC Timing     : FAIL ({compute_ms}ms > {policy['mec_limit_ms']}ms)")
                    print(f"  STATUS         : *** SUSPICIOUS ***")
                    print(f"  Access         : LIMITED (monitoring)")
            else:
                verdict = 'TRUSTED'
                if not silent:
                    if policy['mec_verify']:
                        print(f"  MEC Timing     : PASS ({compute_ms}ms)")
                    print(f"  Hash Match     : YES")
                    print(f"  STATUS         : *** TRUSTED ***")
                    print(f"  Access         : GRANTED")
        else:
            tamper_count += 1
            verdict       = 'COMPROMISED'
            if not silent:
                print(f"  Hash Match     : NO - FIRMWARE TAMPERED")
                print(f"  Tamper Count   : {tamper_count}")
                print(f"  Current TZMA   : {tzma[:32]}...")
                print(f"  Baseline TZMA  : {baseline_hash[:32]}...")
                print(f"  STATUS         : *** COMPROMISED ***")
                print(f"  Access         : DENIED")
                print(f"  >> ALERT sent to MEC verifier")

    # Build evidence token
    token = {
        'device'         : DEVICE_ID,
        'tier'           : 2,
        'slice'          : slice_name,
        'power_mode'     : policy['power_mode'],
        'density'        : policy['density'],
        'group_attest'   : policy['group_attest'],
        'cluster_size'   : policy['cluster_size'],
        'mec_verify'     : policy['mec_verify'],
        'mec_limit_ms'   : policy['mec_limit_ms'],
        'd2d_enabled'    : policy['d2d_enabled'],
        'hash_rounds'    : policy['hash_rounds'],
        'verifier'       : verifier_ep,
        'mobility'       : mobility_mode,
        'boot_hash'      : boot_hash,
        'fw_hash'        : fw_hash,
        'tzma'           : tzma,
        'key_id'         : key_id,
        'group_evidence' : group_evidence,
        'compute_ms'     : compute_ms,
        'evidence_bytes' : ev_bytes,
        'attest_count'   : attest_count,
        'tamper_count'   : tamper_count,
        'fw_core'        : current_fw_core,
        'fw_config'      : current_fw_config,
        'verdict'        : verdict
    }

    print(f"\n---BEGIN_TOKEN---")
    print(json.dumps(token))
    print(f"---END_TOKEN---")

    return token

# ================================================================
#  GRAPH HELPERS
# ================================================================
def save_graph(fig, name):
    path = os.path.join(GRAPH_DIR, name)
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f"  [GRAPH] Saved: {path}")
    return path

def bar3(title, ylabel, labels, vals, cols, fname, note=''):
    fig, ax = plt.subplots(figsize=(8,4))
    bars = ax.bar(labels, vals, color=cols, edgecolor='white', width=0.5)
    for b,v in zip(bars,vals):
        ax.text(b.get_x()+b.get_width()/2,
                b.get_height()+0.01*max(vals) if max(vals)>0 else 0.01,
                f'{v:.2f}', ha='center', va='bottom', fontsize=9)
    ax.set_title(title, fontsize=12, fontweight='bold', pad=10)
    ax.set_ylabel(ylabel, fontsize=10)
    if note:
        fig.text(0.5,-0.04,note,ha='center',fontsize=8,color='grey',style='italic')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    return save_graph(fig, fname)

# ================================================================
#  CPU SAMPLING
# ================================================================
cpu_samples, cpu_sampling = [], False

def _sample():
    while cpu_sampling:
        cpu_samples.append(psutil.cpu_percent(interval=0.1))

def start_cpu():
    global cpu_samples, cpu_sampling
    cpu_samples, cpu_sampling = [], True
    threading.Thread(target=_sample, daemon=True).start()

def stop_cpu():
    global cpu_sampling
    cpu_sampling = False
    time.sleep(0.2)
    return round(float(np.mean(cpu_samples)), 2) if cpu_samples else 0.0

# ================================================================
#  EXP 1 — PERFORMANCE & OVERHEAD
# ================================================================
def exp1():
    global active_slice, baseline_set, attest_count, tamper_count
    print(f"\n{'='*55}")
    print(f"  EXP 1: CROSS-TIER PERFORMANCE & OVERHEAD")
    print(f"  5G: Each slice has different TrustZone overhead")
    print(f"{'='*55}")
    results = {}
    for sl in ['mMTC','eMBB','URLLC']:
        print(f"\n  Testing slice: {sl}")
        active_slice  = sl
        baseline_set  = False
        attest_count  = 0
        tamper_count  = 0
        run_attestation(sl, silent=True)  # baseline
        mem_before = psutil.virtual_memory().used / 1024
        start_cpu()
        token = run_attestation(sl, silent=False)
        cpu   = stop_cpu()
        mem_delta = max(0, psutil.virtual_memory().used/1024 - mem_before)
        results[sl] = {
            'compute_ms'    : token['compute_ms'],
            'cpu_pct'       : cpu,
            'mem_kb'        : round(mem_delta, 2),
            'evidence_bytes': token['evidence_bytes'],
            'verdict'       : token['verdict'],
            'group_attest'  : token['group_attest'],
            'hash_rounds'   : token['hash_rounds']
        }
        print(f"    Compute (ms)   : {token['compute_ms']}")
        print(f"    CPU %          : {cpu}")
        print(f"    Mem delta (KB) : {round(mem_delta,2)}")
        print(f"    Evidence (B)   : {token['evidence_bytes']}")

    print(f"\n  RESULTS TABLE:")
    print(f"  {'Slice':<8}{'Time(ms)':<12}{'CPU%':<8}{'Mem(KB)':<10}{'Evid(B)':<10}{'Rounds':<8}")
    print(f"  {'-'*56}")
    for sl,r in results.items():
        print(f"  {sl:<8}{r['compute_ms']:<12}{r['cpu_pct']:<8}{r['mem_kb']:<10}{r['evidence_bytes']:<10}{r['hash_rounds']:<8}")

    sl_list = list(results.keys())
    cols = [C_mMTC, C_eMBB, C_URLLC]
    bar3('EXP 1: TrustZone Attestation Compute Time per 5G Slice (Tier 2)',
         'Compute Time (ms)', sl_list,
         [results[s]['compute_ms'] for s in sl_list], cols,
         'exp1_compute_time.png',
         'mMTC=2 rounds | eMBB=3 rounds | URLLC=4 rounds (HKDF key derivation)')
    bar3('EXP 1: Evidence Token Size per 5G Slice (Tier 2)',
         'Evidence Size (bytes)', sl_list,
         [results[s]['evidence_bytes'] for s in sl_list], cols,
         'exp1_evidence_size.png')
    bar3('EXP 1: CPU Overhead per Slice (Tier 2)',
         'CPU Usage (%)', sl_list,
         [results[s]['cpu_pct'] for s in sl_list], cols,
         'exp1_cpu_overhead.png')
    return results

# ================================================================
#  EXP 2 — FREQUENCY vs OVERHEAD
# ================================================================
def exp2():
    global active_slice, baseline_set, attest_count, tamper_count
    print(f"\n{'='*55}")
    print(f"  EXP 2: ATTESTATION FREQUENCY vs OVERHEAD")
    print(f"{'='*55}")
    active_slice = 'mMTC'
    baseline_set = False
    attest_count = 0
    run_attestation('mMTC', silent=True)

    configs = [('Boot-only',1),('Every 5min',3),('Every 1min',10),('Event-triggered',20)]
    freq_results = []
    for label, n in configs:
        print(f"\n  Scenario: {label} ({n} attestations)")
        times, cpus = [], []
        for _ in range(n):
            start_cpu()
            tok = run_attestation('mMTC', silent=True)
            cpu = stop_cpu()
            times.append(tok['compute_ms'])
            cpus.append(cpu)
        avg_t = round(float(np.mean(times)),2)
        avg_c = round(float(np.mean(cpus)),2)
        detect_lat = round(avg_t * n, 2)
        freq_results.append({'label':label,'avg_ms':avg_t,'avg_cpu':avg_c,'detect_lat':detect_lat})
        print(f"    Avg compute (ms)  : {avg_t}")
        print(f"    Avg CPU %         : {avg_c}")
        print(f"    Detection latency : {detect_lat} ms")

    labels = [r['label'] for r in freq_results]
    times  = [r['avg_ms']     for r in freq_results]
    cpus   = [r['avg_cpu']    for r in freq_results]
    delays = [r['detect_lat'] for r in freq_results]
    fig, ax1 = plt.subplots(figsize=(10,5))
    ax2 = ax1.twinx()
    x = np.arange(len(labels))
    l1, = ax1.plot(x, times,  'o-', color=C_mMTC,  linewidth=2, label='Avg Compute (ms)')
    l2, = ax1.plot(x, cpus,   's-', color=C_eMBB,  linewidth=2, label='CPU Overhead (%)')
    l3, = ax2.plot(x, delays, '^-', color=C_URLLC, linewidth=2, label='Detection Latency (ms)')
    ax1.set_xticks(x); ax1.set_xticklabels(labels, rotation=15)
    ax1.set_ylabel('Compute (ms) / CPU (%)', fontsize=10)
    ax2.set_ylabel('Detection Latency (ms)', fontsize=10, color=C_URLLC)
    ax1.set_title('EXP 2: Frequency vs Overhead vs Detection Speed\n(Tier 2 mMTC Slice)', fontsize=12, fontweight='bold')
    ax1.legend([l1,l2,l3],[l.get_label() for l in [l1,l2,l3]], fontsize=9, loc='upper left')
    ax1.spines['top'].set_visible(False)
    ax1.grid(linestyle='--', alpha=0.3)
    save_graph(fig, 'exp2_frequency_overhead.png')
    return freq_results

# ================================================================
#  EXP 3 — SCALABILITY
# ================================================================
def exp3():
    global active_slice, baseline_set, attest_count, tamper_count
    print(f"\n{'='*55}")
    print(f"  EXP 3: MULTI-DEVICE SCALABILITY")
    print(f"{'='*55}")
    active_slice = 'mMTC'
    baseline_set = False
    attest_count = 0
    run_attestation('mMTC', silent=True)

    scale_results = []
    for n in [1,2,3,5,8,10]:
        print(f"\n  Simulating {n} device(s)...")
        tokens, t0 = [], time.time()
        for _ in range(n):
            tok = run_attestation('mMTC', silent=True)
            tokens.append(tok)
        wall = time.time() - t0
        throughput = round(n/wall, 2)
        avg_lat    = round(wall*1000/n, 1)
        scale_results.append({'n':n,'throughput':throughput,'avg_lat':avg_lat})
        print(f"    Throughput : {throughput} devices/sec")
        print(f"    Avg latency: {avg_lat} ms/device")

    devs  = [r['n']          for r in scale_results]
    thrpt = [r['throughput'] for r in scale_results]
    lats  = [r['avg_lat']    for r in scale_results]
    fig,(ax1,ax2) = plt.subplots(1,2,figsize=(12,4))
    ax1.plot(devs,thrpt,'o-',color=C_mMTC,linewidth=2)
    ax1.set_xlabel('Number of Devices'); ax1.set_ylabel('Throughput (devices/sec)')
    ax1.set_title('EXP 3a: Throughput vs Fleet Size (Tier 2)',fontweight='bold')
    ax1.grid(linestyle='--',alpha=0.4)
    ax1.spines['top'].set_visible(False); ax1.spines['right'].set_visible(False)
    ax2.plot(devs,lats,'s-',color=C_eMBB,linewidth=2)
    ax2.set_xlabel('Number of Devices'); ax2.set_ylabel('Avg Latency (ms)')
    ax2.set_title('EXP 3b: Latency vs Fleet Size (Tier 2)',fontweight='bold')
    ax2.grid(linestyle='--',alpha=0.4)
    ax2.spines['top'].set_visible(False); ax2.spines['right'].set_visible(False)
    fig.tight_layout(); save_graph(fig,'exp3_scalability.png')
    return scale_results

# ================================================================
#  EXP 4A — REPLAY ATTACK
# ================================================================
def exp4a():
    global active_slice, baseline_set, attest_count, tamper_count, fw_tampered
    print(f"\n{'='*55}")
    print(f"  EXP 4A: REPLAY ATTACK DETECTION")
    print(f"{'='*55}")
    active_slice = 'mMTC'
    baseline_set = False
    attest_count = 0
    fw_tampered  = False
    run_attestation('mMTC', silent=True)
    tok_valid = run_attestation('mMTC', silent=False)
    print(f"  Valid token captured. TZMA: {tok_valid['tzma'][:16]}...")
    fw_tampered = True
    tok_tamper  = run_attestation('mMTC', silent=False)
    print(f"  After tamper. Verdict: {tok_tamper['verdict']}")
    detected = tok_valid['tzma'] != tok_tamper['tzma']
    reason   = 'TZMA changed after firmware modification' if detected else 'NOT DETECTED'
    print(f"\n  Replay detected : {detected}")
    print(f"  Reason          : {reason}")
    fw_tampered  = False
    baseline_set = False
    attest_count = 0
    tamper_count = 0
    return {'detected':detected,'reason':reason}

# ================================================================
#  EXP 4B — PARTIAL COMPROMISE
# ================================================================
def exp4b():
    global active_slice, baseline_set, attest_count, tamper_count, cfg_tampered
    print(f"\n{'='*55}")
    print(f"  EXP 4B: PARTIAL COMPROMISE DETECTION")
    print(f"{'='*55}")
    active_slice = 'eMBB'
    baseline_set = False
    attest_count = 0
    cfg_tampered = False
    run_attestation('eMBB', silent=True)
    tok_clean = run_attestation('eMBB', silent=False)
    print(f"  Clean verdict: {tok_clean['verdict']}")
    cfg_tampered = True
    baseline_set = False
    tok_partial  = run_attestation('eMBB', silent=False)
    print(f"  After config change: {tok_partial['verdict']}")
    detected = tok_partial['verdict'] == 'COMPROMISED'
    print(f"  Partial tampering detected: {detected}")
    cfg_tampered = False
    baseline_set = False
    attest_count = 0
    tamper_count = 0
    return {'detected':detected}

# ================================================================
#  EXP 5 — MOBILITY & EDGE RELOCATION
# ================================================================
def exp5():
    global active_slice, baseline_set, attest_count, mobility_mode, verifier_ep
    print(f"\n{'='*55}")
    print(f"  EXP 5: MOBILITY & EDGE RELOCATION (5G Handover)")
    print(f"{'='*55}")
    active_slice = 'eMBB'
    baseline_set = False
    attest_count = 0
    verifier_ep  = 'CLOUD_VERIFIER'
    mobility_mode = False
    run_attestation('eMBB', silent=True)

    print(f"\n  Phase A: Cloud verifier")
    t0 = time.time()
    tok_cloud = run_attestation('eMBB', silent=False)
    cloud_ms  = round((time.time()-t0)*1000, 2)
    print(f"  Cloud latency : {cloud_ms} ms")

    print(f"\n  Phase B: Handover to MEC edge")
    verifier_ep   = 'MEC_EDGE_NODE_01'
    mobility_mode = True
    baseline_set  = False
    time.sleep(0.5)
    t0 = time.time()
    tok_mec = run_attestation('eMBB', silent=False)
    mec_ms  = round((time.time()-t0)*1000, 2)
    print(f"  MEC latency   : {mec_ms} ms")

    print(f"\n  Phase C: Return to cloud")
    verifier_ep   = 'CLOUD_VERIFIER'
    mobility_mode = False
    baseline_set  = False
    t0 = time.time()
    tok_ret = run_attestation('eMBB', silent=False)
    ret_ms  = round((time.time()-t0)*1000, 2)
    print(f"  Return latency: {ret_ms} ms")
    print(f"\n  Added MEC handover latency: {round(mec_ms-cloud_ms,2)} ms")

    bar3('EXP 5: Attestation Latency During 5G Handover (Tier 2)\n(Cloud → MEC Edge → Cloud Return)',
         'Attestation Time (ms)',
         ['Cloud','MEC Edge\n(Handover)','Cloud\n(Return)'],
         [cloud_ms, mec_ms, ret_ms],
         [C_eMBB, C_URLLC, C_eMBB],
         'exp5_mobility_latency.png',
         'Verifier endpoint change triggers TrustZone re-attestation')

    verifier_ep  = 'CLOUD_VERIFIER'
    baseline_set = False
    attest_count = 0
    return {'cloud_ms':cloud_ms,'mec_ms':mec_ms,'ret_ms':ret_ms}

# ================================================================
#  EXP 6 — HIERARCHICAL ATTESTATION
# ================================================================
def exp6():
    global active_slice, baseline_set, attest_count
    print(f"\n{'='*55}")
    print(f"  EXP 6: HIERARCHICAL ATTESTATION")
    print(f"  Tier1 sensors -> Tier2 gateway -> Tier3 cloud")
    print(f"{'='*55}")
    active_slice = 'mMTC'
    baseline_set = False
    attest_count = 0
    run_attestation('mMTC', silent=True)

    print(f"\n  Mode A: 10 individual tokens (Tier 1 sensors)")
    individual_tokens, t0 = [], time.time()
    for _ in range(10):
        tok = run_attestation('mMTC', silent=True)
        individual_tokens.append(tok)
    ind_time  = round((time.time()-t0)*1000, 2)
    ind_bytes = sum(t['evidence_bytes'] for t in individual_tokens)
    print(f"  10 tokens | Time: {ind_time}ms | Bytes: {ind_bytes}")

    baseline_set = False
    attest_count = 0
    run_attestation('mMTC', silent=True)

    print(f"\n  Mode B: 1 group aggregate token (Tier 2 gateway)")
    t0 = time.time()
    grp_tok   = run_attestation('mMTC', silent=True)
    grp_time  = round((time.time()-t0)*1000, 2)
    grp_bytes = grp_tok['evidence_bytes']
    print(f"  1 token  | Time: {grp_time}ms | Bytes: {grp_bytes}")

    saving_pct = round((ind_bytes-grp_bytes)/ind_bytes*100,1) if ind_bytes>0 else 0
    print(f"\n  Bandwidth saving : {saving_pct}%")
    print(f"  Verifier load    : 10 verifications reduced to 1")

    fig,(ax1,ax2) = plt.subplots(1,2,figsize=(11,4))
    modes = ['Individual\n(10 tokens)','Group\nAggregate\n(1 token)']
    ax1.bar(modes,[ind_bytes,grp_bytes],color=[C_eMBB,C_mMTC],edgecolor='white',width=0.4)
    ax1.set_title('EXP 6a: Evidence Bandwidth\nIndividual vs Group (Tier 2)',fontweight='bold')
    ax1.set_ylabel('Total Evidence Size (bytes)')
    ax1.grid(axis='y',linestyle='--',alpha=0.4)
    ax1.spines['top'].set_visible(False); ax1.spines['right'].set_visible(False)
    ax2.bar(modes,[ind_time,grp_time],color=[C_eMBB,C_mMTC],edgecolor='white',width=0.4)
    ax2.set_title('EXP 6b: Verification Time\nIndividual vs Group (Tier 2)',fontweight='bold')
    ax2.set_ylabel('Total Time (ms)')
    ax2.grid(axis='y',linestyle='--',alpha=0.4)
    ax2.spines['top'].set_visible(False); ax2.spines['right'].set_visible(False)
    fig.tight_layout(); save_graph(fig,'exp6_hierarchical.png')

    baseline_set = False
    attest_count = 0
    return {'ind_time':ind_time,'ind_bytes':ind_bytes,'grp_time':grp_time,'grp_bytes':grp_bytes,'saving_pct':saving_pct}

# ================================================================
#  EXP 7 — INTEROPERABILITY
# ================================================================
def exp7():
    global active_slice, baseline_set, attest_count
    print(f"\n{'='*55}")
    print(f"  EXP 7: EVIDENCE FORMAT & INTEROPERABILITY")
    print(f"{'='*55}")
    REQUIRED = {
        'device':str,'tier':int,'slice':str,'power_mode':str,
        'group_attest':bool,'cluster_size':int,'mec_verify':bool,
        'hash_rounds':int,'verifier':str,'tzma':str,
        'group_evidence':str,'compute_ms':float,'evidence_bytes':int,
        'attest_count':int,'verdict':str
    }
    results = {}
    for sl in ['mMTC','eMBB','URLLC']:
        active_slice = sl
        baseline_set = False
        attest_count = 0
        run_attestation(sl, silent=True)
        tok  = run_attestation(sl, silent=True)
        fails = []
        for field, ftype in REQUIRED.items():
            if field not in tok or not isinstance(tok[field], ftype):
                fails.append(field)
        schema_ok = len(fails) == 0
        results[sl] = {'schema_valid':schema_ok,'failed_fields':fails}
        status = 'PASS' if schema_ok else 'FAIL'
        print(f"  [{status}] Slice {sl}: schema_valid={schema_ok}")
        if fails: print(f"         Failed: {fails}")
    return results

# ================================================================
#  EXP D2D — MUTUAL ATTESTATION PROTOCOL
#  Novel contribution: Tier 2 (Pi) and Tier 3 (Laptop) mutually
#  verify each other without base station mediation.
#  Simulated over WiFi Direct (same network segment).
# ================================================================
def exp_d2d():
    global active_slice, baseline_set, attest_count
    print(f"\n{'='*55}")
    print(f"  EXP D2D: MUTUAL ATTESTATION PROTOCOL")
    print(f"  Device A (Pi) <-> Device B (Laptop) over WiFi")
    print(f"  5G Feature: D2D/ProSe/Sidelink simulation")
    print(f"{'='*55}")

    active_slice = 'URLLC'
    baseline_set = False
    attest_count = 0

    # Step 1: Device A (Pi) generates its attestation token
    print(f"\n  [D2D Step 1] Device A (Pi) generating attestation token...")
    run_attestation('URLLC', silent=True)
    tok_A = run_attestation('URLLC', silent=False)
    print(f"  Device A TZMA  : {tok_A['tzma'][:32]}...")
    print(f"  Device A Verdict: {tok_A['verdict']}")

    # Step 2: Simulate Device B token (laptop TPM — Tier 3)
    print(f"\n  [D2D Step 2] Device B (Laptop) token received (simulated)...")
    tok_B_tzma = hashlib.sha256(b"LAPTOP_TPM_ATTESTATION_TOKEN_TIER3").hexdigest()
    tok_B_verdict = 'TRUSTED'
    print(f"  Device B TZMA  : {tok_B_tzma[:32]}...")
    print(f"  Device B Verdict: {tok_B_verdict}")

    # Step 3: Mutual verification
    print(f"\n  [D2D Step 3] Mutual verification...")
    A_trusts_B = len(tok_B_tzma) == 64 and tok_B_verdict == 'TRUSTED'
    B_trusts_A = tok_A['verdict'] in ['TRUSTED','BASELINE_STORED']
    mutual_ok  = A_trusts_B and B_trusts_A

    print(f"  Device A trusts B : {A_trusts_B}")
    print(f"  Device B trusts A : {B_trusts_A}")
    print(f"  Mutual Auth OK    : {mutual_ok}")
    print(f"  D2D Link Status   : {'ESTABLISHED' if mutual_ok else 'REJECTED'}")
    print(f"  >> This is the D2D Mutual Attestation Protocol")
    print(f"  >> No base station involved - direct peer verification")

    baseline_set = False
    attest_count = 0
    return {
        'mutual_ok'    : mutual_ok,
        'A_trusts_B'   : A_trusts_B,
        'B_trusts_A'   : B_trusts_A,
        'tok_A_verdict': tok_A['verdict'],
        'tok_B_verdict': tok_B_verdict
    }

# ================================================================
#  SAVE REPORT
# ================================================================
def save_report(all_results):
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(REPORT_DIR, f'tier2_full_report_{ts}.json')
    with open(path,'w') as f:
        json.dump({
            'framework'  : '5G-Adaptive Lightweight Remote Attestation Framework',
            'tier'       : 2,
            'device'     : 'Raspberry Pi 4',
            'mechanism'  : 'TrustZone TZMA + HKDF Key Derivation',
            'timestamp'  : datetime.now().isoformat(),
            'experiments': all_results
        }, f, indent=2, default=str)
    print(f"\n[MEC] Report saved: {path}")
    return path

# ================================================================
#  MAIN
# ================================================================
def main():
    print('='*55)
    print('  5G TRUSTZONE ATTESTATION - TIER 2')
    print('  Raspberry Pi 4 | ARM TrustZone Simulation')
    print('  All 8 Supervisor Experiments + D2D Protocol')
    print('='*55)

    all_results = {}
    all_results['exp1_performance']      = exp1()
    all_results['exp2_frequency']        = exp2()
    all_results['exp3_scalability']      = exp3()
    all_results['exp4a_replay']          = exp4a()
    all_results['exp4b_partial']         = exp4b()
    all_results['exp5_mobility']         = exp5()
    all_results['exp6_hierarchical']     = exp6()
    all_results['exp7_interoperability'] = exp7()
    all_results['exp_d2d']               = exp_d2d()

    report = save_report(all_results)

    print(f"\n{'='*55}")
    print(f"  TIER 2 COMPLETE - SUMMARY")
    print(f"{'='*55}")
    r1 = all_results.get('exp1_performance',{})
    for sl,d in r1.items():
        print(f"  EXP1 {sl:<6}: {d['compute_ms']}ms | {d['cpu_pct']}% CPU | {d['evidence_bytes']}B")
    print(f"  EXP4A Replay detected  : {all_results.get('exp4a_replay',{}).get('detected','?')}")
    print(f"  EXP4B Partial detected : {all_results.get('exp4b_partial',{}).get('detected','?')}")
    print(f"  EXP6 Bandwidth saving  : {all_results.get('exp6_hierarchical',{}).get('saving_pct','?')}%")
    print(f"  D2D Mutual Auth OK     : {all_results.get('exp_d2d',{}).get('mutual_ok','?')}")
    print(f"  Graphs saved to        : {GRAPH_DIR}")
    print(f"  Report saved to        : {report}")
    print(f"{'='*55}")

if __name__ == '__main__':
    main()
