import serial, json, time, os, sys, psutil, threading
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

PORT       = 'COM4'
BAUD       = 9600
BASE_DIR   = r'C:\Users\HP\OneDrive\Desktop\Rahaf\ZU\Thesis\Tier 1\tier1_5g_attestation'
REPORT_DIR = os.path.join(BASE_DIR, 'attestation_reports')
GRAPH_DIR  = os.path.join(BASE_DIR, 'graphs')
os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(GRAPH_DIR,  exist_ok=True)

C_mMTC  = '#E07B39'
C_eMBB  = '#2E75B6'
C_URLLC = '#70AD47'

def connect():
    print(f'\n[MEC] Connecting to Arduino on {PORT}...')
    try:
        ser = serial.Serial(PORT, BAUD, timeout=8)
    except serial.SerialException as e:
        print(f'[MEC] ERROR: Cannot open {PORT}.')
        print(f'      Open Arduino IDE, check Tools > Port, then change PORT at top of this script.')
        print(f'      Detail: {e}')
        sys.exit(1)
    time.sleep(2)
    ser.reset_input_buffer()
    print('[MEC] Waiting for READY signal...')
    deadline = time.time() + 15
    while time.time() < deadline:
        if ser.in_waiting:
            line = ser.readline().decode('utf-8', errors='ignore').strip()
            if line: print(f'  Arduino >> {line}')
            if 'READY' in line:
                print('[MEC] Arduino is online.\n')
                return ser
    print('[MEC] ERROR: Arduino did not respond. Make sure Serial Monitor is CLOSED in Arduino IDE.')
    sys.exit(1)

def send(ser, cmd, wait_token=True, timeout_s=20):
    print(f'\n  [MEC >>] {cmd}')
    ser.reset_input_buffer()
    ser.write((cmd + '\n').encode())
    time.sleep(0.3)
    token, in_token, token_raw = None, False, ''
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if ser.in_waiting:
            raw = ser.readline().decode('utf-8', errors='ignore').strip()
            if raw: print(f'  Arduino >> {raw}')
            if '---BEGIN_TOKEN---' in raw:
                in_token, token_raw = True, ''
            elif '---END_TOKEN---' in raw:
                in_token = False
                try:    token = json.loads(token_raw.strip())
                except: print(f'  [MEC] JSON parse error. Raw: {token_raw}')
                if wait_token: break
            elif in_token:
                token_raw += raw
        else:
            time.sleep(0.05)
    return token

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

def save_graph(fig, name):
    path = os.path.join(GRAPH_DIR, name)
    fig.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)
    print(f'  [GRAPH] Saved: {path}')
    return path

def bar3(title, ylabel, labels, vals, cols, fname, note=''):
    fig, ax = plt.subplots(figsize=(8,4))
    bars = ax.bar(labels, vals, color=cols, edgecolor='white', width=0.5)
    for b,v in zip(bars,vals):
        ax.text(b.get_x()+b.get_width()/2, b.get_height()+0.01*max(vals) if max(vals)>0 else 0.01,
                f'{v:.2f}', ha='center', va='bottom', fontsize=9)
    ax.set_title(title, fontsize=12, fontweight='bold', pad=10)
    ax.set_ylabel(ylabel, fontsize=10)
    if note: fig.text(0.5,-0.04,note,ha='center',fontsize=8,color='grey',style='italic')
    ax.spines['top'].set_visible(False); ax.spines['right'].set_visible(False)
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    return save_graph(fig, fname)

def exp1(ser):
    print('\n' + '='*55)
    print('  EXP 1: CROSS-TIER PERFORMANCE AND OVERHEAD')
    print('='*55)
    results = {}
    for sl in ['mMTC','eMBB','URLLC']:
        print(f'\n  Testing slice: {sl}')
        send(ser, f'SLICE:{sl}', wait_token=False); time.sleep(0.5)
        send(ser, 'ATTEST', wait_token=True);       time.sleep(0.3)
        mem_before = psutil.virtual_memory().used / 1024
        start_cpu()
        t0    = time.time()
        token = send(ser, 'ATTEST', wait_token=True)
        wall  = time.time() - t0
        cpu   = stop_cpu()
        mem_delta = max(0, psutil.virtual_memory().used/1024 - mem_before)
        if token:
            results[sl] = {
                'compute_ms'    : token.get('compute_ms', 0),
                'compute_us'    : token.get('compute_us', 0),
                'wall_ms'       : round(wall*1000, 2),
                'cpu_pct'       : cpu,
                'mem_kb'        : round(mem_delta, 2),
                'evidence_bytes': token.get('evidence_bytes', 0),
                'verdict'       : token.get('verdict',''),
                'group_attest'  : token.get('group_attest', False)
            }
            r = results[sl]
            print(f'    Compute (us)   : {r["compute_us"]}')
            print(f'    Compute (ms)   : {r["compute_ms"]}')
            print(f'    Wall time (ms) : {r["wall_ms"]}')
            print(f'    CPU %          : {r["cpu_pct"]}')
            print(f'    Mem delta (KB) : {r["mem_kb"]}')
            print(f'    Evidence (B)   : {r["evidence_bytes"]}')
            print(f'    Verdict        : {r["verdict"]}')
        send(ser, 'RESET', wait_token=False); time.sleep(0.5)
    if results:
        sl_list = list(results.keys())
        cols = [C_mMTC, C_eMBB, C_URLLC]
        print('\n  RESULTS TABLE:')
        print(f'  {"Slice":<8}{"Time(ms)":<12}{"CPU%":<8}{"Mem(KB)":<10}{"Evid(B)":<10}{"Group":<8}')
        print('  ' + '-'*56)
        for sl in sl_list:
            r = results[sl]
            print(f'  {sl:<8}{r["compute_ms"]:<12}{r["cpu_pct"]:<8}{r["mem_kb"]:<10}{r["evidence_bytes"]:<10}{str(r["group_attest"]):<8}')
        bar3('EXP 1: Attestation Compute Time per 5G Slice (Tier 1)',
             'Compute Time (ms)', sl_list,
             [results[s]['compute_ms'] for s in sl_list], cols,
             'exp1_compute_time.png',
             'mMTC=1 round | eMBB=2 rounds | URLLC=3 rounds')
        bar3('EXP 1: Evidence Token Size per 5G Slice (Tier 1)',
             'Evidence Size (bytes)', sl_list,
             [results[s]['evidence_bytes'] for s in sl_list], cols,
             'exp1_evidence_size.png',
             'mMTC group token covers 5 sensors - bandwidth saving vs individual')
        bar3('EXP 1: CPU Overhead During Attestation per Slice (Tier 1)',
             'CPU Usage (%)', sl_list,
             [results[s]['cpu_pct'] for s in sl_list], cols,
             'exp1_cpu_overhead.png')
    return results

def exp2(ser):
    print('\n' + '='*55)
    print('  EXP 2: ATTESTATION FREQUENCY vs OVERHEAD')
    print('='*55)
    send(ser, 'SLICE:mMTC', wait_token=False); time.sleep(0.5)
    send(ser, 'ATTEST', wait_token=True);      time.sleep(0.3)
    configs = [('Boot-only',1),('Every 5min',3),('Every 1min',10),('Event-triggered',20)]
    freq_results = []
    for label, n in configs:
        print(f'\n  Scenario: {label} ({n} attestations)')
        times, cpus = [], []
        for _ in range(n):
            start_cpu()
            tok = send(ser, 'ATTEST:SILENT', wait_token=True, timeout_s=10)
            cpu = stop_cpu()
            if tok:
                times.append(tok.get('compute_ms', 0))
                cpus.append(cpu)
        avg_t = round(float(np.mean(times)),2) if times else 0
        avg_c = round(float(np.mean(cpus)),2)  if cpus  else 0
        detect_lat = round(avg_t * n, 2)
        freq_results.append({'label':label,'n':n,'avg_ms':avg_t,'avg_cpu':avg_c,'detect_lat':detect_lat})
        print(f'    Avg compute (ms)  : {avg_t}')
        print(f'    Avg CPU %         : {avg_c}')
        print(f'    Detection latency : {detect_lat} ms')
    send(ser, 'RESET', wait_token=False); time.sleep(0.3)
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
    ax1.set_title('EXP 2: Frequency vs Overhead vs Detection Speed\n(Tier 1 mMTC Slice)', fontsize=12, fontweight='bold')
    ax1.legend([l1,l2,l3],[l.get_label() for l in [l1,l2,l3]], fontsize=9, loc='upper left')
    ax1.spines['top'].set_visible(False); ax1.grid(linestyle='--',alpha=0.3)
    save_graph(fig, 'exp2_frequency_overhead.png')
    return freq_results

def exp3(ser):
    print('\n' + '='*55)
    print('  EXP 3: MULTI-DEVICE SCALABILITY')
    print('='*55)
    send(ser,'SLICE:mMTC',wait_token=False); time.sleep(0.5)
    send(ser,'ATTEST',wait_token=True);      time.sleep(0.3)
    scale_results = []
    for n in [1,2,3,5,8,10]:
        print(f'\n  Simulating {n} device(s)...')
        tokens, t0 = [], time.time()
        for _ in range(n):
            tok = send(ser,'ATTEST:SILENT',wait_token=True,timeout_s=10)
            if tok: tokens.append(tok)
        wall = time.time() - t0
        success    = len(tokens)
        throughput = round(success/wall,2) if wall>0 else 0
        avg_lat    = round(wall*1000/success,1) if success>0 else 0
        scale_results.append({'n':n,'success':success,'throughput':throughput,'avg_lat':avg_lat})
        print(f'    Throughput : {throughput} devices/sec')
        print(f'    Avg latency: {avg_lat} ms/device')
    send(ser,'RESET',wait_token=False); time.sleep(0.3)
    devs  = [r['n']          for r in scale_results]
    thrpt = [r['throughput'] for r in scale_results]
    lats  = [r['avg_lat']    for r in scale_results]
    fig,(ax1,ax2)=plt.subplots(1,2,figsize=(12,4))
    ax1.plot(devs,thrpt,'o-',color=C_mMTC,linewidth=2)
    ax1.set_xlabel('Number of Devices'); ax1.set_ylabel('Throughput (devices/sec)')
    ax1.set_title('EXP 3a: Verification Throughput vs Fleet Size',fontweight='bold')
    ax1.grid(linestyle='--',alpha=0.4); ax1.spines['top'].set_visible(False); ax1.spines['right'].set_visible(False)
    ax2.plot(devs,lats,'s-',color=C_eMBB,linewidth=2)
    ax2.set_xlabel('Number of Devices'); ax2.set_ylabel('Avg Latency per Device (ms)')
    ax2.set_title('EXP 3b: Processing Latency vs Fleet Size',fontweight='bold')
    ax2.grid(linestyle='--',alpha=0.4); ax2.spines['top'].set_visible(False); ax2.spines['right'].set_visible(False)
    fig.tight_layout(); save_graph(fig,'exp3_scalability.png')
    return scale_results

def exp4a(ser):
    print('\n' + '='*55)
    print('  EXP 4A: REPLAY ATTACK DETECTION')
    print('='*55)
    send(ser,'SLICE:mMTC',wait_token=False); time.sleep(0.5)
    send(ser,'ATTEST',wait_token=True); time.sleep(0.3)
    tok_valid = send(ser,'ATTEST',wait_token=True); time.sleep(0.3)
    print(f'  Valid token captured. CDI_1: {tok_valid.get("cdi1","?")[:16]}...')
    send(ser,'TAMPER:FULL',wait_token=False); time.sleep(0.5)
    tok_tamper = send(ser,'ATTEST',wait_token=True); time.sleep(0.3)
    print(f'  After tamper. Verdict: {tok_tamper.get("verdict","?") if tok_tamper else "N/A"}')
    detected, reason = False, ''
    if tok_valid and tok_tamper:
        if tok_valid.get('cdi1') != tok_tamper.get('cdi1'):
            detected = True; reason = 'CDI_1 changed after firmware modification'
        if tok_tamper.get('attest_count',0) <= tok_valid.get('attest_count',0):
            detected = True; reason += ' | Counter did not advance'
    print(f'\n  Replay detected : {detected}')
    print(f'  Reason          : {reason}')
    send(ser,'TAMPER:RESTORE',wait_token=False)
    send(ser,'RESET',wait_token=False); time.sleep(0.3)
    return {'detected':detected,'reason':reason}

def exp4b(ser):
    print('\n' + '='*55)
    print('  EXP 4B: PARTIAL COMPROMISE DETECTION')
    print('='*55)
    send(ser,'SLICE:eMBB',wait_token=False); time.sleep(0.5)
    send(ser,'ATTEST',wait_token=True);      time.sleep(0.3)
    tok_clean = send(ser,'ATTEST',wait_token=True); time.sleep(0.3)
    print(f'  Clean verdict: {tok_clean.get("verdict","?") if tok_clean else "N/A"}')
    send(ser,'TAMPER:PARTIAL',wait_token=False); time.sleep(0.5)
    tok_partial = send(ser,'ATTEST',wait_token=True); time.sleep(0.3)
    print(f'  After config change: {tok_partial.get("verdict","?") if tok_partial else "N/A"}')
    detected = tok_partial.get('verdict')=='COMPROMISED' if tok_partial else False
    print(f'  Partial tampering detected: {detected}')
    send(ser,'TAMPER:RESTORE',wait_token=False)
    send(ser,'RESET',wait_token=False); time.sleep(0.3)
    return {'detected':detected}

def exp5(ser):
    print('\n' + '='*55)
    print('  EXP 5: MOBILITY AND EDGE RELOCATION')
    print('='*55)
    results = {}
    send(ser,'SLICE:eMBB',wait_token=False); time.sleep(0.5)
    send(ser,'ATTEST',wait_token=True); time.sleep(0.3)
    print('\n  Phase A: Cloud verifier')
    t0=time.time(); tok_cloud=send(ser,'ATTEST',wait_token=True)
    cloud_ms=round((time.time()-t0)*1000,2)
    print(f'  Cloud latency : {cloud_ms} ms | Verdict: {tok_cloud.get("verdict","?") if tok_cloud else "N/A"}')
    results['cloud']={'ms':cloud_ms}
    print('\n  Phase B: Handover to MEC edge')
    send(ser,'MOBILITY:MEC',wait_token=False); time.sleep(0.8)
    t0=time.time(); tok_mec=send(ser,'ATTEST',wait_token=True)
    mec_ms=round((time.time()-t0)*1000,2)
    print(f'  MEC latency   : {mec_ms} ms | Verdict: {tok_mec.get("verdict","?") if tok_mec else "N/A"}')
    results['mec']={'ms':mec_ms}
    print('\n  Phase C: Return to cloud')
    send(ser,'MOBILITY:CLOUD',wait_token=False); time.sleep(0.5)
    t0=time.time(); tok_ret=send(ser,'ATTEST',wait_token=True)
    ret_ms=round((time.time()-t0)*1000,2)
    print(f'  Return latency: {ret_ms} ms | Verdict: {tok_ret.get("verdict","?") if tok_ret else "N/A"}')
    results['return']={'ms':ret_ms}
    print(f'\n  Added MEC handover latency: {round(mec_ms-cloud_ms,2)} ms')
    bar3('EXP 5: Attestation Latency During 5G Handover\n(Cloud to MEC Edge to Cloud Return)',
         'Attestation Wall Time (ms)',
         ['Cloud','MEC Edge\n(Handover)','Cloud\n(Return)'],
         [cloud_ms, mec_ms, ret_ms],
         [C_eMBB, C_URLLC, C_eMBB],
         'exp5_mobility_latency.png',
         'Verifier endpoint change triggers re-attestation - measures 5G handover overhead')
    send(ser,'RESET',wait_token=False); time.sleep(0.3)
    return results

def exp6(ser):
    print('\n' + '='*55)
    print('  EXP 6: HIERARCHICAL ATTESTATION')
    print('='*55)
    send(ser,'SLICE:mMTC',wait_token=False); time.sleep(0.5)
    send(ser,'ATTEST',wait_token=True); time.sleep(0.3)
    print('\n  Mode A: 5 individual tokens')
    individual_tokens, t0 = [], time.time()
    for _ in range(5):
        tok=send(ser,'ATTEST:SILENT',wait_token=True,timeout_s=10)
        if tok: individual_tokens.append(tok)
    ind_time  = round((time.time()-t0)*1000,2)
    ind_bytes = sum(t.get('evidence_bytes',0) for t in individual_tokens)
    print(f'  5 tokens | Time: {ind_time}ms | Bytes: {ind_bytes}')
    send(ser,'RESET',wait_token=False); time.sleep(0.3)
    send(ser,'SLICE:mMTC',wait_token=False); time.sleep(0.5)
    send(ser,'ATTEST',wait_token=True); time.sleep(0.3)
    print('\n  Mode B: 1 group aggregate token')
    t0=time.time(); grp_tok=send(ser,'ATTEST:SILENT',wait_token=True,timeout_s=10)
    grp_time  = round((time.time()-t0)*1000,2)
    grp_bytes = grp_tok.get('evidence_bytes',0) if grp_tok else 0
    print(f'  1 token  | Time: {grp_time}ms | Bytes: {grp_bytes}')
    saving_pct = round((ind_bytes-grp_bytes)/ind_bytes*100,1) if ind_bytes>0 else 0
    print(f'\n  Bandwidth saving : {saving_pct}%')
    fig,(ax1,ax2)=plt.subplots(1,2,figsize=(11,4))
    modes=['Individual\n(5 tokens)','Group\nAggregate\n(1 token)']
    ax1.bar(modes,[ind_bytes,grp_bytes],color=[C_eMBB,C_mMTC],edgecolor='white',width=0.4)
    ax1.set_title('EXP 6a: Evidence Bandwidth',fontweight='bold')
    ax1.set_ylabel('Total Evidence Size (bytes)')
    ax1.grid(axis='y',linestyle='--',alpha=0.4); ax1.spines['top'].set_visible(False); ax1.spines['right'].set_visible(False)
    ax2.bar(modes,[ind_time,grp_time],color=[C_eMBB,C_mMTC],edgecolor='white',width=0.4)
    ax2.set_title('EXP 6b: Verification Time',fontweight='bold')
    ax2.set_ylabel('Total Time (ms)')
    ax2.grid(axis='y',linestyle='--',alpha=0.4); ax2.spines['top'].set_visible(False); ax2.spines['right'].set_visible(False)
    fig.tight_layout(); save_graph(fig,'exp6_hierarchical.png')
    send(ser,'RESET',wait_token=False); time.sleep(0.3)
    return {'ind_time':ind_time,'ind_bytes':ind_bytes,'grp_time':grp_time,'grp_bytes':grp_bytes,'saving_pct':saving_pct}

def exp7(ser):
    print('\n' + '='*55)
    print('  EXP 7: EVIDENCE FORMAT AND INTEROPERABILITY')
    print('='*55)
    REQUIRED = {'device':str,'tier':int,'slice':str,'power_mode':str,
                'group_attest':bool,'cluster_size':int,'mec_verify':bool,
                'hash_rounds':int,'verifier':str,'cdi0':str,'cdi1':str,
                'group_evidence':str,'compute_us':int,'compute_ms':int,
                'evidence_bytes':int,'attest_count':int,'verdict':str}
    results = {}
    for sl in ['mMTC','eMBB','URLLC']:
        send(ser,f'SLICE:{sl}',wait_token=False); time.sleep(0.5)
        send(ser,'ATTEST',wait_token=True);       time.sleep(0.3)
        tok=send(ser,'ATTEST',wait_token=True)
        fails=[]
        if tok:
            for field,ftype in REQUIRED.items():
                if field not in tok or not isinstance(tok[field],ftype):
                    fails.append(field)
        schema_ok = len(fails)==0
        results[sl]={'schema_valid':schema_ok,'failed_fields':fails}
        status='PASS' if schema_ok else 'FAIL'
        print(f'  [{status}] Slice {sl}: schema_valid={schema_ok}')
        if fails: print(f'         Failed fields: {fails}')
        send(ser,'RESET',wait_token=False); time.sleep(0.3)
    return results

def save_report(all_results, graphs):
    ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = os.path.join(REPORT_DIR, f'tier1_full_report_{ts}.json')
    with open(path,'w') as f:
        json.dump({
            'framework' : '5G-Adaptive Lightweight Remote Attestation Framework',
            'tier'      : 1,
            'device'    : 'Arduino Uno R3',
            'verifier'  : 'HP Laptop MEC Node',
            'timestamp' : datetime.now().isoformat(),
            'experiments': all_results,
            'graphs'    : graphs
        }, f, indent=2, default=str)
    print(f'\n[MEC] Master report saved: {path}')
    return path

def main():
    print('='*55)
    print('  5G MEC VERIFIER - TIER 1 FULL EXPERIMENT SUITE')
    print('  Arduino Uno R3 | HP Laptop MEC Node')
    print('='*55)
    ser = connect()
    all_results = {}
    all_results['exp1_performance']      = exp1(ser)
    all_results['exp2_frequency']        = exp2(ser)
    all_results['exp3_scalability']      = exp3(ser)
    all_results['exp4a_replay']          = exp4a(ser)
    all_results['exp4b_partial']         = exp4b(ser)
    all_results['exp5_mobility']         = exp5(ser)
    all_results['exp6_hierarchical']     = exp6(ser)
    all_results['exp7_interoperability'] = exp7(ser)
    graphs = [os.path.join(GRAPH_DIR,f) for f in os.listdir(GRAPH_DIR) if f.endswith('.png')]
    report = save_report(all_results, graphs)
    print('\n' + '='*55)
    print('  TIER 1 COMPLETE - SUMMARY')
    print('='*55)
    r1 = all_results.get('exp1_performance',{})
    for sl,d in r1.items():
        print(f'  EXP1 {sl:<6}: {d["compute_ms"]}ms | {d["cpu_pct"]}% CPU | {d["evidence_bytes"]}B')
    print(f'  EXP4A Replay detected  : {all_results.get("exp4a_replay",{}).get("detected","?")}')
    print(f'  EXP4B Partial detected : {all_results.get("exp4b_partial",{}).get("detected","?")}')
    print(f'  EXP6 Bandwidth saving  : {all_results.get("exp6_hierarchical",{}).get("saving_pct","?")}%')
    print(f'  Graphs saved to        : {GRAPH_DIR}')
    print(f'  Report saved to        : {report}')
    print('='*55)
    ser.close()

if __name__ == '__main__':
    main()
