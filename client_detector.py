# client_detector.py
"""
Client-side Rogue AP detector heuristics.

Functions:
- detect_rogue_aps(aps_info, whitelist_ssids, whitelist_bssids, strict_vendor_match=True)
    -> returns dict: bssid -> {"score": int, "reasons":[...], "info": original_info}

Heuristics used (simple, explainable):
- whitelist: if SSID or BSSID in whitelist -> low suspiciousness
- duplicate_ssid: same SSID seen with many different BSSIDs (possible evil-twin)
- vendor_ie_mismatch: when multiple BSSIDs advertise same SSID but vendor_elements differ
- channel_mismatch: same SSID on many widely different channels
- missing_vendor_ies: an AP that clones SSID but lacks vendor IEs of legitimate AP
- short_beacon_interval: unusual beacon interval (optional, if available)
- rssi_anomaly: if RSSI present and far weaker/stronger than cluster (optional)

Notes:
- aps_info format expected: { bssid: { 'ssid': str, 'ies_hex': hexstr|None, 'channel': int|None, 'beacon_int': int|None, 'rssi': int|None } }
- This is client-side heuristic code for demo/prototype only.
"""

from collections import defaultdict
import math

# Config / weights (tweak these for your evaluation)
WEIGHTS = {
    'whitelist': -5,
    'duplicate_ssid': 3,
    'vendor_mismatch': 4,
    'channel_spread': 2,
    'missing_vendor_ies': 2,
    'short_beacon': 1,
    'rssi_anomaly': 2,
}

def _normalize_ssid(s):
    if s is None:
        return ''
    return s.strip()

def detect_rogue_aps(aps_info,
                     whitelist_ssids=None,
                     whitelist_bssids=None,
                     strict_vendor_match=True):
    """
    Return dict bssid -> detection result:
    {
      'score': int,   # higher -> more suspicious
      'reasons': [str],
      'info': original_info
    }
    """
    whitelist_ssids = set((s.strip() for s in (whitelist_ssids or []) if s))
    whitelist_bssids = set((b.lower() for b in (whitelist_bssids or []) if b))
    # Prepare grouping by SSID
    ssid_map = defaultdict(list)  # ssid -> list of (bssid, info)
    for bssid, info in (aps_info or {}).items():
        ssid = _normalize_ssid(info.get('ssid') if isinstance(info, dict) else info)
        ssid_map[ssid].append((bssid.lower(), info))

    results = {}
    # Precompute some distributions for RSSI-based checks
    rssi_by_ssid = {}
    for ssid, entries in ssid_map.items():
        rssis = []
        for b, info in entries:
            r = None
            try:
                r = int(info.get('rssi')) if info and isinstance(info, dict) and info.get('rssi') is not None else None
            except Exception:
                r = None
            if r is not None:
                rssis.append(r)
        if rssis:
            # mean & std
            mean = sum(rssis) / len(rssis)
            var = sum((x-mean)**2 for x in rssis) / len(rssis)
            std = math.sqrt(var)
            rssi_by_ssid[ssid] = {'mean': mean, 'std': std, 'samples': rssis}

    # Analyze per-SSID groups
    for ssid, entries in ssid_map.items():
        # Threat heuristics that use group-level stats:
        bss_count = len(entries)
        # collect vendor IE hex strings for group
        ies_set = set()
        channels = set()
        beacon_ints = set()
        for b, info in entries:
            ies = None
            ch = None
            b_int = None
            if isinstance(info, dict):
                ies = info.get('ies_hex')
                ch = info.get('channel')
                b_int = info.get('beacon_int')
            if ies:
                ies_set.add(ies)
            if ch is not None:
                channels.add(int(ch))
            if b_int is not None:
                beacon_ints.add(int(b_int))

        # If many BSSIDs for same SSID -> possible twin(s)
        group_duplicate_flag = bss_count >= 2  # threshold: 2 or more
        for bssid, info in entries:
            score = 0
            reasons = []
            b_low = bssid.lower()
            info_dict = info if isinstance(info, dict) else {'ssid': info}

            ssid_norm = ssid
            # whitelist checks
            if ssid_norm in whitelist_ssids or b_low in whitelist_bssids:
                reasons.append("Whitelisted (SSID or BSSID)")
                score += WEIGHTS['whitelist']

            # Duplicate SSID heuristic
            if group_duplicate_flag:
                reasons.append(f"SSID appears with {bss_count} BSSID(s) nearby")
                score += WEIGHTS['duplicate_ssid']

            # Vendor IE mismatch: group has multiple vendor IE sets -> suspicious
            ies = info_dict.get('ies_hex') if isinstance(info_dict, dict) else None
            if len(ies_set) > 1:
                # If current AP's IEs differ from the majority (or missing) => suspicious
                if not ies:
                    reasons.append("This AP missing vendor IEs while others have them")
                    score += WEIGHTS['missing_vendor_ies']
                else:
                    # Check if this ies matches majority
                    # compute counts
                    freq = {}
                    for x in ies_set:
                        freq[x] = 0
                    for _, ii in entries:
                        val = ii.get('ies_hex') if isinstance(ii, dict) else None
                        if val in freq:
                            freq[val] += 1
                    # determine majority IE
                    maj_ie = max(freq.items(), key=lambda x: x[1])[0] if freq else None
                    if maj_ie and ies != maj_ie:
                        reasons.append("Vendor IEs differ from majority of APs advertising same SSID")
                        score += WEIGHTS['vendor_mismatch']

            # Channel spread: if many different channels -> suspicious
            if len(channels) >= 3:
                reasons.append(f"SSID present on many channels: {sorted(list(channels))}")
                score += WEIGHTS['channel_spread']

            # Beacon interval check (if present)
            b_int = info_dict.get('beacon_int')
            if b_int:
                try:
                    bi = int(b_int)
                    # typical values are 100 TU (102.4 ms) on many APs. very small intervals suspicious.
                    if bi < 50:
                        reasons.append(f"Unusually short beacon interval: {bi}")
                        score += WEIGHTS['short_beacon']
                except Exception:
                    pass

            # RSSI anomaly (if RSSI data present for group)
            try:
                r = int(info_dict.get('rssi')) if info_dict.get('rssi') is not None else None
            except Exception:
                r = None
            if r is not None and ssid in rssi_by_ssid:
                stats = rssi_by_ssid[ssid]
                mean = stats['mean']
                std = stats['std'] or 1.0
                # if r is an outlier >2 std away -> suspicious
                if abs(r - mean) > 2 * std:
                    reasons.append(f"RSSI {r} dBm is an outlier vs peers (mean={mean:.1f}, std={std:.1f})")
                    score += WEIGHTS['rssi_anomaly']

            # If no reasons found, low score (but keep info)
            if not reasons:
                reasons.append("No strong client-side suspicious indicators found")
            results[b_low] = {
                'score': int(score),
                'reasons': reasons,
                'info': info_dict
            }

    # Post-process: normalize & attach severity label
    # Compute thresholds (simple)
    if results:
        max_score = max(r['score'] for r in results.values())
    else:
        max_score = 0
    for b, r in results.items():
        s = r['score']
        if s <= 0:
            severity = 'benign'
        elif s <= max(3, max_score//2):
            severity = 'suspicious'
        else:
            severity = 'highly suspicious'
        r['severity'] = severity

    return results


if __name__ == "__main__":
    # tiny self-test
    sample = {
        'aa:aa:aa:aa:aa:aa': {'ssid': 'CampusWiFi', 'ies_hex': 'deadbeef', 'channel': 6, 'beacon_int': 100, 'rssi': -45},
        'bb:bb:bb:bb:bb:bb': {'ssid': 'CampusWiFi', 'ies_hex': 'cafebabe', 'channel': 1, 'beacon_int': 100, 'rssi': -80},
        'cc:cc:cc:cc:cc:cc': {'ssid': 'OtherNet', 'ies_hex': None, 'channel': 6, 'beacon_int': 100, 'rssi': -50},
    }
    res = detect_rogue_aps(sample, whitelist_ssids=['OtherNet'], whitelist_bssids=[])
    import pprint
    pprint.pprint(res)
