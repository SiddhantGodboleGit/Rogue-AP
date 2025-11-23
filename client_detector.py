# client_detector.py
"""
Client-side Rogue AP detector heuristics (structured reasons)

Functions:
- detect_rogue_aps(aps_info, whitelist_ssids, whitelist_bssids, strict_vendor_match=True)
    -> returns dict: bssid -> {
         "score": int,
         "reasons": [str],                # legacy textual reasons
         "detailed_reasons": [ {key, weight, text}, ... ],  # structured
         "info": original_info
       }

Heuristics used:
- whitelist, duplicate_ssid, vendor_mismatch, channel_spread,
  missing_vendor_ies, short_beacon, rssi_anomaly
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

# Human-friendly text for each heuristic key
HEURISTIC_TEXT = {
    'whitelist': "Whitelisted (SSID or BSSID)",
    'duplicate_ssid': "SSID appears with multiple BSSIDs nearby",
    'vendor_mismatch': "Vendor IEs differ from majority of APs advertising same SSID",
    'channel_spread': "SSID present on many channels",
    'missing_vendor_ies': "This AP missing vendor IEs while others have them",
    'short_beacon': "Unusually short beacon interval",
    'rssi_anomaly': "RSSI is an outlier vs peers",
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
      'reasons': [str],   # legacy text reasons
      'detailed_reasons': [ {'key':..., 'weight':..., 'text':...}, ... ],
      'info': original_info,
      'severity': 'benign' | 'suspicious' | 'highly suspicious'
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
    # Precompute some distributions for RSSI-based checks (legacy mean/std method)
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
                try:
                    channels.add(int(ch))
                except Exception:
                    pass
            if b_int is not None:
                try:
                    beacon_ints.add(int(b_int))
                except Exception:
                    pass

        # If many BSSIDs for same SSID -> possible twin(s)
        group_duplicate_flag = bss_count >= 2  # threshold: 2 or more
        for bssid, info in entries:
            detailed = []   # list of dicts {key, weight, text}
            reasons_text = []
            triggered_keys = []
            b_low = bssid.lower()
            info_dict = info if isinstance(info, dict) else {'ssid': info}

            ssid_norm = ssid
            # whitelist checks
            if ssid_norm in whitelist_ssids or b_low in whitelist_bssids:
                k = 'whitelist'
                w = WEIGHTS.get(k, 0)
                detailed.append({'key': k, 'weight': w, 'text': HEURISTIC_TEXT.get(k, "")})
                reasons_text.append(HEURISTIC_TEXT.get(k, "Whitelisted"))
                triggered_keys.append(k)

            # Duplicate SSID heuristic
            if group_duplicate_flag:
                k = 'duplicate_ssid'
                w = WEIGHTS.get(k, 0)
                detailed.append({'key': k, 'weight': w, 'text': f"{HEURISTIC_TEXT.get(k)} ({bss_count} BSSID(s))"})
                reasons_text.append(f"SSID appears with {bss_count} BSSID(s) nearby")
                triggered_keys.append(k)

            # Vendor IE mismatch: group has multiple vendor IE sets -> suspicious
            ies = info_dict.get('ies_hex') if isinstance(info_dict, dict) else None
            if len(ies_set) > 1:
                # If current AP's IEs differ from the majority (or missing) => suspicious
                if not ies:
                    k = 'missing_vendor_ies'
                    w = WEIGHTS.get(k, 0)
                    detailed.append({'key': k, 'weight': w, 'text': HEURISTIC_TEXT.get(k)})
                    reasons_text.append("This AP missing vendor IEs while others have them")
                    triggered_keys.append(k)
                else:
                    # Check if this ies matches majority
                    freq = {}
                    for x in ies_set:
                        freq[x] = 0
                    for _, ii in entries:
                        val = ii.get('ies_hex') if isinstance(ii, dict) else None
                        if val in freq:
                            freq[val] += 1
                    maj_ie = max(freq.items(), key=lambda x: x[1])[0] if freq else None
                    if maj_ie and ies != maj_ie:
                        k = 'vendor_mismatch'
                        w = WEIGHTS.get(k, 0)
                        detailed.append({'key': k, 'weight': w, 'text': HEURISTIC_TEXT.get(k)})
                        reasons_text.append("Vendor IEs differ from majority of APs advertising same SSID")
                        triggered_keys.append(k)

            # Channel spread: if many different channels -> suspicious
            if len(channels) >= 3:
                k = 'channel_spread'
                w = WEIGHTS.get(k, 0)
                detailed.append({'key': k, 'weight': w, 'text': f"{HEURISTIC_TEXT.get(k)}: {sorted(list(channels))}"})
                reasons_text.append(f"SSID present on many channels: {sorted(list(channels))}")
                triggered_keys.append(k)

            # Beacon interval check (if present)
            b_int = info_dict.get('beacon_int')
            if b_int:
                try:
                    bi = int(b_int)
                    if bi < 50:
                        k = 'short_beacon'
                        w = WEIGHTS.get(k, 0)
                        detailed.append({'key': k, 'weight': w, 'text': f"{HEURISTIC_TEXT.get(k)} ({bi})"})
                        reasons_text.append(f"Unusually short beacon interval: {bi}")
                        triggered_keys.append(k)
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
                    k = 'rssi_anomaly'
                    w = WEIGHTS.get(k, 0)
                    detailed.append({'key': k, 'weight': w, 'text': f"{HEURISTIC_TEXT.get(k)} ({r} dBm vs mean {mean:.1f})"})
                    reasons_text.append(f"RSSI {r} dBm is an outlier vs peers (mean={mean:.1f}, std={std:.1f})")
                    triggered_keys.append(k)

            # If no heuristics triggered, add benign message (no weight)
            if not detailed:
                reasons_text.append("No strong client-side suspicious indicators found")

            # Score: sum of weights for the triggered keys (this is deterministic and avoids double-counting)
            score = 0
            for d in detailed:
                try:
                    score += int(d.get('weight', 0))
                except Exception:
                    pass

            # legacy result plus structured details
            results[b_low] = {
                'score': int(score),
                'reasons': reasons_text,
                'detailed_reasons': detailed,
                'info': info_dict
            }

    # Post-process: normalize & attach severity label
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
