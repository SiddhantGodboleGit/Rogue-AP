# client_detector.py
"""
Client-side Rogue AP detector heuristics (structured reasons, robust RSSI)

This version uses:
- median + MAD (modified z-score) where possible for RSSI anomaly detection
- fallback absolute dB threshold for small groups (n==2)
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


def _median(lst):
    if not lst:
        return None
    s = sorted(lst)
    n = len(s)
    mid = n // 2
    if n % 2 == 1:
        return float(s[mid])
    return (s[mid - 1] + s[mid]) / 2.0


def _mad(lst, med=None):
    if not lst:
        return 0.0
    if med is None:
        med = _median(lst)
    devs = [abs(x - med) for x in lst]
    return _median(devs)


def detect_rogue_aps(aps_info,
                     whitelist_ssids=None,
                     whitelist_bssids=None,
                     strict_vendor_match=True):
    """
    Return dict bssid -> detection result:
    {
      'score': int,   # higher -> more suspicious
      'reasons': [str],   # legacy text reasons
      'detailed_reasons': [ {'key', 'weight', 'text'}, ... ],
      'info': original_info,
      'severity': 'benign' | 'suspicious' | 'highly suspicious'
    }
    """
    whitelist_ssids = set((s.strip() for s in (whitelist_ssids or []) if s))
    whitelist_bssids = set((b.lower() for b in (whitelist_bssids or []) if b))

    # Group APs by SSID
    ssid_map = defaultdict(list)
    for bssid, info in (aps_info or {}).items():
        ssid = _normalize_ssid(info.get('ssid') if isinstance(info, dict) else info)
        ssid_map[ssid].append((bssid.lower(), info))

    results = {}

    # PRECOMPUTE RSSI SAMPLES per SSID (use any samples present in info)
    rssi_by_ssid = {}
    for ssid, entries in ssid_map.items():
        all_samples = []
        for b, info in entries:
            if not isinstance(info, dict):
                continue
            # support both rssi_samples (list) and single rssi
            samples = []
            rs = info.get('rssi_samples')
            if isinstance(rs, (list, tuple)) and rs:
                samples.extend([int(x) for x in rs if x is not None])
            else:
                r = info.get('rssi')
                if r is not None:
                    try:
                        samples.append(int(r))
                    except Exception:
                        pass
            if samples:
                all_samples.extend(samples)
        if all_samples:
            med = _median(all_samples)
            mad = _mad(all_samples, med) or 0.0
            # store raw list too
            rssi_by_ssid[ssid] = {'samples': all_samples, 'median': med, 'mad': mad, 'count': len(all_samples)}
        else:
            rssi_by_ssid[ssid] = {'samples': [], 'median': None, 'mad': 0.0, 'count': 0}

    # analyze per-SSID groups
    for ssid, entries in ssid_map.items():
        bss_count = len(entries)
        # collect vendor IE hex strings and channels and beacon intervals
        ies_set = set()
        channels = set()
        beacon_ints = set()
        for b, info in entries:
            if isinstance(info, dict):
                ies = info.get('ies_hex')
                ch = info.get('channel')
                bi = info.get('beacon_int')
                if ies:
                    ies_set.add(ies)
                if ch is not None:
                    try:
                        channels.add(int(ch))
                    except Exception:
                        pass
                if bi is not None:
                    try:
                        beacon_ints.add(int(bi))
                    except Exception:
                        pass

        group_duplicate_flag = bss_count >= 2

        # For each AP in this SSID group compute heuristics
        for bssid, info in entries:
            detailed = []
            reasons_text = []
            b_low = bssid.lower()
            info_dict = info if isinstance(info, dict) else {'ssid': info}

            ssid_norm = ssid

            # whitelist
            if ssid_norm in whitelist_ssids or b_low in whitelist_bssids:
                k = 'whitelist'
                w = WEIGHTS.get(k, 0)
                detailed.append({'key': k, 'weight': w, 'text': HEURISTIC_TEXT.get(k, "")})
                reasons_text.append(HEURISTIC_TEXT.get(k, "Whitelisted"))

            # duplicate SSID
            if group_duplicate_flag:
                k = 'duplicate_ssid'
                w = WEIGHTS.get(k, 0)
                detailed.append({'key': k, 'weight': w, 'text': f"{HEURISTIC_TEXT.get(k)} ({bss_count} BSSID(s))"})
                reasons_text.append(f"SSID appears with {bss_count} BSSID(s) nearby")

            # vendor IE checks
            ies = info_dict.get('ies_hex') if isinstance(info_dict, dict) else None
            if len(ies_set) > 1:
                if not ies:
                    k = 'missing_vendor_ies'
                    w = WEIGHTS.get(k, 0)
                    detailed.append({'key': k, 'weight': w, 'text': HEURISTIC_TEXT.get(k)})
                    reasons_text.append("This AP missing vendor IEs while others have them")
                else:
                    # majority IE detection
                    freq = {x: 0 for x in ies_set}
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

            # channel spread
            if len(channels) >= 3:
                k = 'channel_spread'
                w = WEIGHTS.get(k, 0)
                detailed.append({'key': k, 'weight': w, 'text': f"{HEURISTIC_TEXT.get(k)}: {sorted(list(channels))}"})
                reasons_text.append(f"SSID present on many channels: {sorted(list(channels))}")

            # short beacon
            b_int = info_dict.get('beacon_int')
            if b_int:
                try:
                    bi = int(b_int)
                    if bi < 50:
                        k = 'short_beacon'
                        w = WEIGHTS.get(k, 0)
                        detailed.append({'key': k, 'weight': w, 'text': f"{HEURISTIC_TEXT.get(k)} ({bi})"})
                        reasons_text.append(f"Unusually short beacon interval: {bi}")
                except Exception:
                    pass

            # RSSI anomaly — robust handling
            # Build list of per-AP samples: prefer rssi_samples, else single rssi
            ap_samples = []
            if isinstance(info_dict, dict):
                rs = info_dict.get('rssi_samples')
                if isinstance(rs, (list, tuple)) and rs:
                    ap_samples = [int(x) for x in rs if x is not None]
                else:
                    r = info_dict.get('rssi')
                    if r is not None:
                        try:
                            ap_samples = [int(r)]
                        except Exception:
                            ap_samples = []

            # group-level precomputed stats
            group_stats = rssi_by_ssid.get(ssid, {'samples': [], 'median': None, 'mad': 0.0, 'count': 0})
            g_samples = group_stats['samples']
            g_med = group_stats['median']
            g_mad = group_stats['mad']
            g_count = group_stats['count']

            # Only run RSSI heuristic if group has any RSSI samples
            r_value = None
            if ap_samples:
                # use median of AP samples as representative
                r_value = _median(ap_samples)
            else:
                # if AP didn't collect sample list but group has single-sample per AP, try to derive single value
                try:
                    r_single = info_dict.get('rssi')
                    if r_single is not None:
                        r_value = float(int(r_single))
                except Exception:
                    r_value = None

            flagged_rssi = False
            if r_value is not None and g_samples:
                # If group large enough (>=3), use modified z-score with MAD
                if len(g_samples) >= 3:
                    mad = g_mad or 1.0
                    mod_z = 0.6745 * (r_value - g_med) / mad if mad != 0 else 0.0
                    # Use >3.5 as robust threshold
                    if abs(mod_z) > 3.5:
                        flagged_rssi = True
                elif len(g_samples) == 2:
                    # If only two samples in group, modified z-score and mean/std are unstable.
                    # Use absolute dB threshold: if delta >= 12 dB, mark as RSSI anomaly.
                    other_med = g_med
                    if other_med is not None and abs(r_value - other_med) >= 12.0:
                        flagged_rssi = True
                elif len(g_samples) == 1:
                    # Only one sample in group: cannot compare; skip
                    flagged_rssi = False

            if flagged_rssi:
                k = 'rssi_anomaly'
                w = WEIGHTS.get(k, 0)
                detailed.append({'key': k, 'weight': w, 'text': f"{HEURISTIC_TEXT.get(k)} ({int(r_value)} dBm vs median {int(g_med) if g_med is not None else 'N/A'})"})
                reasons_text.append(f"RSSI {int(r_value)} dBm is an outlier vs peers (median={g_med:.1f}, mad={g_mad:.1f})")

            # If nothing triggered, keep benign message
            if not detailed:
                reasons_text.append("No strong client-side suspicious indicators found")

            # Score as sum of weights in detailed reasons
            score = 0
            for d in detailed:
                try:
                    score += int(d.get('weight', 0))
                except Exception:
                    pass

            results[b_low] = {
                'score': int(score),
                'reasons': reasons_text,
                'detailed_reasons': detailed,
                'info': info_dict
            }

    # severity labeling (same as before)
    if results:
        max_score = max(r['score'] for r in results.values())
    else:
        max_score = 0
    for b, r in results.items():
        s = r['score']
        if s <= 0:
            severity = 'benign'
        elif s <= max(3, max_score // 2):
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
