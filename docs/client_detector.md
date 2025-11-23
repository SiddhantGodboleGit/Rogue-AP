# client_detector.py - Client-Side Rogue AP Detection

## Overview

Implements heuristic-based client-side detection algorithms to identify potentially rogue access points by analyzing their characteristics and comparing them against known legitimate networks.

## Key Functions

### `detect_rogue_aps(aps_info, whitelist_ssids=None, whitelist_bssids=None, strict_vendor_match=True)`

**Purpose**: Analyze scanned APs and score them based on suspicious characteristics

**Parameters**:
- `aps_info` (dict): BSSID → AP info dict from scanner
- `whitelist_ssids` (list): Known legitimate SSIDs
- `whitelist_bssids` (list): Known legitimate BSSIDs  
- `strict_vendor_match` (bool): Enable vendor IE comparison (default: True)

**Returns**: dict mapping BSSID → detection result:
```python
{
    'score': int,              # Higher = more suspicious
    'reasons': [str],          # Human-readable explanations
    'detailed_reasons': [      # Structured heuristic data
        {
            'key': str,        # Heuristic identifier
            'weight': int,     # Score contribution
            'text': str        # Description
        }
    ],
    'info': dict,             # Original AP data
    'severity': str           # 'benign' | 'suspicious' | 'highly suspicious'
}
```

**Implementation**:
1. Groups APs by SSID
2. Applies heuristics in parallel for each AP
3. Calculates weighted scores
4. Assigns severity levels based on score distribution

---

## Detection Heuristics

### Configured Weights
```python
WEIGHTS = {
    'whitelist': -5,           # Negative = reduces suspicion
    'duplicate_ssid': 3,
    'vendor_mismatch': 4,
    'channel_spread': 2,
    'missing_vendor_ies': 2,
    'short_beacon': 1,
    'rssi_anomaly': 2,
}
```

### 1. Whitelist Check (weight: -5)
**Trigger**: SSID or BSSID matches whitelist
**Effect**: Reduces suspicion score
**Rationale**: Known legitimate network

### 2. Duplicate SSID (weight: +3)
**Trigger**: Same SSID appears with 2+ different BSSIDs nearby
**Rationale**: Possible evil twin attack
**Note**: Legitimate networks may have multiple APs

### 3. Vendor Mismatch (weight: +4)
**Trigger**: AP's vendor IEs differ from majority of same-SSID APs
**Rationale**: Inconsistent hardware/firmware suggests impersonation
**Implementation**: Compares IE hex strings, flags outliers

### 4. Channel Spread (weight: +2)
**Trigger**: Same SSID present on 3+ different channels
**Rationale**: Unusual for legitimate deployments
**Example**: Campus network on channels 1, 6, 11 is normal; on 1-13 is suspicious

### 5. Missing Vendor IEs (weight: +2)
**Trigger**: AP lacks vendor IEs while others with same SSID have them
**Rationale**: Generic/fake AP setup missing manufacturer-specific elements

### 6. Short Beacon Interval (weight: +1)
**Trigger**: Beacon interval < 50ms
**Rationale**: Unusual timing, may indicate misconfigured rogue AP
**Normal**: 100ms (most common)

### 7. RSSI Anomaly (weight: +2)
**Trigger**: RSSI >2 standard deviations from mean for that SSID
**Rationale**: Suspiciously strong/weak signal compared to legitimate APs
**Implementation**: Statistical outlier detection using z-score

---

## Utility Functions

### `_normalize_ssid(s) -> str`
Strips whitespace and handles None values for SSID comparison.

---

## Usage Examples

### Basic Detection
```python
from scanner import scan_aps
from client_detector import detect_rogue_aps

# Scan network
aps = scan_aps("wlan0mon", timeout=30)

# Detect rogues
results = detect_rogue_aps(aps)

# Show suspicious APs
for bssid, result in results.items():
    if result['severity'] != 'benign':
        print(f"{bssid}: {result['info']['ssid']}")
        print(f"  Score: {result['score']} ({result['severity']})")
        print(f"  Reasons: {', '.join(result['reasons'])}")
```

### With Whitelist
```python
whitelist_ssids = ['CampusWiFi', 'Eduroam']
whitelist_bssids = ['00:11:22:33:44:55', 'aa:bb:cc:dd:ee:ff']

results = detect_rogue_aps(
    aps,
    whitelist_ssids=whitelist_ssids,
    whitelist_bssids=whitelist_bssids
)
```

### Detailed Analysis
```python
result = results['aa:bb:cc:dd:ee:ff']
print(f"Score: {result['score']}")
for heuristic in result['detailed_reasons']:
    print(f"  [{heuristic['key']}] +{heuristic['weight']}: {heuristic['text']}")
```

---

## Algorithm Flow

```
Input: AP scan results
  ↓
Group by SSID
  ↓
For each AP:
  ├─ Check whitelist → -5 if match
  ├─ Count BSSIDs per SSID → +3 if ≥2
  ├─ Compare vendor IEs → +4 if mismatch
  ├─ Count channels → +2 if ≥3
  ├─ Check beacon interval → +1 if <50ms
  └─ Calculate RSSI z-score → +2 if outlier
  ↓
Sum weights → final score
  ↓
Assign severity:
  - ≤0: benign
  - 1-50%max: suspicious  
  - >50%max: highly suspicious
```

---

## Tuning Detection

### Adjusting Sensitivity
Modify weights in code:
```python
detector.WEIGHTS['duplicate_ssid'] = 5  # More sensitive
detector.WEIGHTS['rssi_anomaly'] = 1    # Less sensitive
```

### Custom Heuristics
Add new detection logic:
```python
# In detect_rogue_aps() function
if some_condition:
    k = 'custom_heuristic'
    w = 3
    detailed.append({'key': k, 'weight': w, 'text': 'Custom check failed'})
    triggered_keys.append(k)
```

---

## Limitations

1. **False Positives**: Legitimate multi-AP networks may trigger duplicate_ssid
2. **Geographic Variance**: Different vendors may be legitimate in different locations
3. **RSSI Unreliability**: Signal strength varies with environment
4. **Timing**: Single snapshot may miss temporal patterns
5. **Active Attacks**: Cannot detect sophisticated clones that perfectly mimic legitimate APs

---

## Best Practices

1. **Maintain Accurate Whitelist**: Regularly update known networks
2. **Combine with Server-Side**: Use behavioral analysis for higher confidence
3. **User Training**: Educate users on verifying network legitimacy
4. **Multi-Scan**: Run multiple scans over time to build confidence
5. **Context Awareness**: Consider physical location when interpreting results

---

## Related Modules

- **scanner.py**: Provides input data (AP scan results)
- **gui_client_detector.py**: GUI implementation of this detector
- **server_detector.py**: Complementary server-side behavioral analysis
