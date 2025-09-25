
# KILLCHAIN TO STIX
                                                                     
## What is a killchain and what is a STIX2 ? 

### Killchain

The cyber kill chain is the process by which perpetrators carry out cyberattacks.

https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html

### STIX

Structured Threat Information Expression (STIX) is a language and serialization format used to exchange cyber threat intelligence (CTI).
Contributing and ingesting CTI becomes a lot easier. With STIX, all aspects of suspicion, compromise and attribution can be represented clearly with objects and descriptive relationships. STIX information can be visually represented for an analyst or stored as JSON to be quickly machine readible. STIX's openness allows for integration into existing tools and products or utilized for your specific analyst or network needs.

https://oasis-open.github.io/cti-documentation/stix/intro

## What is this script for ? 

This script idea comes from the Europeean Cybersecurity project named "SOCCER" (Security Operation Centres Capacity Building for European Resilience) which aims to :

- Develop and implement cutting-edge technologies for secure data access (Security Hub) and the sharing of threat intelligence signals (TIS) across European entities, enhancing the capacity to monitor and detect cyber threats.
- Interconnect and strengthen advanced Security Operation Centres (SOCs) ecosystems in Germany, Hungary, and Romania, with the goal of enhancing cybersecurity resilience at both national and EU levels.

We help this project in part by making these threat intelligence signals of attacks and attackers which are composed by artefacts such as :

- Samples
    - Poc or Malware
    - Pcaps
-  Rules (against the compromission)
    - Snort
    - Yara
    - Audit.d
    - Sigma 
    - Sysmon 
    - Fainotify 
- Killchain.md 
- Report.pdf (about the attack or the attacker)

The script help to build a Stix2 report based on the above elements in a fast and correct way.

## how it works ? 

### Requirements

First you need to create a virtual environment and install the required dependencies:

```bash
python3 -m venv myenv
source myenv/bin/activate
pip install stix2 pyyaml
```

**Required Python packages:**
- `stix2` - For creating STIX 2.1 objects and bundles
- `pyyaml` - For parsing Sigma rules in YAML format

**Supported Detection Rule Types:**
- **YARA** rules (`.yar`, `.yara`)
- **Snort** rules (`.snort`, `.rules`)
- **Auditd** rules (`.rules`, `.log`)
- **Sigma** rules (`.yml`, `.yaml`) 
- **Sysmon** configurations (`.xml`, `.config`)
- **Fainotify** rules (`.py`, `.sh`, `.conf`) 

### Use the script 

To properly use the script, once you are in your virtual environment with stix installed you need to copy the script into your TIS folder well structured (you have the "Folder_for_test_exemple" as reference)


```
.
├── detection
│   ├── auditd
│   │   ├── process_monitoring.log
│   │   └── syscall_trace.log
│   ├── snort
│   │   ├── network_ids.rules
│   │   └── snort_alerts.rules
│   └── yara
│       ├── malware_rules.yar
│       └── string_match.yar
├── killchain.md
├── Report.pdf
└── samples
    ├── bin
    │   ├── malware_sample2.py
    │   ├── malware_sample3.sh
    │   ├── malware_sample4.bin
    │   └── malware_sample.exe
    └── pcap
        └── network_capture.pcap
```


Once you have the script, you can launch it by specifying the directory containing your data:

```bash
python3 Killchain2stix.py <directory_path> --output <output_filename>
```

**Examples:**
```bash
# Process the Folder_for_test_example directory and create stix_report.json inside it
python3 Killchain2stix.py Folder_for_test_example/ --output stix_report.json

# Process current directory (default behavior)
python3 Killchain2stix.py . --output my_report.json

# Or simply (current directory is default)
python3 Killchain2stix.py --output my_report.json
```


It going to take the "killchain.md" file, and if the syntax is correct create a STIX file with the correct killchain and artefacts

### New Features

The script now supports additional detection rule types:

**Extended Directory Structure:**
```
.
├── detection
│   ├── auditd
│   ├── snort
│   ├── yara
│   ├── sigma              
│   ├── sysmon            
│   └── fainotify          
├── killchain.md
├── Report.pdf
└── samples
    ├── bin
    └── pcap
```

**Smart Error Handling:**
- The script will automatically skip missing rule types
- Warning messages are displayed for missing directories
- Processing continues even if some rule types are not present
- Detailed error reporting for problematic files

**Example Output:**
```
Parsing detection rules and artifacts...
Warning: No Sigma rules found in /path/to/detection/sigma
Total indicators parsed: 15
Creating relationships between indicators and attack patterns...
Total relationships created: 15
Creating STIX bundle...
STIX bundle successfully written to output.json
Bundle contains: 4 attack patterns, 15 indicators, 15 relationships
```
