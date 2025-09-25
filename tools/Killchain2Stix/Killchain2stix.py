import os
import sys
import json
import argparse
import yaml
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from stix2 import Indicator, Malware, Relationship, Bundle, AttackPattern, KillChainPhase

MITRE = "mitre-killchain"

# Parse kill chain markdown
def parse_killchain_file(filepath):
    entries = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip().startswith("|") and not line.strip().startswith("| ---"):
                    parts = [p.strip() for p in line.strip("|\n").split("|")]
                    if len(parts) == 4 and parts[1]:
                        entries.append({
                            "tactic": parts[0],
                            "tech_id": parts[1],
                            "tech_name": parts[2],
                            "context": parts[3]
                        })
    except Exception as e:
        print(f"Error reading killchain file: {e}", file=sys.stderr)
    return entries

# Helper function to check if directory exists and has files
def check_directory_exists(directory, extensions):
    """Check if directory exists and contains files with specified extensions"""
    if not os.path.exists(directory):
        return False

    for filename in os.listdir(directory):
        if any(filename.endswith(ext) for ext in extensions):
            return True
    return False

# Parse YARA rules
def parse_yara_rules(yara_dir):
    indicators = []
    if not check_directory_exists(yara_dir, (".yar", ".yara")):
        print(f"Warning: No YARA rules found in {yara_dir}", file=sys.stderr)
        return indicators

    for filename in os.listdir(yara_dir):
        if filename.endswith((".yar", ".yara")):
            try:
                with open(os.path.join(yara_dir, filename)) as f:
                    content = f.read()
                    if content.strip():  # Only process non-empty files
                        indicators.append(Indicator(
                            name=f"YARA Rule from {filename}",
                            pattern=content,
                            pattern_type="yara",
                            valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                        ))
            except Exception as e:
                print(f"Error parsing YARA file {filename}: {e}", file=sys.stderr)
    return indicators

# Parse Snort rules
def parse_snort_rules(snort_dir):
    indicators = []
    if not check_directory_exists(snort_dir, (".snort", ".rules")):
        print(f"Warning: No Snort rules found in {snort_dir}", file=sys.stderr)
        return indicators

    for filename in os.listdir(snort_dir):
        if filename.endswith((".snort", ".rules")):
            try:
                with open(os.path.join(snort_dir, filename)) as f:
                    for line in f:
                        rule = line.strip()
                        if rule and not rule.startswith("#"):
                            indicators.append(Indicator(
                                name=f"Snort Rule from {filename}",
                                pattern=rule,
                                pattern_type="snort",
                                valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                            ))
            except Exception as e:
                print(f"Error parsing Snort file {filename}: {e}", file=sys.stderr)
    return indicators

# Parse audit logs
def parse_audit_logs(auditd_dir):
    indicators = []
    if not check_directory_exists(auditd_dir, (".rules", ".log")):
        print(f"Warning: No Auditd rules found in {auditd_dir}", file=sys.stderr)
        return indicators

    for filename in os.listdir(auditd_dir):
        if filename.endswith((".rules", ".log")):
            try:
                with open(os.path.join(auditd_dir, filename)) as f:
                    for line in f:
                        rule = line.strip()
                        if rule and not rule.startswith("#"):
                            # Create a simpler STIX pattern for auditd rules
                            escaped_rule = rule.replace("'", "\\'")
                            pattern = f"[x-auditd:rule_content = '{escaped_rule}']"
                            indicators.append(Indicator(
                                name=f"Auditd rule from {filename}",
                                pattern=pattern,
                                pattern_type="stix",
                                valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                            ))
            except Exception as e:
                print(f"Error parsing Auditd file {filename}: {e}", file=sys.stderr)
    return indicators

# Parse Sigma rules
def parse_sigma_rules(sigma_dir):
    indicators = []
    if not check_directory_exists(sigma_dir, (".yml", ".yaml")):
        print(f"Warning: No Sigma rules found in {sigma_dir}", file=sys.stderr)
        return indicators

    for filename in os.listdir(sigma_dir):
        if filename.endswith((".yml", ".yaml")):
            try:
                with open(os.path.join(sigma_dir, filename)) as f:
                    content = f.read()
                    if content.strip():
                        # Try to parse YAML to validate
                        sigma_rule = yaml.safe_load(content)
                        rule_title = sigma_rule.get('title', f'Sigma rule from {filename}')
                        indicators.append(Indicator(
                            name=rule_title,
                            pattern=content,
                            pattern_type="sigma",
                            valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                        ))
            except yaml.YAMLError as e:
                print(f"Error parsing Sigma YAML file {filename}: {e}", file=sys.stderr)
            except Exception as e:
                print(f"Error parsing Sigma file {filename}: {e}", file=sys.stderr)
    return indicators

# Parse Sysmon configuration
def parse_sysmon_config(sysmon_dir):
    indicators = []
    if not check_directory_exists(sysmon_dir, (".xml", ".config")):
        print(f"Warning: No Sysmon configuration found in {sysmon_dir}", file=sys.stderr)
        return indicators

    for filename in os.listdir(sysmon_dir):
        if filename.endswith((".xml", ".config")):
            try:
                with open(os.path.join(sysmon_dir, filename)) as f:
                    content = f.read()
                    if content.strip():
                        # Try to parse XML to validate
                        ET.fromstring(content)
                        indicators.append(Indicator(
                            name=f"Sysmon Configuration from {filename}",
                            pattern=content,
                            pattern_type="sysmon",
                            valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                        ))
            except ET.ParseError as e:
                print(f"Error parsing Sysmon XML file {filename}: {e}", file=sys.stderr)
            except Exception as e:
                print(f"Error parsing Sysmon file {filename}: {e}", file=sys.stderr)
    return indicators

# Parse Fainotify rules
def parse_fainotify_rules(fainotify_dir):
    indicators = []
    if not check_directory_exists(fainotify_dir, (".py", ".sh", ".conf")):
        print(f"Warning: No Fainotify rules found in {fainotify_dir}", file=sys.stderr)
        return indicators

    for filename in os.listdir(fainotify_dir):
        if filename.endswith((".py", ".sh", ".conf")):
            try:
                with open(os.path.join(fainotify_dir, filename)) as f:
                    content = f.read()
                    if content.strip():
                        indicators.append(Indicator(
                            name=f"Fainotify Rule from {filename}",
                            pattern=content,
                            pattern_type="fainotify",
                            valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                        ))
            except Exception as e:
                print(f"Error parsing Fainotify file {filename}: {e}", file=sys.stderr)
    return indicators

# Parse binary samples
def parse_bin_samples(samples_dir):
    indicators = []
    if not check_directory_exists(samples_dir, (".py", ".exe", ".bin", ".sh")):
        print(f"Warning: No binary samples found in {samples_dir}", file=sys.stderr)
        return indicators

    for filename in os.listdir(samples_dir):
        if filename.endswith((".py", ".exe", ".bin", ".sh")):
            try:
                pattern = f"[file:name = '{filename}']"
                indicators.append(Indicator(
                    name=f"Executable sample: {filename}",
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                ))
            except Exception as e:
                print(f"Error processing binary sample {filename}: {e}", file=sys.stderr)
    return indicators

# Parse PCAPs
def parse_pcap_samples(pcaps_dir):
    indicators = []
    if not check_directory_exists(pcaps_dir, (".pcap", ".pcapng")):
        print(f"Warning: No PCAP files found in {pcaps_dir}", file=sys.stderr)
        return indicators

    for filename in os.listdir(pcaps_dir):
        if filename.endswith((".pcap", ".pcapng")):
            try:
                pattern = f"[file:name = '{filename}']"
                indicators.append(Indicator(
                    name=f"PCAP file: {filename}",
                    pattern=pattern,
                    pattern_type="stix",
                    valid_from=datetime.now(timezone.utc).replace(microsecond=0)
                ))
            except Exception as e:
                print(f"Error processing PCAP file {filename}: {e}", file=sys.stderr)
    return indicators

# Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a STIX bundle from killchain and detection artifacts")
    parser.add_argument("directory", nargs="?", default=".", help="Directory containing detection rules and samples (default: current directory)")
    parser.add_argument("--output", default="stix_report.json", help="Output filename (will be created in the target directory)")
    args = parser.parse_args()

    # Set base path to the provided directory
    base_path = os.path.abspath(args.directory)

    # Check if the directory exists
    if not os.path.exists(base_path):
        print(f"Error: Directory '{args.directory}' does not exist", file=sys.stderr)
        sys.exit(1)

    print(f"Processing directory: {base_path}")

    # Detection rule directories
    yara_dir = os.path.join(base_path, "detection", "yara")
    snort_dir = os.path.join(base_path, "detection", "snort")
    auditd_dir = os.path.join(base_path, "detection", "auditd")
    sigma_dir = os.path.join(base_path, "detection", "sigma")
    sysmon_dir = os.path.join(base_path, "detection", "sysmon")
    fainotify_dir = os.path.join(base_path, "detection", "fainotify")

    # Sample directories
    samples_dir = os.path.join(base_path, "samples", "bin")
    pcaps_dir = os.path.join(base_path, "samples", "pcap")

    # Killchain file
    killchain_file = os.path.join(base_path, "killchain.md")

    # Parse killchain entries
    attack_patterns = []
    for entry in parse_killchain_file(killchain_file):
        attack_patterns.append(AttackPattern(
            name=entry["tech_name"],
            external_references=[{
                "source_name": "mitre-attack",
                "external_id": entry["tech_id"],
                "url": f"https://attack.mitre.org/techniques/{entry['tech_id']}/"
            }],
            description=entry["context"],
            kill_chain_phases=[KillChainPhase(
                kill_chain_name=MITRE,
                phase_name=entry["tactic"].lower().replace(" ", "-")
            )]
        ))

    # Parse all detection artifacts
    print("Parsing detection rules and artifacts...")
    indicators = []

    # Parse detection rules
    indicators.extend(parse_yara_rules(yara_dir))
    indicators.extend(parse_snort_rules(snort_dir))
    indicators.extend(parse_audit_logs(auditd_dir))
    indicators.extend(parse_sigma_rules(sigma_dir))
    indicators.extend(parse_sysmon_config(sysmon_dir))
    indicators.extend(parse_fainotify_rules(fainotify_dir))

    # Parse samples
    indicators.extend(parse_bin_samples(samples_dir))
    indicators.extend(parse_pcap_samples(pcaps_dir))

    print(f"Total indicators parsed: {len(indicators)}")

    # Create relationships between indicators and attack patterns
    relationships = []
    if indicators and attack_patterns:
        print("Creating relationships between indicators and attack patterns...")
        for ind in indicators:
            # Create relationship with the first attack pattern (or could be more sophisticated)
            relationships.append(Relationship(
                source_ref=ind.id,
                relationship_type="indicates",
                target_ref=attack_patterns[0].id
            ))
        print(f"Total relationships created: {len(relationships)}")
    else:
        print("Warning: No relationships created (missing indicators or attack patterns)")

    # Create and output STIX bundle
    print("Creating STIX bundle...")
    all_objects = attack_patterns + indicators + relationships

    if all_objects:
        stix_bundle = Bundle(*all_objects)
        try:
            # Create output path in the target directory
            output_path = os.path.join(base_path, args.output)
            with open(output_path, "w") as f:
                f.write(stix_bundle.serialize(pretty=True))
            print(f"STIX bundle successfully written to {output_path}")
            print(f"Bundle contains: {len(attack_patterns)} attack patterns, {len(indicators)} indicators, {len(relationships)} relationships")
        except Exception as e:
            print(f"Error writing STIX bundle: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Warning: No STIX objects to include in bundle", file=sys.stderr)
