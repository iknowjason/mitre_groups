import requests
import os
import sys
import copy
from jinja2 import Template
import json
from datetime import datetime

# Directory structure
current_directory = os.path.dirname(__file__)
documents_directory = os.path.join(current_directory, "documents")
contrib_directory = os.path.join(current_directory, "contrib")
embeddings_directory = os.path.join(current_directory, "embeddings")
templates_directory = os.path.join(current_directory, "templates")
group_template = os.path.join(templates_directory, "group.md")
cache_file = os.path.join(current_directory, "mitre_attack_cache.json")

def download_all_attack_domains():
    """Download all MITRE ATT&CK domains: enterprise, mobile, and ICS"""
    domains = {
        'enterprise-attack': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
        'mobile-attack': 'https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json',
        'ics-attack': 'https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json'
    }
    
    all_data = {'objects': []}
    
    for domain_name, url in domains.items():
        print(f"[+] Downloading {domain_name} data")
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            domain_data = response.json()
            
            # Add domain objects to combined data
            all_data['objects'].extend(domain_data.get('objects', []))
            print(f"[+] Added {len(domain_data.get('objects', []))} objects from {domain_name}")
        except Exception as e:
            print(f"[!] Error downloading {domain_name}: {e}")
    
    return all_data

def parse_stix_data(stix_data):
    """Parse STIX bundle and extract groups with their techniques"""
    
    objects = stix_data.get('objects', [])
    
    # Create lookup dictionaries
    groups = {}
    techniques = {}
    relationships = []
    
    # First pass: collect all objects by type
    for obj in objects:
        obj_type = obj.get('type')
        
        if obj_type == 'intrusion-set':  # Groups are intrusion-sets in STIX
            groups[obj['id']] = obj
        elif obj_type == 'attack-pattern':  # Techniques are attack-patterns
            techniques[obj['id']] = obj
        elif obj_type == 'relationship':
            relationships.append(obj)
    
    print(f"[+] Found {len(groups)} groups, {len(techniques)} techniques, {len(relationships)} relationships")
    
    # Build the group-technique mapping
    all_groups = {}
    
    for rel in relationships:
        # We want relationships where a group uses a technique
        if rel.get('relationship_type') == 'uses':
            source_id = rel.get('source_ref')
            target_id = rel.get('target_ref')
            
            # Check if source is a group and target is a technique
            if source_id in groups and target_id in techniques:
                group_obj = groups[source_id]
                technique_obj = techniques[target_id]
                
                # Initialize group if not already present
                if source_id not in all_groups:
                    # Get external references for group ID
                    group_ext_refs = group_obj.get('external_references', [])
                    group_id = next((ref['external_id'] for ref in group_ext_refs 
                                   if ref.get('source_name') == 'mitre-attack'), 'Unknown')
                    
                    all_groups[source_id] = {
                        'group_name': group_obj.get('name', 'Unknown'),
                        'group_id': group_id,
                        'created': group_obj.get('created', ''),
                        'modified': group_obj.get('modified', ''),
                        'description': group_obj.get('description', ''),
                        'aliases': group_obj.get('aliases', []),
                        'contributors': group_obj.get('x_mitre_contributors', []),
                        'techniques': []
                    }
                
                # Get technique external references
                tech_ext_refs = technique_obj.get('external_references', [])
                technique_id = next((ref['external_id'] for ref in tech_ext_refs 
                                   if ref.get('source_name') == 'mitre-attack' or 
                                      ref.get('source_name') == 'mitre-mobile-attack' or
                                      ref.get('source_name') == 'mitre-ics-attack'), 'Unknown')
                
                # Get kill chain phases (tactics) - handle different kill chain names
                kill_chains = technique_obj.get('kill_chain_phases', [])
                tactics = [phase['phase_name'] for phase in kill_chains]
                
                # Determine matrix/domain from kill chain name or x_mitre_domains
                matrix = []
                for phase in kill_chains:
                    kc_name = phase.get('kill_chain_name', '')
                    if 'mitre-attack' in kc_name:
                        matrix.append('enterprise-attack')
                    elif 'mitre-mobile-attack' in kc_name:
                        matrix.append('mobile-attack')
                    elif 'mitre-ics-attack' in kc_name:
                        matrix.append('ics-attack')
                
                # Build technique info
                technique_used = {
                    'technique_id': technique_id,
                    'technique_name': technique_obj.get('name', 'Unknown'),
                    'tactics': tactics,
                    'platform': technique_obj.get('x_mitre_platforms', []),
                    'domain': technique_obj.get('x_mitre_domains', []),
                    'matrix': list(set(matrix)) if matrix else technique_obj.get('x_mitre_domains', []),
                    'use': rel.get('description', ''),
                    'data_sources': technique_obj.get('x_mitre_data_sources', [])
                }
                
                all_groups[source_id]['techniques'].append(technique_used)
    
    return all_groups

# Main execution
print("[+] Fetching MITRE ATT&CK data from all domains")
stix_data = download_all_attack_domains()

# Cache the combined data
print("[+] Caching combined data for future use")
with open(cache_file, 'w') as f:
    json.dump(stix_data, f)

print("[+] Parsing STIX data")
all_groups = parse_stix_data(stix_data)

print(f"[+] Processed {len(all_groups)} groups with technique mappings")

# Create documents directory if needed
if not os.path.exists(documents_directory):
    print("[+] Creating knowledge directory")
    os.makedirs(documents_directory)

# Generate markdown files
print("[+] Creating markdown files for each group")
markdown_template = Template(open(group_template).read())

for group_id, group in all_groups.items():
    if len(group['techniques']) > 0:  # Only create files for groups with techniques
        print(f"  [>>] Creating markdown file for {group['group_name']} ({len(group['techniques'])} techniques)")
        group_for_render = copy.deepcopy(group)
        markdown = markdown_template.render(
            metadata=group_for_render, 
            group_name=group['group_name'], 
            group_id=group['group_id']
        )
        file_name = (group['group_name']).replace(' ', '_').replace('/', '_')
        with open(f'{documents_directory}/{file_name}.md', encoding='utf-8', mode='w') as f:
            f.write(markdown)

print(f"[+] Script complete - created {len([g for g in all_groups.values() if len(g['techniques']) > 0])} group documents")
