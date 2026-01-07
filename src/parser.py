from typing import Dict, List, Optional, Any
from datetime import datetime
import logging


#Helper function to calculate SSVC score 
def calculate_ssvc_score(exploitation: str, automatable: str, technical_impact: str) -> str:
    # Normalize inputs to lowercase
    exploitation = exploitation.lower()
    automatable = automatable
    technical_impact = technical_impact.lower()

    if exploitation == 'active':
        if technical_impact == 'total':
            return 'Act'
        else:  # partial
            if automatable == 'yes':
                return 'Act'
            else:  # no
                return 'Attend'
    
    elif exploitation == 'poc':
        if automatable == 'yes':
            if technical_impact == 'total':
                return 'Attend'
            else:  # partial
                return 'Attend'
        else:  # no
            if technical_impact == 'total':
                return 'Attend'
            else:  # partial
                return 'Track'
            
    elif exploitation == 'none':
        if automatable == 'yes':
            if technical_impact == 'total':
                return 'Attend'
            else:  # partial
                return 'Track'
        else:  # no
            return 'Track'
        
    return 'Unknown'  

# Helper function to convert vector string to metric values if they are not present in the CVE data entry already
def vector_string_to_metrics(cve_entry_template,vector_string: str) -> Dict[str, Any]:
    if not vector_string:
        return cve_entry_template
    
    try:
        #Splitting the vector string into individual metrics using '/' as separator
        metrics_string_split = vector_string.split('/')[1:]

        metrics_new = []
        for metric in metrics_string_split:
            metrics_new.append(metric.split(':'))

        #Converting the list of lists into a dictionary for easier access
        dict_metrics = dict(metrics_new)


        # Parse each metric
        match dict_metrics.get('AV'):
            case 'N': cve_entry_template['attack_vector'] = 'NETWORK'
            case 'A': cve_entry_template['attack_vector'] = 'ADJACENT_NETWORK'
            case 'L': cve_entry_template['attack_vector'] = 'LOCAL'
            case 'P': cve_entry_template['attack_vector'] = 'PHYSICAL'
            case _: cve_entry_template['attack_vector'] = ''
        
        match dict_metrics.get('AC'):
            case 'L': cve_entry_template['attack_complexity'] = 'LOW'
            case 'H': cve_entry_template['attack_complexity'] = 'HIGH'
            case _: cve_entry_template['attack_complexity'] = ''
        
        match dict_metrics.get('PR'):
            case 'N': cve_entry_template['privileges_required'] = 'NONE'
            case 'L': cve_entry_template['privileges_required'] = 'LOW'
            case 'H': cve_entry_template['privileges_required'] = 'HIGH'
            case _: cve_entry_template['privileges_required'] = ''
        
        match dict_metrics.get('UI'):
            case 'N': cve_entry_template['user_interaction'] = 'NONE'
            case 'R': cve_entry_template['user_interaction'] = 'REQUIRED'
            case _: cve_entry_template['user_interaction'] = ''
        
        match dict_metrics.get('S'):
            case 'U': cve_entry_template['scope'] = 'UNCHANGED'
            case 'C': cve_entry_template['scope'] = 'CHANGED'
            case _: cve_entry_template['scope'] = ''
        
        match dict_metrics.get('C'):
            case 'N': cve_entry_template['confidentiality_impact'] = 'NONE'
            case 'L': cve_entry_template['confidentiality_impact'] = 'LOW'
            case 'H': cve_entry_template['confidentiality_impact'] = 'HIGH'
            case _: cve_entry_template['confidentiality_impact'] = ''
        
        match dict_metrics.get('I'):
            case 'N': cve_entry_template['integrity_impact'] = 'NONE'
            case 'L': cve_entry_template['integrity_impact'] = 'LOW'
            case 'H': cve_entry_template['integrity_impact'] = 'HIGH'
            case _: cve_entry_template['integrity_impact'] = ''
        
        match dict_metrics.get('A'):
            case 'N': cve_entry_template['availability_impact'] = 'NONE'
            case 'L': cve_entry_template['availability_impact'] = 'LOW'
            case 'H': cve_entry_template['availability_impact'] = 'HIGH'
            case _: cve_entry_template['availability_impact'] = ''
    except Exception as e:
        logging.error(f"❌ Error parsing vector string: {e}")
    
    return cve_entry_template 

# Helper function to parse date time string values to clean them and convert them using suitable datetime string formats
def parse_cve_datetime_strings(dt_string: str, column_value: str = '', cve_id: str = ''):
        
    # Return if noneType
    if not dt_string:
        logging.info(f'None type value detected for {cve_id} record, returning back')
        return None

    # Step 1: Check for extra Z charcter
    str_list = list(dt_string)

    if column_value != 'kevdateAdded' and 'Z' or 'z' in str_list:
        logging.info(f'Stripping away last index for {cve_id} parsing {column_value}')
        dt_string= dt_string[:-1]
    
    #Step 2: use the correct format and return a strptime dt object
    formats = [
        '%Y-%m-%dT%H:%M:%S.%f',  # With microseconds
        '%Y-%m-%dT%H:%M:%S', #Without microseconds
        '%Y-%m-%d' # Only date
    ]
    try:
        for format in formats:
            try:
                dt_object = datetime.strptime(dt_string, format)
                logging.info(f'This is being returned as dt_object for {column_value} and CVE ID {cve_id}: {dt_object}')
                return dt_object
            except Exception as e:
                logging.error(f'Format error when processing date time for {column_value} for {cve_id} trying the next format: {e} ')
                continue
    except Exception as e:
        logging.error(f'No formats match. Error when processing date/time for {column_value} for {cve_id}: {e} ')



def extract_cvedata (cve_data_json: Dict = {}):
    cve_entry_template={

            'cve_id': '',
            'published_date': None,
            'updated_date': None,

            'cisa_kev': False,
            'cisa_kev_date': None,

            #Cvss v3.1 and 4.0 (partial) metrics
            'cvss_version': None,
            'base_score': None,
            'base_severity': '',
            'attack_vector': '',
            'attack_complexity': '',
            'privileges_required': '',
            'user_interaction': '',
            'scope': '',
            'confidentiality_impact': '',
            'integrity_impact': '',
            'availability_impact': '',

            #SSVC metrics
            'ssvc_timestamp': None,
            'ssvc_exploitation': None,
            'ssvc_automatable': '',
            'ssvc_technical_impact': '',
            'ssvc_decision': '',  
            
            #'exploitability_score': '',
            #'impact_score': '',
            #'epss_score': '',
            #'epss_percentile': '',           

            'impacted_vendor': '',
            'impacted_products': [],
            'vulnerable_versions': [],

            'cwe_number': '',
            'cwe_description': '',

        }
    
    try:
        # 1. FINDING TOP LEVEL METADATA CONTAINER
            cve_id = cve_data_json.get('cveMetadata', {}).get('cveId', '')
            #Extract CVE Id, date publsihed and date updated values
            cve_entry_template['cve_id'] = cve_id

            # Passing datepublished to helper method so we can get isoformat timestamp
            published_date_string = cve_data_json.get('cveMetadata', {}).get('datePublished', '')
            pdt_object = parse_cve_datetime_strings(dt_string=published_date_string, column_value='datePublished', cve_id = cve_id)
            cve_entry_template['published_date'] = pdt_object.isoformat()

            # Passing dateUpdated to helper method so we can get isoformat timestamp
            updated_date_string = cve_data_json.get('cveMetadata', {}).get('dateUpdated', '')
            udt_object = parse_cve_datetime_strings(dt_string=updated_date_string, column_value='dateUpdated', cve_id = cve_id)
            cve_entry_template['updated_date'] = udt_object.isoformat()

            # 2. FINDING THE ADP CONTAINER FROM TOP LEVEL 'CONTAINERS' CONTAINER
            if 'adp' in cve_data_json.get('containers', {}):
                # 2.1. Searching for the ADP container
                adp_containers = cve_data_json['containers'].get('adp', [])

                cisa_adp_vulnrcihment_container = None

                # 2.2. Iterating over all ADP containers to find the specific CISA ADP vulnerichment container
                for adp_container in adp_containers:

                    if adp_container.get('title') == "CISA ADP Vulnrichment":
                        cisa_adp_vulnrcihment_container = adp_container

                    # logging.info(f'These are all the adp containers: {all_adp_containers}')
                
                if cisa_adp_vulnrcihment_container:

                    all_adp_vulnrichment_containers = set()

                    for container in cisa_adp_vulnrcihment_container:
                        all_adp_vulnrichment_containers.update(container)
                    
                    # 2.2.1. Getting the metrics list in the CISA ADP vulnerichment container
                    cisa_adp_vulnrichment_metrics_container = cisa_adp_vulnrcihment_container.get('metrics', [])
                    # 2.2.2. Getting the problemTypes list in the CISA ADP vulnerichment container
                    cisa_adp_vulnrichment_problem_container = cisa_adp_vulnrcihment_container.get('problemTypes', [])
                    # Getting the affected items list in CISA ADP vulnerichmenet container
                    cisa_adp_vulnrcihment_affected_container = cisa_adp_vulnrcihment_container.get('affected', [])

                    
                    #logging.info(f'This is the metrics container: {cisa_adp_vulnrichment_metrics_container }')
                    if cisa_adp_vulnrichment_metrics_container:
                        #2.2.1.1. Iterrating through the CISA ADP metrics list to find CVSS metrics
                        valid_versions = ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']
                        all_versions_found = set()

                        for metric in cisa_adp_vulnrichment_metrics_container:
                            if isinstance(metric,  dict):
                                all_versions_found.update([version_key for version_key in valid_versions if version_key in metric]) 
                                #logging.info(f" Available CVSS versions in ADP container for {cve_id}: {all_versions_found}")

                            version_key = next((str(version_key) for version_key in valid_versions if version_key in all_versions_found), None)
                            #logging.info(f" The latest CVSS version_key key in ADP metrics container is  {version_key} for {cve_id}")

                            # Here we are looking for the CVSS version an the metrics
                            if version_key in metric:
                                cve_entry_template['cvss_version'] = float(metric[version_key].get('version', '1.1'))
                                cve_entry_template['base_score'] = float(metric[version_key].get('baseScore', '0.0'))
                                cve_entry_template['base_severity'] = metric[version_key].get('baseSeverity', '')

                                # Extract individual metrics if available
                                if 'attackVector' in metric[version_key]:
                                    cve_entry_template['attack_vector'] = metric[version_key].get('attackVector', '')
                                if 'attackComplexity' in metric[version_key]:
                                    cve_entry_template['attack_complexity'] = metric[version_key].get('attackComplexity', '')
                                if 'integrityImpact' in metric[version_key]:
                                    cve_entry_template['integrity_impact'] = metric[version_key].get('integrityImpact', '')
                                if 'availabilityImpact' in metric[version_key]:
                                    cve_entry_template['availability_impact'] = metric[version_key].get('availabilityImpact', '')
                                if 'confidentialityImpact' in metric[version_key]:
                                    cve_entry_template['confidentiality_impact'] = metric[version_key].get('confidentialityImpact', '')
                                if 'privilegesRequired' in metric[version_key]:
                                    cve_entry_template['privileges_required'] = metric[version_key].get('privilegesRequired', '')
                                if 'userInteraction' in metric[version_key]:
                                    cve_entry_template['user_interaction'] = metric[version_key].get('userInteraction', '')
                                if 'scope' in metric[version_key]:
                                    cve_entry_template['scope'] = metric[version_key].get('scope', '')

                                #Finding any of the missing metrics
                                missing_metrics = []
                                for key in ['attack_vector', 'attack_complexity', 'privileges_required', 'user_interaction', 
                                                'scope', 'confidentiality_impact', 'integrity_impact', 'availability_impact']:
                                    # Check if the metric is empty
                                    if not cve_entry_template[key]:
                                        missing_metrics.append(key)

                                if missing_metrics:
                                    cvss_vector_string = metric[version_key].get('vectorString', '')
                                    logging.warning(f" Missing CVSS {version_key} metrics for {cve_id}: {missing_metrics} in ADP container")

                                    if cvss_vector_string:
                                        vector_string_to_metrics(cve_entry_template ,cvss_vector_string)

                                    continue
                        
                            # 2.2.1.2. Extracting CISA SSVC metrics from CISA ADP vulnerichment metrics 'other' containers
                            if 'other' in metric:
                                cisa_adp_vulnrichment_metrics_other_container = metric['other']
                                content_other = cisa_adp_vulnrichment_metrics_other_container.get('content', {})

                                # For the other container with type ssvvc
                                type_other = cisa_adp_vulnrichment_metrics_other_container.get('type', '')
                                # For the other container with type kev
                                if type_other == 'kev':
                                    cve_entry_template['cisa_kev'] = True
                                    kev_date_string = content_other.get('dateAdded', '')
                                    kdt_object = parse_cve_datetime_strings(dt_string=kev_date_string, column_value='kevdateAdded', cve_id=cve_id)
                                    
                                    if kdt_object:
                                        logging.info(f'This is kdt_object for cve record - {cve_id}: {kdt_object}')
                                        cve_entry_template['cisa_kev_date'] = kdt_object.date().isoformat()
                                    else:
                                        cve_entry_template['cisa_kev_date'] = None

                                if type_other =='ssvc':
                                    ssvc_time_string = content_other.get('timestamp', '')
                                    sssvc_dt_object = parse_cve_datetime_strings(dt_string=ssvc_time_string, column_value='ssvc_timestamp', cve_id = cve_id)
                                    cve_entry_template['ssvc_timestamp']  = sssvc_dt_object.isoformat()

                                    options = content_other.get('options', [])

                                    for option in options:
                                        if 'Exploitation' in option:
                                            logging.info
                                            cve_entry_template['ssvc_exploitation'] = option.get('Exploitation', '')
                                        if 'Automatable' in option:
                                            cve_entry_template['ssvc_automatable'] = bool(option.get('Automatable', '').lower()) == 'yes'
                                        if 'Technical Impact' in option:
                                            cve_entry_template['ssvc_technical_impact'] = option.get('Technical Impact', '')
                                    
                                    # Calculate SSVC decision if all required fields are present
                                    #if cve_entry_template['ssvc_exploitation'] and cve_entry_template['ssvc_automatable'] and cve_entry_template['ssvc_technical_impact']:
                                        logging.info(f'Getting the ssvc decision for {cve_id}')
                                        cve_entry_template['ssvc_decision'] = calculate_ssvc_score(
                                            cve_entry_template['ssvc_exploitation'],
                                            cve_entry_template['ssvc_automatable'],
                                            cve_entry_template['ssvc_technical_impact']
                                        )

                                
                    # 2.2.2. Finding the problem types container in the CISA ADP container
                    if cisa_adp_vulnrichment_problem_container:
                        for problem_type in cisa_adp_vulnrichment_problem_container:
                          #Extract the descriptions list from the problemTypes list in the adp container
                          descriptions = problem_type.get('descriptions', [])

                          if descriptions:
                              for description in descriptions:
                                  if description.get('type') == 'CWE':
                                      cve_entry_template['cwe_number'] = description.get('cweId', '')
                                      cve_entry_template['cwe_description'] = description.get('description', '')
                                      break

                    # 2.2.3. Finding the affected products if they exist
                    if cisa_adp_vulnrcihment_affected_container:
                        #logging.info(f'The affected container exists in adp')
                        for container in cisa_adp_vulnrcihment_affected_container:

                            cve_entry_template['impacted_vendor'] = container.get('vendor', '')
                            cve_entry_template['impacted_products'].append(container.get('product', ''))
                            
                            versions_list = container.get('versions', [])
                            for version in versions_list:
                                cve_entry_template['vulnerable_versions'].append(version.get('version', ''))
                    
                    #logging.info(f'This is the CVE entry template: {cve_entry_template}')
                                

            # 3. THIS IS FOR THE CNA CONTAINER
            if 'cna' in cve_data_json.get('containers', {}):
                #3.1. Finding the cna container in containers array
                cna_container = cve_data_json['containers']['cna']

                affected_list = cna_container.get('affected', [])
                for affected_item in affected_list:
                    # Extract vendor and product
                    vendor = affected_item.get('vendor', '')
                    product = affected_item.get('product', '')

                    cve_entry_template['impacted_vendor'] = vendor
                    cve_entry_template['impacted_products'].append(product)

                    versions_list = affected_item.get('versions', []) 
                    for version_item in versions_list:
                        cve_entry_template['vulnerable_versions'].append(version_item.get('version', ''))

                # SOMETIMES extracting metrics from the cna container if adp container has no metrics
                if "metrics" in cna_container:
                    #Fetch the mertics list from the cna container
                    cna_metrics_container = cna_container.get('metrics', [])
                    
                    #Iterrating through the metrics list
                    valid_versions1 = ['cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0']

                    all_versions_found1 = set()

                    for metric in cna_metrics_container:
                        if isinstance(metric, dict):
                            all_versions_found1.update([version for version in valid_versions1 if version in metric])
                            logging.info(f" Available CVSS versions in CNA container for {cve_id}: {all_versions_found}")
                    
                    version_key1 = next((version for version in valid_versions1 if version in all_versions_found1), None)
                    logging.info(f" The latest CVSS version key in CNA metrics container is  {version_key1} for {cve_id}")  
                    
                    #iterate over all the metrics in the metrics container
                    for metric in cna_metrics_container:
                        #logging.info(f" Processing metric in CNA container for {cve_id}: {metric.keys()}")

                        #if not isinstance(metric, dict) or not isinstance(metric, list):
                            #continue


                        #Checking if the version key is in the metric
                        if version_key1 in metric:
                            #logging.info(f" Extracting CVSS {version_key1} metrics from CNA container for {cve_id}")

                            if version_key1 in valid_versions:
                                # Extracting the CVSS  metrics
                                cve_entry_template['cvss_version'] = float(metric[version_key1].get('version', '1.1')) 
                                cve_entry_template['base_score']  = float(metric[version_key1].get('baseScore', '0.0'))
                                cve_entry_template['base_severity'] = metric[version_key1].get('baseSeverity', '')
                                cvss_vector_string = metric[version_key1].get('vectorString', '')
                                
                                # Extract individual metrics if available
                                if 'attackVector' in metric[version_key1]:
                                    cve_entry_template['attack_vector'] = metric[version_key1].get('attackVector', '')
                                if 'attackComplexity' in metric[version_key1]:
                                    cve_entry_template['attack_complexity'] = metric[version_key1].get('attackComplexity', '')
                                if 'integrityImpact' in metric[version_key1]:
                                    cve_entry_template['integrity_impact'] = metric[version_key1].get('integrityImpact', '')
                                if 'availabilityImpact' in metric[version_key1]:
                                    cve_entry_template['availability_impact'] = metric[version_key1].get('availabilityImpact', '')
                                if 'confidentialityImpact' in metric[version_key1]:
                                    cve_entry_template['confidentiality_impact'] = metric[version_key1].get('confidentialityImpact', '')
                                if 'privilegesRequired' in metric[version_key1]:
                                    cve_entry_template['privileges_required'] = metric[version_key1].get('privilegesRequired', '')
                                if 'userInteraction' in metric[version_key1]:
                                    cve_entry_template['user_interaction'] = metric[version_key1].get('userInteraction', '')
                                if 'scope' in metric[version_key1]:
                                    cve_entry_template['scope'] = metric[version_key1].get('scope', '')

                                # Check for missing metrics
                                missing_metrics= []
                                for key in ['attack_vector', 'attack_complexity', 'privileges_required', 'user_interaction', 
                                                    'scope', 'confidentiality_impact', 'integrity_impact', 'availability_impact']:
                                    # Check if the metric is empty
                                    if not cve_entry_template[key]:
                                        missing_metrics.append(key)

                                if missing_metrics:
                                    # Handle missing metrics (e.g., log a warning)
                                    print(f" Missing CVSS {version_key1} metrics for {cve_id}: {missing_metrics} in the metrics container")

                                    if cvss_vector_string:
                                        vector_string_to_metrics(cve_entry_template ,cvss_vector_string)

                                continue

                if 'problemTypes' in cna_container:
                    # Finding the problem types in the CNA container
                    cna_problem_container = cna_container.get('problemTypes', [])

                    for problem_type in cna_problem_container:
                        descriptions = problem_type.get('descriptions', [])

                        for description in descriptions:
                            if description.get('type') == 'CWE':
                                cve_entry_template['cwe_number'] = description.get('cweId', '')
                                cve_entry_template['cwe_description'] = description.get('description', '')
                                break

                logging.info(f" Successfully extracted data for {cve_id}")
                return cve_entry_template



    except Exception as e:
            logging.warning(f"❌ Error in extract_cve_data: {e}")
            import traceback
            traceback.print_exc()
            return None