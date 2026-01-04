import logging
import argparse
from src.extract2 import cveExtractor
from src.config import IS_LOCAL

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

if __name__ == '__main__':

    argparser = argparse.ArgumentParser(description='Start cve json raws extraction from github repo in local or cloud mode')

    # Argument for local flag that creates a cveExtractor() instance with islocal set to true
    argparser.add_argument('--local', action='store_true', help='Run in local mode and store datasets to dataset_local folder')

    # Argument for local flag that creates a cveExtractor() instance with islocal set to false
    argparser.add_argument('--cloud', action='store_true', help='Run in GC mode and save to cloud storage + bigquery')

    # Argument for custom, reduced list of years passed in either mode for testing purposes 
    argparser.add_argument('testyearslist',
                           nargs='?',
                           default= None,
                           type= str, 
                           help='Comma separated years list passed manually for testing')

    is_local_mode = bool(IS_LOCAL)

    args = argparser.parse_args()

    if args.cloud:
        #If terminal execution was done using --cloud argument then is_local is set to false obviously
        is_local_mode = False
    elif args.local:
        is_local_mode = True

    # Instantaiting the cveExtractor in either local or cloud mode first 
    extractor = cveExtractor(islocal=is_local_mode)

    if args.testyearslist:
        # If testyears list is provided
        # example: python main.py --local 1999,2000,2001 -> Only gets data for custom list of years in local mode
        # example: python main.py --cloud 1999,2000,2001 -> Only gets data for custom list of years in cloud mode 
        years = [testyear.strip() for testyear in args.testyearslist.split(',')]
        logging.info(f'Starting test mode for years: {years}')

    else:
        # In automated mode gets years directly from get_years() function 
        years = extractor.get_years()
    
    extractor.run(years)
