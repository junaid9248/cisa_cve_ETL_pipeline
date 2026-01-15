
from src.fetch_years import fetch_all_years
from src.extract2 import cveExtractor
from src.load_raws_bq import ndjson_loader
from src.transform_to_final import run_dbt_command
import argparse
import os

import logging 
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

#If not available locally will not execute
from dotenv import load_dotenv
load_dotenv(override=True)

def run_elt_pipeline(args):

    #Either get years list from the arguments or from fetch_years() method
    if args.testyearslist:
        # If testyears list is provided
        # example: python main.py --local 1999,2000,2001 -> Only gets data for custom list of years in local mode
        # example: python main.py --cloud 1999,2000,2001 -> Only gets data for custom list of years in cloud mode 
        years = [testyear.strip() for testyear in args.testyearslist.split(',')]
        logging.info(f'Starting test mode for years: {years}')
    else:
        years = fetch_all_years()


    # STEP 1: Extract the raws and dump ndjson into data lake (GCS bucket)
    # Set whther executing extraction in local or cloud only mode
    if args.cloud:
        islocal = False
        os.environ['IS_LOCAL'] = 'false'

    elif args.local:
        islocal = True
        os.environ['IS_LOCAL'] = 'true'

    if args.task ==  'extract':
        logging.info(f'---STARTING EXTRACTION OF CVE RECORDS---')
        extractor = cveExtractor(islocal= islocal)
        extractor.run(years=years)

    # STEP 2: Initialize the loader class and load ndjsons to a cve_raws table
    if args.task == 'load':
        logging.info(f'---STARTING LOADING OF NDJSONS TO RAWS TABLE---')
        loader = ndjson_loader(isLocal=islocal)
        loader.load_ndjsons_to_bq(years=years)
        
    # STEP 3: Pass dbt command to run_dbt_command() method
    if args.task == 'transform':
        logging.info(f'---STARTING TRANSFORM OF RAWS TABLE TO FINAL TABLE---')     

        dbt_command = f'dbt build --project-dir ./dbt --profiles-dir ./dbt --select sources'.split()
        run_dbt_command(dbt_command=dbt_command)
        

if __name__ == '__main__':
    argparser = argparse.ArgumentParser(description='Arguments passed to pipeline run function')

    argparser.add_argument('--task', 
                            required= True,
                            help='Defines what step should be performed from ETL pipeline',
                            choices=['extract', 'load', 'transform'])

    # Argument for local flag that creates a cveExtractor() instance with islocal set to true
    operation_mode_group = argparser.add_mutually_exclusive_group(required=True)
    operation_mode_group.add_argument('--local', 
                           action='store_true', 
                           help='Run in local mode and store datasets to dataset_local folder')

    # Argument for local flag that creates a cveExtractor() instance with islocal set to false
    operation_mode_group.add_argument('--cloud', 
                           action='store_true', 
                           help='Run in GC mode and save to cloud storage + bigquery')

    # Argument for custom, reduced list of years passed in either mode for testing purposes 
    argparser.add_argument('testyearslist',
                           nargs='?',
                           default= None,
                           type= str, 
                           help='Comma separated years list passed manually for testing')
    
    args= argparser.parse_args()

    if args:
        run_elt_pipeline(args = args)

