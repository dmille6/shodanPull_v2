#this is rough.. but works
import argparse
from datetime import datetime, timedelta, timezone
import datetime
import json
import yaml
import os
import shutil
from library import shodan_lib
from library import jsonDataStore_lib
from tabulate import tabulate
from colorama import Fore, Back, Style, init
import logging
import argparse
from art import text2art

from library.shodan_lib import shodan_api_class
# --===============================================================--
#                               Gather
# --===============================================================--
def gather(config, dataStore, logger):
    shodan_obj=shodan_lib.shodan_api_class(shodan_api_key=config['shodan_api'], logger=logger)

    # Get the current UTC date and time
    now_utc = datetime.datetime.now(timezone.utc)

    # Calculate yesterday's date in UTC
    yesterday_utc = now_utc - timedelta(days=3)

    # Format yesterday's UTC date as a string
    yesterday_utc_str = yesterday_utc.strftime("%Y-%m-%d")
    now_utc_str = now_utc.strftime("%Y-%m-%d")

    print (yesterday_utc_str)

    # Define the search query with the timestamp and geographical filters
    query = f'after:{yesterday_utc_str} country:US state:LA'
    current_date = datetime.datetime.now()

    results=shodan_obj.query_shodan(query)
    ProcessShodanResults(results['matches'], dataStore)

# --===============================================================--
#                               Hunt
# --===============================================================--
def hunt(config, dataStore):
    print (Fore.GREEN + f'[*]: Hunting through Shodan Data')
    print (Fore.GREEN + f'  [+]: Hunter has {dataStore.countRecords()} of records to go through')

    data=dataStore.getDataStore()

    #Pruning Data Store (removing old/dead records)
    print(Fore.GREEN + f'  [+]: Pruning records that are over {config['data_retention']} days old.')
    for record in data:
        firstLastDelta = (dataStore.convertStrTimeStamptoDateTime(data[record]['last_seen']) - dataStore.convertStrTimeStamptoDateTime(data[record]['first_seen']))

        if firstLastDelta.days > config['data_retention']:
            #TODO: pop dead records
            print (Fore.RED + "     Kill It  [-]: record ",":", firstLastDelta.days)

        if (data[record]['last_scan'] == 0) or (datetime.now() - dataStore.convertStrTimeStamptoDateTime(data[record]['last_scan']) > config['scan_interval']):
            #TODO: scan here
            #TODO: put current date in last_scan
            print (f'Scan here')

# --===============================================================--
#                                Show
# --===============================================================--
def show(config, dataStore):
    print(Fore.GREEN + f'[*]: Displaying Shodan Data')
    print(Fore.GREEN + f'  [+]: Displaying {dataStore.countRecords()} records')

    data = dataStore.getDataStore()

    headers = ['IP', 'First Seen Date', 'Last Seen Date', 'Last Seen -> Today', 'Last Scan Date', 'Vulnerability Count','Seen Count','Location']
    tableData = []
    table_row_count=0

    date_str=str(datetime.datetime.now())
    file_str="table_"+date_str+".txt"
    file_str=file_str.replace(" ","_")

    for record in data:
        dateDiff = datetime.datetime.now() - dataStore.convertStrTimeStamptoDateTime(data[record]['last_seen'])
        vulnCount = len(data[record]['vuln_list'])

        if dateDiff.days < config['data_retention']:
            location_str=data[record]['location']['city']+","+data[record]['location']['region_code']

            row = [data[record]['ip_str'], data[record]['first_seen'],
                   data[record]['last_seen'], dateDiff, data[record]['last_scan'],
                   vulnCount, data[record]['seen_count'],location_str]

            tableData.append(row)
            print (f'[+]: {row}')
            table_row_count+=1

    print(tabulate(tableData, headers, tablefmt="pretty"))

    if table_row_count>20:
        print (f'   [+]: large amount of records, saving output to table.txt')
        print (f'   [+]: records saved: {table_row_count}')
        finalTable=tabulate(tableData, headers, tablefmt="pretty")
        with open(file_str, "w") as file:
            file.write(finalTable)

    print (config['data_retention'])

# --===============================================================--
#                    Process Shodan Results
# --===============================================================--
def ProcessShodanResults(results, dataStore):
    dictEntry={}

    #pulling out important fields and throwing out the crap
    for result in results:
        if result.get('vulns'): #if there is a vulnerability add it to list
            if result.get('ip_str'):
                dictEntry['timestamp'] = result.get('timestamp')
                dictEntry['ip_str']=result.get('ip_str')
                dictEntry['port'] = result.get('port')
                dictEntry['version'] = result.get('version')
                dictEntry['location'] = result.get('location')
                dictEntry['ip'] = result.get('ip')
                dictEntry['product'] = result.get('product')
                dictEntry['timestamp'] = result.get('timestamp')
                dictEntry['hostnames'] = result.get('hostnames')
                dictEntry['org'] = result.get('org')
                dictEntry['isp'] = result.get('isp')
                dictEntry['os'] = result.get('os')
                dictEntry['vuln_list'] = list(set(result['vulns'].keys()))

                print (Fore.GREEN + f'     [+ Had vulnerability +]: : {result['ip_str']} to dataStore')
                logger.info(f'     [+ Had vulnerability +]: : {result['ip_str']} added to dataStore')
                dataStore.addDataToStore(data_key=dictEntry['ip_str'], data_to_store=dictEntry.copy())
        else:
            print(Fore.YELLOW + f'     [-  No Vulnerability -]: : {result['ip_str']} not added')
            logger.info(f'     [-  No Vulnerability -]: : {result['ip_str']} not added to data store')

# --===============================================================--
#                    Read JSON Files from folder
# --===============================================================--
def list_json_files(folder_path):
    # Get a list of all files in the specified folder
    files = os.listdir(folder_path)

    # Filter the list to include only JSON files
    json_files = [f for f in files if f.endswith('.json')]

    return json_files

def read_json_file(file_path):
    json_objects = []
    try:
        # Open the text file
        with open(file_path, 'r') as file:
            # Read each line in the file
            for line in file:
                # Strip any extra whitespace and parse the JSON object
                json_object = json.loads(line.strip())
                json_objects.append(json_object)

    except FileNotFoundError:
        print(Fore.GREEN + f"The file {file_path} does not exist.")
    except json.JSONDecodeError as e:
        print(Fore.GREEN + f"Invalid JSON on line: {line.strip()}. Error: {e}")
    except Exception as e:
        print(Fore.GREEN + f"An error occurred: {e}")

    return json_objects

def ingest(folderToProcess):
    fileWithPath=[]

    print (Fore.GREEN + f' [+]: folder being processed: {folderToProcess}')
    jsonFileList = list_json_files(folderToProcess)

    # adding folder to filename for processing
    folderToProcess=folderToProcess+'/'
    for item in jsonFileList:
        item=folderToProcess+item
        fileWithPath.append(item)

    for fileItem in fileWithPath:
        print (Fore.GREEN + f'  [+]: Processing: {fileItem}')
        jsonFile=read_json_file(fileItem)

        ProcessShodanResults(jsonFile, dataStore)



# --===============================================================--
#                            Load Config
# --===============================================================--
def load_config(file_path):
    #todo: check for file, if no file, create it

    with open(file_path, 'r') as file:
        config = yaml.safe_load(file)
    return config

def check_config_exists():
    source_file = 'config.example'
    target_file = 'config.yml'

    if not os.path.exists(target_file):
        if os.path.exists(source_file):
            shutil.copyfile(source_file, target_file)
            print(Fore.GREEN + f"Copied {source_file} to {target_file}.")
            print (Fore.GREEN + f"Error: {target_file} Configuration file did not exist.")
            print (Fore.GREEN + f"{target_file} was created, please edit with text editor for your configuration")
            return False
        else:
            print(Fore.GREEN + f"Source file {source_file} does not exist.")
            return False
    else:
        print(Fore.YELLOW + f"  [+]: {target_file} already exists.")
        return True

# --===============================================================--
#                               Main
# --===============================================================--

if __name__ == "__main__":
    init()

    # Configure logging settings
    logging.basicConfig(
        level=logging.INFO,  # Set the logging level to DEBUG
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Log message format
        filename='shodanPull_v2.log',  # Log file name
        filemode='a'  # Append mode
    )

    logger = logging.getLogger('shodanPull_v2 Logger')
    logger.info(f'--===========================================--')

    config_exists=check_config_exists()

    if config_exists:
        print(Fore.BLUE + f"--===============================================================--")
        print(Fore.BLUE + f"--==                       qShodan                             ==--")
        print(Fore.BLUE + f"--===============================================================--")

        dataStore = jsonDataStore_lib.jsonDataStore('./shodanDataStore.json', logger)
        dataStore.readDataStoreFromFile('./shodanDataStore.json')

        config = load_config('config.yml')

        # ---
        # UnComment to pull data from shodan with query in config.yml
        # ---
        # gather(config, dataStore, logger)

        # ---
        # UnComment to show data from shodan data file
        # ---
        #show(config, dataStore)

        # ---
        # UnComment to import default json files from shodan cli download command
        #     - put files in a folder, it will iterate through all json files in
        #     - the folder.
        # ---

        ingest('./shodanLa')


        dataStore.saveDataStore('./shodanDataStore.json')
        logger.info(f'--===========================================--')
