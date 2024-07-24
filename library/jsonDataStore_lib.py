import os
import json
from datetime import datetime, timedelta, timezone
from colorama import Fore, Back, Style, init

##############################################################################
# jsonDataStore Class
# Description: VERY basic way of storing information in a json formatted text file.
# Long term probably need to convert this to something else.. sql-lite? i dunno.
##############################################################################
class jsonDataStore:
    dataStore={}
    datestoreFilename=''
    logger=''


    # Creation Method: Nothing really going on here other than creating object
    def __init__(self, filename, logger):
        self.logger=logger
        init(autoreset=True)
        print (Fore.GREEN + f'   [*]: Data Store Object Created')
        self.logger.debug("   [*]: Data Store Object Created")
        self.datestoreFilename=filename

        #self.getDataStore(filename)

    # getDataStore Method: returns data stored in class/method
    def getDataStore(self):
        return self.dataStore.copy()

    # readDataStoreFromFile: reads json datastore master file
    def readDataStoreFromFile(self, file_path):
        file_path=self.datestoreFilename
        self.check_file_exists(file_path)

        try:
            # Open and read the JSON file
            with open(file_path, 'r') as file:
                data = json.load(file)
                self.logger.debug("   [+]: reading data from file.")
                self.dataStore=data.copy()
            return data
        except FileNotFoundError:
            print(Fore.RED + f"   [+]: The file {file_path} does not exist.")
            self.logger.debug("[+]: The file does not exist.")
        except json.JSONDecodeError as e:
            print(Fore.RED + f"   [-]: Invalid JSON in file: {file_path}. Error: {e}")
            self.logger.debug(f"[-]: Invalid JSON in file: {file_path}. Error: {e}")
        except Exception as e:
            print(Fore.RED + f"An error occurred: {e}")
            self.logger.debug(f"[-]: An error occurred: {e}")
        return None

    # addDataToStore: adds new shodan data to datestore.
    def addDataToStore(self, data_key, data_to_store):
        if self.dataStore.get(data_key): #already in DB
            dataFromDictionary=self.dataStore.get(data_key)

            # converts text timestamp to datetime stamp so you can compare
            firstseen_timestamp = self.convertStrTimeStamptoDateTime(self.dataStore[data_key]['first_seen'])
            lastseen_timestamp = self.convertStrTimeStamptoDateTime(self.dataStore[data_key]['last_seen'])

            # converts text timestamp from new entry to datetime stamp so you can compare
            data_to_store_timestamp = self.convertStrTimeStamptoDateTime(data_to_store['timestamp'])

           # Because python reads files in a random order not alphabetically or by date, you gotta compare dates with
           # each item read. (only applies to reading old data files)
            if firstseen_timestamp > data_to_store_timestamp:
                dataFromDictionary['first_seen']=data_to_store['timestamp']

            if lastseen_timestamp < data_to_store_timestamp:
                dataFromDictionary['last_seen']=data_to_store['timestamp']

            dataFromDictionary['seen_count']+=1
            self.dataStore[data_key]=dataFromDictionary.copy()
            self.logger.info(f"        [+]: Updated Entry: {data_key}")

        else: # new entry
            self.dataStore[data_key] = {}

            data_to_store['first_seen'] = data_to_store['timestamp']
            data_to_store['last_seen'] = data_to_store['timestamp']
            data_to_store['last_scan'] = 0
            data_to_store['seen_count'] = 1
            data_to_store['vulnerability_count']: len(data_to_store['vulns'])

            self.dataStore[data_key] = data_to_store.copy()
            self.logger.info(f"        [+]: New Entry: {data_key}")
            data = {}

    # deleteFromDataStore: delete entry in data store by key. used for pruning
    # old entries in the database
    def deleteFromDataStore(self, key):
        print (f'deleting from store {key}')
        self.logger.info(f'   [+]: Deleting from store {key}')

    # countRecords: returns number of records in data store
    def countRecords(self):
        return len(self.dataStore)

    # saveDataStore: saves all data in data store to json file
    def saveDataStore(self, filename):
        data=self.dataStore
        file_path=self.datestoreFilename
        try:
            # Open and write to the JSON file
            with open(file_path, 'w') as file:
                json.dump(self.dataStore, file, indent=4)
            print(Fore.GREEN + f"[*]: Data successfully written to {file_path}.")
            print (Fore.GREEN + f'   [+]: Number of Records saved: {self.countRecords()}')
            self.logger.debug(f"   [*]: Data successfully written to {file_path}.")
            self.logger.debug(f'   [+]: Number of Records saved: {self.countRecords()}')

        except Exception as e:
            print(f"An error occurred: {e}")
            self.logger.info(f"[-]: An error occurred: {e}")

    # check_file_exists: just checks if the data store file exists, if not creates one
    def check_file_exists(self, file_path):
        # Check if the file exists
        if not os.path.exists(file_path):
            # Create the file
            with open(file_path, 'w') as file:
                # Optionally write initial content to the file
                file.write('')
            print(Fore.GREEN + f"  [+]: DataStore {file_path} created.")
            self.logger.debug(f"   [+]: DataStore {file_path} created.")
        else:
            print(Fore.YELLOW + f"  [+]: DataStore {file_path} already exists.")
            self.logger.debug(f"   [+]: DataStore {file_path} already exists.")

    # convertStrTimeStamptoDateTime: datastore file saves date as text, this converts
    # back to python datetime
    def convertStrTimeStamptoDateTime(self, strTimeStamp):
        datetime_obj = datetime.fromisoformat(strTimeStamp)

        # Format the datetime object to the desired format
        # For example, converting to 'YYYY-MM-DD HH:MM:SS' format
        formatted_timestamp = datetime.strptime(strTimeStamp, '%Y-%m-%dT%H:%M:%S.%f')

        return formatted_timestamp
