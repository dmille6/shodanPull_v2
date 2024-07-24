from datetime import datetime, timedelta, timezone
import shodan
from colorama import Fore, Back, Style, init

'''
shodan_api_class: just a wrapper for shodan api

__init__ : takes in the shodan api and verifies communication
check_api : verifies communication with shodan
query_shodan : queries shodan with given query
'''
class shodan_api_class:
    shodan_api_key=''
    shodan_query=''
    shodan_valid_key=False
    shodan_obj=''
    logger=''
    def __init__(self, shodan_api_key, logger):
        self.logger=logger
        init(autoreset=True)
        print (Fore.GREEN + "Initializing Shodan")
        self.shodan_api_key=shodan_api_key
        self.shodan_obj=shodan.Shodan(self.shodan_api_key)

        self.shodan_valid_key=self.check_api(self)
        print (Fore.YELLOW + f'   [+]: Shodan Communication is: {self.shodan_valid_key}')

    def check_api(self,shodan_obj):
        try:
            results = self.shodan_obj.info()

            if results:
                self.logger.debug(f"   [+]: Shodan API is valid")
                return True
            else:
                self.logger.debug(f"   [-]: Shodan API is NOT valid")
                return False
        except shodan.APIError as e:
            print(Fore.RED + f"Error: {e}")
            self.logger.ERROR(f"   [+]: Shodan API Error: {e}")
            return False

    def query_shodan(self, shodan_query):
        print (Fore.CYAN + f'   [+]: Querying: {shodan_query}')
        self.logger.info(f'   [+]: Querying Shodan: {shodan_query}')

        # Define the query parameters

        # Perform the search query
        try:
            results = self.shodan_obj.search(shodan_query)
            # Print the results
            print(Fore.GREEN + f"   [+]: Results found: {results['total']}")
            self.logger.info(f'   [+]: Results found: {results['total']}')

            return results.copy()
        except shodan.APIError as e:
            print(Fore.RED + f"Error: {e}")
            self.logger.ERROR(f"Error: {e}")