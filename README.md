# ShodanPull v2
Prototype that pulls shodan data into a json/text database based on a query

## Install/Setup:
> git pull https://github.com/dmille6/shodanPull_v2.git

> python shodanPull.py

- first run will create a config.yml file you will need to edit, add your own shodan API key and the query you want to run'

## Use:
- if you want the script to gather every day, create a cron job to do so. 

example:  #runs script every night at 2am

create bash script: runPullShodanLa.sh
> cd /data/shodanPull_v2
> /bin/python3 /data/shodanPull_v2/shodanPull.py

> crontab -e

in crontab editor: Runs every 2am
> 0 2 * * * /bin/bash /data/shodanPull_v2/runPullShodaLA.sh
 
## Usage:

> gather : pulls data from shodan
> 
> show : displays data, saves data to textfile if over 25 entries
>
> hunt : will be used to actually do processing on data/shodan entries
>
> processShodanJSONFiles : import shodan cli "shodan download <arguments>" default json files.
> 
 --- put files in an folder, point command to folder to import all

## TODO:
- Turn hunt, gather, show into commandline arguments
- Build gui
- Prune data file, delete old data entries
