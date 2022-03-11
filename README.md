# Nessusbeat
A python script designed to collect scan-data from the nessus pro vulnerability scanner and send it to elasticsearch in more or less ECS format (Some fields might need better naming, but for now, this is only in the alpha stage)...

The script was designed to work as a linux service (This was only tested on an ubuntu 20.04 using systemd).

In order to use
- simply place the files in the appropriate paths
- install the dependencies (the elasticsearch python package)
- edit the config file with the appropriate info
- reload the service daemon
- start the service


Please feel free to use this code however you see fit, and to report back with any issues, suggestions or anything else.
