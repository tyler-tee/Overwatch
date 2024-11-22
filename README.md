# Overwatch

![SonarCloud Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=tyler-tee_Overwatch&metric=alert_status)

Overwatch is intended to leverage Masscan's speed and Nmap's versatility.

Rapidly discover any open ports using Masscan, then automatically feed only those ports to Nmap for further interrogation.

## Prerequisites
- Python3.5+
- Nmap
- Masscan

## Usage

### General Use
For best results, please launch Overwatch with elevated privileges:
> sudo python3 ./run.py

### Headless
If running headless, configure your desired ranges in config.py.
Ex: ({'Scan_Title': 'Subnet'})

Headless mode will allow you to run Overwatch unattended. Set it up with a cronjob/scheduled task and you can keep an eye on your external footprint automatically.

If GUI use is never needed, configure config.py accordingly (you can also set this behavior using the GUI):
> 'run_mode': 'headless'

### GUI
![main](https://user-images.githubusercontent.com/64701075/132075379-c17ef979-df80-45f3-bf34-f4ce73429045.png)

### View Previous Nmap Results
![scan_results](https://user-images.githubusercontent.com/64701075/132075380-726908c8-1164-4566-b5b3-60fb0ab7f01a.png)

## License
MIT
