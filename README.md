# Overwatch
Simple port scanner designed to leverage the best of both worlds from Masscan and Nmap.

## Prerequisites
- Python3.5+
- Nmap
- Masscan

## Usage

### General Use
If running headless, configure your desired ranges in config.py ({'Scan_Title': 'Subnet'})

Then simply launch Overwatch with elevated privileges:
>sudo python3 ./run.py


### GUI
![main](https://user-images.githubusercontent.com/64701075/132075379-c17ef979-df80-45f3-bf34-f4ce73429045.png)

### View Previous Nmap Results
![scan_results](https://user-images.githubusercontent.com/64701075/132075380-726908c8-1164-4566-b5b3-60fb0ab7f01a.png)

## License
[GNUv3](https://www.gnu.org/licenses/gpl-3.0.en.html)
