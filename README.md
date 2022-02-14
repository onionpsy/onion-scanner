# onion-scanner

Simple ARP network scan with passive OS detection

![](example.PNG?raw=true)

## Usage

1. Compile the project using `cargo build
2. `.\onion_scanner.exe -i 3` where `i <number>` is your network card number

## TODO

 - add more fingerprint
 - add tcp flags handling to improve detection
 - improve the way the scan ends
 - export as csv/json