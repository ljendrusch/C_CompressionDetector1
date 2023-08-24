### CS 621
### Logan Jendrusch
### Prof. Vahab Pournaghshband

# Compression Detection Standalone
This repository contains a standalone program that attempts to detect data compression on the path between two machines connected to the internet.

## Setup
- Clone / download the repository anywhere onto your machine
- Ensure you have a C compiler for your hardware; the Makefile is set up to use gcc
- Open a terminal

## Usage
1. Target IP address
    Find an IP address to target, perhaps by using [ping] in a terminal
    In config.json, change the "server_ipa" value to match (keep the quotes)
2. Install and run the program
    Open a terminal and enter:
        cd (download_path)/compr_detect
        make
    Run the program:
        bin/compr_detect config.json
        (Admin or sudo permissions may be needed)

Values in config.json may be changed as needed.
