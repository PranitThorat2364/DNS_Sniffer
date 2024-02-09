# Mr.Root DNS Sniffer

Mr.Root DNS Sniffer is a Python script for monitoring DNS traffic, capturing DNS queries and responses, and logging them to a SQLite database. It provides a user-friendly interface for analyzing DNS traffic patterns and identifying potential security threats.

## Features

- Captures DNS queries and responses
- Logs DNS traffic to a SQLite database
- User-friendly interface for analysis
- Supports filtering by interface
- Export data to CSV for further analysis
- Customizable options for quiet mode and database logging

## Requirements

- Python 3.x
- Scapy library
- Termcolor library
- Pyfiglet library
- SQLite database

## Installation

1. Clone the repository:

     git clone https://github.com/MrRoot2364/DNS_Sniffer.git

2. Install the required Python libraries:

     pip install -r requirements.txt


## Usage

Run the script with Python, providing optional arguments as needed:

python3 dns_sniffer.py [options]


### Options

- `-i, --iface`: Specify the interface (e.g., Wi-Fi or Ethernet) to capture DNS traffic.
- `-t, --type`: Specify the interface type (e.g., wifi or ethernet).
- `-q, --quiet`: Run in quiet mode, suppressing output.
- `-d, --database`: Specify the path to the SQLite database for logging DNS traffic.
- `-e, --export`: Export the SQLite database to CSV format.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- This project uses the [Scapy](https://scapy.net/) library for packet manipulation.
- Special thanks to [Termcolor](https://pypi.org/project/termcolor/) and [Pyfiglet](https://pypi.org/project/pyfiglet/) for their contributions to the user interface.
