# Git Repository Enumerator

This script allows you to enumerate open git repositories to identify potential misconfigurations and exposures. It scans domains from a CSV file and checks if there is a valid `.git/config` file. It can be used for security research or to raise awareness about the importance of securing Git repositories.

## Inspiration
This script is inspired by the research conducted by Truffle Security, which revealed that approximately 4,500 out of the top 1 million websites had leaked source code secrets from their publicly accessible `.git` repositories. The following resources were also used as references and inspiration during the development of this tool:

- [Truffle Security Blog: 4500 of the Top 1 Million Websites Leaked Source Code Secrets](https://trufflesecurity.com/blog/4500-of-the-top-1-million-websites-leaked-source-code-secrets/)
- [Git Config File Enumeration Gist](https://gist.github.com/joeleonjr/98b5f3b629a049954ed7bac67a80451f#file-git_config_file_enumeration-py)
- [goop by nyancrimew](https://github.com/nyancrimew/goop)
- [trufflehog by Truffle Security](https://github.com/trufflesecurity/trufflehog/tree/main/pkg/detectors)

## Features
- Enumerate open git repositories for potential misconfigurations and exposures.
- Supports CSV files containing domain names for easy scanning of multiple domains.
- Optional proxy server support for anonymous scanning.
- User-defined User-Agent for HTTP requests.
- Handles SSL errors and timeouts gracefully.

## Installation and Usage
1. Clone the repository:
```bash
git clone https://github.com/your-username/git-repo-enumerator.git
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. Run the script with the desired arguments:
```bash
python script.py <csv_file> <proxy>
- `<csv_file>`: Path to the CSV file containing domain names.
- `<proxy>`: Proxy server URL (e.g., `socks5://username:password@proxy-server:port`).
```

4. The script will scan the provided domains and print the ones that have a valid `.git/config` file.

## Example Usage
```bash
python script.py domains.csv socks5://user:pass@proxy-server:port
```

## Disclaimer
Please use this tool responsibly and only on systems you have proper authorization to test. The script is provided as-is without any warranties or guarantees. The author and contributors are not responsible for any misuse or illegal activities conducted with this tool.

## Contributing
Contributions are welcome! If you find any issues, have suggestions, or want to add new features, please submit a pull request.

## License
[MIT License](LICENSE)
