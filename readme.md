![cerberus](logo.png)
<!-- Added badges for visual flair -->
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/ryanelouarrat/cerberus.svg?style=social)](https://github.com/ryanelouarrat/cerberus)
[![GitHub issues](https://img.shields.io/github/issues/ryanelouarrat/cerberus)](https://github.com/ryanelouarrat/cerberus)

# Cerberus
_An advanced web security scanner for identifying vulnerabilities._

---
<!-- Added Table of Contents -->
## Table of Contents
- [Cerberus](#cerberus)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Project Structure](#project-structure)
  - [Installation](#installation)
  - [Usage](#usage)
    - [Parameters Explained](#parameters-explained)
    - [How It Works](#how-it-works)
  - [Contributing](#contributing)
  - [License](#license)

## Overview
Cerberus is a web security scanner designed to identify various vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), Path Traversal, and more. It incorporates multiple scanning modules for a comprehensive analysis with an option for a full scan.

## Project Structure

- **cerberusscan.py**: Main entry point for the scanner. Parses command-line arguments and triggers respective modules.  
- **modules/**: Contains scanning modules:
  - `xss.py`: Scans for XSS vulnerabilities.
  - `crawler.py`: Crawls the target website.
  - `dirbuster.py`: Performs directory brute-force attacks.
  - `pathTraversal.py`: Tests for path traversal vulnerabilities.
  - `sqli.py`: Detects SQL injection possibilities.
  - `techscan.py`: Analyzes the technology stack.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/ryanelouarrat/cerberus.git
   ```
2. Change directory:
   ```
   cd cerberus
   ```
3. **Python Environment Setup (Linux):**  
   Make sure you have Python 3 installed. Create and activate a virtual environment before installing dependencies:
   ```
   python3 -m venv venv
   source venv/bin/activate
   ```
4. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```
5. (For Linux Users) Make the script executable:
   ```
   chmod +x cerberusscan.py
   ```

## Usage

The tool uses a range of command-line parameters to control which testing modules to run. If no specific module parameter is set, a full scan will be executed by default.

### Parameters Explained

- `-f`, `--fullscan`: Perform a full scan including all vulnerability tests.
- `--sqli`: Test for SQL Injection vulnerabilities. This module scans discovered URLs for login forms.
- `--crawler`: Crawl the target website for pages and links.
- `--xss`: Scan for Cross-Site Scripting (XSS) vulnerabilities.
- `--dirbuster`: Run a directory brute-force attack.
- `--pathtraversal`: Test for path traversal vulnerabilities.
- `--techscan`: Analyze and identify the technology stack used by the target website.
- `--quiet`: Reduce informational logging during the scan.

### How It Works

When you run the tool, the main script parses the command-line arguments and triggers the appropriate scanning modules. For example:
- The crawler locates pages on the target site.
- SQLi tests are applied to discovered pages to check for vulnerable login forms.
- The XSS module checks for potential XSS vector opportunities.
- Path traversal tests and directory brute-forcing help uncover server misconfigurations.
- Technology analysis determines the tech used by the target.
All results are combined into a final report saved to a file.

Basic command structure:
```
python cerberusscan.py [argument(s)] [url]
```

Examples:
- **Full Scan**:
  ```
  python cerberusscan.py -f https://example.com
  ```
- **SQL Injection Test**:
  ```
  python cerberusscan.py --sqli https://example.com
  ```
- **XSS Scan with Crawler**:
  ```
  python cerberusscan.py --xss --crawler https://example.com
  ```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your proposed changes.

## License

[MIT License](LICENSE)

