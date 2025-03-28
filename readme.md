# Cerberus

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
3. Ensure you have Python 3 installed. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```
4. (for linux Users) Make the script executable:
   ```
   chmod +x cerberusscan.py
   ```

## Usage

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

