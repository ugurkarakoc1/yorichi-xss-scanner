# YORICHI - XSS Scanner Tool

## 🚀 Introduction
YORICHI is a powerful and automated XSS (Cross-Site Scripting) vulnerability scanning tool. This tool helps penetration testers and security researchers to find potential XSS vulnerabilities on a target website by scanning subdomains, collecting URLs, and injecting payloads to detect vulnerabilities.

## 📋 Features
- **Subdomain Discovery**: Automatically discovers subdomains using `subfinder`.
- **URL Collection**: Collects live URLs using `httpx`, `gau`, `waybackurls`, and `katana`.
- **XSS Payload Injection**: Tests for XSS vulnerabilities by injecting a variety of payloads.
- **Multi-Level Retry**: Retries requests up to 3 times in case of failures.
- **Automation**: Fully automated process from start to finish.

## 📦 Prerequisites
Make sure you have the following tools installed on your system:

- **Python 3.x**
- **pip** (Python package manager)
- Required Python packages (install with `pip install -r requirements.txt`):
  ```
  requests
  colorama
  pyfiglet
  tqdm
  tabulate
  ```
- **Subfinder** (for subdomain discovery)
  ```bash
  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  ```
- **Httpx** (for URL probing)
  ```bash
  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
  ```
- **GF (Gf-Patterns)** (for filtering XSS URLs)
  ```bash
  go install -v github.com/tomnomnom/gf@latest
  ```
- **Gxss** (for identifying reflected XSS)
  ```bash
  go install -v github.com/KathanP19/Gxss@latest
  ```
- **Other tools**: gau, waybackurls, katana
  ```bash
  go install -v github.com/lc/gau/v2/cmd/gau@latest
  go install -v github.com/tomnomnom/waybackurls@latest
  go install -v github.com/projectdiscovery/katana/cmd/katana@latest
  ```

## 📁 Project Structure
```
YORICHI/
├── README.md           # Project documentation (this file)
├── yorichi_xss_scanner.py  # The main tool script
├── payloads/           # Directory containing the XSS payloads file
├── tmp/                # Directory for temporary files
└── requirements.txt    # Python dependencies
```

## 🚀 Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/yorichi-xss-scanner.git
   cd yorichi-xss-scanner
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install necessary tools (subfinder, httpx, gf, gau, waybackurls, katana, and gxss) as mentioned in the **Prerequisites** section.

4. Add XSS payloads in `payloads/xss-payload.txt`.

## 🔥 Usage
To run YORICHI, use the following command:
```bash
python3 yorichi_xss_scanner.py
```
Follow the instructions on the screen to enter the domain you want to scan.

## 📘 Example
```bash
$ python3 yorichi_xss_scanner.py
Enter the domain to scan: example.com
```
This will perform the following steps automatically:
1. Discover subdomains for `example.com`.
2. Collect URLs from discovered subdomains.
3. Filter URLs that are likely vulnerable to XSS.
4. Attempt to inject XSS payloads and detect potential vulnerabilities.

## 🛠️ Customization
- **Payloads**: You can add your custom XSS payloads by editing the `payloads/xss-payload.txt` file.
- **Timeouts & Retries**: Modify the retry logic in the script to suit your needs.
- **Output**: Results are saved in `tmp/results.txt`, so you can analyze them later.

## 📄 Example Output
```
System Information
Operating System: Linux
Version: 5.15.0-58-generic
Current Directory: /home/user/yorichi-xss-scanner

[INFO] Discovering subdomains...
[INFO] Probing HTTP/HTTPS endpoints...
[INFO] Collecting URL endpoints...
[INFO] Filtering URLs for XSS vulnerabilities...
[INFO] Testing XSS payloads...
[SUCCESS] XSS found at http://example.com?query=<script>alert(1)</script>
[INFO] The program will close in 3 seconds...
```

## 📜 License
This project is licensed under the MIT License. You are free to modify, distribute, and use it for personal or commercial purposes.

## 💬 Contributing
Contributions are welcome! If you have any improvements, bug fixes, or new features to suggest, feel free to open a pull request.

## ⚠️ Disclaimer
This tool is intended for educational purposes only. Use it only on websites you have permission to test. The authors are not responsible for any misuse or damage caused by this tool.

## 💡 Credits
- Developed by **ugurkarakoc**
- Thanks to the developers of subfinder, httpx, gf, gxss, gau, waybackurls, and katana for their essential tools.

## 📞 Contact
For any inquiries or issues, please open an issue on the GitHub repository.

Happy Hacking! 🚀
