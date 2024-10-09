# 🐕 KeyHound

KeyHound is an advanced JavaScript secrets hunting tool that sniffs out sensitive information from JavaScript files across web applications. Like a trained hunting dog, it tracks down secrets through web archives and crawling results, specializing in detecting API keys, credentials, and other sensitive data.

![Go Version](https://img.shields.io/badge/Go-1.20+-00ADD8?style=for-the-badge&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Last Commit](https://img.shields.io/badge/Last_Commit-June_2024-orange?style=for-the-badge)

## 🌟 Features

- 🐾 Persistent tracking through waybackurls and katana
- 👃 Advanced pattern sniffing for sensitive data
- 🦮 Automatic path finding and tool installation
- 🎯 High-precision concurrent scanning
- 🦴 Discovered secrets including:
  - API Keys & Tokens
  - AWS Keys
  - Private Keys
  - Database Connection Strings
  - Internal Endpoints
  - JWT Tokens
  - Credentials
  - And more...

## 🛠️ Installation

1. Ensure Go 1.20 or later is installed:
```bash
go version
```

2. Fetch KeyHound:
```bash
git clone https://github.com/elit3pwner/KeyHound.git
cd KeyHound
```

3. Install dependencies:
```bash
go mod init keyhound
go mod tidy
```

4. Train your hound:
```bash
go build -o keyhound
```

## 📋 Prerequisites

KeyHound will automatically fetch these tools, but you can manually install them:

- waybackurls: `go install github.com/tomnomnom/waybackurls@latest`
- katana: `go install github.com/projectdiscovery/katana/cmd/katana@latest`

## 🏃 Running the Hunt

1. Release the hound:
```bash
./keyhound
```

2. Choose your hunting mode:
   - Use pre-collected trails (existing waybackurls and katana files)
   - Start a fresh hunt on a new domain

3. For a fresh hunt:
   - Specify the target domain
   - Set the number of concurrent hunting threads

4. KeyHound will:
   - Track URLs using waybackurls and katana
   - Sniff out JavaScript files
   - Hunt for sensitive information
   - Store its findings in the `output` directory

## 📂 The Hunt Results

KeyHound organizes its findings in the `output` directory:
- `waybackurls_domain.txt`: The tracked URL paths
- `katana_domain.txt`: Additional discovered trails
- `jsfiles_domain.txt`: Located JavaScript files
- `sensitive_findings.txt`: The valuable discoveries

## 📸 KeyHound in Action

[Insert screenshots here showing KeyHound's hunting process]

## 🎯 Sample Discoveries

```plaintext
URL: https://example.com/assets/main.js
Pattern: api[_-]?key
Match: api_key: "abcd1234xyz"
---
URL: https://example.com/js/config.js
Pattern: mongodb(\+srv)?:\/\/[^\s<>"']+
Match: mongodb://admin:password@localhost:27017/db
```

## ⚠️ Disclaimer

KeyHound is designed for security research and educational purposes only. Always obtain proper authorization before unleashing KeyHound on any domains. The authors are not responsible for any misuse or damage caused by this tool.

## 🤝 Contributing

Got ideas to make KeyHound a better hunter? Contributions are welcome! Feel free to submit a Pull Request.

## 📝 License

KeyHound is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [tomnomnom](https://github.com/tomnomnom) for waybackurls
- [projectdiscovery](https://github.com/projectdiscovery) for katana

---
Created with ❤️ by [elit3pwner](https://github.com/elit3pwner/)