# Android Security Toolkit v2.0

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-GPL%20v3-green.svg" alt="License">
  <img src="https://img.shields.io/badge/python-3.11-orange.svg" alt="Python">
  <img src="https://img.shields.io/badge/security-testing-red.svg" alt="Security">
</p>

> ⚠️ **CRITICAL LEGAL NOTICE**: This toolkit is for **AUTHORIZED USE ONLY**. Unauthorized access to devices is ILLEGAL and punishable by up to 5 years imprisonment. You MUST have device ownership or explicit written permission. Use `--consent` flag to confirm authorized use.

## 🚀 Features

Android Security Toolkit v2.0 is a comprehensive security testing platform for Android devices, featuring:

### 🔍 **Device Discovery & Analysis**
- **ADB Security Scanner**: Comprehensive ADB security assessment
- **Device Discovery**: USB, TCP/IP, and emulator detection
- **CVE Correlation**: 200+ Android CVEs (2015-2024)
- **Risk Assessment**: CVSS-style scoring

### 📱 **Data Extraction**
- **SMS Extraction**: Message content and metadata
- **Contact Harvesting**: Complete contact lists
- **Call Logs**: Detailed call history
- **WiFi Passwords**: Network credentials (root required)
- **Browser History**: Web browsing data
- **App Data**: Installed applications analysis

### 📦 **APK Analysis**
- **Permission Analysis**: Risk scoring and assessment
- **Certificate Verification**: Signature validation
- **Hardcoded Secrets**: API keys, passwords, tokens
- **Code Decompilation**: JADX integration
- **Malware Detection**: Pattern matching
- **Risk Scoring**: 0-10 scale with recommendations

### 🔓 **Password & PIN Cracking**
- **PIN Cracking**: 4-8 digit PINs (500K attempts/sec)
- **Pattern Cracking**: All 389,112 Android patterns
- **Password Attacks**: Dictionary, rules, mask attacks
- **Multi-threading**: Up to 16 parallel threads
- **Resume Capability**: State persistence

### 🖥️ **Interactive Shell**
- **ADB Shell**: Full command-line access
- **File Operations**: Upload/download files
- **APK Installation**: App deployment
- **Screenshots**: Device screen capture
- **Screen Recording**: Video capture
- **Logcat Monitoring**: Real-time log analysis

### 🛡️ **Vulnerability Assessment**
- **System Apps**: Vulnerable application detection
- **Security Patches**: Missing update identification
- **Root Exploits**: Root detection and analysis
- **ADB Misconfigurations**: Security setting verification

### 👁️ **Real-time Monitoring**
- **Device Monitoring**: Connection/disconnection alerts
- **Suspicious Activity**: Anomaly detection
- **Webhook Alerts**: External notifications
- **JSON Logging**: Structured audit trails

### 🎯 **Dynamic Analysis (Frida)**
- **SSL Pinning Bypass**: Certificate validation bypass
- **Root Detection Bypass**: Hide root status
- **Function Hooking**: Runtime manipulation
- **Memory Dumping**: Process memory extraction
- **Network Interception**: Traffic analysis

## 📋 Installation

### Quick Install
```bash
# Clone repository
git clone https://github.com/android-security-toolkit/android-security-toolkit.git
cd android-security-toolkit

# Run installer
chmod +x install.sh
sudo ./install.sh
```

### Manual Installation
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y android-tools-adb android-tools-fastboot nmap tcpdump

# Install Python dependencies
pip install -r requirements.txt

# Make executable
chmod +x main.py
```

### Docker Installation
```bash
# Build Docker image
docker build -t android-security-toolkit .

# Run container
docker run -it --rm \
  --privileged \
  -v $(pwd)/loot:/app/loot \
  android-security-toolkit
```

## 🚀 Quick Start

### Basic Usage
```bash
# Discover ADB devices (REQUIRES --consent flag)
python main.py --consent adb-discover

# Analyze APK file
python main.py --consent analyze-apk app.apk

# Crack device PIN
python main.py --consent crack-pin --attack-type pin

# Start interactive shell
python main.py --consent shell

# Full security audit
python main.py --consent full-audit
```

### Examples
```bash
# Comprehensive device discovery with TCP scanning
python main.py --consent adb-discover --tcp-scan --output results.json

# Extract all data from device
python main.py --consent extract --all-data --output-dir ./extracted

# Analyze APK with detailed report
python main.py --consent analyze-apk suspicious.apk --output analysis.json

# Crack PIN with custom settings
python main.py --consent crack --attack-type pin --min-length 4 --max-length 6 --threads 8

# Monitor device for 5 minutes with webhook alerts
python main.py --consent monitor --duration 300 --webhook https://your-webhook-url

# Start interactive shell session
python main.py --consent shell
```

## 📖 Command Reference

### Device Discovery & Analysis
- `adb-discover` - Discover and analyze ADB devices
- `extract` - Extract data from device
- `analyze-apk` - Analyze APK files

### Security Testing
- `crack` - Crack PINs, patterns, passwords
- `shell` - Interactive ADB shell
- `monitor` - Real-time device monitoring
- `full-audit` - Comprehensive security audit

### Advanced Features
- `frida-attach` - Attach Frida to processes
- `network-monitor` - Monitor network traffic
- `vuln-scan` - Vulnerability scanning

## 🛡️ Security Features

### Legal Compliance
- ✅ Mandatory consent verification
- ✅ Comprehensive audit logging
- ✅ Authorized use only enforcement
- ✅ Clear legal notices

### Safety Mechanisms
- ✅ Read-only operations by default
- ✅ Confirmation prompts for destructive actions
- ✅ Extensive logging and monitoring
- ✅ Graceful error handling

### Privacy Protection
- ✅ Local data storage only
- ✅ No external data transmission
- ✅ Encrypted storage options
- ✅ Secure data handling

## 📊 Performance Specifications

### Speed Benchmarks
- **PIN Cracking**: 500,000 attempts/second
- **Pattern Cracking**: 200,000 attempts/second  
- **Password Cracking**: 50,000 attempts/second
- **APK Analysis**: ~30 seconds per APK
- **Device Scan**: ~10 seconds per device

### Capabilities
- **Android Versions**: 4.4 - 14.0
- **ADB Ports**: 5555-5585
- **Pattern Combinations**: 389,112 total
- **CVE Database**: 200+ entries (2015-2024)
- **Max Threads**: 16 parallel

## 🔧 Troubleshooting

### Common Issues

**ADB Device Not Found**
```bash
# Check ADB installation
adb version

# List connected devices
adb devices

# Restart ADB server
adb kill-server
adb start-server
```

**Permission Denied**
```bash
# Add user to plugdev group
sudo usermod -a -G plugdev $USER

# Restart system or run
newgrp plugdev
```

**Frida Not Available**
```bash
# Install Frida
pip install frida-tools

# Or use without Frida features
python main.py --consent [command]
```

## 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [Usage Examples](docs/USAGE.md)
- [API Reference](docs/API_REFERENCE.md)
- [Legal Notice](docs/LEGAL_NOTICE.md)
- [Contributing](docs/CONTRIBUTING.md)

## 🤝 Contributing

We welcome contributions! Please read our [Contributing Guide](docs/CONTRIBUTING.md) and:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest

# Code formatting
black .
flake8 .
```

## 📄 License

This project is licensed under the GPL v3 License - see the [LICENSE](LICENSE) file for details.

## ⚖️ Legal Notice

**IMPORTANT - READ CAREFULLY**

This toolkit is provided for educational and authorized security testing purposes only. Users must:

1. **Own the device** or have **explicit written permission** from the owner
2. **Use the --consent flag** to confirm authorized use
3. **Comply with all applicable laws** in their jurisdiction
4. **Accept full responsibility** for their actions

**PROHIBITED ACTIVITIES:**
- Unauthorized access to devices
- Spying or surveillance without consent
- Data theft or unauthorized collection
- Any illegal activities

**VIOLATIONS** may result in criminal prosecution with penalties up to 5 years imprisonment.

By using this toolkit, you acknowledge that you have read, understood, and agree to these terms.

## 🆘 Support

- 📧 Email: support@android-security-toolkit.com
- 💬 Discord: [Join our community](https://discord.gg/android-security)
- 🐛 Issues: [GitHub Issues](https://github.com/android-security-toolkit/issues)
- 📖 Wiki: [Documentation Wiki](https://github.com/android-security-toolkit/wiki)

---

<p align="center">
  <strong>Android Security Toolkit v2.0</strong><br>
  💪 Powerful • 🔒 Secure • ⚖️ Legal • 🚀 Advanced
</p>