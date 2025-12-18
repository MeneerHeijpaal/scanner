# Binaries Directory

This directory should contain the MongoDB and httpx binaries for your platform.

## MongoDB

Download MongoDB Community Server for your operating system:

### macOS
```bash
# Intel Macs
curl -O https://fastdl.mongodb.org/osx/mongodb-macos-x86_64-7.0.4.tgz
tar -zxvf mongodb-macos-x86_64-7.0.4.tgz
cp mongodb-macos-x86_64-7.0.4/bin/{mongod,mongos} .
rm mongodb-macos-x86_64-7.0.4.tgz
rm -r mongodb-macos-x86_64-7.0.4

# Apple Silicon (M1/M2)
curl -O https://fastdl.mongodb.org/osx/mongodb-macos-arm64-7.0.4.tgz
tar -zxvf mongodb-macos-arm64-7.0.4.tgz
cp mongodb-macos-arm64-7.0.4/bin/{mongod,mongos} .
rm mongodb-macos-arm64-7.0.4.tgz
rm -r mongodb-macos-aarch64-7.0.4
```

### Linux
```bash
# Ubuntu/Debian x64
wget https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-ubuntu2204-7.0.4.tgz
tar -zxvf mongodb-linux-x86_64-ubuntu2204-7.0.4.tgz
cp mongodb-linux-x86_64-ubuntu2204-7.0.4/bin/{mongod,mongos} .
rm mongodb-linux-x86_64-ubuntu2204-7.0.4.tgz
rm -r mongodb-linux-x86_64-ubuntu2204-7.0.4
```

### Windows
Download from: https://www.mongodb.com/try/download/community
Extract and copy `mongod.exe` and `mongosh.exe` to this directory.

## httpx
Download httpx binary for your platform from the releases page:
https://github.com/projectdiscovery/httpx/releases

### macOS
```bash
# Intel Macs
wget https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_macOS_amd64.zip
unzip httpx_1.3.7_macOS_amd64.zip
chmod +x httpx

# Apple Silicon (M1/M2)
wget https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_macOS_arm64.zip
unzip httpx_1.3.7_macOS_arm64.zip
chmod +x httpx
```

### Linux
```bash
wget https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_linux_amd64.zip
unzip httpx_1.3.7_linux_amd64.zip
chmod +x httpx
```

### Windows
```bash
# Download and extract
wget https://github.com/projectdiscovery/httpx/releases/download/v1.3.7/httpx_1.3.7_windows_amd64.zip
unzip httpx_1.3.7_windows_amd64.zip
# httpx.exe will be in this directory
```

## Verify Installation

```bash
# Test MongoDB
./mongod --version

# Test mongosh
./mongos --version

# Test httpx
./httpx -version
```

## Alternative: System-wide Installation

Instead of placing binaries here, you can install them system-wide:

### MongoDB
- macOS: `brew install mongodb-community`
- Linux: Follow [official docs](https://www.mongodb.com/docs/manual/administration/install-on-linux/)
- Windows: Use the MSI installer

### httpx
- All platforms: `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`
- Or download from releases page

If you install system-wide, update the commands in README.md:
- Replace `./bin/mongod` with `mongod`
- Replace `./bin/httpx` with `httpx`
