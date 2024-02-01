**c99find - Subdomain Search Tool**

`c99find` is a simple Go tool for discovering subdomains of a specified domain using the [subdomainfinder.c99.nl](https://subdomainfinder.c99.nl/) service whitout an api key.

### Installation

Make sure you have Go installed on your system. You can install the tool with the following command:

```bash
go install github.com/astrazin/c99find@latest
```

**Usage**

```bash
c99find -d <domain> [flags]
<domain>: Specify the domain to search for subdomains.
[flags]:
-od: Display only subdomains, excluding IPs.
-oi: Display only IPs, excluding subdomains.
```

**Examples**

Search for subdomains and IPs:
```bash
c99find -d example.com
```

Display only subdomains:
```bash
c99find -d example.com -od | anew subdomains
```

Display only IPs:
```bash
c99find -d example.com -oi >> ips.txt
```

**License**

This project is licensed under the MIT License.
