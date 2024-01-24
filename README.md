# OCI NSG Python Script

## Table of Contents

- [About](#about)
- [Getting Started](#getting_started)
- [Usage](#usage)
- [TODO](#todo)
- [Contributing](./CONTRIBUTING.md)

## About <a name = "about"></a>

Oracle Cloud Infrastructure (OCI) NSG Python Script is a script that will create a NSG & associated Security Rules in OCI.

It was created to allow for easy creation of NSGs for use with Cloudflare's [IP Lists](https://www.cloudflare.com/ips/) in mind for my own use, but could be adapted to do more than just for Cloudflare's IP Lists.
Of couse you could also use `Terraform` to perform this automations as well, but I like python 🐍 more.

The script can currently create a NSG with the following rules:

- Allow all traffic from Cloudflare IPv4s and/or IPv6s to the TCP HTTP (80) port
- Allow all traffic from Cloudflare IPv4s and/or IPv6s to the TCP HTTPS (443) port
- Allow all traffic from Cloudflare IPv4s and/or IPv6s to the UDP HTTPS (443) port for QUIC/HTTP3

## Getting Started <a name = "getting_started"></a>

Ensure you have setup your OCI tenancy with the following:

- A VCN with a subnet
- A compartment
- A user with API keys

### Prerequisites

What things you need to install the software and how to install them.

```bash
Python 3.9
```

### Installing

A step by step series of examples that tell you how to get a development env running.

Install the required Python modules

```bash
pip install -r requirements.txt
```

Edit the config file with your OCI tenancy details

```bash
cp config.example config
```

Edit the .env file with your OCI VCN/Compartment & environment details

```bash
cp .env.example .env
```

## Usage <a name = "usage"></a>

Run the script

```bash
python3 main.py
```

## TODO <a name = "todo"></a>

- Add support for multiple VCNs
- Add support for multiple compartments
- Add support for multiple NSGs
- Add support for multiple ports
- Add support for custom ip list from .txt file
