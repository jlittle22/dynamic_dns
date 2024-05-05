# dynamic_dns

## Overview

### Protobuf Encode / Decode
- Need to send protobuf encoded messages over tcp to partner.
- Need to receive and decode protobuf messages over tcp from partner.

### Authentication
- Need to authenticate messages from partner.
- Need to sign messages _for_ partner.

### Core
- Need to detect IP address changes based on configurable time quantum.
- [Testing] Need to _simulate_ change of IP address on demand.
- Need to send _new_ IP address to partner upon change.
- Need to _store_ partner's IP address.
- Need to report partner's IP address to any client process on machine.

## Authentication
- Need to send protobuf encoded messages over tcp to partner.
- Need to receive and decode protobuf messages over tcp from partner.

### Digital Signature Keys
- Each partner stores their private key and their partner's public key.
- Messages _from_ their partner are signed using the partner's private key
  and authenticated using their public key.
