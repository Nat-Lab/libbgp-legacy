peer\_and\_show
---
This is a simple BGP speaker. It has an ASN of 65000 and BGP ID of 172.32.0.2. It listens on `0.0.0.0:179`, and It accepts peer from any AS and will print anything received from the peer. 

Usage:
- `make`
- `sudo ./peer_and_show`
- Get someone to talk with it.

Example output:
```
% sudo ./peer_and_show    
OPEN from AS396303, ID: 172.31.0.1
KEEPALIVE received.
UPDATE received, next_hop: 172.31.0.3, as_path: 396303, withdrawn_routes: <empty>, nlri: 141.193.21.0/24.
UPDATE received, next_hop: 0.0.0.0, withdrawn_routes: 141.193.21.0/24, nlri: <empty>.
^C
```
