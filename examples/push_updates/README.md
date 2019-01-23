push\_updates
---
This is a simple BGP speaker. It has an ASN of 65000 and BGP ID of 172.31.0.2. It listens on `0.0.0.0:179`, and It accepts peer from any AS and will send an update with the following information once BGP session established:

```
10.114.0.0/16, nexthop: 172.31.0.2, as_path: 65000
```

Usage:

- `make`
- `sudo ./push_updates`
- Get someone to talk with it.

Example output:

```
% sudo ./push_updates    
OPEN from AS396303, ID: 172.31.0.1
KEEPALIVE received.
Sending update 10.114.0.0/16 to peer.
^C
```
