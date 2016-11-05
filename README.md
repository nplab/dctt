# Simple Command Line Tool for Testing WebRTC Datachannels (dctt)

This is a simple command line tool implementing the WebRTC datachannels
using a kernel SCTP stack. Therefore there is no support for DTLS and ICE.
This tool runs on FreeBSD and Mac OS X (by using the SCTP NKE).
Neither Linux nor Solaris is supported, since these implementations lack
support of [RFC6525](https://tools.ietf.org/html/rfc6525) and
[RFC7496](https://tools.ietf.org/html/rfc7496).

It implements
[DataChannel] (https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel) and [DECP](https://tools.ietf.org/html/draft-ietf-rtcweb-data-protocol).
Both Internet Drafts are in the RFC Editors queue. 
Support for [I-DATA](https://tools.ietf.org/html/draft-ietf-tsvwg-sctp-ndata) is
being developed.

# Building on FreeBSD
```
cc -g -Wall -std=c99 -pedantic -o dctt -pthread dctt.c
```

# Building on Mac OS X
```
cc -g -Wall -std=c99 -pedantic -o dctt -lsctp dctt.c
```

# Usage
Currently only SCTP/IPV4 is supported.
Neither SCTP/IPV6 nor UDP encapsulation as specified in [RFC6951](https://tools.ietf.org/html/rfc6951) is currently supported.
You can run the tool as an SCTP server by using
```
./dctt local_port
```
The server will bind to all available IPv4 addresses and `local_port`.

For using it as a client issue
```
./dctt remote_addr remote_port [local_port]
```
The client will bind to all local addresses and an ephemeral port or `local_port` if set and initiate an
SCTP association towards the IPv4 address `remote_addr` and the port `remote_port`.
