DNS over SSH
---

socks5dns now renamed to ssh2dns.

Usage of ./ssh2dns:
| command | doc |
| --- | --- |
| `-b string` | Bind to this host and port, default to 127.0.0.1:53 (default "127.0.0.1:53") |
| `-c` | Use cache, default to false |
| `-dns` | Use the given dns server to connet, takes no effect if `-x` is set (default "8.8.8.8:53") |
| `-h string` | Specify hostkey to use with ssh server (default "$HOME/.ssh/known_hosts")
| `-i string` | Specify identity file to use when connecting to ssh server (default "$HOME/.ssh/id_rsa") |
| `-r` | Do recursive lookup with the default root servers hint, if set, `-dns` option will take no effect. Default to false. |
| `-s string` | Connect to this ssh server, default to 127.0.0.1:22 (default "127.0.0.1:22") |
| `-t int` | Set timeout for net dial, default to 30 seconds (default 30) |
| `-u string` | Specify user to connect with ssh server (default "$USER") |
| `-w int` | Set the number of worker to run as ssh client, default to number of cpu |
| `-x` | Skip host key verification, makes you vulnerable to man-in-the-middle attack! |
