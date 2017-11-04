# TorTransparentProxy

**Local Redirection Through TOR**: Configuration for proxy all host connections through TOR. Based on TOR guide [Transparently Routing Traffic Through Tor](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxy#LocalRedirectionThroughTor)

It saves your previous `iptables` configuration. To restore:

```
sudo iptables-restore ${LAST_FILE}
```
