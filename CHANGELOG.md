### 0.1.4
- befw now uses stale to get updates faster
- new paths: $ipset$ for ipsets and $service$ for services

### 0.1.3
- befw now checks if its rules is consistent
- befw now can recover firewall access if consul is dead with a hard-coded ( TOTO: configured ) networks

### 0.1.2
- fix 0.0.0.0/0 centos7 ipset bug
- befw-sync now wipes old records
- documentation fixes
- befw-sync timeouts & races fixed

### 0.1.1
- Uses short hostnames instead of FQDN
- Additional sleep(s) if errors repeat
- Fix ipset refresh
- Fix static ipset aliases

### 0.1.0
- a huge documentation update
- befw-firewalld now supports configuration file
- All hard-coded settings gone to the past
### 0.0.9
- Multiple ports support for services via tags
- Performance optimisation
### 0.0.8
- befw-sync added
- logging improvements
- ipset name length quickfix
### 0.0.7
- befw-cli - new functions
### 0.0.6
- befw-cli program added
- now befw-firewalld watches for kv & services changes
### 0.0.5
- befw-firewalld now supports data collection via NFLOG:402
### 0.0.4
- befw-firewalld now watches for configuration changes
### 0.0.3
- Empty ( collect all/block all ) ipset support
### 0.0.2
- Alias (befw/$alias$/*) support
### 0.0.1
- Initial version
