### ipset add 0.0.0.0/0
[buggy since 2016](https://bugzilla.redhat.com/show_bug.cgi?id=1297092) so we split any 0/0 to 0/1 & 128/1, it's ok

### ipset name limit
ipset name length is limited to 31 characters.

### Effects
We have to reduce any service name to 31 characters length.

