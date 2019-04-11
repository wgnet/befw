# Contribution guide
###### It's quite simple, though.
## Purporses of commit
1. Your commit should provide some improvement for widely-used systems.
2. Any bugfix is ok
3. Integrations with ( any public software with > 10k users ) is ok
4. Support of nftables, pf, ipfw & other firewalling systems is ok
5. Integration with your specific business systems is not ok
## Code of conduct
1. Be tolerant to other's failure. Nobody is perfect. Me too.
2. Don't blame anyone. Nor in commit message nor in comments or code itself.
3. No PoC - no merge. Prepare yourself for questions.
4. Don't hesitate ask those questions too.
## Coding style
1. Use camelCase naming style.
2. Don't make methods & variables visible unless it's highly necessary.
3. Avoid using 3pc libraries for generic functions (collections, string parsing, etc).
We don't want to become a hostages of those libraries once.
4. Prepare test, examples and documentation updates along with your code.
We probably refuse to merge a code without single line of documentation on it.
5. Test as much as possible - firewall management fault can grave all your infrastructure in a moment.
## Something I forgot?
Send me PR :)