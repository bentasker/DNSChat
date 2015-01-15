DNSChat
=========

[DNSChat](http://projects.bentasker.co.uk/jira_projects/browse/DNSCHAT.html) is
a simple proof of concept.

It is essentially a small text-chat client which uses DNS requests in order to
transport PGP Encrypted chat between two parties - either directly or via third
party resolvers (depending on how you configure it).

The original design was drafted in [DNSCHAT-1](http://projects.bentasker.co.uk/jira_projects/browse/DNSCHAT-1.html) and the resulting PoC was created (and documented) in 
[DNSCHAT-2](http://projects.bentasker.co.uk/jira_projects/browse/DNSCHAT-2.html)



Dependancies
--------------

* Python
* Python-GnuPG
* Scapy



Usage
-------

Usage is fairly simple 

	./dnschat.py

with optional support for the following command line arguments

	-h/--help		Print this text
	-r/--resolver=		DNS Resolver to use (e.g. --resolver=8.8.8.8)
	-c/--char-limit=	The maximum number of characters to use per query (default 63 - max is also 63)
	-i/--id=		Numeric ID to use
	-d/--domain=		The domain to query (e.g. --domain=example.com)
	-v/--debug		Use debug mode


Any required value which is not provided on the command line will be prompted for.

The user is prompted for a passphrase to be used with the symmetric encryption.

Ctrl-C exits the program



Known Limitations
-------------------

The PoC does have a number of limitations, though most are solely the result of trying to avoid creating a finished product

	- The interface is incredibly basic (did briefly test an Urwid based interface)
	- The traffic is identifiable - for simplicities sake some of the patterns used are very simplistic
	- Error trapping is a little casual

There's no intention to 'finish' the system, but if there were, the following improvements would likely be looked at

	- Switching to using PKI instead of symmetric keys
	- Introducing a (random?) delay between DNS requests
	- Making the queries less identifiable



Copyright
-----------

Copyright (C) 2015 [B Tasker] (https://www.bentasker.co.uk).
Released under (GNU GPL V2)[http://www.gnu.org/licenses/gpl-2.0.html]