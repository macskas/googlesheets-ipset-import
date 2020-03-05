# googlesheets-ipset-import
Import ip addresses from googlesheet into an ipset. You can grant roles to googlesheet columns/rows so its a basic ACL manager for lazy people. Can be useful for your single vps if you want to limit ssh/vpn access to the machine remotely. Just add the script to crontab and run every minute or run it in while true; do... etc.:)

### dependency
 - LWP::UserAgent (debian like systems: libwww-perl)
 - JSON::XS (you can replace it with JSON::PP - debian like systems: libjson-xs-perl) 

### how to
- sheet_id can be extracted from the google sheet document
- get the google api key: https://developers.google.com/sheets/api/guides/authorizing
- ipset create example: ```ipset create allowed_from_sheet hash:net```
- you need a google sheet first row is usernames and below usernames you should specify the list of ip addresses.
   so the an example google sheet would look like this:
```
+---+---------+---------+---------+---------+-----
|   |    A    |    B    |    C    |    D    |
+---+---------+---------+---------+---------+----
| 1 | user1   | user2   | user3   |
+---+---------+---------+---------+------
| 2 | 1.2.3.4 | 1.2.3.5 | 2.3.4.5 |
+---+---------+---------+---------+--------
| 3 |         | 2.5.6.7 |         |
+---+---------+---------+---------+--------
| 4 |         |         |         |
+---+---------+---------+---------+-------
| 5 |         |         |         |
+---+---------+---------+---------+-----
```
- ACLs can be applied in the sheet editor. Tools / Protect the sheet.

### examples
```
server:~# perl sheet2ipset.pl -h
sheet2ipset.pl [-s <sheet_id>] [-k <google-api-key>] [-h] [-i <ipset name>] [-n]
            -n  - dry run
                - sheet_id option can be replaced with SHEET_ID environment variable
                - google-api-key option can be replaced with GOOGLE_API_KEY environment variable

server:~# perl sheet2ipset.pl -s "AAAAAAAAAAAAAAAa" -k "BBBBBBBBB-AAAAAAAa-11111111" -n
Thu Mar  5 15:57:08 2020 INFO  > sheet_get_rules() started.
Thu Mar  5 15:57:09 2020 DEBUG >  - IPs allowed for user1: 1.2.2.2
Thu Mar  5 15:57:09 2020 DEBUG >  - IPs allowed for user2: 1.2.3.5, 2.3.4.1
Thu Mar  5 15:57:09 2020 DEBUG >  - IPs allowed for user3: 1.2.3.4
server:~#
```

