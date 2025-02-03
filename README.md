# Packletdon
Play on wireshark, this will take pcaps and parse them for important data, also it will allow us to execute basic network attacks as well


implement an open source eld block list, so that when trafffic is scanned if any known bad ip addresses are identified they will be highlighted and presented in the report

make a counter of every established session between devices

make a counter of every port that was used within the pcap

make a custom filter into the python program so the user can decide which ips they want to specifically search for in the pcap which the report will be based on

make track bitrate accross the conenction based on connections established and rate of occurance?

possible create a mbps filter for data transfers to detect data exfiltration

will need a parser to analyse each line in the pcap indidividually

possibly implent a way to identify port/applicaiton based on open source application signatures with the first bits in the packets of the data transfer, for instance port 22 - host magic bits = application ssh

make a final report at the end of the pcap to provide all important info

also implement network level attacks such as flood attacks, and arp spoofing if the user wants, there will be a terminal created for the application which will allow the user to select multiple options, such as pcap analysis, or attacks, so there is multifunctionality rather than just the pcap analyser
