# packet-stat
bob9 packet-stat  
$ make  
g++ -c -o main.o main.cpp  
lsg++ -o packet-stat main.o -lpcap 

$ ./packet-stat test.pcap   
ip		 Tx Packet	 Tx Byte	 Rx Packet	 Rx Byte	  
10.2.2.1	 2		 166		 2		 150		  
10.2.2.3	 8		 696		 6		 875		  
175.213.35.39	 4		 709		 6		 546  


