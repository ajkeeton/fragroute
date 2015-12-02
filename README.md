At times I've need to use and modify Dug Song's Fragroute. This serves as a central repository.

* Fragroute 1.2 uses an obsolete version of libevent and won't compile 
out-of-the-box. I've hacked around that.
* Added ability to write the unchanged traffic to the destination but the 
  manipulated version of the traffic to a pcap file. Doing so means nothing 
  fishy reaches the target host, but the modified traffic is still saved for 
  inspection, analysis, testing, etc.
