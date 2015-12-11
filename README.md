At times I have needed to use or modify Dug Song's Fragroute. Figured it was due time to begin tracking those changes.

* Fragroute 1.2 uses an obsolete version of libevent and won't compile 
out-of-the-box. I've hacked around that.
* Added ability to forward the original traffic to the destination but save
  the manipulated version of the traffic to a pcap file. Doing so means nothing 
  fishy reaches the target host, but the would-be modified traffic is still saved for 
  inspection, analysis, testing, etc.
