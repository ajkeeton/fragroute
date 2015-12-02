At times I've need to use and modify Dug Song's Fragroute. This serves as a central repository.

* Fragroute 1.2 uses an obsolete version of libevent and won't compile 
out-of-the-box. I've hacked around that.
* Added ability to write the raw traffic to the destination but the would-be i
  manipulated traffic to a pcap file. That way nothing fishy reaches the remote
  end, but the modified traffic is still saved for inspection, analysis, or 
  testing.
