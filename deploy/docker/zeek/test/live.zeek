##! Live-capture check for test/run.sh: the first UDP packet to port 9 that
##! zeek sees on its interface proves the capture socket works under the
##! security context the test gives the container. Prints a marker and
##! stops zeek, so the test needs no log files and no timeout on success.

event new_connection(c: connection)
	{
	if ( c$id$resp_p == 9/udp )
		{
		print "netsoldier live capture: ok";
		terminate();
		}
	}
