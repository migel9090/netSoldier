##! Test site policy for the Intel golden test: mirrors the production
##! configmap (netsoldier-intel + Intel::read_files) against the fixture.
@load netsoldier-intel

redef Intel::read_files += { "/t/intel/intel.dat" };
redef LogAscii::use_json = T;
redef ignore_checksums = T;

# Offline-replay only: hold packet processing until the intel file is
# ingested (the input framework reads asynchronously; a live sensor has
# no such race). Standard Zeek testing pattern.
event zeek_init()
	{
	suspend_processing();
	}

event Input::end_of_data(name: string, source: string)
	{
	if ( source == "/t/intel/intel.dat" )
		continue_processing();
	}
