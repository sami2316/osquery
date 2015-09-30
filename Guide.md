This module has been tested with 
linux: CENTOS7 (3.10.0-229.11.1.el7.x86_64)

-------------------------------------------------------
###Step 1: Follow Osquery Extension Guidelines###
-------------------------------------------------------
We have developed osquery extension which will enable bro users to subscribe to 
(single or group) SQL queries remotely and then get the queries updates till the
broker connection is alive. Once the SQL queries are received form bro then
extension will send an initial dump if the inidump flag is set to true;
otherwise, it will only monitor updates of events and send them to bro.


Broker is a communication library which is used as a communication module 
between osquery extension and bro IDS.
  
####1.1 Files Structure:####
#####1.1.1 Following files have been added into the osquery directory:#####
*	```osquery/osquery/main/BrokerQueryManager.cpp```
*	```osquery/osquery/main/BrokerQueryManager.h```
*	```osquery/osquery/main/BrokerConnectionManager.cpp```
*	```osquery/osquery/main/BrokerConnectionManager.h```
*	```osquery/osquery/main/BrokerQueryManagerPlugin.cpp```
*	```osquery/osquery/main/BrokerQueryManagerPlugin.h```
*	```osquery/osquery/main/utility.cpp```
*	```osquery/osquery/main/utility.h```
*	```osquery/osquery/main/bro_osquery.cpp```

#####1.1.2 Following files have been updated into the osquery directory:#####
*	osquery/osquery/CMakeLists.txt

####1.2 Installation Steps: ####
*	```Install actor framework from github```
*	```git clone --recursive https://github.com/bro/broker```
*	```cd broker && ./configure && make && make install```
*	```git clone https://github.com/sami2316/osquery```
*	```cd osquery && make deps```
*	```make```
*	```make install```

####1.3 Application usage guide:####
*	copy ```broker.ini``` in ```/var/osquery/```
*	``` cp -rf osquery/build/centos7/osquery/BrokerQueryManagerExtension.ext /usr/lib/osquery/extensions/ ```
*	create ```/etc/Osquery/extensions.load``` with following content
	``` /usr/lib/osquery/extensions/BrokerQueryManagerExtension.ext ```
*	```osqueryd --extensions_autoload=/etc/osquery/extensions.load ```

-------------------------------------------------				
###Step 2: Follow Bro Extension Guideline###
-------------------------------------------------

We have added osquery query subscription module with a broker functionality in 
bro IDS. This module is about subscribing SQL queries from bro (master) to 
osquery hosts and then receiving updates of subscribed events. 
Default subscription behavior is for update events only but you can request an 
initial dump by setting inidump
flag to true during the subscription process. 

This module enables following modes of connections and monitoring:
*  A master to a single remote host monitoring with a single query subscription
*  A master to a single remote host monitoring with multiple queries subscription
*  A master to a remote group of hosts monitoring with a single query subscription
*  A master to a remote group of hosts monitoring with multiple queries subscription

####2.1 Files Structure:####
#####2.1.1 Following files have been added into the bro directory:#####
*	```bro/src/broker/QueryManager.h```
*	```bro/src/broker/QueryManager.cpp```
*	```bro/src/broker/querying .bif```

#####2.1.2 Following files have been updated into the bro directory:#####
*	```bro/scripts/base/framework/broker/main.bro```
*	```bro/src/broker/Manager.h```
*	```bro/src/main.cc```
*	```bro/src/broker/CMakeLists.txt```

####2.2 Installation steps:####
*	install actor-framework from github
*	```git clone --recursive https://github.com/sami2316/bro```
*	```./configure```
*	```make```
*	```make install```

Note: actor framework version should be the same at both sides (bro and 
       osquery side)

----------------------------------------------
###Step 3: Start Using Monitoring Application###
----------------------------------------------

####3.1 Scenario 1: A master to a single remote host monitoring with a single####
####query subscription####

First you need to run osqueryd on both hosts. Then at bro side write the 
following script to subscribe to a single query. An example script, extracted 
from singlequerysubscription.bro, to monitor ACPI tables is given below:

```
module osquery;

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef osquery::endpoint_name = "Printer";

global added_acpi_tables: event(host: string, name: string, size: count,
 md5: string);
global removed_acpi_tables: event(host: string, name: string,size: count,
 md5: string);


event bro_init()
{
	##enable broker communication
	osquery::enable();
	##subscribe to events
	osquery::subscribe_to_events("/bro/event/");
	##connect with the osquery host at IP
	osquery::connect("192.168.1.90",broker_port, 2sec); 
}

##if the connection is established then connection_extablished event will
##be trigered.
event BrokerComm::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
{
	print "BrokerComm::outgoing_connection_establisted", 	peer_address, peer_port, peer_name;
		
     ##if we are interested in new entries of acpi_tables then write event name as "added_acpi_tables"
	osquery::subscribe("osquery::added_acpi_tables","SELECT name,size,md5 FROM acpi_tables");

    ##if we are interested in removed entries of acpi_tables then write event name as "removed_acpi_tables"
	osquery::subscribe("osquery::removed_acpi_tables","SELECT name,size,md5 FROM acpi_tables");
}

event BrokerComm::incoming_connection_broken(peer_name: string)
{
	print "BrokerComm::incoming_connection_broken", peer_name;
	terminate();
}


event added_acpi_tables(host: string, name: string, size: count, md5: 	string)
{
	print "New acpi_table Entry";
	print fmt("Host = %s Table_name = %s size = %d md5 = %s",host, 	name,
     size, md5);
}
event removed_acpi_tables(host: string, name: string,size: count,md5: 	string)
{
	print "Deleted acpi_table Entry";
	print fmt("Host = %s Table_name = %s size = %d md5 = %s",host, 	name,
     size, md5);
}
```

Please refer to singlequerysubscription.bro to have a look at the scripts 
written to monitor other events.

####3.2 Scenario 2: A master to a single remote host monitoring with a single####
####query subscription####
An example script for multiple queries subscription, extracted from 
multiplequerysubscription.bro,
to monitor ACPI tables is given below:
```
module osquery;

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef osquery::endpoint_name = "Printer";

global added_acpi_tables: event(host: string, name: string, size: count, md5: string);
global removed_acpi_tables: event(host: string, name: string,size: count, md5: string);

global query: table[string] of string;

event bro_init()
{
	##enable broker communication
	osquery::enable();
	##subscribe to events
	osquery::subscribe_to_events("/bro/event/");
	##connect with the osquery host at IP
	osquery::connect("192.168.1.90",broker_port, 2sec); 

        query["osquery::added_acpi_tables"] = "SELECT name,size,md5 FROM acpi_tables";
	query["osquery::removed_acpi_tables"] = "SELECT name,size,md5 FROM acpi_tables";
}

##if the connection is established then connection_extablished event will be trigered.
event BrokerComm::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
{
	print "BrokerComm::outgoing_connection_establisted", peer_address, peer_port, peer_name;
	osquery::groupsubscribe("/bro/event/group1",query);

}

event BrokerComm::incoming_connection_broken(peer_name: string)
{
	print "BrokerComm::incoming_connection_broken", peer_name;
	terminate();
}


event added_acpi_tables(host: string, name: string, size: count, md5: 	string)
{
	print "New acpi_table Entry";
	print fmt("Host = %s Table_name = %s size = %d md5 = %s",host, 	name, size, md5);
}
event removed_acpi_tables(host: string, name: string,size: count,md5: 	string)
{
	print "Deleted acpi_table Entry";
	print fmt("Host = %s Table_name = %s size = %d md5 = %s",host, 	name, size, md5);
}
```
Please refer to multiplequerysubscription.bro to have a look at the scripts 
written to monitor other
events.

####3.3 Scenario 3: A master to a remote group of hosts monitoring with a single####
####query subscription####
An example script for a group of connections and single query subscription,
to monitor ACPI tables is given below:
```
module osquery;

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef osquery::endpoint_name = "Printer";

global added_acpi_tables: event(host: string, name: string, size: count, md5: string);
global removed_acpi_tables: event(host: string, name: string,size: count, md5: string);

global gconn: table[string] of string;


event bro_init()
{
	##enable broker communication
	osquery::enable();
	##subscribe to events
	osquery::subscribe_to_events("/bro/event/");
	##connect with a group of osquery host at IPs
	gconn["192.168.1.187"] = "9999";

	gconn["192.168.1.211"] = "9999";

	gconn["192.168.1.33"] = "9999"; 

 	osquery::groupconnect(gconn, 2sec);
}

##if the connection is established then connection_extablished event will be trigered.
event BrokerComm::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
{
	print "BrokerComm::outgoing_connection_establisted", 	peer_address, 
        peer_port, peer_name;

	##if we are interested in new entries of acpi_tables then write event name as "added_acpi_tables"
	osquery::subscribe("osquery::added_acpi_tables","SELECT name,size,md5 FROM acpi_tables");

	##if we are interested in removed entries of acpi_tables then write event name as "removed_acpi_tables"
	osquery::subscribe("osquery::removed_acpi_tables","SELECT name,size,md5 FROM acpi_tables");
}

event BrokerComm::incoming_connection_broken(peer_name: string)
{
	print "BrokerComm::incoming_connection_broken", peer_name;
	terminate();
}
```
####3.4 Scenario 4: A master to a remote group of hosts monitoring with multiple#### 
####queries subscription####
An example script for a group of connection and multiple queries subscription,
to monitor ACPI tables is given below:
```
module osquery;

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef osquery::endpoint_name = "Printer";

global added_acpi_tables: event(host: string, name: string, size: count, md5: string);
global removed_acpi_tables: event(host: string, name: string,size: count, md5: string);

global query: table[string] of string;
global gconn: table[string] of string;


event bro_init()
{
	##enable broker communication
	osquery::enable();
	##subscribe to events
	osquery::subscribe_to_events("/bro/event/");
	##connect with a group of osquery host at IPs
	gconn["192.168.1.187"] = "9999";

	gconn["192.168.1.211"] = "9999";

	gconn["192.168.1.33"] = "9999"; 

 	osquery::groupconnect(gconn, 2sec);

	query["osquery::added_acpi_tables"] = "SELECT name,size,md5 FROM acpi_tables";
	query["osquery::removed_acpi_tables"] = "SELECT name,size,md5 FROM acpi_tables";
}   

##if the connection is established then connection_extablished event will be trigered.
event BrokerComm::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
{
	print "BrokerComm::outgoing_connection_establisted", 	peer_address, peer_port, peer_name;
	osquery::groupsubscribe("/bro/event/group1",query);
	
}

event BrokerComm::incoming_connection_broken(peer_name: string)
{
	print "BrokerComm::incoming_connection_broken", peer_name;
	terminate();
}


event added_acpi_tables(host: string, name: string, size: count, md5: 	string)
{
	print "New acpi_table Entry";
	print fmt("Host = %s Table_name = %s size = %d md5 = %s",host, 	name, size, md5);
}
event removed_acpi_tables(host: string, name: string,size: count,md5: 	string)
{
	print "Deleted acpi_table Entry";
	print fmt("Host = %s Table_name = %s size = %d md5 = %s",host, 	name, size, md5);
}
```
