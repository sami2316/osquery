This module has been tested with 
linux: CENTOS7 (3.10.0-229.11.1.el7.x86_64)

```singlequerysubscription.bro ``` and ```multiplequerysubscription.bro``` are the sample script files
which are in https://github.com/sami2316/osquery directory.

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

####3.1 Scenario 1: A master to a single remote host monitoring with a single query subscription####

First you need to run osqueryd on both hosts. Then at bro side write the 
following script to subscribe to a single query. An example script, extracted 
from singlequerysubscription.bro, to monitor usb_devices is given below:

```
module osquery;

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef osquery::endpoint_name = "Printer";

global added_usb_devices: event(host: string, usb_address: count, vendor: string, model: string);


event bro_init()
{
	##enable broker communication
	osquery::enable();
	##subscribe to events
	osquery::subscribe_to_events("/bro/event/");
	##connect with the osquery host at IP
	osquery::connect("192.168.1.90",broker_port, 2sec); 
}

##if the connection is established then connection_extablished event will be trigered.
event BrokerComm::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
{
	print "BrokerComm::outgoing_connection_establisted", 	peer_address, peer_port, peer_name;
		
        ##if we are interested in inserted usb_devices then write event name as "added_usb_devices"
	osquery::subscribe("osquery::added_usb_devices","SELECT usb_address,vendor,model FROM usb_devices");
	##if you want an initial dump for the requrest query then set inidumpflag to True
	##osquery::subscribe("osquery::added_usb_devices","SELECT usb_address,vendor,model FROM usb_devices",T);


}

event BrokerComm::incoming_connection_broken(peer_name: string)
{
	print "BrokerComm::incoming_connection_broken", peer_name;
	terminate();
}


event added_usb_devices(host: string, usb_address: count, vendor: string, model: string)
{
	print "New Usb Device Added";
 	print fmt("Host = %s Usb_address = %d Vendor = %s Model = %s",host, usb_address, vendor, model);
}
```

Please refer to singlequerysubscription.bro to write scripts to monitor other events.

####3.2 Scenario 2: A master to a single remote host monitoring with multiple queries subscription####
An example script for multiple queries subscription, extracted from multiplequerysubscription.bro,
to monitor multiple OS events is given below:

```
module osquery;

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef osquery::endpoint_name = "Printer";

global added_acpi_tables: event(host: string, name: string, size: count, md5: string);
global added_usb_devices: event(host: string, usb_address: count, vendor: string, model: string);
global added_users: event(host: string, username: string, uid: count, gid: count);

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
	query["osquery::added_usb_devices"] =  "SELECT usb_address,vendor,model FROM usb_devices";
	query["osquery::added_users"] =  "SELECT username,uid,gid FROM users";
}

##if the connection is established then connection_extablished event will be trigered.
event BrokerComm::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
{
	print "BrokerComm::outgoing_connection_establisted", peer_address, peer_port, peer_name;
	osquery::groupsubscribe("/bro/event/",query);
	##if you want an initial dump for the requrest query then set inidumpflag to True
	##osquery::groupsubscribe("/bro/event/",query,T);
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
event added_usb_devices(host: string, usb_address: count, vendor: string, model: string)
{
	print "New Usb Device Added";
 	print fmt("Host = %s Usb_address = %d Vendor = %s Model = %s",host, usb_address, vendor, model);
}
event added_users(host: string, username: string, uid: count, gid: count)
{
	print "New User Added";
 	print fmt("Host = %s UserName = %s UID = %d GID = %d",host, username, uid, gid);
}
```
Please refer to multiplequerysubscription.bro to have a look at the scripts written to monitor other
events.

####3.3 Scenario 3: A master to a remote group of hosts monitoring with a single query subscription####
Make sure the broker.ini at each osquery host in a group has the same broker_topic. In our example, we are using 
"broker_topic=/bro/event/group1"
An example script for a group of connections and single query subscription,
to monitor usb_devices is given below:
```
module osquery;

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef osquery::endpoint_name = "Printer";

global added_usb_devices: event(host: string, usb_address: count, vendor: string, model: string);

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

	##if we are interested in inserted usb_devices then write event name as "added_usb_devices"
	osquery::subscribe("osquery::added_usb_devices","SELECT usb_address,vendor,model FROM 
	usb_devices","/bro/event/group1");
}

event BrokerComm::incoming_connection_broken(peer_name: string)
{
	print "BrokerComm::incoming_connection_broken", peer_name;
	terminate();
}

event added_usb_devices(host: string, usb_address: count, vendor: string, model: string)
{
	print "New Usb Device Added";
 	print fmt("Host = %s Usb_address = %d Vendor = %s Model = %s",host, usb_address, vendor, model);
}
```
For multiple groups, you need to change the broker.ini at each osquery host to make it a part of specific group. For example, if there are three hosts and we wana make three groups, simply update broker.ini on each host with different 
broker_topic "/bro/event/group1", "/bro/event/group2", "/bro/event/group3" respectively.
Then subscribe different queries on each host in BrokerComm::outgoing_connection_established event body.

```
event BrokerComm::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
{
	print "BrokerComm::outgoing_connection_establisted", 	peer_address, 
        peer_port, peer_name;

	osquery::subscribe("osquery::added_usb_devices","SELECT usb_address,vendor,model FROM 
	usb_devices","/bro/event/group1");
	osquery::subscribe("osquery::added_users","SELECT username,uid,gid FROM users", "/bro/event/group2");
	osquery::subscribe("osquery::added_acpi_tables","SELECT name,size,md5 FROM acpi_tables", "/bro/event/group3");
}
```

####3.4 Scenario 4: A master to a remote group of hosts monitoring with multiple queries subscription####
Make sure the broker.ini at each osquery host in a group has the same broker_topic. In our example, we are using 
"broker_topic=/bro/event/group1"
An example script for a group of connection and multiple queries subscription,
to monitor multiple OS events is given below:

```
module osquery;

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef osquery::endpoint_name = "Printer";

global added_acpi_tables: event(host: string, name: string, size: count, md5: string);
global added_usb_devices: event(host: string, usb_address: count, vendor: string, model: string);
global added_users: event(host: string, username: string, uid: count, gid: count);

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
	query["osquery::added_usb_devices"] =  "SELECT usb_address,vendor,model FROM usb_devices";
	query["osquery::added_users"] =  "SELECT username,uid,gid FROM users";
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
event added_usb_devices(host: string, usb_address: count, vendor: string, model: string)
{
	print "New Usb Device Added";
 	print fmt("Host = %s Usb_address = %d Vendor = %s Model = %s",host, usb_address, vendor, model);
}
event added_users(host: string, username: string, uid: count, gid: count)
{
	print "New User Added";
 	print fmt("Host = %s UserName = %s UID = %d GID = %d",host, username, uid, gid);
}
```

For multiple groups, you need to change the broker.ini at each osquery host to make it a part of specific group. For example, if there are three hosts and we wana make three groups, simply update broker.ini on each host with different 
broker_topic "/bro/event/group1", "/bro/event/group2", "/bro/event/group3" respectively.
And also define three different query tables e.g. query1, query2, query3, respectively.
Then subscribe different group of queries on each group in BrokerComm::outgoing_connection_established event body.
```
event BrokerComm::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
{
	print "BrokerComm::outgoing_connection_establisted", 	peer_address, peer_port, peer_name;
	osquery::groupsubscribe("/bro/event/group1",query1);
	osquery::groupsubscribe("/bro/event/group2",query2);
	osquery::groupsubscribe("/bro/event/group3",query3);
```
