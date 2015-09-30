
module osquery;

const broker_port: port = 9999/tcp &redef;
redef exit_only_after_terminate = T;
redef osquery::endpoint_name = "Printer";


global added_acpi_tables: event(host: string, name: string, size: count, md5: string);
global removed_acpi_tables: event(host: string, name: string,size: count,md5: string);
###################################################################################
global added_arp_cache: event(host: string, address: string, mac: string, interface: string);
global removed_arp_cache: event(host: string, address: string, mac: string, interface: string);
###################################################################################
global added_block_devices: event(host: string, name: string,vendor: string, model: string);
global removed_block_devices: event(host: string, name: string,vendor: string, model: string);
###################################################################################
global added_chrome_extensions: event(host: string, name: string,author: string, path:string);
global removed_chrome_extensions: event(host: string, name: string,author: string, path:string);
###################################################################################
global added_cpuid: event(host: string, feature: string, value: string);
global removed_cpuid: event(host: string, feature: string, value: string);
###################################################################################
global added_crontab: event(host: string, hour: count, command: string, path: string);
global removed_crontab: event(host: string, hour: count, command: string, path: string);
###################################################################################
global added_disk_encryption: event(host: string, name: string, uuid: string, encrypted: count);
global removed_disk_encryption: event(host: string, name: string, uuid: string, encrypted: count);
###################################################################################
global added_etc_hosts: event(host: string, address: string, hostnames: string);
global removed_etc_hosts: event(host: string, address: string, hostnames: string);
###################################################################################
global added_etc_protocols: event(host: string, name: string, number: count);
global removed_etc_protocols: event(host: string, name: string, number: count);
###################################################################################
global added_etc_services: event(host: string, name: string, prt: count, protocol: string);
global removed_etc_services: event(host: string, name: string, prt: count, protocol: string);
###################################################################################
global added_file_events: event(host: string, target_path: string, action: string, t: count);
global removed_file_events: event(host: string, target_path: string, action: string, t: count);
###################################################################################
global added_firefox_addons: event(host: string, name: string, source_url: string, location: string);
global removed_firefox_addons: event(host: string, name: string, source_url: string, location: string);
###################################################################################
global added_groups: event(host: string, gid: count, groupname: string);
global removed_groups: event(host: string, gid: count, groupname: string);
###################################################################################
global added_hardware_events: event(host: string, action: string, model: string, vendor: string);
global removed_hardware_events: event(host: string, action: string, model: string, vendor: string);
###################################################################################
global added_interface_address: event(host: string, interface: string, address: string);
global removed_interface_address: event(host: string, interface: string, address: string);
###################################################################################
global added_interface_details: event(host: string, interface: string, mac: string, mtu: count);
global removed_interface_details: event(host: string, interface: string, mac: string, mtu: count);
###################################################################################
global added_kernel_info: event(host: string, version: string, path: string, device: string);
global removed_kernel_info: event(host: string, version: string, path: string, device: string);
###################################################################################
global added_last: event(host: string, username: string, pid: count, h: string);
global removed_last: event(host: string, username: string, pid: count, h: string);
###################################################################################
global added_listening_ports: event(host: string, pid: count, prt: count, protocol: count);
global removed_listening_ports: event(host: string, pid: count, prt: count, protocol: count);
###################################################################################
global added_logged_in_users: event(host: string, user: string, h: string, t: count);
global removed_logged_in_users: event(host: string, user: string, h: string, t: count);
###################################################################################
global added_mounts: event(host: string, device: string, path: string);
global removed_mounts: event(host: string, device: string, path: string);
###################################################################################
global added_opera_extensions: event(host: string, name: string, description: string, author: string);
global removed_opera_extensions: event(host: string, name: string, description: string, author: string);
###################################################################################
global added_os_version: event(host: string, name: string, patch: count, build: string);
global removed_os_version: event(host: string, name: string, patch: count, build: string);
###################################################################################
global added_passwd_changes: event(host: string, target_path: string, action: string);
global removed_passwd_changes: event(host: string, target_path: string, action: string);
###################################################################################
global added_pci_devices: event(host: string, pci_slot: string, driver: string, vendor: string, model: string);
global removed_pci_devices: event(host: string, pci_slot: string, driver: string, vendor: string, model: string);
###################################################################################
global added_process_envs: event(host: string, pid: count, key: string, value: string);
global removed_process_envs: event(host: string, pid: count, key: string, value: string);
###################################################################################
global added_process_memory_map: event(host: string, pid: count, permissions: string, device: string);
global removed_process_memory_map: event(host: string, pid: count, permissions: string, device: string);
###################################################################################
global added_process_open_files: event(host: string, pid: count, fd: string, path: string);
global removed_process_open_files: event(host: string, pid: count, fd: string, path: string);
###################################################################################
global added_process_open_sockets: event(host: string, pid: count, socket: count, protocol: count);
global removed_process_open_sockets: event(host: string, pid: count, socket: count, protocol: count);
###################################################################################
global added_processes: event(host: string, pid: count, name: string, on_disk: string);
global removed_processes: event(host: string, pid: count, name: string, on_disk: string);
###################################################################################
global added_routes: event(host: string, destination: string, source: string, interface: string);
global removed_routes: event(host: string, destination: string, source: string, interface: string);
###################################################################################
global added_shell_history: event(host: string, username: string, command: string);
global removed_shell_history: event(host: string, username: string, command: string);
###################################################################################
global added_smbios_tables: event(host: string, number: count, description: string, size: count);
global removed_smbios_tables: event(host: string, number: count, description: string, size: count);
###################################################################################
global added_system_controls: event(host: string, name: string, oid: string, subsystem: string);
global removed_system_controls: event(host: string, name: string, oid: string, subsystem: string);
###################################################################################
global added_uptime: event(host: string, days: count, hours: count);
global removed_uptime: event(host: string, days: count, hours: count);
###################################################################################
global added_usb_devices: event(host: string, usb_address: count, vendor: string, model: string);
global removed_usb_devices: event(host: string, usb_address: count, vendor: string, model: string);
###################################################################################
global added_user_groups: event(host: string, uid: count, gid: count);
global removed_user_groups: event(host: string, uid: count, gid: count);
###################################################################################
global added_users: event(host: string, username: string, uid: count, gid: count);
global removed_users: event(host: string, username: string, uid: count, gid: count);
###################################################################################

event bro_init()
{
	osquery::enable();
	osquery::subscribe_to_events("/bro/event/");
	osquery::connect("192.168.1.211",broker_port, 2sec); 
	##osquery::connect("192.168.1.187",broker_port, 2sec); 
	##osquery::connect("192.168.1.33",broker_port, 2sec); 
}

event BrokerComm::outgoing_connection_established(peer_address: string, peer_port: port, peer_name: string)
{
	print "BrokerComm::outgoing_connection_establisted", peer_address, peer_port, peer_name;
	
	osquery::subscribe("osquery::added_acpi_tables","SELECT name,size,md5 FROM acpi_tables",T);
	#osquery::subscribe("osquery::removed_acpi_tables","SELECT name,size,md5 FROM acpi_tables");
	#######################################################################################
	osquery::subscribe("osquery::added_arp_cache","SELECT address,mac,interface FROM arp_cache");
	#osquery::subscribe("osquery::removed_arp_cache","SELECT address,mac,interface FROM arp_cache");
	#######################################################################################
	#osquery::subscribe("osquery::added_block_devices","SELECT name,vendor,model FROM block_devices");
	#osquery::subscribe("osquery::removed_block_devices","SELECT name,vendor,model FROM block_devices");
	#######################################################################################
	#osquery::subscribe("osquery::added_chrome_extensions","SELECT name,author,path FROM chrome_extensions");
	#osquery::subscribe("osquery::removed_chrome_extensions","SELECT name,author,path FROM chrome_extensions");
	########################################################################################
	#osquery::subscribe("osquery::added_cpuid","SELECT feature,value FROM cpuid");
	#osquery::subscribe("osquery::removed_cpuid","SELECT feature,value FROM cpuid");
	#######################################################################################
	#osquery::subscribe("osquery::added_crontab","SELECT hour,command,path FROM crontab");
	#osquery::subscribe("osquery::removed_crontab","SELECT hour,command,path FROM crontab");
	#######################################################################################
	#osquery::subscribe("osquery::added_disk_encryption","SELECT name,uuid,encrypted FROM disk_encryption");
	#osquery::subscribe("osquery::removed_disk_encryption","SELECT name,uuid,encrypted FROM disk_encryption");
	########################################################################################
	#osquery::subscribe("osquery::added_etc_hosts","SELECT address,hostnames FROM etc_hosts");
	#osquery::subscribe("osquery::removed_etc_hosts","SELECT address,hostnames FROM etc_hosts");
	########################################################################################
	#osquery::subscribe("osquery::added_etc_protocols","SELECT name,number FROM etc_protocols");
	#osquery::subscribe("osquery::removed_etc_protocols","SELECT name,number FROM etc_protocols");
	#######################################################################################
	#osquery::subscribe("osquery::added_etc_services","SELECT name,port,protocol FROM etc_services");
	#osquery::subscribe("osquery::removed_etc_services","SELECT name,port,protocol FROM etc_services");
	#######################################################################################
	#osquery::subscribe("osquery::added_file_events","SELECT target_path,action,time FROM file_events");
	#osquery::subscribe("osquery::removed_file_events","SELECT target_path,action,time FROM file_events");
	#######################################################################################
	#osquery::subscribe("osquery::added_firefox_addons","SELECT name,source_url,location FROM firefox_addons");
	#osquery::subscribe("osquery::removed_firefox_addons","SELECT name,source_url,location FROM firefox_addons");
	#######################################################################################
	#osquery::subscribe("osquery::added_groups","SELECT gid,groupname FROM groups");
	#osquery::subscribe("osquery::removed_groups","SELECT gid,groupname FROM groups");
	#######################################################################################
	#osquery::subscribe("osquery::added_hardware_events","SELECT action,model,vendor FROM hardware_events");
	#osquery::subscribe("osquery::removed_hardware_events","SELECT action,model,vendor FROM hardware_events");
	#######################################################################################
	#osquery::subscribe("osquery::added_interface_address","SELECT interface,address FROM interface_address");
	#osquery::subscribe("osquery::removed_interface_address","SELECT interface,address FROM interface_address");
	#######################################################################################
	#osquery::subscribe("osquery::added_interface_details","SELECT interface,mac,mtu FROM interface_details");
	#osquery::subscribe("osquery::removed_interface_details","SELECT interface,mac,mtu FROM interface_details");
	#######################################################################################
	#osquery::subscribe("osquery::added_kernel_info","SELECT version,path,device FROM kernel_info");
	#osquery::subscribe("osquery::removed_kernel_info","SELECT version,path,device FROM kernel_info");
	#######################################################################################
	#osquery::subscribe("osquery::added_last","SELECT username,pid,host FROM last");
	#osquery::subscribe("osquery::removed_last","SELECT username,pid,host FROM last");
	#######################################################################################
	#osquery::subscribe("osquery::added_listening_ports","SELECT pid,port,protocol FROM listening_ports");
	#osquery::subscribe("osquery::removed_listening_ports","SELECT pid,port,protocol FROM listening_ports");
	#######################################################################################
	#osquery::subscribe("osquery::added_logged_in_users","SELECT user,host,time FROM logged_in_users");
	#osquery::subscribe("osquery::removed_logged_in_users","SELECT user,host,time FROM logged_in_users");
	########################################################################################
	#osquery::subscribe("osquery::added_mounts","SELECT device,path FROM mounts");
	#osquery::subscribe("osquery::removed_mounts","SELECT device,path FROM mounts");
	########################################################################################
	#osquery::subscribe("osquery::added_opera_extensions","SELECT name,description,author FROM opera_extensions");
	#osquery::subscribe("osquery::removed_opera_extensions","SELECT name,description,author FROM opera_extensions");
	#######################################################################################
	osquery::subscribe("osquery::added_os_version","SELECT name,patch,build FROM os_version",T);
	#osquery::subscribe("osquery::removed_os_version","SELECT name,patch,build FROM os_version");
	#######################################################################################
	#osquery::subscribe("osquery::added_passwd_changes","SELECT target_path,action FROM passwd_changes");
	#osquery::subscribe("osquery::removed_passwd_changes","SELECT target_path,action FROM passwd_changes");
	#######################################################################################
	#osquery::subscribe("osquery::added_pci_devices","SELECT pci_slot,driver,vendor,model FROM pci_devices");
	#osquery::subscribe("osquery::removed_pci_devices","SELECT pci_slot,driver,vendor,model FROM pci_devices");
	#######################################################################################
	#osquery::subscribe("osquery::added_process_envs","SELECT pid,key,value FROM process_envs");
	#osquery::subscribe("osquery::removed_process_envs","SELECT pid,key,value FROM process_envs");
	#######################################################################################
	#osquery::subscribe("osquery::added_process_memory_map","SELECT pid,permissions,device FROM process_memory_map");
	#osquery::subscribe("osquery::removed_process_memory_map","SELECT pid,permissions,device FROM process_memory_map");
	#######################################################################################
	#osquery::subscribe("osquery::added_process_open_files","SELECT pid,fd,path FROM process_open_files");
	#osquery::subscribe("osquery::removed_process_open_files","SELECT pid,fd,path FROM process_open_files");
	#######################################################################################
	osquery::subscribe("osquery::added_process_open_sockets","SELECT pid,socket,protocol FROM process_open_sockets");
	#osquery::subscribe("osquery::removed_process_open_sockets","SELECT pid,socket,protocol FROM process_open_sockets");
	#######################################################################################
	#osquery::subscribe("osquery::added_processes","SELECT pid,name,on_disk FROM processes");
	#osquery::subscribe("osquery::removed_processes","SELECT pid,name,on_disk FROM processes");
	#######################################################################################
	#osquery::subscribe("osquery::added_routes","SELECT destination,source,interface FROM routes");
	#osquery::subscribe("osquery::removed_routes","SELECT destination,source,interface FROM routes");
	#######################################################################################
	#osquery::subscribe("osquery::added_shell_history","SELECT username,command FROM shell_history");
	#osquery::subscribe("osquery::removed_shell_history","SELECT username,command FROM shell_history");
	#######################################################################################
	osquery::subscribe("osquery::added_smbios_tables","SELECT number,description,size FROM smbios_tables");
	#osquery::subscribe("osquery::removed_smbios_tables","SELECT number,description,size FROM smbios_tables");
	#######################################################################################
	#osquery::subscribe("osquery::added_system_controls","SELECT name,oid,subsystem FROM system_controls");
	#osquery::subscribe("osquery::removed_system_controls","SELECT name,oid,subsystem FROM system_controls");
	#######################################################################################
	#osquery::subscribe("osquery::added_uptime","SELECT days,hours FROM uptime",T);
	#osquery::subscribe("osquery::removed_uptime","SELECT days,hours FROM uptime");
	#######################################################################################
	#osquery::subscribe("osquery::added_usb_devices","SELECT usb_address,vendor,model FROM usb_devices",T);
	#osquery::subscribe("osquery::removed_usb_devices","SELECT usb_address,vendor,model FROM usb_devices");
	########################################################################################
	#osquery::subscribe("osquery::added_user_groups","SELECT uid,gid FROM user_groups");
	#osquery::subscribe("osquery::removed_user_groups","SELECT uid,gid FROM user_groups");
	########################################################################################
	osquery::subscribe("osquery::added_users","SELECT username,uid,gid FROM users");
	#osquery::subscribe("osquery::removed_users","SELECT username,uid,gid FROM users");
	#######################################################################################
	
}


event BrokerComm::incoming_connection_broken(peer_name: string)
{
	print "BrokerComm::incoming_connection_broken", peer_name;
	terminate();
}
########################### ACPI TABLES ################################################

event added_acpi_tables(host: string, name: string, size: count, md5: string)
{
	print "New acpi_table Entry";
	print fmt("Host = %s Table_name = %s size = %d md5 = %s",host, name, size, md5);
}
event removed_acpi_tables(host: string, name: string,size: count,md5: string)
{
	print "Deleted acpi_table Entry";
	print fmt("Host = %s Table_name = %s size = %d md5 = %s",host, name, size, md5);
}
############################## ARP CACHE ##############################################
event added_arp_cache(host: string, address: string, mac: string, interface: string)
{
	print fmt("Host = %s Address = %s mac = %s Interface = %s",host, address, mac, interface);
}
event removed_arp_cache(host: string, address: string, mac: string, interface: string)
{
	print fmt("Host = %s Address = %s mac = %s Interface = %s",host, address, mac, interface);
}
############################## BLOCK DEVICES ###########################################
event added_block_devices(host: string, name: string,vendor: string, model: string)
{
	print fmt("Host = %s Name = %s Vendor = %s Model = %s",host, name, vendor, model);
}
event removed_block_devices(host: string, name: string,vendor: string, model: string)
{
	print fmt("Host = %s Name = %s Vendor = %s Model = %s",host, name, vendor, model);
}
############################## CHROME EXTENSIONS ##########################################
event added_chrome_extensions(host: string, name: string,author: string, path:string)
{
	print fmt("New entry added");
	print fmt("Host = %s Name = %s Author = %s Path = %s",host, name, author, path);
}
event removed_chrome_extensions(host: string, name: string,author: string, path:string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Name = %s Author = %s Path = %s",host, name, author, path);
}
############################# CPUID #####################################################
event added_cpuid(host: string, feature: string, value: string)
{
	print fmt("New entry added");
	print fmt("Host = %s Feature = %s Value = %s",host, feature,value);
}
event removed_cpuid(host: string, feature: string, value: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Feature = %s Value = %s",host, feature,value);
}
############################ CRONTAB ####################################################
event added_crontab(host: string, hour: count, command: string, path: string)
{
	print fmt("New entry added");
	print fmt("Host = %s Hour = %d Command = %s Path=%s",host, hour, command, path);
}
event removed_crontab(host: string, hour: count, command: string,path: string)
{
	print fmt("Host = %s Hour = %d Command = %s Path=%s",host, hour, command, path);
}
########################### DISK ENCRYPTION ###############################################
event added_disk_encryption(host: string, name: string, uuid: string, encrypted: count)
{
	print fmt("New entry added");
	print fmt("Host = %s Name = %s uuid = %s encrypted=%d",host, name, uuid, encrypted);
}
event removed_disk_encryption(host: string, name: string, uuid: string, encrypted: count)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Name = %s uuid = %s encrypted=%d",host, name, uuid, encrypted);
}
########################### ETC HOSTS ########################################################
event added_etc_hosts(host: string, address: string, hostnames: string)
{
	print fmt("New entry added");
	print fmt("Host = %s Address = %s hostnames = %s ",host, address, hostnames);
}
event removed_etc_hosts(host: string, address: string, hostnames: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Address = %s hostnames = %s ",host, address, hostnames);
}
########################### ETC PROTOCOLS #################################################
event added_etc_protocols(host: string, name: string, number: count)
{
	print fmt("New entry added");
	print fmt("Host = %s Name = %s number = %d ",host, name, number);
}
event removed_etc_protocols(host: string, name: string, number: count)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Name = %s number = %d ",host, name, number);
}
########################### ETC SERVICES ##################################################
event added_etc_services(host: string, name: string, prt: count, protocol: string)
{
	print fmt("New entry added");
	print fmt("Host = %s Name = %s prt = %d Protocol = %s ",host, name, prt, protocol);
}
event removed_etc_services(host: string, name: string, prt: count, protocol: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Name = %s prt = %d Protocol = %s ",host, name, prt, protocol);
}
########################### FILE EVENTS ####################################################
event added_file_events(host: string, target_path: string, action: string, t: count)
{
	print fmt("New entry added");
	print fmt("Host = %s target_path = %s Action = %s Time = %d",host, target_path,action,t);
}
event removed_file_events(host: string, target_path: string, action: string, t: count)
{
	print fmt("Entry Removed");
	print fmt("Host = %s target_path = %s Action = %s Time = %d",host, target_path,action,t);
}
############################ FIREFOX ADDONS #################################################
event added_firefox_addons(host: string, name: string, source_url: string, location: string)
{
	print fmt("New entry added");
	print fmt("Host = %s Name = %s source_url = %s Locatoin= %s ",host, name, source_url, location);
}
event removed_firefox_addons(host: string, name: string, source_url: string, location: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Name = %s source_url = %s Locatoin= %s ",host, name, source_url, location);
}
############################ ADDED GROUPS ###################################################
event added_groups(host: string, gid: count, groupname: string)
{
	print fmt("New entry added");
	print fmt("Host = %s gid = %d groupnumber = %s ",host, gid, groupname);
}
event removed_groups(host: string, gid: count, groupname: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s gid = %d groupnumber = %s ",host, gid, groupname);
}
############################ HARDWARE EVENTS ##################################################
event added_hardware_events(host: string, action: string, model: string, vendor: string)
{
	print fmt("New entry added");
	print fmt("Host = %s action = %s model = %s  Vendor =%s",host, action, model,vendor);
}
event removed_hardware_events(host: string, action: string, model: string, vendor: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s action = %s model = %s  Vendor =%s",host, action, model,vendor);
}
########################### INTERFACE ADDRESS ##################################################
event added_interface_address(host: string, interface: string, address: string)
{
	print fmt("New entry added");
	print fmt("Host = %s Interface = %s Address = %s ",host, interface,address);
}
event removed_interface_address(host: string, interface: string, address: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Interface = %s Address = %s ",host, interface,address);
}
############################ INTERFACE DETAILS ##################################################
event added_interface_details(host: string, interface: string, mac: string, mtu: count)
{
	print fmt("New entry added");
	print fmt("Host = %s interface= %s mac = %s Mtu =%d ",host, interface,mac,mtu);
}
event removed_interface_details(host: string, interface: string, mac: string, mtu: count)
{
	print fmt("Entry Removed");
	print fmt("Host = %s interface= %s mac = %s Mtu =%d ",host, interface,mac,mtu);
}
############################ KERNEL INFO ####################################################
event added_kernel_info(host: string, version: string, path: string, device: string)
{
	print fmt("New entry added");
	print fmt("Host = %s version = %s path = %s Device =%s",host, version,path,device);
}
event removed_kernel_info(host: string, version: string, path: string, device: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s version = %s path = %s Device =%s",host, version,path,device);
}
############################# LAST ##########################################################
event added_last(host: string, username: string, pid: count, h: string)
{
	print fmt("New entry added");
	print fmt("Host = %s username = %s pid = %d Host=%s",host, username, pid,h);
}
event removed_last(host: string, username: string, pid: count, h: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s username = %s pid = %d Host=%s",host, username, pid,h);
}
############################# LISTENING PORTS ################################################
event added_listening_ports(host: string, pid: count, prt: count, protocol: count)
{
	print fmt("New entry added");
	print fmt("Host = %s pid = %d prt = %d Protocol =%d ",host, pid,prt,protocol);
}
event removed_listening_ports(host: string, pid: count, prt: count, protocol: count)
{
	print fmt("Entry Removed");
	print fmt("Host = %s pid = %d prt = %d Protocol =%d ",host, pid,prt,protocol);
}
############################# LOGGED IN USERS #################################################
event added_logged_in_users(host: string, user: string, h: string, t: count)
{
	print fmt("New entry added");
	print fmt("Host = %s User = %s Host = %s Time =%d ",host, user,h,t);
}
event removed_logged_in_users(host: string, user: string, h: string, t: count)
{
	print fmt("Entry Removed");
	print fmt("Host = %s User = %s Host = %s Time =%d ",host, user,h,t);
}
############################ MOUNTS ##########################################################
event added_mounts(host: string, device: string, path: string)
{
	print fmt("New entry added");
	print fmt("Host = %s Device = %s Path = %s ",host, device,path);
}
event removed_mounts(host: string, device: string, path: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Device = %s Path = %s ",host, device,path);
}
############################ OPERA EXTENSIONS #################################################
event added_opera_extensions(host: string, name: string, description: string, author: string)
{
	print fmt("New entry added");
	print fmt("Host = %s Name = %s description = %s Author=%s ",host, name,description,author);
}
event removed_opera_extensions(host: string, name: string, description: string, author: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Name = %s description = %s Author=%s ",host, name,description,author);
}
############################ OS VERSION ######################################################
event added_os_version(host: string, name: string, patch: count, build: string)
{
	print fmt("New entry added");
	print fmt("Host = %s Name = %s Patch = %d Build = %s ",host, name, patch,build);
}
event removed_os_version(host: string, name: string, patch: count, build: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Name = %s Patch = %d Build = %s ",host, name, patch,build);
}
############################ PASSWORD CHANGES ##################################################
event added_passwd_changes(host: string, target_path: string, action: string)
{
	print fmt("New entry added");
	print fmt("Host = %s Target_Path = %s Action = %s ",host, target_path,action);
}
event removed_passwd_changes(host: string, target_path: string, action: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Target_Path = %s Action = %s ",host, target_path,action);
}
############################ PCI DEVICES #####################################################
event added_pci_devices(host: string, pci_slot: string, driver: string, vendor: string, model: string)
{
	print fmt("New entry added");
	print fmt("Host = %s PCI_Slot = %s Driver = %s Vendor =%s Model= %s",host, pci_slot,driver,vendor,model);
}
event removed_pci_devices(host: string, pci_slot: string, driver: string, vendor: string, model: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s PCI_Slot = %s Driver = %s Vendor =%s Model= %s",host, pci_slot,driver,vendor,model);
}
########################### PROCESS EVENTS #####################################################
event added_process_envs(host: string, pid: count, key: string, value: string)
{
	print fmt("New entry added");
	print fmt("Host = %s PID = %d Key = %s Value = %s ",host, pid,key,value);
}
event removed_process_envs(host: string, pid: count, key: string, value: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s PID = %d Key = %s Value = %s ",host, pid,key,value);
}
########################### PROCESS MOMORY ######################################################
event added_process_memory_map(host: string, pid: count, permissions: string, device: string)
{
	print fmt("New entry added");
	print fmt("Host = %s PID = %d Permissions = %s Device = %s ",host, pid,permissions,device);
}
event removed_process_memory_map(host: string, pid: count, permissions: string, device: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s PID = %d Permissions = %s Device = %s ",host, pid,permissions,device);
}
########################## PROCESS OPEN FILES ###################################################
event added_process_open_files(host: string, pid: count, fd: string, path: string)
{
	print fmt("New entry added");
	print fmt("Host = %s PID = %d FD = %s Path = %s",host, pid,fd,path);
}
event removed_process_open_files(host: string, pid: count, fd: string, path: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s PID = %d FD = %s Path = %s",host, pid,fd,path);
}
########################## PROCESS OPEN SOCKETS ####################################################
event added_process_open_sockets(host: string, pid: count, socket: count, protocol: count)
{
	print fmt("New entry added");
	print fmt("Host = %s PID = %d Socket = %d Protocol =%d",host, pid,socket,protocol);
}
event removed_process_open_sockets(host: string, pid: count, socket: count, protocol: count)
{
	print fmt("Entry Removed");
	print fmt("Host = %s PID = %d Socket = %d Protocol =%d",host, pid,socket,protocol);
}
########################## PROCESSES #########################################################
event added_processes(host: string, pid: count, name: string, on_disk: string)
{
	print fmt("New entry added");
	print fmt("Host = %s PID = %d Name = %s on_disk = %s",host, pid,name,on_disk);
}
event removed_processes(host: string, pid: count, name: string, on_disk: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s PID = %d Name = %s on_disk = %s",host, pid,name,on_disk);
}
########################### ROUTES ########################################################
event added_routes(host: string, destination: string, source: string, interface: string)
{
	print fmt("New entry added");
	print fmt("Host = %s Destination = %s Source = %s Interface = %s ",host, destination,source,interface);
}
event removed_routes(host: string, destination: string, source: string, interface: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Destination = %s Source = %s Interface = %s ",host, destination,source,interface);
}
########################### SHELL HISTORY ####################################################
event added_shell_history(host: string, username: string, command: string)
{
	print fmt("New entry added");
	print fmt("Host = %s UserNmae = %s Command = %s ",host, username, command);
}
event removed_shell_history(host: string, username: string, command: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s UserNmae = %s Command = %s ",host, username, command);
}
############################ SMBIOS TABLES ###################################################
event added_smbios_tables(host: string, number: count, description: string, size: count)
{
	print fmt("New entry added");
	print fmt("Host = %s Number = %d Description = %s Size=%d ",host, number, description,size);
}
event removed_smbios_tables(host: string, number: count, description: string, size: count)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Number = %d Description = %s Size=%d ",host, number, description,size);
}
############################# SYSTEM CONTROLS ###################################################
event added_system_controls(host: string, name: string, oid: string, subsystem: string)
{
	print fmt("New entry added");
	print fmt("Host = %s Name = %s OID = %s Subsystem =%s ",host, name, oid, subsystem);
}
event removed_system_controls(host: string, name: string, oid: string, subsystem: string)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Name = %s OID = %s Subsystem =%s ",host, name, oid, subsystem);
}
############################## UPTIME ###################################################
event added_uptime(host: string, days: count, hours: count)
{
	print fmt("New entry added");
	print fmt("Host = %s Days = %d Hours = %d ",host, days,hours);
}
event removed_uptime(host: string, days: count, hours: count)
{
	print fmt("Entry Removed");
	print fmt("Host = %s Days = %d Hours = %d ",host, days,hours);
}
############################# USB DEVICES ###################################################
event added_usb_devices(host: string, usb_address: count, vendor: string, model: string)
{
	print "New Usb Device Added";
 	print fmt("Host = %s Usb_address = %d Vendor = %s Model = %s",host, usb_address, vendor, model);
}
event removed_usb_devices(host: string, usb_address: count, vendor: string, model: string)
{
	print "Usb Device Removed";
 	print fmt("Host = %s Usb_address = %d Vendor = %s Model = %s",host, usb_address, vendor, model);
}
############################# USER GROUPS ###################################################
event added_user_groups(host: string, uid: count, gid: count)
{
	print fmt("New entry added");
	print fmt("Host = %s UID = %d GID = %d ",host, uid, gid);
}
event removed_user_groups(host: string, uid: count, gid: count)
{
	print fmt("Entry Removed");
	print fmt("Host = %s UID = %d GID = %d ",host, uid, gid);
}
############################# USERS ######################################################
event added_users(host: string, username: string, uid: count, gid: count)
{
	print "New User Added";
 	print fmt("Host = %s UserName = %s UID = %d GID = %d",host, username, uid, gid);
}
event removed_users(host: string, username: string, uid: count, gid: count)
{
	print "User Removed";
 	print fmt("Host = %s UserName = %s UID = %d GID = %d",host, username, uid, gid);
}

