This script can be used to create management ip addresses and address group along with local in policy.  The local in policy created will use ID 100 for permitting HTTP and HTTPS traffic to the address group created while ID 101 will deny all other traffic.  

Add all management IP addresses to the csv file that you want to allow HTTP and HTTPS access to the device.  The addresses need to be in CIDR notation, for example 10.10.10.0/24 for a network or 10.10.10.100/32 for host. 

To run the script an API admin user account will be required and must have read-write access to create the required objects.  

If your WAN interface is in a zone you will need to specify the zone otherwise specify the WAN port number, for example port1.