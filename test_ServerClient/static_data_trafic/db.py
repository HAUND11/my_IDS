import sqlite3
import os

class DATA:
	def CREATE():

		os.system("rm static_data_trafic/static_data.db")  # clear data base 

		con = sqlite3.connect("static_data_trafic/static_data.db")
		cur = con.cursor()   
		cur.execute("""CREATE TABLE IP_request(id INTEGER PRIMARY KEY AUTOINCREMENT, 
												Source_mac CHAR,
												Source_ip INT,
												Destination_mac CHAR, 
												Destination_ip INT,
												Request INT, 
												Type_protocol CHAR);""")
		cur.execute("""CREATE TABLE ARP_data_host(id INTEGER PRIMARY KEY AUTOINCREMENT, 
														Host_ip CHAR,
														Host_mac CHAR);""")

		# con = sqlite3.connect("static_data_trafic/arp_data.db")
		# cur = con.cursor()	
		# cur.execute("CREATE TABLE ARP_packeta(id INTEGER	 PRIMARY KEY AUTOINCREMENT, Sender_hardware_address CHAR,Sender_protocol_address CHAR,Target_hardware_address CHAR,Target_protocol_address CHAR,Protocol_length INT,Hardware_length INT,Protocol_type INT,Hardware_type INT, Operation INT);")

	def CHEK_ARP_DATA_IN_TABLE(host_ip,host_mac):
		con = sqlite3.connect("static_data_trafic/static_data.db")
		cur = con.cursor()
		cur.execute("""SELECT Host_ip FROM ARP_data_host WHERE Host_ip="%s" and Host_mac="%s";""" % (host_ip, host_mac))
		if cur.fetchall()==[]:
			return False
		else:
			return True

	def INSERT_ARP_DATA(host_ip, host_mac):
		con = sqlite3.connect("static_data_trafic/static_data.db")
		cur = con.cursor()
		cur.execute("""INSERT INTO ARP_data_host VALUES(NULL,"%s","%s");""" % (host_ip,host_mac))
		con.commit()

	def INSERT_DATA(all_headers_packet):
		con = sqlite3.connect("static_data_trafic/static_data.db")
		cur = con.cursor()    
		if(all_headers_packet["3L"]["Protocol_type"] == 1 and # echo-request
		all_headers_packet["4L"]["Type_packet"] == 8 and
		all_headers_packet["4L"]["Code"] == 0):
			protocol_type = "ICMP_request"
		elif(all_headers_packet["2L"]["Protocol_type"] == 0x0806 and # ARP-request
		all_headers_packet["3L"]["Operation"] == 0x0001):
			protocol_type = "ARP_repuest"
		elif(all_headers_packet["3L"]["Protocol_type"] == 6 and # TCP-SYNC
		all_headers_packet["4L"]["Flags"] == 0x002):
			protocol_type = "TCP_SYN"
		else:
			return None
#################### check data DB ############################
		if(list(cur.execute("SELECT * FROM IP_request WHERE Source_mac = '%s' AND Destination_mac = '%s' AND Type_protocol = '%s' AND Source_ip = %i AND Destination_ip = %i;"	
		 % (all_headers_packet["2L"]["Source"],all_headers_packet["2L"]["Destination"],protocol_type,all_headers_packet["3L"]["Source"],all_headers_packet["3L"]["Destination"]))) == []):

			cur.execute("""INSERT INTO IP_request VALUES(NULL,"%s",%i,"%s",%i,%i,"%s");"""
						 % (all_headers_packet["2L"]["Source"],all_headers_packet["3L"]["Source"],all_headers_packet["2L"]["Destination"],all_headers_packet["3L"]["Destination"],1,protocol_type) )
		else:
			cur.execute("""UPDATE IP_request SET Request = Request + 1 WHERE Source_mac = '%s' AND Destination_mac = '%s' AND Type_protocol = '%s' AND Source_ip = %i AND Destination_ip = %i;"""
				 % (all_headers_packet["2L"]["Source"],all_headers_packet["2L"]["Destination"],protocol_type,all_headers_packet["3L"]["Source"],all_headers_packet["3L"]["Destination"]))

		con.commit()