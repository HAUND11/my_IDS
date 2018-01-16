class Static_data:

	ip_request_packet = {}
	ip_response_packet = {}

	def GET_STATIC_DATA(all_headers_packet):

		if(all_headers_packet["2L"]["Protocol_type"] == 0x0806):
			Static_data.ARP_DATA(all_headers_packet)

	def ARP_DATA(arp_headers):
		