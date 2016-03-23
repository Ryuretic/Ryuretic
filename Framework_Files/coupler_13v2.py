###############################################################
# Ryuretic: A Modular Framework for RYU
# Author Jacob Cox (jcox70@gatech.edu)
# coupler_13v2.py
# Date 20 March 2016
###############################################################
#Copyright (C) 1883 Thomas Edison - All Rights Reserved
#You may use, distribute and modify this code under the
#terms of the Ryuretic license, which includes citing this 
#work for ongoing projects. 
#You should have received a copy of the Ryuretic license with
#this file. If not, please visit : 
###############################################################
"""How To Run This Program
1) Ensure you have Ryu installed.
2) Save the following files to /home/ubuntu/ryu/ryu/app/
    a) coupler_13v2.py
    b) NFG_13v2.py
    c) Pkt_Parse13.py
    d) switch_mod13.py
2) In your controller terminal type: cd ryu
3) Enter PYTHONPATH=. ./bin/ryu-manager ryu/app/coupler_13v2.py
"""
###################################################
import logging
import struct
# Ryuretic framework files
from ryu.app.Pkt_Parse13 import Pkt_Parse
from ryu.app.switch_mod13 import SimpleSwitch
#####################################################################
#[1] User can add class to NFGRD or create their own file (call it here)
from ryu.app.NFG_13v2 import NFG 
######################################################################
# Standard RYU calls
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
#from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet

class coupler(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(coupler, self).__init__(*args, **kwargs)
        #modules are added to the coupler as objects
        self.switch=SimpleSwitch()
        #created address for crafted packets
        self.hw_addr = 'aa:bb:cc:dd:ee:11'
        self.ip_addr = '10.0.0.25'
        ##############################################################
        #[2] Add Additional modules or object variables here or add
        #    definitions to the provided NFG_13.py file
        self.NFG = NFG()

	#######################################################################
	#[3]Insert proactive rules provided by NFG library, follow format below
	# Only offers drop and redirect options
	def get_proactive_rules(self,dp,parser,ofproto):
		pass
		#fields, ops = self.NFG.simpleFW()
		#self._add_proactive_flow(dp, parser, ofproto, fields, ops)
		
    #####################################################################
    #[4] Use below handles to direct arriving packets to modules in NFG.py; 
    #    modules return match fields (fields) and operations (ops) 
    #    hashes (determined by programmer). Ensure that fields,ops
    #    are only set once in each handle (comment out default_Field_Ops).
    ######################################################################
    #fields contains the following keys:
    #  {'keys':['inport','srcport'], 'ptype':None, 'inport':pkt['inport'],
    #  'srcmac':pkt['srcmac'], 'dstmac':None, 'srcip':None, 'dstip':None,
    #  'srcport':None, 'dstport':None}
    ######################################################################
    #ops contains the following keys:
    # {'hard_t':None, 'idle_t':None, 'priority':None, 'op':'fwd',
    #  'newport':None}
    # set *_t to 0 for permanent or >0 for temporary,
    # set * 'priority' to 0 for lowest
    # 'op':{'fwd', 'drop', 'mir' (mirror), 'newport' (redirect), 'craft'}
    # 'newport': used for mirror and redirect, otherwise None
    ######################################################################
    
    def handle_eth(self,pkt):
        print "handle eth"
        fields, ops = self.NFG.default_Field_Ops(pkt)
        #print pkt['eth']
        #fields, ops = check_list(pkt)
        #fields, ops = self.NFG.Check_List(pkt)
        self._switch_mod(pkt,fields,ops)

    def handle_arp(self,pkt):
        print "handle ARP"
        print pkt
        fields, ops = self.NFG.default_Field_Ops(pkt)
        #print pkt['arp']
        self._switch_mod(pkt, fields, ops)
		
    #Apply the most restrictive fields,ops (based on priority) are applied
    #to each packet. We will use priority to select.    
    def handle_ip(self,pkt):
	#print pkt['ip']
	#fields, ops = self.NFG.default_Field_Ops(pkt)
        print "handle ip"
        #fields2,ops2 = self.NFG.Stateful_FW(pkt)
	##############################################################
        #Determine highest priority fields and ops pair, if needed
        #xfields = [fields0, fields1, fields2]
        #xops = [ops0, ops1, ops2]
        #fields,ops = self._build_FldOps(xfields,xops)
	##############################################################
        
        self._switch_mod(pkt,fields,ops)

    def handle_icmp(self,pkt):
        print "handle icmp"
        fields, ops = self.NFG.default_Field_Ops(pkt)
        #print pkt['icmp'], '\n', pkt['ip']
        #fields, ops = self.NFG.TTL_Check(pkt)
        self._switch_mod(pkt, fields, ops)

    def handle_tcp(self,pkt):
        print "handle tcp"
        #fields, ops = self.NFG.default_Field_Ops(pkt)
        #fields,ops = self.NFG.Simple_FW(pkt)
        #print pkt['tcp']
        fields, ops = self.NFG.TTL_Check(pkt)
        # users can also call modules with no return
        #self.NFG.displayTCPFields(pkt)
        self._switch_mod(pkt, fields, ops)

    def handle_udp(self,pkt):
        print "handle udp"
        fields, ops = self.NFG.default_Field_Ops(pkt)
        #fields, ops = self.NFG.TTL_Check(pkt)
        self._switch_mod(pkt, fields, ops)

    def handle_unk(self,pkt):
        print "handl unk"
        fields, ops = self.NFG.default_Field_Ops(pkt)
        self._switch_mod(pkt, fields, ops)
		
	##################################################################
	# Supporting Code
	##################################################################
    #Initialize switch to send all packets to controller (lowest priority)
    # Adds a Table-miss flow entry (see page 8 of "Ryu: Using OpenFlow 1.3"
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print "Received Switch features"
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
	self.add_flow(datapath, 0, match, actions)
	#self._get_proactive_rules(datapath,parser,ofproto)

	def _add_proactive_flow(self,dp, parser, ofproto, fields,ops):
            actions = []
            if ops['op'] == 'drop':
                out_port = ofproto.OFPPC_NO_RECV
                actions.append(parser.OFPActionOutput(out_port))
            if ops == 'redir':
                out_port = ops['newport']
                actions.append(parser.OFPActionOutput(out_port))
                
	    match = parser.OFPMatch(eth_type=fields['eth_type'], 
					ip_proto=fields['proto'], 
					ipv4_src=fields['srcip'], 
                                        ipv4_dst=fields['dstip'],
                                        tcp_dst = fields['srctcp'])
	    
	    self.add_flow(dp, ops['priority'], match, actions)
    
    ########################################################################
    # Adds flow to the switch so future packets aren't sent to the cntrl 
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)    
       
    ########################################################################
    # Adds flow to the switch so future packets are not sent to the
    # controller (requires priority, idle_t, and hard_t)
    def add_timeFlow(self, dp, ops, match, actions):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
            
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        #fix switch mod to address 'idle_t'
        mod = parser.OFPFlowMod(datapath=dp,
                            priority=ops['priority'],
                            idle_timeout=ops['idle_t'],
                            hard_timeout=ops['hard_t'],
                            match=match, instructions=inst)
        dp.send_msg(mod) 
		
    ######################################################################## 
    #This decorator calls initial_event for packet arrivals
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def initial_event(self,ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        #Call <Pkt_Parse> to Build pkt object
        parsPkt = Pkt_Parse()
        pkt = parsPkt.handle_pkt(ev)
        
        # Call appropriate handler for arriving packets (add IPv6,DHCP,etc.)
        if pkt['udp'] != None:
            self.handle_udp(pkt)
        elif pkt['tcp'] != None:
            self.handle_tcp(pkt)
        elif pkt['icmp'] != None:
            self.handle_icmp(pkt)
        elif pkt['ip']!= None:
            self.handle_ip(pkt)
        elif pkt['arp']!=None:
            self.handle_arp(pkt)
        elif pkt['eth'] != None:
            self.handle_eth(pkt)
        else:
            print "Packet not identified"
            self.handle_unk(pkt)

    ############################################################    
    # Choose the field and ops having the highest priority and 
    # assert it.    
    def _build_FldOps(xfields,xops):
        priority = 0
        for x in len(xfields):
            if xfields[x]['priority'] > priority:
                fields,ops = xfields[x],xops[x]
        return fields,ops  
               
    ##############################################################        
    #Imeplement mac-learning (switch_mod13.py) for ethernet packets.  
    def _switch_mod(self, pkt, fields, ops):
        #Build match from pkt and fields
        match = self.pkt_match(fields)
		#Build actions from pkt and ops
        actions = self.pkt_action(pkt,ops,fields)                            
        priority = ops['priority']
        msg = fields['msg']                          
        parser, ofproto = fields['dp'].ofproto_parser, fields['ofproto']

        # install temporary flow to avoid future packet_in. 
        # idle_t and hard_t must be set to something. 
        if ops['idle_t'] or ops['hard_t']:
            if out_port != ofproto.OFPP_FLOOD:
                self.add_timeFlow(dp, ops, match, actions)

        # For ping and wget, data = None
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=fields['dp'],
                                  buffer_id=msg.buffer_id,
                                  in_port=fields['inport'],
                                  actions=actions, data=data)

        fields['dp'].send_msg(out)

    #############################################################
    #Use fields to build match 
    def pkt_match(self, fields):
        parser = fields['dp'].ofproto_parser
        if fields['srcip'] != None and fields['srcip'] != None:
            match = parser.OFPMatch(ipv4_src=fields['srcip'], 
										ipv4_dst = fields['dst_ip'])
        elif fields['srcip'] != None or fields['srcip'] != None:
            matchfield=fields['srcip'] if fields['srcip'] !=None else fields['dstip']
            match = parser.OFPMatch(ipv4_src=matchfield)
        elif fields['srcmac'] == None:
            match = parser.OFPMatch(in_port=fields['inport'])
        else:
            match = parser.OFPMatch(in_port=fields['inport'],
                                    eth_dst=fields['dstmac'])
        return match

    ###############################################################
    #Determine action to be taken on packet ops={'op':None, 'newport':None}
    #User can forward , drop, redirect, mirror, or craft packets. 
    def pkt_action(self,pkt,ops,fields):
        actions = []
        parser = fields['dp'].ofproto_parser
        if ops['op'] == 'fwd':
            out_port = self.switch.handle_pkt(pkt)
            actions.append(parser.OFPActionOutput(out_port))
        elif ops['op'] == 'drop':
            out_port = fields['ofproto'].OFPPC_NO_RECV
            actions.append(parser.OFPActionOutput(out_port))
        elif ops == 'redir':
            out_port = ops['newport']
            actions.append(parser.OFPActionOutput(out_port))
        elif ops['op'] == 'mir':
            out_port = self.switch.handle_pkt(pkt)
            actions.append(parser.OFPActionOutput(out_port))
            mir_port = ops['newport']
            actions.append(parser.OFPActionOutput(mir_port))
        elif ops['op'] == 'craft':
            #create and send new pkt due to craft trigger
            self._build_pkt(ops, fields) ##need to remove pkt ##########
            #Now drop the arrived packet
            out_port = fields['ofproto'].OFPPC_NO_RECV
            actions.append(parser.OFPActionOutput(out_port))
                                                
        return actions

    #More work is required here to implement active testing for NATs etc.
    # Note fields object must be completely rewritten for crafted packet
    # Probably need to make fields['ptype'] = ['arp', 'ipv4']
    def _build_pkt(self, fields):
        pkt_out = packet.Packet()
        pkt_out.add_protocol(ethernet.ethernet(ethertype=fields['ethtype'],
                                               dst=fields['dstmac'],
                                               src=fields['srcmac']))
        # Add if ARP is required                           
                            
        if 'arp' in fields['ptype']:
            pkt_out.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=fields['srcmac'],
                                 src_ip=fields['srcip'],
                                 dst_mac=fields['dstmac'],
                                 dst_ip=fields['dstip']))

        if ipv4 in fields['ptype']:
            pkt_out.add_protocol(ipv4.ipv4(dst=fields['dstip'],
                                 src=fields['srcip'],
                                 proto=fields['proto']))

        if 'icmp' in fields['ptype']:
            pkt_out.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                 code=icmp.ICMP_ECHO_REPLY_CODE,
                                 csum=0,
                                 data=fields['data']))
								 
        if 'tcp' in fields['ptype']:
            pkt_out.add_protocol(tcp.tcp(dst_port=fields['dstport'],
				bits=fields['bits'],option=fields['opt'],
                                #=str('\\x00' * 4),
                                src_port=fields['srcport']))
                             
        #pkt.add_protocol('\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\t\
            #\n\\x0b\\x0c\\r\\x0e\\x0f\\x10\\x11\\x12\\x13\\x14\\x15\\x16\
            #\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f')

        self._send_packet(fields['dp'], ops['newport'], pkt_out)
	
	#Receive crafted packet and send it to the switch
    def _send_packet(self, datapath, port, pkt_out):
        if port == None: print "Port not defined" 
        #This methods sends the crafted message to the switch
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt_out.serialize()
        self.logger.info("packet-out %s" % (pkt_out,))
        data = pkt_out.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
		
    #Clean up and disconnect ports. Controller going down  
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def handl_port_stat(self, ev):
        switch=SimpleSwitch()
        switch.port_status_handler(ev)


## Future work needed for ryuretic. Removing flows
##    def delete_flow(self, datapath):
##        ofproto = datapath.ofproto
##        parser = datapath.ofproto_parser
##        for dst in self.mac_to_port[datapath.id].keys():
##            match = parser.OFPMatch(eth_dst=dst)
##            mod = parser.OFPFlowMod(
##                datapath, command=ofproto.OFPFC_DELETE,
##                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
##                priority=1, match=match)
##        datapath.send_msg(mod)
"""Options for mod command:
OFPFC_ADD, OFPFC_MODIFY, OFPFC_DELETE, OFPFC_DELETE_STRICT
"""

"""
http://ryu-zhdoc.readthedocs.org/en/latest/ofproto_v1_3_ref.html
in_port	Integer 32bit	Switch input port
in_phy_port	Integer 32bit	Switch physical input port
metadata	Integer 64bit	Metadata passed between tables
eth_dst	MAC address	Ethernet destination address
eth_src	MAC address	Ethernet source address
eth_type	Integer 16bit	Ethernet frame type
vlan_vid	Integer 16bit	VLAN id
vlan_pcp	Integer 8bit	VLAN priority
ip_dscp	Integer 8bit	IP DSCP (6 bits in ToS field)
ip_ecn	Integer 8bit	IP ECN (2 bits in ToS field)
ip_proto	Integer 8bit	IP protocol
ipv4_src	IPv4 address	IPv4 source address
ipv4_dst	IPv4 address	IPv4 destination address
tcp_src	Integer 16bit	TCP source port
tcp_dst	Integer 16bit	TCP destination port
udp_src	Integer 16bit	UDP source port
udp_dst	Integer 16bit	UDP destination port
sctp_src	Integer 16bit	SCTP source port
sctp_dst	Integer 16bit	SCTP destination port
icmpv4_type	Integer 8bit	ICMP type
icmpv4_code	Integer 8bit	ICMP code
arp_op	Integer 16bit	ARP opcode
arp_spa	IPv4 address	ARP source IPv4 address
arp_tpa	IPv4 address	ARP target IPv4 address
arp_sha	MAC address	ARP source hardware address
arp_tha	MAC address	ARP target hardware address
ipv6_src	IPv6 address	IPv6 source address
ipv6_dst	IPv6 address	IPv6 destination address
ipv6_flabel	Integer 32bit	IPv6 Flow Label
icmpv6_type	Integer 8bit	ICMPv6 type
icmpv6_code	Integer 8bit	ICMPv6 code
ipv6_nd_target	IPv6 address	Target address for ND
ipv6_nd_sll	MAC address	Source link-layer for ND
ipv6_nd_tll	MAC address	Target link-layer for ND
mpls_label	Integer 32bit	MPLS label
mpls_tc	Integer 8bit	MPLS TC
mpls_bos	Integer 8bit	MPLS BoS bit
pbb_isid	Integer 24bit	PBB I-SID
tunnel_id	Integer 64bit	Logical Port Metadata
ipv6_exthdr	Integer 16bit	IPv6 Extension Header pseudo-field
pbb_uca	Integer 8bit	PBB UCA header field (EXT-256 Old version of ONF Extension)
tcp_flags	Integer 16bit	TCP flags (EXT-109 ONF Extension)
actset_output	Integer 32bit	Output port from action set metadata (EXT-233 ONF Extension)
"""
