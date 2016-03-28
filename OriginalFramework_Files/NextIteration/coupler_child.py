from coupler_parent import coupler

class NFG_coupler(coupler):
    def __init__(self, *args, **kwargs):
        super(NFG_coupler, self).__init__(*args, **kwargs)

        # Variables.
        self.stat_Fw_tbl = {}

    def get_proactive_rules(self, dp, parser, ofproto):
        # return None, None
        fields, ops = self.honeypot(dp, parser, ofproto)
        return fields, ops


    def handle_eth(self,pkt):
        print "handle eth"
        fields, ops = self.default_Field_Ops(pkt)
        self.install_field_ops(pkt,fields,ops)

    def handle_arp(self,pkt):
        print "handle ARP"
        print pkt
        fields, ops = self.default_Field_Ops(pkt)
        self.install_field_ops(pkt, fields, ops)
		
    def handle_ip(self,pkt):
        print "handle ip"
	#fields, ops = self.default_Field_Ops(pkt)
        fields, ops = self.Stateful_FW(pkt)
	##############################################################
        #Determine highest priority fields and ops pair, if needed
        #xfields = [fields0, fields1, fields2]
        #xops = [ops0, ops1, ops2]
        #fields,ops = self._build_FldOps(xfields,xops)
	##############################################################
        
        self.install_field_ops(pkt,fields,ops)

    def handle_icmp(self,pkt):
        print "handle icmp"
        fields, ops = self.default_Field_Ops(pkt)
        self.install_field_ops(pkt, fields, ops)

    def handle_tcp(self,pkt):
        print "handle tcp"
        #fields, ops = self.default_Field_Ops(pkt)
        fields,ops = self.Simple_FW(pkt)
        #fields, ops = self.TTL_Check(pkt)
        # users can also call modules with no return
        self.install_field_ops(pkt, fields, ops)

    def handle_udp(self,pkt):
        print "handle udp"
        fields, ops = self.default_Field_Ops(pkt)
        #fields, ops = self.TTL_Check(pkt)
        self.install_field_ops(pkt, fields, ops)

    def handle_unk(self,pkt):
        print "handl unk"
        fields, ops = self.default_Field_Ops(pkt)
        self.install_field_ops(pkt, fields, ops)


    # The following are from the old NFG file.
    def default_Field_Ops(self,pkt):
        print "default Field_Ops called"
        fields = _loadFields(pkt)
        ops = _loadOps()
        return fields, ops

        def _loadFields(self,pkt):
            #keys specifies match fields for action. Default is inport and
            #srcmac
            print "loading fields"
            fields = {'keys':['inport','srcmac'],'ptype':[], 
                      'dp':pkt['dp'], 'ofproto':pkt['ofproto'], 
                      'msg':pkt['msg'], 'inport':pkt['inport'], 
                      'srcmac':pkt['srcmac'], 'ethtype':None, 
                      'dstmac':None, 'srcip':None, 'proto':None, 
                      'dstip':None, 'srcport':None, 'dstport':None}
            return fields
    
        def _loadOps(self):
            print "Loading ops"
            #Specifies the timeouts, priority, operation and outport
            #options for op: 'fwd','drop', 'mir', 'redir', 'craft'
            ops = {'hard_t':None, 'idle_t':None, 'priority':0, \
                   'op':'fwd', 'newport':None}
            return ops

    def Simple_FW(self,pkt):
        fields, ops = self.default_Field_Ops(pkt)
        #blocking w3cschools and facebook
        if pkt['dstip'] in ['141.8.225.80', '173.252.120.68']:
            print "W3Cschools or Facebook is not allowed"
            #tell controller to drop pkts destined for dstip
            fields['keys'],fields['dstip'] = ['dstip'],pkt['dstip']
            ops['priority'],ops['op'] = 100,'drop'
        return fields, ops
        
    #Block IP packets with decremented TTL
    def TTL_Check(self, pkt):
        print "TTL Check called"
        fields, ops = self.default_Field_Ops(pkt)
       # print "\n*******pkt_in_handler - TTL_Check********"
        if pkt['ttl'] == 63 or pkt['ttl'] == 127:
            print "XxXxXx  NAT Detected  xXxXxX"
            #drop all packets from port with TTL decrement
            fields['keys'] = ['inport']
            fields['inport'] = pkt['inport']
            ops['priority'] = 100
            ops['op']='drop'
        return fields, ops

    def Stateful_FW(self,pkt):
        fields, ops = self.default_Field_Ops(pkt)
        if pkt['input'] in [1,2,3,4,5,6,7,8]:
            if self.stat_Fw_tbl.has_key(pkt['srcip']):
                if len(self.stat_Fw_tbl[pkt['srcip']]['dstip']) > 4:
                    self.stat_Fw_tbl[pkt['srcip']]['dstip'].pop(3)
                self.self.stat_Fw_tbl[pkt['srcip']]['dstip'].append(pkt['dstip'])
            else:
                self.stat_Fw_tbl[pkt['srcip']]={'dstip':[pkt['dstip']]}
            return fields, ops
        else:
            if self.stat_Fw_tbl.has_key(pkt['dstip']):
                if pkt['srcip'] in stat_Fw_tbl[pkt['dstip']]['dstip']:
                    return fields, ops
                else:
                    fields['keys'] = ['srcip','dstip']
                    fields['srcip'] = pkt['srcip']
                    fields['dstip'] = pkt['dstip']
                    ops['priority'] = 100
                    ops['op']='drop'
                    ops['hard_t'] = 20
                    ops['idle_t'] = 4
                    return fields, ops

    def honeypot(self, dp, parser, ofproto):
        # This should install proactive rules that mirrors data from a 
        # honeypot system
        fields, ops = {}, {}
        fields['dp'] = dp
        fields['keys'] = ['dstip']
        fields['srcip'] = '10.0.0.42'
        ops['priority'] = 100
        ops['op'] = 'mir'
        ops['newport'] = 1

        return fields, ops

    def 
