###############################################################
# Ryuretic: A Modular Framework for RYU
# Author Jacob Cox (jcox70@gatech.edu)
# NFG_13v2.py
# date 22 March 2016
################################################################
#Copyright (C) 1883 Thomas Edison - All Rights Reserved
#You may use, distribute and modify this code under the
#terms of the Ryuretic license, which includes citing this 
#work for ongoing projects. 
#You should have received a copy of the Ryuretic license with
#this file. If not, please visit : 
###############################################################
"""This library augments the coupler_13.py file
1) Ensure you have Ryu installed.
2) Save the following files to /home/ubuntu/ryu/ryu/app/
    a) coupler_13v2.py
    b) NFG_13v2.py
    c) Pkt_Parse13.py
    d) switch_mod13.py
2) In your controller terminal type: cd ryu
3) Enter PYTHONPATH=. ./bin/ryu-manager ryu/app/coupler_13.py
"""
###################################################
"""
Descriptions of library methods can be found at the bottom
of this file. 
"""
################################################
import logging
import struct
###########################################################
#[1] User can add additional libraries here
import csv
import sys


###########################################################
# Standard RYU calls
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, arp, ipv4, icmp, tcp, udp

#Network Flow Guard Class. User definitions are inserted below _init__
class NFG(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(NFG, self).__init__(*args, **kwargs)       
        ######################################################
        #[2] Declare any global variable here
        self.stat_Fw_tbl = {}
        self.ttl_list = {}
        self.fwTbl = {}
        self.flagTbl = {}
        self.nat_list = []
        self.tta = {}
        self.ttaAv = 0
        NAT = False
        self.init_FlagList()

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

    def default_Field_Ops(self,pkt):
        print "default Field_Ops called"
        fields = self._loadFields(pkt)
        ops = self._loadOps()
        return fields, ops
        
    ###########################################################
    # [3] Add user created methods below
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
                

    def craft_pkt(self, pkt):
		#fields = { add all require fields to build packet}
		pass
	
    def Multi_TTL(self, pkt):
        pass

    def Check_List(self, pkt):
       # print "\n*********Checking List*********"
        if self.fTbl.has_key(pkt['srcmac']):
            return self.fTbl[pkt['srcmac']]['op']
        else:
            return 'O'

    def init_FlagList(self):
        self.flagTbl['00:00:00:00:00:02']={'port':4, 'ip':'10.0.0.2',\
                                             'op':'fwd'}
        

    def add2FlagList(self, pkt, op):
        self.flagTbl[pkt['srcmac']]={'port':pkt['inport'], 'op':op}

    
    def displayTCPFields(self,pkt):
        a = pkt['bits']
        #if a != 16 and a != 17 and a != 24:
        if a not in [16,17,24]:
            print "*******************\n", a, '\n ', a,"\n*******************"
        print 'SEQ:', pkt['seq'], '\tACK:', pkt['ack'], \
          '\tSport:', pkt['srcport'], '\tDport:', pkt['dstport'], \
          '\tt_in:', pkt['t_in'], '\tFlags:', pkt['bits']

        if pkt['srcport'] == 80:
            distTuple = (pkt['srcip'],pkt['srcport'])
            locTuple = (pkt['dstip'],pkt['dstport'])
        else:
            locTuple = (pkt['srcip'],pkt['srcport'])
            disTuple = (pkt['dstip'],pkt['dstport'])

        keyFound = self.tta.has_key(locTuple)

        if keyFound and pkt['srcport'] != 80:
            if self.tta[locTuple]['check'] == False:
                ack = self.tta[locTuple]['ack']
                t_old = self.tta[locTuple]['t_in']
                if pkt['seq'] == ack:
                    print '******************\n',pkt['t_in'], ' - ', t_old
                    time2ack= pkt['t_in'] - t_old
                    self.tta[locTuple]['check'] = True
                    if self.ttaAv == 0:
                        self.ttaAv = time2ack
                    else:
                        self.ttaAv = (self.ttaAv + time2ack)/2
                    print 'TTA: ', time2ack, '\tTTA Av: ', \
                          self.ttaAv, '\n************'
        elif pkt['srcport'] == 80:
            if keyFound != True:
                self.tta[locTuple] = {'ack':pkt['ack'], 't_in':pkt['t_in'],\
                                  'check':False, 'cnt':1}   
            elif keyFound == True:
                count = self.tta[locTuple]['cnt']
                #print '*********Count: ', count
                if self.tta[locTuple]['check'] == True:
                    self.tta[locTuple] = {'ack':pkt['ack'], 't_in':pkt['t_in'],\
                                          'check':False, 'cnt':1}
                elif self.tta[locTuple]['check'] == False and count >= 1:
                    self.tta[locTuple]['cnt'] = count + 1
                    self.tta[locTuple]['t_in'] = pkt['t_in']
            else:
                print pkt['tcp']
                

        






















        
