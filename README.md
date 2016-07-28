# Ryuretic: A Modular Framework for RYU

Ryuretic is a modular, SDN-based, framework for network application development. It allows network operators to work directly with packet
header fields at various levels of the OSI model, including L2, L3, L4, and shim layer protocols. The user simply chooses match fields and selects provided operations to update the OpenFlow switch.


To better demonstrate Ryuretic as an enabler for security applications, we examine a few, simple use cases for this framework. First we will consider the implementation of a stateful firewall. Then we will implement a solution for detecting NAT devices on a network. In Ryuretic, the user must ensure that the switch module (switch mod) and that the NFG and Pkt parser libraries are loaded to the same (ryu/app/) director as the coupler module. Afterwards, the coupler is called from the ryu directory as follows:


PYTHONPATH=. ./bin/ryu-manager ryu/app/Ryuretic_Intf.py


This will activate the coupler and it will call the required libraries and instantiate any required modules for our network
applications. All changes are made in the Ryuretic_Intf.py file. 

Visit Ryuretic Labs for some hands on exercises using this framework. [Ryuretic Labs](https://github.com/Ryuretic/RyureticLabs)
