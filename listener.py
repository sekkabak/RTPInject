#!/usr/bin/env python
#
# Copyright (c) 2007 iSEC Partners, Inc.

import Queue
import threading
import time

import pygtk
pygtk.require("2.0")
import gtk

import dnet
import dpkt
import pcap

import utility


_rtp_codecs = {
    0 : "PCM-U, 8kHz",
    3 : "GSM, 8kHz",
    4 : "G.723, 8kHz",
    5 : "DVI4, 8kHz",
    6 : "DVI4, 16kHz",
    7 : "LPC, 8kHz",
    8 : "PCM-A, 8kHz",
    9 : "G.722, 8kHz",
    10 : "L16, 44.1kHz (Stereo)",
    11 : "L16, 44.1kHz (Mono)",
    12 : "QCELP, 8kHz",
    13 : "CN, 8kHz",
    14 : "MPA, 90kHz",
    15 : "G.728, 8kHz",
    16 : "DVI4, 11.025kHz",
    17 : "DVI4, 22.05kHz",
    18 : "G.729, 8kHz",
    33 : "MP2T, 90kHz",
    97 : "Speex",
    110 : "Speex"
}


class Listener(threading.Thread):
    """Sniffs network traffic to identify and enumerate RTP streams."""

    def __init__(self, iface, src_list, dst_list_dict, notify_event, queue):
        """Construct a newly created Listener.
        
        Extends "threading.Thread.__init__"
        
        Keyword Arguments:
            iface -- the network interface to listen on
            src_list -- a GtkListStore that contains observed source hosts
            dst_list_dict -- a dictionary of GtkListStore that contain observed destination hosts
        """
        
        threading.Thread.__init__(self)

        self.iface = iface
        self.src_list = src_list
        self.dst_list_dict = dst_list_dict
        self.ts_dict = {}

        self.notify_event = notify_event
        self.queue = queue
        
    def run(self):
        """Execute the Listener in a separate thread.
        
        Overrides "threading.Thread.run()"
        """

        while True:
            # Set the filter in order to limit captured packets to RTPv2 traffic.
            # RTPv2 traffic is found in UDP packets and is indicated by a magic byte (0x80).
            pkt_capture = pcap.pcap(self.iface)
            pkt_capture.setfilter("udp and ether[42]==128")
            pkt_capture.setnonblock()

            # Capture and parse packets until notified to stop.
            # Either the program is exiting, or the network device has changed.
            while not self.notify_event.isSet():
                 pkt_capture.dispatch(0, self.parse_packet)
                 self.expire_old_connections()

            self.notify_event.clear()
            
            task = self.queue.get()
            if task == "restart":
                self.iface = self.queue.get()             
            elif task == "exit":
                break

    def parse_packet(self, ts, pkt):
        """Parse captured packets and store connection state between RTP endpoints.
        
        Keyword Arguments:
            ts -- the time when the packet was captured
            pkt -- a packed binary string as captured by pcap
        """

        eth_frame = dpkt.ethernet.Ethernet(pkt)
        eth_frame.data.data.data = dpkt.rtp.RTP(eth_frame.data.data.data)
        
        ip_hdr = eth_frame.data
        udp_hdr = ip_hdr.data
        rtp_hdr = udp_hdr.data

        src = dnet.ip_ntoa(ip_hdr.src)
        dst = dnet.ip_ntoa(ip_hdr.dst)

        gtk.gdk.threads_enter()
        if (src, dst) not in self.ts_dict:
            # Store the timestamp of the last seen packet. Used to keep the lists up-to-date.
            self.ts_dict[(src, dst)] = (0, ts)

            # Create a list based off the source for destinations 
            if src not in self.dst_list_dict:
                self.dst_list_dict[src] = gtk.ListStore(str, str, int)
                self.dst_list_dict[src].set_sort_func(0, utility.ip_address_sort)
                self.dst_list_dict[src].set_sort_column_id(0, gtk.SORT_ASCENDING)
        
        elif self.ts_dict[(src, dst)][0] > 10 and rtp_hdr.pt in _rtp_codecs:
            # Store the source in a list.
            if src not in (row[0] for row in self.src_list):
                self.src_list.append([src])

            # Store the destination in a list based off the source.
            if dst not in (row[0] for row in self.dst_list_dict[src]):
                self.dst_list_dict[src].append([dst, _rtp_codecs[rtp_hdr.pt], rtp_hdr.pt])

        gtk.gdk.threads_leave()

        self.ts_dict[(src, dst)] = (self.ts_dict[(src, dst)][0] + 1, ts)


    def expire_old_connections(self):
        """Expire old and non-existant connections and remove stored connection state.
        
        Keyword Arguments:
            None
        """
        now = time.time()
        to_delete = []        

        for (src, dst), (count, ts) in self.ts_dict.iteritems():
            if now > (ts + 10):
                # Note the host pairs that need to be removed. Wait until after iteration to remove them.
                to_delete.append((src, dst))

                if count > 10:
                    gtk.gdk.threads_enter()

                    # Remove the destination from the store based of the source.
                    for row in enumerate(self.dst_list_dict[src]):
                        if row[1][0] == dst:
                            del self.dst_list_dict[src][row[0]]
                            break

                    # Remove the source from the store.                    
                    if len(self.dst_list_dict[src]) == 0:
                        for row in enumerate(self.src_list):
                            if row[1][0] == src:
                                del self.src_list[row[0]]
                                break
            
                    gtk.gdk.threads_leave()

        # Clear the timestamp dictionary of expired host pairs.
        for pair in to_delete:
            del self.ts_dict[pair]

