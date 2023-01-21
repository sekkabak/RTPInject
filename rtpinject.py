#!/usr/bin/env python
#
# Copyright (c) 2007 iSEC Partners, Inc.

import Queue
import threading
import time
import sys
import os

import pygtk
pygtk.require("2.0")
import gtk
import gtk.gdk
import gtk.glade
import gobject

import dnet
import dpkt
import pcap

import utility
import listener
import injector

class RTPInject:
    """Application to perform RTP traffic sniffing and injection."""

    def __init__(self):
        """Construct a newly created RTPInject application object.

        Keyword Arguments:
            None
        """
        # The XML tree representing the GUI.
        self.widget_tree = gtk.glade.XML("rtpinject.glade")

        # A dictionary mapping emitted signals to callback functions
        signal_callback_dict = {
            "on_mainwin_delete_event" : self.program_exit_cb,
            "on_quit_menuitem_activate" : self.program_exit_cb,
            "on_dev_menuitem_activate" : self.select_network_dev_cb,
            "on_about_menuitem_activate" : self.show_aboutdialog_cb,
            "on_inject_button_clicked" : self.show_injectdialog_cb,
            "on_injectdialog_delete_event" : self.hide_injectdialog_cb,
            "on_inject_close_clicked" : self.hide_injectdialog_cb,
            "on_src_list_cursor_changed" : self.update_dst_list_view_cb
        }
        self.widget_tree.signal_autoconnect(signal_callback_dict)

    	# Create a list to store the network device names.
        dev_list = self.widget_tree.get_widget("dev_list")
        dev_list_renderer_text = gtk.CellRendererText()
        self.dev_list_store = gtk.ListStore(str)

        dev_list.set_model(self.dev_list_store)
        dev_list.pack_start(dev_list_renderer_text)
        dev_list.add_attribute(dev_list_renderer_text, "text", 0)

        # Enumerate the network devices.  If "eth0" is found, select it. Else select the first device.
        for iface in enumerate(dnet.intf()):
            self.dev_list_store.append([iface[1]["name"]])
            if iface[1]["name"] == "eth0":
                dev_list.set_active(iface[0])

        if dev_list.get_active() == -1:
            dev_list.set_active(0)

        self.iface = self.dev_list_store[dev_list.get_active()][0]

        # Create the list columns to display connection information.
        for column in [(0, "src_list", "Source"),
                       (0, "dst_list", "Destination"),
                       (1, "dst_list", "Voice Codec")]:
            list_column = gtk.TreeViewColumn(column[2])
            list_renderer_text = gtk.CellRendererText()
            list_column.pack_start(list_renderer_text)
            list_column.add_attribute(list_renderer_text, "text", column[0])
            list_column.set_sort_column_id(column[0])
            list_column.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
            list_column.set_fixed_width(150)

            self.widget_tree.get_widget(column[1]).append_column(list_column)

        # Create the backing list stores to maintain connection information.
        self.dst_list_store_dict = {}
        self.dst_list_store = gtk.ListStore(str, str, int)
        self.src_list_store = gtk.ListStore(str)

        for list_store in (self.src_list_store, self.dst_list_store):
            list_store.set_sort_func(0, utility.ip_address_sort)
            list_store.set_sort_column_id(0, gtk.SORT_ASCENDING)

        self.widget_tree.get_widget("src_list").set_model(self.src_list_store)
        self.widget_tree.get_widget("dst_list").set_model(self.dst_list_store)

        # The background thread that performs network injection.
        self.injector_notify = threading.Event()
        self.injector_queue = Queue.Queue()
        self.injector = None
        
        # The background thread that performs network sniffing.
        self.listener_notify = threading.Event()
        self.listener_queue = Queue.Queue()
        self.listener = listener.Listener(self.iface, self.src_list_store, self.dst_list_store_dict, self.listener_notify, self.listener_queue)
        self.listener.start()

        self.widget_tree.get_widget("mainwin").show_all()        

    
    def program_exit_cb(self, widget, *args, **kwargs):
        """Callback to be called upon program termination.
        
        Keyword Arguments:
            widget -- the widget that emitted the signal.
        """

        self.widget_tree.get_widget("mainwin").hide()
        
        self.listener_queue.put("exit")
        self.listener_notify.set()

        gtk.main_quit()        

    def select_network_dev_cb(self, widget, *args, **kwargs):
        """Callback to update the selected network device.
        
        Extends "threading.Thread.__init__"
        
        Keyword Arguments:
            widget -- the widget that emitted the signal.
        """

        device_dialog = self.widget_tree.get_widget("devicedialog")
        device_list = self.widget_tree.get_widget("dev_list")
        
        # If the user canceled the change, or did not change the selection.
        if device_dialog.run() != gtk.RESPONSE_ACCEPT or \
           self.iface == self.dev_list_store[device_list.get_active()][0]:
            for iface in enumerate(self.dev_list_store):
                if iface[1][0] == self.iface:
                    device_list.set_active(iface[0])

        # The user has changed the selection. Necessitates restarting the listening thread on the new device.
        else:
            self.iface = self.dev_list_store[device_list.get_active()][0]

            self.listener_queue.put("restart")
            self.listener_queue.put(self.iface)
            self.listener_notify.set()

        device_dialog.hide()

    def show_aboutdialog_cb(self, widget, *args, **kwargs):
        """Callback to show the about dialog.
        
        Keyword Arguments:
            widget -- the widget that emitted the signal.
        """

        about_dialog = self.widget_tree.get_widget("aboutdialog")
        about_dialog.run()
        about_dialog.hide()

    def show_injectdialog_cb(self, widget, *args, **kwargs):
        """Callback to be called when the injection thread needs to be started.
        
        Keyword Arguments:
            widget -- the widget that emitted the signal.
        """

        selected_src = self.widget_tree.get_widget("src_list").get_selection().get_selected()
        selected_dst = self.widget_tree.get_widget("dst_list").get_selection().get_selected()
        filename = self.widget_tree.get_widget("audio_filechooser").get_filename()

        # If not all of the required fields have been select, present a warning dialog.
        if not (selected_src[1] and selected_dst[1] and filename):
            error_dialog =  self.widget_tree.get_widget("errordialog")
            error_dialog.run()
            error_dialog.hide()

        else:
            src = selected_src[0][selected_src[1]][0]
            dst = selected_dst[0][selected_dst[1]][0]
            rtp_pt = selected_dst[0][selected_dst[1]][2]

            # Use a timeout function to periodically check the state of the injection thread.
            self.widget_tree.get_widget("injectdialog").show()
            gobject.timeout_add(100, self.is_injection_done)

            ###COMMENT ME TO UNDO TRANSCODING###
            if rtp_pt in (0, 3, 8):
                try:
                    import pygst
                    import transcoder

                    # You caught me doing a really bad thing.
                    # Or at least releasing the lock here does not make sense to me.
                    gtk.gdk.threads_leave()
                    trans = transcoder.Transcoder(filename, rtp_pt)
                    raw_audio = trans.run()
                    gtk.gdk.threads_enter()
                except ImportError:
                    raw_audio = open(filename, "rb").read()
                    raw_audio = [raw_audio[i:i + 160] for i in xrange(0, len(raw_audio), 160)]
            ###COMMENT ME TO UNDO TRANSCODING###
            else:
                raw_audio = open(filename, "rb").read()
                raw_audio = [raw_audio[i:i + 160] for i in xrange(0, len(raw_audio), 160)]

            self.injector = injector.Injector(self.iface, src, dst, rtp_pt, raw_audio, self.injector_notify, self.injector_queue)
            self.injector.start()

    def hide_injectdialog_cb(self, widget, *args, **kwargs):
        """Callback to be called after completion of the injection thread.
        
        Keyword Arguments:
            widget -- the widget that emitted the signal.
        """

        self.widget_tree.get_widget("injectdialog").hide()
        self.widget_tree.get_widget("inject_vbox").hide()
        self.widget_tree.get_widget("inject_progress").set_text("Injecting...")
        self.widget_tree.get_widget("inject_progress").set_fraction(0.1)
        return True
        
    def update_dst_list_view_cb(self, widget, *args, **kwargs):
        """Callback to be called when the selected source changes.
        
        Keyword Arguments:
            widget -- the widget that emitted the signal.
        """

        selected = widget.get_selection().get_selected()
        src = selected[0][selected[1]][0]
        self.widget_tree.get_widget("dst_list").set_model(self.dst_list_store_dict[src])

    def is_injection_done(self):
        """Periodically check the status of the active injection thread.
        
        Keyword Arguments:
            None.
        """
        if self.injector_notify.isSet():
            self.injector_notify.clear()
            
            # Injection has ended, adapt the dialog to indicate success/failure to the user.
            task = self.injector_queue.get()            
            _task_switch = {
                "timeout" : ("Injection Timed-Out!", 0.0),
                "success" : ("Injection Complete!", 1.0)
            }
            self.widget_tree.get_widget("inject_progress").set_text(_task_switch[task][0])
            self.widget_tree.get_widget("inject_progress").set_fraction(_task_switch[task][1])          
            self.widget_tree.get_widget("inject_vbox").show()
            return False

        # Injection is still in progress, therefore update the activity bar.
        else:
            self.widget_tree.get_widget("inject_progress").pulse()
            return True

    def main(self):
        gtk.main()
        
if __name__ == "__main__":
    if os.geteuid():
        print "RTPInject requires root privileges to run."
        sys.exit()  

    gobject.threads_init()
    gtk.gdk.threads_init()

    gtk.gdk.threads_enter()
    rtpinject = RTPInject()
    rtpinject.main()
    gtk.gdk.threads_leave()

