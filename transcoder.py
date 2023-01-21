#!/usr/bin/env python
#
# Copyright (c) 2007 iSEC Partners, Inc.

import pygst
pygst.require("0.10")
import gst


_rtp_encoders = {
    0 : ("mulawenc", "audio/x-mulaw"),
    3 : ("gsmenc", "audio/x-gsm"),
    8 : ("alawenc", "audio/x-alaw")
}


class Transcoder:
    """Transcodes a specified audio file to one of PCM-U, PCM-A, or GSM audio format."""
    def __init__(self, filename, rtp_pt):
        """Construct a newly created Transcoder.
        
        Keyword Arguments:
            filename -- the name of the file to transcode
            rtp_pt -- the RTP payload type of the target codec (PCM-U, PCM-A, or GSM)
        """

        self.full_audio = ""

        # The pipeline and buses that perform automagic
        self.pipeline = gst.Pipeline("automatic-rtp-transcode")
        self.bus = self.pipeline.get_bus()
        self.bus.add_signal_watch()

        # Create filter elements
        self.file_src = gst.element_factory_make("filesrc")
        self.decode_bin = gst.element_factory_make("decodebin2")
        self.audio_convert = gst.element_factory_make("audioconvert")
        self.audio_resample = gst.element_factory_make("audioresample")
        self.caps_filter = gst.element_factory_make("capsfilter")
        self.encoder = gst.element_factory_make(_rtp_encoders[rtp_pt][0])
        self.fake_sink = gst.element_factory_make("fakesink")

        # Connect signals to their respective callbacks.
        self.decode_bin.connect("new-decoded-pad", self.on_new_decoded_pad)
        self.fake_sink.connect("handoff", self.on_fake_sink_handoff)

        # Set element properties so that stuff works awesome.
        self.file_src.set_property("location", filename)
        self.fake_sink.set_property("signal-handoffs", True)
        self.caps_filter.set_property("caps", gst.Caps("audio/x-raw-int, rate=8000, channels=1"))

        # Add some elements to pipeline and link them together.
        self.pipeline.add(self.file_src, self.decode_bin, self.audio_convert)
        self.pipeline.add(self.audio_resample, self.encoder, self.caps_filter, self.fake_sink)
        gst.element_link_many(self.file_src, self.decode_bin)
        gst.element_link_many(self.audio_convert, self.audio_resample, self.caps_filter, self.encoder, self.fake_sink)

    def run(self):
        """Run the pipeline to completion.
        
        Keyword Arguments:
            None
        """

        self.pipeline.set_state(gst.STATE_PLAYING)       
        self.bus.poll(gst.MESSAGE_EOS, -1)

        return [self.full_audio[i:i + 160] for i in xrange(0, len(self.full_audio), 160)]

    def on_fake_sink_handoff(self, gst_element, gst_buffer, gst_pad, *args, **kwargs):
        """Handoff callback used to read the contents of the GstBuffer.
        
        Keyword Arguments:
            gst_element -- the element that this callback is associated with (e.g. 'fakesink')
            gst_buffer -- the GstBuffer object that holds the raw data
            gst_pad -- the GstPad object that the buffer arrived through
        """

        self.full_audio += gst_buffer.data

    def on_new_decoded_pad(self, gst_element, gst_pad, *args, **kwargs):
        """Callback used to finish linking the pipeline together.
        
        This is needed because of the dynamic nature of 'decodebin2.'
        
        Keyword Arguments:
            gdt_element -- the element that the callback is associated with (e.g. 'decodebin2')
            gst_pad -- the newly created pad that needs to be linked into the pipeline
        """
        name = gst_pad.get_caps()[0].get_name()
        if name == "audio/x-raw-float" or name == "audio/x-raw-int":
            if not self.audio_convert.get_pad("sink").is_linked(): # Only link once
                gst_pad.link(self.audio_convert.get_pad("sink"))

