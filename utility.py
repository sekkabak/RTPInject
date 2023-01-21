#!/usr/bin/env python
#
# Copyright (c) 2007 iSEC Partners, Inc.

import struct

import pygtk
pygtk.require("2.0")
import gtk

import dnet


def ip_address_sort(tree_model, iter1, iter2):
    # Convert from a string to a packed binary string to an integer suitable for sorting.
    value1 = struct.unpack("!I", dnet.ip_aton(tree_model[iter1][0]))[0]
    value2 = struct.unpack("!I", dnet.ip_aton(tree_model[iter2][0]))[0]

    if value1 < value2:
        return -1
    else:
        return 1

