"""
Base classes for test cases

Tests will usually inherit from one of these classes to have the controller
and/or dataplane automatically set up.
"""

import os
import logging
import unittest

import ptf
from ptf.base_tests import BaseTest
from ptf import config
import ptf.dataplane as dataplane
import ptf.testutils as testutils

################################################################
#
# Thrift interface base tests
#
################################################################

import switch_sai_thrift.switch_sai_rpc as switch_sai_rpc
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

class ThriftInterface(BaseTest):

    def setUp(self):
        BaseTest.setUp(self)

        # Set up thrift client and contact server
        test_params   = testutils.test_params_get()
	print "Test Params: ", test_params

        try:
          sai_thrift_ip = test_params['sai_thrift_ip']
        except KeyError:
          sai_thrift_ip = 'localhost'

        try:
          sai_thrift_port = test_params['sai_thrift_port']
        except KeyError:
          sai_thrift_port = 9092

	print "Connecting to %s:%d" % (sai_thrift_ip, sai_thrift_port)

        self.transport = TSocket.TSocket(sai_thrift_ip, sai_thrift_port)
        self.transport = TTransport.TBufferedTransport(self.transport)
        self.protocol = TBinaryProtocol.TBinaryProtocol(self.transport)

        self.client = switch_sai_rpc.Client(self.protocol)
        self.transport.open()

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        BaseTest.tearDown(self)
        self.transport.close()

class ThriftInterfaceDataPlane(ThriftInterface):
    """
    Root class that sets up the thrift interface and dataplane
    """
    def setUp(self):
        ThriftInterface.setUp(self)
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()
        if config["log_dir"] != None:
            filename = os.path.join(config["log_dir"], str(self)) + ".pcap"
            self.dataplane.start_pcap(filename)

    def tearDown(self):
        if config["log_dir"] != None:
            self.dataplane.stop_pcap()
        ThriftInterface.tearDown(self)
