# -*- coding: utf-8 -*-
# Copyright 2019 Green Valley Belgium NV
# NOTICE: THIS FILE HAS BEEN MODIFIED BY GREEN VALLEY BELGIUM NV IN ACCORDANCE WITH THE APACHE LICENSE VERSION 2.0
# Copyright 2018 GIG Technology NV
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# @@license_version:1.6@@

from binascii import b2a_hex
import json
import os
import socket
import struct
import time
from urllib import urlencode
import urllib

from OpenSSL import SSL, crypto  # @UnresolvedImport
from twisted.application import internet
from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.protocol import Protocol, ReconnectingClientFactory, ClientFactory
from twisted.internet.ssl import ClientContextFactory
from twisted.python import log
from twisted.web.http_headers import Headers

from configuration import configuration, HTTP_GET_APPLE_PUSH_CERTS, APPLE_PUSH_RECONNECT_INTERVAL, \
    APPLE_CERT_AND_KEY_ENCRYPTION_SECRET, APPLE_PUSH_FEEDBACK_POLL_INTERVAL, HTTP_BASE_URL
from util import ReceiverProtocol, decrypt_from_appengine, decode_AES


PID = os.getpid()
TIMEOUT = 30 * 60

class ApplePushConnectionFactory(object):

    def __init__(self, http_agent, appengine_secret, server_time, application):
        self.http_agent = http_agent
        self.appengine_secret = appengine_secret
        self.server_time = server_time
        self.connections = dict()
        self.stash = dict()
        self.application = application

    def kick(self, app, device, message, priority):
        if app in self.connections:
            # Yihaa we already have a running connection for this app to apple push services
            self.connections[app].kick(device, message, priority)
            return
        # Right, let's get the details from the app engine to make a correct connection to apple push services for
        # this app
        app_stash = self.stash.get(app)
        if app_stash is None:
            self.stash[app] = dict([(device, message)])
        else:
            app_stash[device] = message
            log.msg("kick has been added to stash (size = %s)" % len(app_stash))
            return

        def get_cert_and_key_from_server():
            url = "%s?%s" % (configuration[HTTP_GET_APPLE_PUSH_CERTS], urlencode(dict(id=app)))

            def handle_response(status_code, body):
                try:
                    if status_code == 200:
                        # Decrypt response from app engine
                        _, decrypted_data = decrypt_from_appengine(self.appengine_secret, body, self.server_time)
                        data = json.loads(decrypted_data)
                        # Decrypt with special cert and key protection secret
                        cert = decode_AES(configuration[APPLE_CERT_AND_KEY_ENCRYPTION_SECRET], data["cert"])
                        key = decode_AES(configuration[APPLE_CERT_AND_KEY_ENCRYPTION_SECRET], data["key"])
                        valid_until = data["valid_until"]
                        valid_until_str = time.ctime(valid_until)
                        log.msg("Apple push cert of %s is valid until %s" % (app, valid_until_str))
                        now = int(time.time())
                        if valid_until < now:
                            raise Exception("Downloaded certificate is not valid. "
                                            "It is valid until %s." % valid_until_str)
                        seconds_until_renew = valid_until - now - 2 * 3600 * 24
                        if seconds_until_renew < 0:
                            raise Exception("Downloaded certificate will be invalid within 2 days. "
                                            "It is valid until %s." % valid_until_str)

                        # Start the connections to apple
                        feedBackFactory = ApplePushFeedbackFactory()
                        feedBackFactory.setHTTPAgent(self.http_agent)
                        feedBackFactory.setAppEngineSecret(self.appengine_secret)
                        pushFactory = ApplePushNotificationServiceClientFactory()
                        pushFactory.maxDelay = configuration[APPLE_PUSH_RECONNECT_INTERVAL]
                        pushService = internet.SSLClient('gateway.push.apple.com', 2195, pushFactory, ApplePushNotificationServiceClientContextFactory(cert, key))  # @UndefinedVariable
                        pushService.setServiceParent(self.application)
                        feedbackService = internet.SSLClient('feedback.push.apple.com', 2196, feedBackFactory, ApplePushNotificationServiceClientContextFactory(cert, key)).setServiceParent(self.application)  # @UndefinedVariable
                        # Empty the stash for this app
                        app_stash = self.stash[app]
                        for device, message in app_stash.items():
                            pushFactory.kick(device, message, priority)
                            del app_stash[device]
                        del self.stash[app]
                        # Store the connections to apple push for this app
                        self.connections[app] = pushFactory
                        # Stop using these certificates two days before they expire.
                        def autoRenewCert():
                            log.msg("Stopping connections for app %s because certificates are almost outdated" % app)
                            pushFactory.stopTrying()
                            pushService.stopService()
                            feedBackFactory.stop()
                            feedbackService.stopService()
                            del self.connections[app]
                        reactor.callLater(seconds_until_renew, autoRenewCert)  # @UndefinedVariable
                    else:
                        log.msg("Failed to retrieve cert and key from app engine: Got server error from %s.\n"
                                "Will retry in 10 seconds.\nError: \n%s" % (url, body))
                        reactor.callLater(10, get_cert_and_key_from_server)  # @UndefinedVariable
                except:
                    log.err()
                    raise

            def response(response):
                finished = Deferred()
                response.deliverBody(ReceiverProtocol(finished))
                finished.addBoth(lambda body: handle_response(response.code, body))
                return finished

            def connection_failed(buffer_):
                log.msg("Failed to retrieve cert and key from app engine: Could not establish connection to %s.\n"
                        "Will retry in 10 seconds." % url)
                reactor.callLater(10, get_cert_and_key_from_server)  # @UndefinedVariable

            d = self.http_agent.request("GET", url, Headers({'X-Nuntiuz-Secret': [self.appengine_secret]}))
            d.addCallback(response)
            d.addErrback(connection_failed)

        get_cert_and_key_from_server()

class ApplePushNotificationServiceClientContextFactory(ClientContextFactory):

    def __init__(self, certificate, key):
        self.ctx = SSL.Context(SSL.TLSv1_METHOD)
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate)
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, key)
        self.ctx.use_certificate(certificate)
        self.ctx.use_privatekey(key)

    def getContext(self):
        return self.ctx

class ApplePushNotificationServiceProtocol(Protocol):

    def __init__(self):
        self.counter = 0
        self.buf = ""
        self.connection_established = False

    def nextId(self):
        self.counter += 1
        return self.counter & 0xffff

    def connectionMade(self):
        log.msg ("Successfully connected with Apple Push Notification Service.")
        self.transport.setTcpKeepAlive(True)
        self.transport.setTcpNoDelay(True)
        self.transport.socket.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 30)  # @UndefinedVariable
        self.transport.socket.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 30)  # @UndefinedVariable
        self.transport.socket.setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, 1)  # @UndefinedVariable
        self.factory.connectionMade(self)
        self.connection_established = True
        def recycle():
            log.msg ("Recycling connection with Apple Push Notification Service.")
            if self.connection_established:
                self.transport.loseConnection()
                log.msg ("Closed connection to Apple Push Notification Service.")
            else:
                log.msg("Connection to Apple Push Notification Service.")
        # reactor.callLater(TIMEOUT, recycle)

    def connectionLost(self, reason):
        self.connection_established = False

    def dataReceived(self, data):
        log.msg("<=== APNS %s" % data.encode("hex"))
        self.buf += data
        while len(self.buf) > 5:
            brokske = self.buf[0:6]
            self.buf = self.buf[6:]
            _, status, pid, id_ = struct.unpack("!ccHH", brokske)
            log.msg("Received status %s for %s-%s" % (status, pid, id_))

    def kick(self, device, message, priority):
        id_ = self.nextId()
        log.msg("Sending iOs push notification with id: %s-%s\ncontent: %s" % (PID, id_, message))
        expiry = int(time.time()) + 24 * 3600 * 30
        # |COMMAND|FRAME-LEN|{token}|{payload}|{id:4}|{expiry:4}|{priority:1}
        frame_len = 3 * 5 + len(device) + len(message) + 4 + 4 + 1  # 5 items, each 3 bytes prefix, then each item length
        buf = struct.pack("!BIBH%dsBH%dsBHIBHIBHB" % (len(device), len(message)), 2, frame_len,
                1, len(device), device,
                2, len(message), message,
                3, 4, id_,
                4, 4, expiry,
                5, 1, priority)

        log.msg("===> APNS %s" % (buf.encode("hex")))
        self.transport.write(buf)

class ApplePushNotificationServiceClientFactory(ReconnectingClientFactory):
    protocol = ApplePushNotificationServiceProtocol

    def __init__(self):
        self.protinst = None
        self.buf = list()

    def startedConnecting(self, connector):
        log.msg("Initiating connection with Apple Push Notification Service.")

    def clientConnectionLost(self, connector, reason):
        log.msg("Lost connection with Apple Push Notification Service. Reason: %s" % reason)
        self.protinst = None
        ReconnectingClientFactory.clientConnectionLost(self, connector, reason)

    def clientConnectionFailed(self, connector, reason):
        log.msg("Initiating connection with Apple Push Notification Service. Reason: %s" % reason)
        ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)

    def connectionMade(self, protocol):
        self.protinst = protocol
        while self.protinst and self.buf:
            device, message, priority = self.buf.pop(0)
            self.protinst.kick(device, message, priority)

    def kick(self, device, message, priority):
        if self.protinst:
            self.protinst.kick(device, message, priority)
        else:
            self.buf.append((device, message, priority))

class ApplePushFeedbackProtocol(Protocol):

    def __init__(self):
        self.buf = ""

    def connectionMade(self):
        log.msg("Successfully connected with Apple Push Feedback Service.")

    def dataReceived(self, data):
        log.msg("<=== APFS %s" % data.encode("hex"))
        self.buf += data
        while len(self.buf) > 37:
            brokske = self.buf[0:38]
            self.buf = self.buf[38:]
            try:
                time, length, device = struct.unpack("!LH32s", brokske)
                self.factory.onFeedBack(time, b2a_hex(device[0:length]))
            except struct.error:
                log.err("Could not decode incomming data from feedback service %s" % data.encode("hex"))

class ApplePushFeedbackFactory(ClientFactory):
    protocol = ApplePushFeedbackProtocol
    go = True

    def stop(self):
        self.go = False

    def setAppEngineSecret(self, secret):
        self.appengine_secret = secret

    def setHTTPAgent(self, agent):
        self.http_agent = agent

    def onFeedBack(self, time, device):
        def got_response(response):
            status_code = response.code
            finished = Deferred()
            response.deliverBody(ReceiverProtocol(finished))
            if status_code == 200:
                finished.addBoth(lambda body: log.msg("Posted apple push feedback to appengine:\nstatus: %s\nbody:\n%s" % (status_code, body)))
            else:
                finished.addBoth(lambda body: log.err("Error posting apple push feedback to appengine:\nstatus: %s\nbody:\n%s" % (status_code, body)))
            return finished

        def connection_failed(_):
            log.err("Could not post back result to appengine (connection refused)!\n")

        log.msg("Posting apple push feedback to appengine:\n\ttime: %(time)s\n\tdevice: %(device)s" % locals())
        url = configuration[HTTP_BASE_URL] + "/api/1/apple_feedback?" + urllib.urlencode((('time', time), ('device', device)))

        d = self.http_agent.request("GET", url, Headers({'X-Nuntiuz-Secret': [self.appengine_secret]}), None)
        d.addCallback(got_response)
        d.addErrback(connection_failed)

    def startedConnecting(self, connector):
        log.msg("Initiating connection with Apple Push Feedback Service.")

    def clientConnectionLost(self, connector, reason):
        log.msg("Lost connection with Apple Push Feedback Service. Reason: %s" % reason)
        if self.go:
            self.call = reactor.callLater(configuration[APPLE_PUSH_FEEDBACK_POLL_INTERVAL], connector.connect)  # @UndefinedVariable


    def clientConnectionFailed(self, connector, reason):
        log.err("Initiating connection with Apple Push Feedback Service." % reason)
        if self.go:
            self.call = reactor.callLater(configuration[APPLE_PUSH_FEEDBACK_POLL_INTERVAL], connector.connect)  # @UndefinedVariable
