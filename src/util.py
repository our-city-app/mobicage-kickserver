# -*- coding: utf-8 -*-
# Copyright 2016 Mobicage NV
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
# @@license_version:1.1@@

from zope.interface import implements
from twisted.internet.defer import succeed, Deferred
from twisted.web.iweb import IBodyProducer, UNKNOWN_LENGTH
from twisted.internet import protocol, reactor
from twisted.web.http_headers import Headers
import struct
import hashlib
import uuid
from twisted.python import log
import time
from twisted.application import internet
from configuration import GAE_TRANSPORT_ENCRYPTED, HTTP_SERVER_TIME_URL, configuration
import base64
try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
try:
    from Crypto.Cipher import AES  # @UnresolvedImport
except ImportError:
    if configuration[GAE_TRANSPORT_ENCRYPTED] is True:
        raise
    else:
        pass

PADDING = "{"
BLOCK_SIZE = 32
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

class StringProducer(object):
    implements(IBodyProducer)

    def __init__(self, body):
        self.body = body
        self.length = len(body)

    def startProducing(self, consumer):
        consumer.write(self.body)
        return succeed(None)

    def pauseProducing(self):
        pass

    def stopProducing(self):
        pass

class ReceiverProtocol(protocol.Protocol):
    def __init__(self, finished):
        self.finished = finished
        self.buffer = StringIO()

    def dataReceived(self, bytes_):
        self.buffer.write(bytes_)

    def connectionLost(self, reason):
        self.finished.callback(self.buffer.getvalue())

class ProxyDeliveryProducer(protocol.Protocol):
    implements(IBodyProducer)

    def __init__(self, finished, length=UNKNOWN_LENGTH):
        self.length = length
        self.finished = finished
        self.consumer = None
        self.buffer = None
        self.done = Deferred()
        self.producing = False

    def dataReceived(self, bytes_):
        if self.producing:
            self.consumer.write(bytes_)
        else:
            if not self.buffer:
                self.buffer = StringIO()
            self.buffer.write(bytes_)

    def connectionLost(self, reason):
        print 'Finished receiving body: ', reason.getErrorMessage()
        self.finished.callback(None)
        if self.done:
            self.done.callback(None)

    def startProducing(self, consumer):
        self.producing = True
        self.consumer = consumer
        if self.buffer:
            consumer.write(self.buffer.getvalue())
            self.buffer = None
        return self.done

    def pauseProducing(self):
        self.producing = False

    def resumeProducing(self):
        self.producing = True
        if self.buffer:
            self.consumer.write(self.buffer.getvalue())
            self.buffer = None

    def stopProducing(self):
        self.done = None

def azzert(condition, error_message=None):
    if not condition:
        if error_message:
            raise AssertionError(error_message)
        else:
            raise AssertionError()

def decrypt_from_appengine(secret, data, serverTime):
    pack_format = 'bq32s'
    pack_size = struct.calcsize(pack_format)
    version, timestamp, signature = struct.unpack(pack_format, data[:pack_size])
    azzert(version == 1, "Version mismatch")
    if configuration[GAE_TRANSPORT_ENCRYPTED] is True:
        cipher = AES.new(hashlib.sha256(secret).digest())
        decrypted_data = cipher.decrypt(data[pack_size:])
    else:
        decrypted_data = data[pack_size:]
    pack_format = 'b36si'
    pack_size = struct.calcsize(pack_format)
    encrypted_version, challenge, data_size = struct.unpack(pack_format, decrypted_data[:pack_size])
    azzert(encrypted_version == version)
    d = hashlib.sha256(secret)
    d.update(decrypted_data[:pack_size + data_size])
    d.update(struct.pack("q", timestamp))
    d.update(challenge)
    calculated_signature = d.digest()
    azzert(signature == calculated_signature, "Signature could not be validated")
    serverTime.validate(timestamp)
    return challenge, decrypted_data[pack_size:pack_size + data_size]

def encrypt_for_appengine(secret, challenge, data):
    azzert(isinstance(data, str))
    azzert(isinstance(secret, str))
    azzert(isinstance(challenge, str))
    salt = str(uuid.uuid4())
    data = struct.pack('b36s36si', 1, challenge, salt, len(data)) + data
    if configuration[GAE_TRANSPORT_ENCRYPTED] is True:
        cipher = AES.new(hashlib.sha256(secret).digest())
        encrypted_data = cipher.encrypt(pad(data))
    else:
        encrypted_data = data
    return struct.pack('b36s', 1, salt) + encrypted_data

def decode_AES(secret, data):
    cipher = AES.new(hashlib.sha256(secret).digest())
    return cipher.decrypt(base64.b64decode(data)).rstrip(PADDING)

class ServerTime(object):

    def __init__(self, http_agent):
        self.set = False
        self.server_time_diff = 0
        self.http_agent = http_agent
        reactor.callLater(0, self.poll)  # @UndefinedVariable

    def poll(self):
        log.msg("Refreshing server time")
        reactor.callLater(600, self.poll)  # @UndefinedVariable
        self.poll_now()

    def poll_now(self):
        def got_response(response):
            status_code = response.code
            finished = Deferred()
            response.deliverBody(ReceiverProtocol(finished))
            def success(body):
                self.server_time_diff = int(time.time()) - struct.unpack('q', body)[0]
                self.set = True
                log.msg("Refreshed server time diff: %s" % self.server_time_diff)
            def failure(body):
                log.msg("Failed to refresh server time: %s" % body)
            if status_code == 200:
                finished.addCallback(success)
            else:
                finished.addCallback(failure)
            return finished

        def connection_failed(_):
            log.msg("Failed to refresh server time: Connection to appengine failed.")

        d = self.http_agent.request("GET", configuration[HTTP_SERVER_TIME_URL], Headers({}), None)

        d.addCallback(got_response)
        d.addErrback(connection_failed)

    def validate(self, timestamp):
        if not self.set:
            return
        if abs(int(time.time()) - self.server_time_diff - timestamp) > 30:
            self.poll_now()
            raise ValueError("Timestamp diff to large!")

class HighLoadTCPServer(internet.TCPServer):  # @UndefinedVariable

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, request_queue_size=5):
        self.request_queue_size = request_queue_size
        internet.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)  # @UndefinedVariable
