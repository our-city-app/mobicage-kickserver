# -*- coding: utf-8 -*-
# Copyright 2017 Mobicage NV
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
# @@license_version:1.2@@

# Content of this file was based on example found at
# http://butterfat.net/wiki/Documentation/TwistedJabberComponentExample

from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.python import log
from twisted.web import resource
from twisted.web.http_headers import Headers
from twisted.words.protocols.jabber import component
from twisted.words.protocols.jabber.ijabber import IService
from twisted.words.xish import domish
from util import StringProducer, ReceiverProtocol, decrypt_from_appengine, encrypt_for_appengine
from zope.interface import implements
import base64
import json
import zlib
import urllib
import hashlib
from configuration import configuration, XMPP_SERVICE_NAME, HTTP_BASE_URL, HTTP_REPLACE_URL, HTTP_RPC_URL_PATH

IQ_COMMUNICATE = '/iq/communicate'

DEBUG = '/message/body'

class KickService(component.Service):
    implements(IService)
    apnsFactory = None

    def setApplePushNotificationServiceClientFactory(self, factory):
        self.apnsFactory = factory

    def setAppEngineSecret(self, secret):
        self.appengine_secret = secret

    def setHTTPAgent(self, agent):
        self.http_agent = agent

    def componentConnected(self, xmlstream):
        self.jabberId = xmlstream.authenticator.otherHost
        xmlstream.addObserver(IQ_COMMUNICATE, self.onCommunicate, 1)
        xmlstream.addObserver(DEBUG, self.onDebug, 1)

    def appengineIncomming(self, msg):
        recipient = msg['r']
        priority = msg['p']
        type_ = msg['t']
        log.msg("Incoming kick:\n%s" % msg)
        log.msg("User is online ==> pushing on xmpp channel")
        if "xmpp" in type_:
            # Send xmpp kick
            kick = domish.Element((None, 'message'))
            kick['to'] = recipient
            kick['from'] = 'kick.%s' % configuration[XMPP_SERVICE_NAME]
            kick['type'] = 'normal'
            kick['kid'] = msg['kid']
            kick.addElement('body', content='kickHTTP')
            self.send(kick)
        device = msg.get("d", None)
        app = msg.get("a", None)
        if self.apnsFactory and "apns" in type_ and device and app:
            log.msg("Kicking via apple push")
            device = device.decode("hex")
            message = base64.decodestring(msg["m"])
            if(len(message) > 256):
                log.err("Message cannot exceed 256 bytes!\nMessage: %s" % message.encode("hex"))
                return
            if(len(device) != 32):
                log.err("Device must be exactly 32 bytes: %s" % device)
                return
            self.apnsFactory.kick(app, device, message, priority)

    def onCommunicate(self, msg):
        log.msg("Incoming communication IQ")

        comm = msg.firstChildElement()
        user = str(msg['from']).split('/')[0]
        key = str(comm['key'])
        http_url = comm.hasAttribute('dest') and str(comm['dest']) or configuration[HTTP_BASE_URL]
        if http_url == configuration[HTTP_REPLACE_URL]:
            http_url = configuration[HTTP_BASE_URL]

        url = "%s%s" % (http_url, configuration[HTTP_RPC_URL_PATH])

        comm_body = unicode(comm).encode('utf-8')
        if comm_body.startswith("b64:"):
            comm_body = zlib.decompress(base64.b64decode(comm_body[4:]))

        log.msg("Sending call to %s: \n%s" % (url, comm_body))

        def _send_reply(type_, content):
            reply = domish.Element((None, 'iq'))
            reply['id'] = msg['id']
            reply['to'] = msg['from']
            reply['from'] = msg['to']
            reply['type'] = type_
            child = domish.Element((None, 'communicate'))
            child.addContent(content)
            try:
                if comm.hasAttribute('count'):
                    child['count'] = comm['count']
            except KeyError:
                pass
            reply.addChild(child)
            log.msg("Sending reply:\n%s" % reply.toXml())
            self.send(reply)

        def got_response(response):
            status_code = response.code
            finished = Deferred()
            response.deliverBody(ReceiverProtocol(finished))
            if status_code == 200:
                finished.addBoth(lambda body: _send_reply('result', body))
            else:
                finished.addBoth(lambda body: _send_reply('error', body))
            return finished

        def connection_failed(_):
            log.msg(str(_))
            _send_reply('error', "Connection to rogerthat app engine cloud was refused!")

        d = self.http_agent.request("POST", url, Headers({'Content-Type': ['application/json-rpc; charset="utf-8"'],
                    'X-MCTracker-Pass': [base64.b64encode(key)], 'X-MCTracker-User': [base64.b64encode(user)]}),
                    StringProducer(comm_body))

        d.addCallback(got_response)
        d.addErrback(connection_failed)

    def onDebug(self, msg):
        log.msg("Incoming message")

        jid = str(msg['to'])
        jid_parts = jid.split('/', 1)
        if len(jid_parts) == 2 and jid_parts[1].startswith("debug:"):
            body = msg.firstChildElement()
            body_content = unicode(body)
            if "[BRANDING]" in body_content:
                forward_jid = base64.b64decode(jid_parts[1][6:]).decode('utf-8')
                hash_ = hashlib.sha256()
                hash_.update(forward_jid)
                hash_.update(body_content)
                hash_.update(self.appengine_secret)
                data = urllib.urlencode((("user", forward_jid), ("message", body_content), ("hash", hash_.hexdigest())))
                log.msg(u"url: %s" % configuration[HTTP_BASE_URL])
                self.http_agent.request("POST", configuration[HTTP_BASE_URL] + '/unauthenticated/forward_log', Headers({'Content-Type': ['application/x-www-form-urlencoded']}),
                    StringProducer(data))
                log.msg(u"Forwarded debug message to %s" % forward_jid)

class KickResource(resource.Resource):
    isLeaf = True

    def __init__(self, kick_service, secret, serverTime):
        self.kick_service = kick_service
        self.secret = secret
        self.serverTime = serverTime

    def render_POST(self, request):
        challenge, data = decrypt_from_appengine(self.secret, request.content.read(), self.serverTime)
        reactor.callLater(0, self.kick_service.appengineIncomming, json.loads(data))  # @UndefinedVariable
        return encrypt_for_appengine(self.secret, challenge, 'OK')
