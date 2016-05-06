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

from twisted.python import log
from twisted.web import resource
from twisted.words.protocols.jabber import component
from twisted.words.protocols.jabber.ijabber import IService
from twisted.words.xish import domish
from zope.interface import implements
from twisted.web.http_headers import Headers
from util import StringProducer, ProxyDeliveryProducer, ReceiverProtocol, decrypt_from_appengine, encrypt_for_appengine
from twisted.internet.defer import Deferred
import base64
from twisted.internet.utils import getProcessOutputAndValue
import os
from twisted.web.server import NOT_DONE_YET
import json
from twisted.internet import reactor, threads
import struct
import urllib
from configuration import configuration, HTTP_CALLBACK_URL, XMPP_SERVICE_NAME, HTTP_FLAG_FLOW_STARTED_URL

_BASE_DIR = os.path.dirname(__file__)
_REGISTER_CMD = os.path.join(_BASE_DIR, 'register_user.sh')
_UNREGISTER_CMD = os.path.join(_BASE_DIR, 'unregister_user.sh')

def postResultToAppEngine(agent, secret, sik, content_type, status, result_url, bodyProducer, pb=configuration[HTTP_CALLBACK_URL]):

    def got_response(response):
        status_code = response.code
        finished = Deferred()
        response.deliverBody(ReceiverProtocol(finished))
        if status_code == 200:
            finished.addBoth(lambda body: log.msg("Posted response to appengine:\nstatus: %s\nbody:\n%s" % (status_code, body)))
        else:
            finished.addBoth(lambda body: log.err("Error posting response to appengine:\nstatus: %s\nbody:\n%s" % (status_code, body)))
        return finished

    def connection_failed(_):
        log.err("Could not post back result to appengine (%s)!\n" % _)

    pb = pb if isinstance(pb, str) else pb.encode('utf8')
    result_url = result_url if isinstance(result_url, str) else result_url.encode('utf-8')
    d = agent.request("POST", pb, Headers({'Content-Type': [content_type],
         'X-Nuntiuz-Service-Key': [sik.encode('utf8')], 'X-Nuntiuz-Service-Status': [str(status)],
         'X-Nuntiuz-Service-Result-Url': [result_url], 'X-Nuntiuz-Secret': [secret]}), bodyProducer)

    d.addCallback(got_response)
    d.addErrback(connection_failed)

class CallbackService(component.Service):
    implements(IService)

    def setAppEngineSecret(self, secret):
        self.appengine_secret = secret

    def setHTTPAgent(self, agent):
        self.http_agent = agent

    def componentConnected(self, xmlstream):
        self.jabberId = xmlstream.authenticator.otherHost
        xmlstream.addObserver("/message/result", self.onCallbackResult, 1)

    def onCallbackResult(self, msg):
        result = msg.elements('mobicage:comm', 'result').next()
        sik = str(result["sik"])
        body = base64.decodestring(str(result))
        postResultToAppEngine(self.http_agent, self.appengine_secret, sik, "application/json-rpc", 200, "", StringProducer(body))

    def appengineIncomming(self, payload):
        if payload["p"] == "http":
            self.sendCallbackViaHTTP(payload)
        elif payload["p"] == "xmpp":
            self.sendCallbackViaXMPP(payload)
        else:
            log.err("Unknown callback protocol: %s" % payload["p"])

    def sendCallbackViaHTTP(self, payload):

        def got_response(response):
            log.msg("Receiving response")
            content_type = response.headers.getRawHeaders('Content-Type', default=['application/binary'])[0]
            log.msg("Content-type: %s" % content_type)
            status_code = response.code
            log.msg("Status code: %s" % status_code)
            finished = Deferred()
            pdp = ProxyDeliveryProducer(finished, response.length)
            response.deliverBody(pdp)
            postResultToAppEngine(self.http_agent, self.appengine_secret, payload["rs"], content_type, status_code, payload["r"], pdp, payload["b"])
#
#            response.deliverBody(ReceiverProtocol(finished))
#            def postback(body):
#                log.msg("Posting back to appengine:\n%s" % body)
#                postResultToAppEngine(self.http_agent, self.appengine_secret, payload["s"], content_type, status_code, payload["r"], StringProducer(body), payload["b"])
#            finished.addBoth(postback)
            return finished

        def connection_failed(_):
            log.err(_)
            postResultToAppEngine(self.http_agent, self.appengine_secret, payload["rs"], "text/plain", 600, "", StringProducer("Connection refused!"), payload["b"])

        log.msg("Performing callback to " + payload["r"])
        d = self.http_agent.request("POST", payload["r"].encode('utf-8'), Headers({'Content-Type': ['application/json-rpc; charset="utf-8"'],
                             'X-Nuntiuz-Service-Key': [payload["s"].encode('utf-8')]}), StringProducer(payload["c"].encode('utf-8')))

        d.addCallback(got_response)
        d.addErrback(connection_failed)

    def sendCallbackViaXMPP(self, payload):
        callback = domish.Element((None, 'message'))
        callback['to'] = payload["r"]
        callback['from'] = "bot@callback.%s" % configuration[XMPP_SERVICE_NAME]
        callback['type'] = 'normal'
        content = callback.addElement("call", "mobicage:comm", base64.b64encode(payload["c"]))
        content["sik"] = payload["s"]
        self.send(callback)


class CallbackResource(resource.Resource):
    isLeaf = True

    def __init__(self, callback_service, secret, serverTime):
        self.callback_service = callback_service
        self.secret = secret
        self.serverTime = serverTime

    def render_POST(self, request):
        challenge, data = decrypt_from_appengine(self.secret, request.content.read(), self.serverTime)
        reactor.callLater(0, self.callback_service.appengineIncomming, json.loads(data))  # @UndefinedVariable
        return encrypt_for_appengine(self.secret, challenge, 'OK')

class StartFlowResource(resource.Resource):
    isLeaf = True

    def __init__(self, secret, serverTime, http_agent):
        self.secret = secret
        self.serverTime = serverTime
        self.http_agent = http_agent

    def render_POST(self, request):
        challenge, data = decrypt_from_appengine(self.secret, request.content.read(), self.serverTime)
        reactor.callLater(0, self.start_flow, data)  # @UndefinedVariable
        return encrypt_for_appengine(self.secret, challenge, 'OK')

    def start_flow(self, data):
        headers_pattern_length = struct.calcsize('i')
        headers_length = struct.unpack('i', data[:headers_pattern_length])[0]
        headers = json.loads(data[headers_pattern_length:headers_pattern_length + headers_length])
        xml = data[headers_pattern_length + headers_length:]

        message_flow_run_key = headers['X-Nuntiuz-MessageFlowRunKey']

        def got_response(response):
            status_code = response.code
            finished = Deferred()
            response.deliverBody(ReceiverProtocol(finished))
            if status_code == 200:
                finished.addCallback(lambda _: self.flag_message_flow_as_running(message_flow_run_key))
            else:
                finished.addBoth(lambda body: log.err("Error starting message flow:\nstatus: %s\nbody:\n%s" % (status_code, body)))
            return finished

        def connection_failed(_):
            log.err("Could not post back result to appengine (%s)!\n" % _)

        url = headers['X-Nuntiuz-MFRURL'].encode('utf8')
        request_headers = dict(((k.encode('utf8'), [v.encode('utf8')]) for k, v in headers.iteritems() if k not in ('X-Nuntiuz-MessageFlowRunKey', 'X-Nuntiuz-MFRURL')))
        d = self.http_agent.request("POST", url, Headers(request_headers), StringProducer(xml))

        d.addCallback(got_response)
        d.addErrback(connection_failed)

    def flag_message_flow_as_running(self, message_flow_run_key):
        def got_response(response):
            status_code = response.code
            finished = Deferred()
            response.deliverBody(ReceiverProtocol(finished))
            if status_code == 200:
                finished.addBoth(lambda body: log.msg("Successfully flagged message flow run %s as started." % message_flow_run_key))
            else:
                finished.addBoth(lambda body: log.err("Error flagging message flow run %s as started." % (status_code, body)))
            return finished

        def connection_failed(_):
            log.err("Could not post back result to appengine (%s)!\n" % _)

        url = "%s?%s" % (configuration[HTTP_FLAG_FLOW_STARTED_URL], urllib.urlencode((('message_flow_run_key', message_flow_run_key),)))
        d = self.http_agent.request("GET", url, Headers({'X-Nuntiuz-Secret': [self.secret]}))

        d.addCallback(got_response)
        d.addErrback(connection_failed)

class RegisterResource(resource.Resource):
    isLeaf = True

    def __init__(self, secret, serverTime):
        self.secret = secret
        self.serverTime = serverTime

    def render_POST(self, request):
        challenge, data = decrypt_from_appengine(self.secret, request.content.read(), self.serverTime)
        register_details = json.loads(data)
        username = str(register_details["username"])
        server = str(register_details["server"])
        password = str(register_details["password"])

        def result(results):
            out, err, code = results
            if code == 0:
                log.msg("Successfully created new Rogerthat mobile account!\noutput: %s\nerrors: %s\nexit code: %s" % results)
            else:
                log.msg("Failed to create new Rogerthat mobile account!\noutput: %s\nerrors: %s\nexit code: %s" % results)
            data = json.dumps((code == 0, code, out, err))
            request.write(encrypt_for_appengine(self.secret, challenge, data))
            request.finish()

        def killed(results):
            out, err, signalNum = results
            log.msg("Command to create new Rogerthat mobile account was killed!\noutput: %s\nerrors: %s\nsignal: %s" % results)
            data = json.dumps((False, signalNum, out, err))
            request.write(encrypt_for_appengine(self.secret, challenge, data))
            request.finish()

        d = getProcessOutputAndValue(_REGISTER_CMD, (username, server, password))
        d.addCallback(result)
        d.addErrback(killed)

        return NOT_DONE_YET

class UnRegisterResource(resource.Resource):
    isLeaf = True

    def __init__(self, secret, serverTime):
        self.secret = secret
        self.serverTime = serverTime

    def render_POST(self, request):
        challenge, data = decrypt_from_appengine(self.secret, request.content.read(), self.serverTime)
        register_details = json.loads(data)
        username = register_details["username"]
        server = register_details["server"]

        def result(results):
            out, err, code = results
            if code == 0:
                log.msg("Successfully removed Rogerthat mobile account!\noutput: %s\nerrors: %s\nexit code: %s" % results)
            else:
                log.msg("Failed to remove Rogerthat mobile account!\noutput: %s\nerrors: %s\nexit code: %s" % results)
            data = json.dumps((code == 0, code, out, err))
            request.write(encrypt_for_appengine(self.secret, challenge, data))
            request.finish()

        def killed(results):
            out, err, signalNum = results
            log.msg("Command to remove Rogerthat mobile account was killed!\noutput: %s\nerrors: %s\nsignal: %s" % results)
            data = json.dumps((False, signalNum, out, err))
            request.write(encrypt_for_appengine(self.secret, challenge, data))
            request.finish()

        d = getProcessOutputAndValue(_UNREGISTER_CMD, (username, server))
        d.addCallback(result)
        d.addErrback(killed)

        return NOT_DONE_YET

class IpToCountryResource(resource.Resource):
    isLeaf = True

    def __init__(self, secret, serverTime):
        self.secret = secret
        self.serverTime = serverTime

    def render_POST(self, request):
        challenge, ip = decrypt_from_appengine(self.secret, request.content.read(), self.serverTime)

        def calculate_country():
            import pygeoip
            try:
                g = pygeoip.GeoIP('GeoLiteCity.dat')
                return g.country_code_by_addr(ip)
            except:
                log.err(None)
                return "XX"

        def result(result):
            request.write(encrypt_for_appengine(self.secret, challenge, result))
            request.finish()

        d = threads.deferToThread(calculate_country)
        d.addCallback(result)

        return NOT_DONE_YET
