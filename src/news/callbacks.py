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

import json

from twisted.internet import reactor
from twisted.web import resource
from twisted.web.resource import Resource

from twisted.python import log

from util import decrypt_from_appengine, encrypt_for_appengine


class NewsUpdatedCallback(resource.Resource):
    isLeaf = True

    def __init__(self, secret, server_time, http_agent, news_factory):
        Resource.__init__(self)
        self.secret = secret
        self.http_agent = http_agent
        self.server_time = server_time
        self.news_factory = news_factory

    def render_POST(self, request):
        content = request.content.read()
        log.msg(content)
        challenge, data = decrypt_from_appengine(self.secret, content, self.server_time)
        reactor.callLater(0, self.news_updated, json.loads(data))
        return encrypt_for_appengine(self.secret, challenge, 'OK')

    def news_updated(self, news_item):
        self.news_factory.news_updated(news_item)
