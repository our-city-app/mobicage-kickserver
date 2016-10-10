# coding=utf-8
# COPYRIGHT (C) 2011 MOBICAGE NV
# ALL RIGHTS RESERVED.
#
# ALTHOUGH YOU MAY BE ABLE TO READ THE CONTENT OF THIS FILE, THIS FILE
# CONTAINS CONFIDENTIAL INFORMATION OF MOBICAGE NV. YOU ARE NOT ALLOWED
# TO MODIFY, REPRODUCE, DISCLOSE, PUBLISH OR DISTRIBUTE ITS CONTENT,
# EMBED IT IN OTHER SOFTWARE, OR CREATE DERIVATIVE WORKS, UNLESS PRIOR
# WRITTEN PERMISSION IS OBTAINED FROM MOBICAGE NV.
#
# THE COPYRIGHT NOTICE ABOVE DOES NOT EVIDENCE ANY ACTUAL OR INTENDED
# PUBLICATION OF SUCH SOURCE CODE.
#
# @@license_version:1.4@@

import os

from twisted.application import service
from twisted.internet import reactor
from twisted.web import resource, server
from twisted.web.client import Agent, HTTPConnectionPool

from configuration import APP_ENGINE_SECRET, WEBSERVICE_PORT, configuration
from configuration import NEWS_PORT
from news.callbacks import NewsUpdatedCallback
from news.factory import NewsFactory
from util import ServerTime, HighLoadTCPServer

# Let's get started
application = service.Application('Rogerthat news update server')

# One single agent to perform outbound http requests ===> HTTP/1.1 Connection pooling
pool = HTTPConnectionPool(reactor)
agent = Agent(reactor, pool=pool)
serverTime = ServerTime(agent)
root = resource.Resource()

news_factory = NewsFactory(agent)
news_service_port = int(os.environ.get('NEWS_PORT', configuration[NEWS_PORT]))
news_service = HighLoadTCPServer(news_service_port, news_factory, request_queue_size=100)
news_service.setServiceParent(application)

root.putChild('news_updated', NewsUpdatedCallback(configuration[APP_ENGINE_SECRET], serverTime, agent, news_factory))

webservice_port = int(os.environ.get('WEBSERVICE_PORT', configuration[WEBSERVICE_PORT]))
webservice = HighLoadTCPServer(webservice_port, server.Site(root), request_queue_size=100)
webservice.setServiceParent(application)
