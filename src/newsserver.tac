import os
from OpenSSL import SSL

from twisted.application import service
from twisted.internet import reactor, ssl
from twisted.web import resource, server
from twisted.web.client import Agent, HTTPConnectionPool

from configuration import APP_ENGINE_SECRET, configuration, NEWS_WEBSERVICE_PORT, NEWS_SSL_KEY, NEWS_SSL_CERT
from configuration import NEWS_PORT
from news.callbacks import NewsUpdatedCallback
from news.factory import NewsFactory
from util import ServerTime, HighLoadTCPServer, HighLoadSSLServer, ChainedOpenSSLContextFactory

# Let's get started
application = service.Application('Rogerthat news update server')

# One single agent to perform outbound http requests ===> HTTP/1.1 Connection pooling
pool = HTTPConnectionPool(reactor)
agent = Agent(reactor, pool=pool)
serverTime = ServerTime(agent)
root = resource.Resource()

news_factory = NewsFactory(agent)
news_service_port = int(os.environ.get('NEWS_PORT', configuration[NEWS_PORT]))

if configuration[NEWS_SSL_KEY]:
    news_service = HighLoadSSLServer(news_service_port, news_factory,
                                     ChainedOpenSSLContextFactory(configuration[NEWS_SSL_KEY],
                                                                  configuration[NEWS_SSL_CERT], SSL.TLSv1_METHOD),
                                     request_queue_size=100)
else:
    news_service = HighLoadTCPServer(news_service_port, news_factory, request_queue_size=100)
news_service.setServiceParent(application)

root.putChild('news_updated', NewsUpdatedCallback(configuration[APP_ENGINE_SECRET], serverTime, agent, news_factory))

webservice_port = int(os.environ.get('NEWS_WEBSERVICE_PORT', configuration[NEWS_WEBSERVICE_PORT]))
webservice = HighLoadTCPServer(webservice_port, server.Site(root), request_queue_size=100)
webservice.setServiceParent(application)
