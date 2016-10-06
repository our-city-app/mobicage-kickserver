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

import hashlib
import json
import time
from contextlib import closing

from twisted.internet.defer import Deferred
from twisted.web.http_headers import Headers

from news.models import NewsInfo
from util import ReceiverProtocol

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO
from collections import defaultdict
from twisted.internet.protocol import Factory
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet import reactor
from twisted.python import log
from configuration import configuration, NEWS_SERVER_AUTH_TIMEOUT, NEWS_SERVER_READ_UPDATES_TIMEOUT, \
    NEWS_SERVER_NEWS_RETENTION_JOB_TIMEOUT, NEWS_SERVER_NEWS_RETENTION_CACHE_SIZE, HTTP_AUTH_PATH, HTTP_BASE_URL, \
    HTTP_NEWS_PATH, DEBUG_ON

BASE_URL = configuration[HTTP_BASE_URL]
DEBUG = configuration[DEBUG_ON]


class Commands(object):
    AUTH = 'AUTH'
    SET_INFO = 'SET INFO'
    NEWS_READ = 'NEWS READ'
    NEWS_STATS_READ = 'NEWS STATS READ'
    NEWS_ROGER = 'NEWS ROGER'
    PING = 'PING'

class Responses(object):
    AUTH_OK = 'AUTH: OK'
    AUTH_ERROR = 'AUTH: ERROR'
    ACK_NEWS_READ = 'ACK NEWS READ: %s'
    NEWS_STATS_READ = 'NEWS STATS READ: %s'
    NEWS_READ_UPDATE = 'NEWS READ UPDATE: '
    ACK_NEWS_ROGER = 'ACK NEWS ROGER: %s'
    NEWS_ROGER_UPDATE = 'NEWS ROGER UPDATE: %s %s'
    NEWS_PUSH = 'NEWS PUSH: %s'
    PONG = 'PONG'


class NewsProtocol(object, LineOnlyReceiver):
    commands = {}
    log.msg('initializing protocol')

    def __init__(self):
        self.connected = False
        self.authenticated = False
        self.app = None
        self.friends = []
        self.account = None

    def connectionMade(self):
        self.connected = True

        # Close unauthenticated connections after NEWS_SERVER_AUTH_TIMEOUT seconds
        def disconnect():
            if not self.connected:
                return
            if not self.authenticated:
                log.msg('Disconnecting user, authentication timeout')
                self.transport.loseConnection()

        reactor.callLater(configuration[NEWS_SERVER_AUTH_TIMEOUT], disconnect)

    def sendLine(self, line):
        if DEBUG:
            log.msg('Sending line: %s' % line)
        super(NewsProtocol, self).sendLine(line)

    def connectionLost(self, reason):
        self.connected = False
        self.factory.unregister_connection(self)

    def lineReceived(self, line):
        if DEBUG:
            log.msg('%s -  %s' % (self.account or 'unauthenticated', line))
        if line == Commands.PING:
            self._ping_pong()
            return
        try:
            command, args = line.split(': ', 1)
        except ValueError:
            log.err('Invalid syntax, line must be of the format COMMAND: COMMAND_DATA')
            return
        implementation = self.commands.get(command)
        if not implementation:
            log.err('Received unknown command: %s' % line)
            return
        implementation(self, args)

    def _authenticate(self, args):
        # Parse arguments
        username, password_in_base64 = args.strip().split(' ')

        # Validate authentication parameters
        def success():
            self.authenticated = True
            self.sendLine(Responses.AUTH_OK)

        def failure():
            self.sendLine(Responses.AUTH_ERROR)
            self.transport.loseConnection()

        self.factory.authenticate(username, password_in_base64, success, failure)

    def is_authenticated(self, method):
        if not self.authenticated:
            log.err('Received unauthenticated request for %s' % method)
            self.transport.loseConnection()
            return False
        return True

    def _set_info(self, args):
        if not self.is_authenticated('set_info'):
            return
        info, data = args.strip().split(' ', 1)
        if info == 'APP':
            self.app = data
            self.factory.register_app_connection(self.app, self)
        elif info == 'ACCOUNT':
            self.account = data
        elif info == 'FRIENDS':
            self.friends = json.loads(data)
            for friend in self.friends:
                self.factory.register_friend_connection(friend, self)
        else:
            log.err('Unknown information set: %s' % info)

    def _news_read(self, args):
        if not self.is_authenticated('news_read'):
            return
        news_id = int(args)
        self.factory.read_news(self.app, news_id)
        self.sendLine(Responses.ACK_NEWS_READ % news_id)

    def _news_stats_read(self, args):
        """
        Returns the stats of NewsItems
        Args:
            args (unicode:
        """
        if not self.is_authenticated('news_stats_read'):
            return

        stats = self.factory.news_stats_read(self.app, (long(news_id) for news_id in args.split(' ')))
        self.sendLine(Responses.NEWS_STATS_READ % ' '.join((str(stat) for stat in stats)))

    def _news_roger(self, args):
        if not self.is_authenticated('news_roger'):
            return
        news_id = args.strip()
        try:
            int(news_id)
        except ValueError:
            log.err('Invalid news_id %s' % news_id)
        self.factory.news_roger(news_id, self.account)
        self.sendLine(Responses.ACK_NEWS_ROGER % news_id)

    def _ping_pong(self):
        self.sendLine(Responses.PONG)

    commands[Commands.AUTH] = _authenticate
    commands[Commands.SET_INFO] = _set_info
    commands[Commands.NEWS_READ] = _news_read
    commands[Commands.NEWS_STATS_READ] = _news_stats_read
    commands[Commands.NEWS_ROGER] = _news_roger
    commands[Commands.PING] = _ping_pong


class NewsFactory(Factory):
    protocol = NewsProtocol

    def __init__(self, http_agent):
        self.http_agent = http_agent
        self._authenticated_users = set()
        self._news = defaultdict(NewsInfo)  # contains NewsInfo objects
        self._news_read_updates = set()
        self._connections_per_app = defaultdict(set)  # index app
        self._connections_per_friend = defaultdict(set)  # index friend
        reactor.callLater(configuration[NEWS_SERVER_READ_UPDATES_TIMEOUT], self._send_news_read_updates)
        reactor.callLater(configuration[NEWS_SERVER_NEWS_RETENTION_JOB_TIMEOUT], self._news_retention)

    def authenticate(self, username, password, success, failure):
        """
        Check authentication against the server
        Args:
            username (unicode): base64 encoded email
            password (unicode): base64 encoded password
            success (function)
            failure (function)
        """

        def got_response(response):
            status_code = response.code
            if status_code == 200:
                self._authenticated_users.add(username_password_hash)
                success()
            else:
                failure()

        def connection_failed(_):
            log.err(_)
            failure()

        # Calculate hash for authentication caching
        username_password_hasher = hashlib.sha256()
        username_password_hasher.update(username)
        username_password_hasher.update(password)
        username_password_hash = username_password_hasher.digest()

        # Check authentication against the cache
        if username_password_hash in self._authenticated_users:
            success()
            return

        headers = {
            'X-MCTracker-User': [username],
            'X-MCTracker-Pass': [password]
        }
        auth_url = configuration[HTTP_BASE_URL] + configuration[HTTP_AUTH_PATH]
        d = self.http_agent.request('POST', auth_url, Headers(headers))
        d.addCallback(got_response)
        d.addErrback(connection_failed)

    def log_current_connections(self):
        log.msg('Currently connected users: %d' % sum(
            [len(self._connections_per_app[app_id]) for app_id in self._connections_per_app]))

    def register_app_connection(self, app, connection):
        self._connections_per_app[app].add(connection)
        self.log_current_connections()

    def register_friend_connection(self, friend, connection):
        self._connections_per_friend[friend].add(connection)

    def unregister_connection(self, connection):
        if connection.app:
            self._connections_per_app[connection.app].discard(connection)
        for friend in connection.friends:
            self._connections_per_friend[friend].discard(connection)
        self.log_current_connections()

    def _send_news_read_updates(self):
        reactor.callLater(configuration[NEWS_SERVER_READ_UPDATES_TIMEOUT], self._send_news_read_updates)
        app_updates = defaultdict(list)
        for news_id in self._news_read_updates:
            news_info = self._news.get(news_id)
            if news_info:
                for app in news_info.app_ids:
                    app_updates[app].append((news_id, news_info.read_count))
        for app, updates in app_updates.iteritems():
            with closing(StringIO()) as buf:
                buf.write(Responses.NEWS_READ_UPDATE)
                for news_id, read_count in updates:
                    buf.write(str(news_id))
                    buf.write(' ')
                    buf.write(str(read_count))
                    buf.write(' ')
                update = buf.getvalue()
            for connection in self._connections_per_app[app]:
                connection.sendLine(update)
        self._news_read_updates.clear()

    def _news_retention(self):
        reactor.callLater(configuration[NEWS_SERVER_NEWS_RETENTION_JOB_TIMEOUT], self._news_retention)
        max_cache_size = configuration[NEWS_SERVER_NEWS_RETENTION_CACHE_SIZE]
        if len(self._news) <= max_cache_size:
            return
        news = list(self._news.values())
        news.sort(key=lambda news_info: news_info.timestamp)
        for news_info in news[:len(self._news) - max_cache_size]:
            del self._news[news_info.news_id]

    def _ask_server_for_stats(self, app, news_ids):
        """
        Gets the statistics for news items from the server and adds them to the local cache.
        Args:
            news_ids (list of long)
            callback (function):
        """
        if not news_ids:
            return

        for news_id in news_ids:
            self._news[news_id] = NewsInfo(app_ids={ app },
                                           read_count=0,
                                           news_id=news_id)

        def news_response(response):
            if response.code != 200:
                news_received_fail(response)
            else:
                def process_body(response_content):
                    news_stats = json.loads(response_content)
                    log.msg('News stats from server: %s' % news_stats)
                    if not news_stats:
                        log.err('Could not find news stats with ids %s' % news_ids)
                    else:
                        for stat in news_stats:
                            news_id = stat['news_id']
                            news = self._news[news_id]
                            news.news_id = news_id
                            news.app_ids.update(stat['app_ids'])
                            news.read_count += stat['read_count']
                            self._news_read_updates.add(news_id)

                finished = Deferred()
                response.deliverBody(ReceiverProtocol(finished))
                finished.addBoth(process_body)

        def news_received_fail(response):
            log.err('Failed to receive news')
            log.err(response)

        news_read_url = '%s%s?news_ids=%s' % (
            BASE_URL, configuration[HTTP_NEWS_PATH], ','.join(str(i) for i in news_ids))
        d = self.http_agent.request('GET', news_read_url, Headers({}))
        d.addCallback(news_response)
        d.addErrback(news_received_fail)

    def read_news(self, app, news_id):
        if news_id in self._news:
            news_info = self._news[news_id]
            news_info.app_ids.add(app)
            news_info.read_count += 1
            self._news_read_updates.add(news_id)
        else:
            self._ask_server_for_stats(app, [news_id])

    def news_stats_read(self, app, news_ids):
        """
        Returns the statistics of a news item. When not found (yet), returns -1. Real value will be returned in
         the _send_news_read_updates function that gets executed every x seconds.
         Structure: news_id read_count news_id read_count
        Args:
            news_ids (list of long):
        Returns:
            list of News
        """
        stats = list()
        need_server_stats = list()
        for news_id in news_ids:
            stats.append(news_id)
            if news_id in self._news:
                stats.append(self._news[news_id].read_count)
            else:
                stats.append(-1)
                need_server_stats.append(news_id)
        self._ask_server_for_stats(app, need_server_stats)
        return stats

    def news_roger(self, news_id, friend):
        line = Responses.NEWS_ROGER_UPDATE % (news_id, friend)
        for connection in self._connections_per_friend[friend]:
            connection.sendLine(line)

    def news_updated(self, news_item):
        if DEBUG:
            log.msg('News updated: %s' % news_item)
        news_id = news_item['id']
        if news_id not in self._news:
            self._news[news_id] = NewsInfo(app_ids=set(news_item['app_ids']),
                                           read_count=0,
                                           news_id=news_id)
        else:
            self._news[news_id].app_ids = news_item['app_ids']
        news_item['sort_timestamp'] = news_item['sticky_until'] if news_item['sticky_until'] else news_item['timestamp']

        for app_id in news_item['app_ids']:
            for connection in self._connections_per_app[app_id]:
                news_item['sort_priority'] = sort_priority(news_item, connection.friends)
                line = Responses.NEWS_PUSH % json.dumps(news_item)
                connection.sendLine(line)


def sort_priority(news_item, friends):
    if news_item['sticky']:
        return 10
    if news_item['users_that_rogered'] and any(
                    user_that_rogered in friends for user_that_rogered in news_item['users_that_rogered']):
        return 20
    if news_item['sender'] in friends:
        return 30
    return 40
