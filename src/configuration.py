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

import os

import yaml

DEBUG_ON = 'debug'
GAE_TRANSPORT_ENCRYPTED = 'gae-transport-encrypted'
APNS_ENABLED = 'apns-enabled'
APP_ENGINE_SECRET = 'appengine-secret'
WEBSERVICE_PORT = 'webservice-port'
XMPP_SERVICE_NAME = 'xmpp-service-name'
XMPP_RECONNECT_INTERVAL = 'xmpp-reconnect-interval'
KICK_SERVICE = 'kick-service'
CALLBACK_SERVICE = 'callback-service'
PASSWORD = 'password'
ADDRESS = 'address'
APPLE_PUSH_RECONNECT_INTERVAL = 'apple-push-reconnect-interval'
APPLE_PUSH_FEEDBACK_POLL_INTERVAL = 'apple-push-feedback-poll-interval'
HTTP_BASE_URL = 'http-base-url'
HTTP_REPLACE_URL = 'http-replace-url'
HTTP_RPC_URL_PATH = 'http-rpc-url-path'
HTTP_AUTH_PATH = 'http-auth-path'
HTTP_NEWS_PATH = 'http-news-path'
HTTP_SERVER_TIME_URL = 'http-time-server-url'
HTTP_CALLBACK_URL = 'http-callback-url'
HTTP_FLAG_FLOW_STARTED_URL = 'http-flag-flow-started-url'
HTTP_GET_APPLE_PUSH_CERTS = 'http-get-apple-push-certs'
APPLE_CERT_AND_KEY_ENCRYPTION_SECRET = 'apple-cert-and-key-encryption-secret'
NEWS_PORT = 'news-port'
NEWS_WEBSERVICE_PORT = 'news-webservice-port'
NEWS_SERVER_SSL_CERT = 'news-server-ssl-cert'
NEWS_SERVER_AUTH_TIMEOUT = 'news-server-auth-timeout'
NEWS_SERVER_READ_UPDATES_TIMEOUT = 'news-server-read-updates-timeout'
NEWS_SERVER_NEWS_RETENTION_JOB_TIMEOUT = 'news-server-news-retention-job-timeout'
NEWS_SERVER_NEWS_RETENTION_CACHE_SIZE = 'news-server-news-retention-cache-size'
NEWS_SSL_KEY = 'news-ssl-key'
NEWS_SSL_CERT = 'news-ssl-cert'

# Get configuration
configuration_file = os.environ.get('KICK_CONF', '/etc/rogerthat/kick.yaml')
with open(configuration_file, 'r') as _f:
    configuration = yaml.load(_f)
