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


class NewsInfo(object):
    def __init__(self, app_ids=None, read_count=0, timestamp=0, news_id=None):
        """
        Args:
            app_ids (set of unicode)
            read_count (long)
            timestamp (long)
            news_id (long)
        """
        if app_ids is None:
            app_ids = set()
        self.app_ids = app_ids
        self.read_count = read_count
        self.timestamp = timestamp
        self.news_id = news_id
