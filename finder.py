from os import environ

import asyncio
from autobahn.asyncio.wamp import ApplicationSession, ApplicationRunner
import socket
import struct
import time
import requests


FIND_GROUP = "mag15gaylord"
TRACK_URL = "http://badges.magevent.net:8003/track"


class Component(ApplicationSession):
    def send_scan(self, badge_id, data):
        res = requests.post(TRACK_URL, json=data)
        if res.status_code == 200:
            body = res.json()
            if body.get("success", False):
                self.publish(u'me.magbadge.badge.location', badge_id, body.get("location", None))
            else:
                print("[ERROR] /track returned unsuccessful result, message is: {}".format(body.get("message", "<none present>")))
        else:
            print("[ERROR] /track returned HTTP status code {}".format(res.status_code))

    @asyncio.coroutine
    def scan_received(self, badge_id, scan_data):
        data = {
            "group": FIND_GROUP,
            "username": badge_id,
            "time": int(time.time()),
            "wifi-fingerprint": scan_data,
        }

        yield from asyncio.get_event_loop().run_in_executor(None, self.send_scan, badge_id, data)

    @asyncio.coroutine
    def onJoin(self, details):
        yield from self.subscribe(self.scan_received, u'me.magbadge.badge.scan')

runner = ApplicationRunner(u"ws://badges.magevent.net:8080/ws", u"MAGBadges",)
runner.run(Component)

