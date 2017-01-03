from os import environ

import asyncio
from autobahn.asyncio.wamp import ApplicationSession, ApplicationRunner

class Component(ApplicationSession):
    async def onJoin(self, details):
        counter = 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 8000))
        while True:
            data, addr = sock.recvfrom(1024)
            if addr[0] in socket.gethostbyname_ex(socket.gethostname())[2]:
                continue
            print("Received udp message from {0}: {1}".format(addr, data))
            if data[0] == 0:
                self.publish(u'com.badge.button', data[1:7], data[8])

runner = ApplicationRunner(u"ws://badges.magevent.net:8080/ws", u"MAGBadges",)
runner.run(Component)

