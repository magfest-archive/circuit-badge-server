from os import environ

import asyncio
from autobahn.asyncio.wamp import ApplicationSession, ApplicationRunner
import socket
import struct
import time
import requests
import collections


EXIT_SEQUENCE = ['start', 'start', 'start']
JOIN_PREFIX = ('start', 'select')
# Not including prefix
JOIN_LENGTH = 4
JOIN_KEYS = ['up', 'down', 'left', 'right', 'a', 'b']
TOTAL_JOIN = JOIN_LENGTH + len(JOIN_PREFIX)

KONAMI = ('up', 'up', 'down', 'down', 'left', 'right', 'left', 'right', 'b', 'a', 'start')

JOIN_INDEX_MAX = 6**4 # 1296

MODE_STATIC = 'static'
MODE_UNIQUE = 'unique'
MODE_SINGLE = 'single'


def convert_joincode(seq):
    res = []
    for i in range(JOIN_LENGTH):
        res.append(JOIN_KEYS[seq % 6])
        seq //= 6
    return tuple(res)


class Badge:
    def __init__(self, badge_id):
        self.id = badge_id
        self.buttons = collections.deque(maxlen=len(JOIN_PREFIX)+JOIN_LENGTH)
        self.game = None
        self.join_time = 0
        self.last_update = 0


class GameManager(ApplicationSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        #: Maps a join code onto its game
        self.join_codes = {}

        #: Maps badge IDs onto badge states
        self.badges = {}

        self._join_index = 0

        self.games = {}

        self.player_mapping = {}

    def generate_joincode(self):
        res = convert_joincode((JOIN_INDEX_MAX-1)^self._join_index)
        self._join_index += 1
        return res

    def expire_joincode(self, joincode):
        if joincode in self.join_codes:
            game_id, mode, mnemonic, timeout = self.join_codes[joincode]
            self.publish(u'me.magbadge.app.' + game_id + '.join')
            del self.join_codes[joincode]

    @asyncio.coroutine
    def request_joincode(self, game_id, mode='static', mnemonic='', timeout=120):
        code = self.generate_joincode()
        if timeout != 0:
            asyncio.get_event_loop().call_later(timeout, self.expire_joincode, (code,))
        self.join_codes[code] = game_id, MODE_UNIQUE, mnemonic, timeout
        return code

    def on_joincode(self, badge_id, joincode):
        game_id, mode, mnemonic, timeout = self.join_codes[joincode]
        self.publish(u'me.magbadge.app.' + game_id + '.user.join', badge_id, mnemonic)

    def check_joincode(self, badge):
        print(len(badge.buttons))
        if len(badge.buttons) >= len(JOIN_PREFIX)+JOIN_LENGTH:
            entered = tuple(badge.buttons)[-TOTAL_JOIN:]
            if tuple(badge.buttons)[-len(KONAMI):] == KONAMI:
                self.publish(u'me.magbadge.badge.lights', 255, 0, 0)
                print("KONAMI")
            if entered in self.join_codes:
                print("Joincode entered!")
                game_id, mode, mnemonic, timeout = self.join_codes[entered]
                self.player_mapping[badge.id] = game_id
                self.publish(u'me.magbadge.app.' + game_id + '.user.join', badge.id)

                if mode == MODE_STATIC:
                    pass
                elif mode == MODE_UNIQUE:
                    del self.join_codes[entered]
                    new_code = self.generate_joincode()
                    self.join_codes[new_code] = game_id, mode, mnemonic, timeout
                    self.publish(u'me.magbadge.app.' + game_id + '.joincode.updated', new_code)

    @asyncio.coroutine
    def button_down(self, badge_id, button):
        print(button + " down")
        yield from self.button_pressed(badge_id, button, True)

    @asyncio.coroutine
    def button_up(self, badge_id, button):
        yield from self.button_pressed(badge_id, button, False)

    @asyncio.coroutine
    def button_pressed(self, badge_id, button, down):
        if badge_id not in self.badges:
            self.badges[badge_id] = Badge(badge_id)

        # if the player is in a game:
        #   - record the button
        #   - if they entered the exit sequence, kick them
        #   - otherwise, relay the
        if badge_id not in self.badges:
            badge = self.badges[badge_id] = Badge(badge_id)
        else:
            badge = self.badges[badge_id]

        if down:
            badge.buttons.append(button)

            if badge_id in self.player_mapping:
                if len(badge.buttons) and tuple(badge.buttons)[-3:] == EXIT_SEQUENCE:
                    print("Exit sequence pressed")
                    self.publish(u'me.magbadge.app.' + self.player_mapping[badge_id] + '.user.leave', badge_id)
                    del self.player_mapping[badge_id]
                else:
                    print("Button " + button + " pressed")
                    self.publish(u'me.magbadge.app.' + self.player_mapping[badge_id] + '.user.button.down', badge_id, button)

            else:
                self.check_joincode(self.badges[badge_id])
        else:
            if badge_id in self.player_mapping:
                print("Button " + button + " released")
                self.publish(u'me.magbadge.app.' + self.player_mapping[badge_id] + '.user.button.up', badge_id, button)

    @asyncio.coroutine
    def kick_player(self, player):
        if player in self.player_mapping:
            del self.player_mapping[player]

    @asyncio.coroutine
    def onJoin(self, details):
        yield from self.subscribe(self.button_down, 'me.magbadge.badge.button.down')
        yield from self.subscribe(self.button_up, u'me.magbadge.badge.button.up')
        yield from self.register(self.request_joincode, u'me.magbadge.app.request_joincode')
        while True:
            yield from asyncio.sleep(.1)

try:
    runner = ApplicationRunner(u"ws://badges.magevent.net:8080/ws", u"MAGBadges",)
    runner.run(GameManager)
except e:
    print(e)
