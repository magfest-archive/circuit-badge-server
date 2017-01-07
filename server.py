from os import environ

import asyncio
from autobahn.asyncio.wamp import ApplicationSession, ApplicationRunner
import socket
import struct
from autobahn import wamp
import time
import pickle
import concurrent.futures
import traceback
import collections
import random
from autobahn.wamp.types import PublishOptions
import json
import threading

BUTTON_RIGHT = 1
BUTTON_DOWN = 2
BUTTON_LEFT = 3
BUTTON_UP = 4
BUTTON_SELECT = 5
BUTTON_START = 6
BUTTON_B = 7
BUTTON_A = 8

BUTTON_NAMES = {
    BUTTON_RIGHT: "right",
    BUTTON_DOWN: "down",
    BUTTON_LEFT: "left",
    BUTTON_UP: "up",
    BUTTON_SELECT: "select",
    BUTTON_START: "start",
    BUTTON_B: "b",
    BUTTON_A: "a",
}

KONAMI = (BUTTON_UP, BUTTON_UP, BUTTON_DOWN, BUTTON_DOWN, BUTTON_LEFT, BUTTON_RIGHT, BUTTON_LEFT, BUTTON_RIGHT)

STATUS_UPDATE = 1
LED_CONTROL = 2
LED_RSSI_MODE = 3
WIFI_UPDATE = 4
WIFI_UPDATE_REPLY = 5
LED_RAINBOW_MODES = 7
CONFIGURE = 8
DEEP_SLEEP = 9

SCAN_INTERVAL = 600
WIFI_INTERVAL = 10000

EXIT_SEQUENCE = (BUTTON_START,) * 3
JOIN_PREFIX = (BUTTON_START, BUTTON_SELECT)
# Not including prefix
JOIN_LENGTH = 4
JOIN_KEYS = (BUTTON_UP, BUTTON_DOWN, BUTTON_LEFT, BUTTON_RIGHT, BUTTON_A, BUTTON_B)
TOTAL_JOIN = JOIN_LENGTH + len(JOIN_PREFIX)

JOIN_INDEX_MAX = 6**4 # 1296

MODE_STATIC = 'static'
MODE_UNIQUE = 'unique'
MODE_SINGLE = 'single'

MORSE_ON = (64,) * 12
MORSE_OFF = (0,) * 12


DEBUG_BADGES = (
    'A0:20:A6:07:18:96', # dylan
#    'A0:20:A6:00:EE:18', # charles
)

MORSE_CODE = {
    'A': '.-', 'B': '-...', 'C': '-.-.',
    'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..',
    'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-',
    'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',

    '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....',
    '6': '-....', '7': '--...', '8': '---..',
    '9': '----.'
}

MORSE_ELEMENT = .092
MORSE_DIT = MORSE_ELEMENT * 1
MORSE_DAH = MORSE_ELEMENT * 3
MORSE_CHAR = MORSE_ELEMENT * 1
MORSE_SPACE = MORSE_ELEMENT * 7


def debug(badge_id, *strs):
    if badge_id in DEBUG_BADGES:
        print(*strs)


def convert_joincode(seq):
    res = []
    for i in range(JOIN_LENGTH):
        res.append(JOIN_KEYS[seq % 6])
        seq //= 6
    return tuple(res)

executor = concurrent.futures.ThreadPoolExecutor(max_workers=32)

class Badge:
    @classmethod
    def from_bytes(cls, packet):
        res = cls(
            packet[1], # wifi_power
            packet[2:8], # connected_bssid
            packet[8], # gpio_state
            packet[9], # gpio_trigger
            packet[10], # trigger_direction
            packet[11], # led_power
            int.from_bytes(packet[12:14], 'big'), # batt_voltage
            int.from_bytes(packet[14:16], 'big'),  # update_id
            int.from_bytes(packet[16:18], 'big'), # heap_free
            packet[18], # sleep_performance
            int.from_bytes(packet[20:24], 'big'), # status_count
        )

        return res

    def __init__(self, badge_id):
        self.id = badge_id
        self.buttons = collections.deque(maxlen=max(TOTAL_JOIN, len(KONAMI)))
        self.game = None
        self.join_time = 0
        self.last_update = 0
        self.pings = 0


def format_mac(mac):
    return ':'.join(('%02X' % d for d in mac))


class Konami:
    COLOR_MAP = {
        'a': (128, 0, 0),
        'b': (0, 128, 0),
        'up': (0, 0, 128),
        'down': (0, 128, 28),
        'left': (128, 0, 128),
        'right': (128, 128, 0),
    }
    def __init__(self):
        self.players = set()
        self.color = (0, 255, 255)

    def add_player(self, badge_id):
        self.players.add(badge_id)


class Component(ApplicationSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.wifi_scans = {}
        self.badge_ips = {}
        self.badges = {}
        self.socket = None
        self.buttons = {}
        self.join_codes = {}
        self.game_map = {}
        self.default_color = (0,) * 12
        self.konami = Konami()
        self._join_index = 0

    def ping_all_the_things(self):
        while True:
            for badge_id, badge in list(self.badges.items()):
                if badge.pings > 0:
                    self.noop(badge_id)
                    badge.pings -= 1
            time.sleep(.05)

    def save_thread(self):
        while True:
            time.sleep(30)
            self.save()

    def noop(self, badge_id):
        self.send_packet(badge_id, b'\x00\x00')

    def generate_joincode(self):
        res = convert_joincode((JOIN_INDEX_MAX-1)^self._join_index)
        self._join_index += 1
        print("Generated joincode", res)
        return tuple([BUTTON_NAMES[b] for b in (JOIN_PREFIX + res)])

    def expire_joincode(self, joincode):
        if joincode in self.join_codes:
            game_id, mode, mnemonic, timeout = self.join_codes[joincode]
            self.publish(u'me.magbadge.app.' + game_id + '.joincode.expired')
            del self.join_codes[joincode]

    @asyncio.coroutine
    def request_joincode(self, game_id, mode='static', mnemonic='', timeout=120):
        print("Got joincode request from game", game_id, "mode=", mode, "mem", mnemonic, "timeout", timeout)
        code = self.generate_joincode()
        if timeout != 0:
            asyncio.get_event_loop().call_later(timeout, self.expire_joincode, (code,))
        self.join_codes[code] = game_id, MODE_UNIQUE, mnemonic, timeout
        self.publish(u'me.magbadge.app.' + game_id + '.joincode.updated', code)
        return code

    def on_joincode(self, badge_id, joincode):
        game_id, mode, mnemonic, timeout = self.join_codes[joincode]
        self.publish(u'me.magbadge.app.' + game_id + '.user.join', badge_id, mnemonic)

    @asyncio.coroutine
    def check_joincode(self, badge):
        debug(badge.id, "check_joincode()")
        if len(badge.buttons) >= TOTAL_JOIN:
            entered = tuple(badge.buttons)[-TOTAL_JOIN:]

            if tuple(badge.buttons)[-len(KONAMI):] == KONAMI:
                debug(badge.id, "KONAMI was entered")
                self.game_map[badge.id] = "konami"
                debug(badge.id, "added to game map")
                yield from self.rainbow(badge.id)
                debug(badge.id, "dane rainbowing")
                debug(badge.id, "publishing konami join")
                self.konami.players.add(badge.id)
                self.publish(u'me.magbadge.app.konami.user.join', badge.id)
                debug(badge.id, "done konami join")
            elif entered in self.join_codes:
                debug(badge.id, "Joincode entered!")
                game_id, mode, mnemonic, timeout = self.join_codes[entered]
                self.game_map[badge.id] = game_id
                self.publish(u'me.magbadge.app.' + game_id + '.user.join', badge.id)

                if mode == MODE_STATIC:
                    pass
                elif mode == MODE_UNIQUE:
                    del self.join_codes[entered]
                    new_code = self.generate_joincode()
                    self.join_codes[new_code] = game_id, mode, mnemonic, timeout
                    self.publish(u'me.magbadge.app.' + game_id + '.joincode.updated', new_code)

    @asyncio.coroutine
    def kick_player(self, player):
        if player in self.game_map:
            print("Badge ID {} (ip {}) exited".format(player, self.badge_ips[player]))
            self.game_map[player] = None

    def send_button_updates(self, game, badge, button, down):
        if down:
            if len(badge.buttons) and tuple(badge.buttons)[-3:] == EXIT_SEQUENCE:
                debug(badge.id, "Exit sequence pressed")
                self.publish(u'me.magbadge.app.' + game + '.user.leave', badge.id)
                self.game_map[badge.id] = None
            else:
                debug(badge.id, "[ " + game + " ] Button " + button + " pressed")
                self.publish(u'me.magbadge.app.' + game + '.user.button.down', badge.id, button, options=PublishOptions(exclude_me=False))

        else:
            debug(badge.id, "Button " + button + " released")
            self.publish(u'me.magbadge.app.' + game + '.user.button.up', badge.id, button, options=PublishOptions(exclude_me=False))

    @asyncio.coroutine
    def konami_button(self, sender, button):
        debug(sender, "konami! button " + button)
        if button == 'start':
            self.konami.players.remove(sender)
            yield from self.set_lights(sender, *((0,) * 12))
            yield from self.kick_player(sender)
        elif button == 'select':
            pass
        else:
            self.konami.color = Konami.COLOR_MAP[button]
            for badge_id in set(self.konami.players):
                yield from self.set_lights(badge_id, *(self.konami.color * 4))

    @asyncio.coroutine
    def konami_join(self, badge_id):
        debug(badge_id, "rainbowing")
        self.konami.add_player(badge_id)
        yield from self.rainbow(badge_id, 5000, 32, 128, 64)
        #yield from asyncio.sleep(2)
        yield from self.set_lights(badge_id, *(self.konami.color * 4))

    def send_packet(self, badge_id, packet):
        if badge_id in self.badge_ips:
            ip = self.badge_ips[badge_id]
            self.socket.sendto(b'\x00\x00\x00\x00\x00\x00' + packet, (ip, 8001))
        else:
            print("LOL NOPE CAN'T DO THAT")

    def request_scan(self, badge_id):
        debug(badge_id, "Requesting scan from {}".format(badge_id))
        self.send_packet(badge_id, b'\x04')

    def scan_all(self):
        for badge_id in set(self.badge_ips.keys()):
            self.request_scan(badge_id)

    def send_packet_all(self, packet):
        for badge_id in set(self.badge_ips.keys()):
            self.send_packet(badge_id, packet)

    @asyncio.coroutine
    def rainbow(self, badge_id, runtime=1000, speed=128, intensity=128, offset=0):
        #debug(badge_id, "RAINBOW " + badge_id)
        executor.submit(self.send_packet, badge_id, struct.pack(">BBBBHBBB", LED_RAINBOW_MODES, 0, 0, 0, runtime, speed, intensity, offset))

    @asyncio.coroutine
    def rainbow_all(self, *args, **kwargs):
        for badge_id in set(self.badge_ips.keys()):
            yield from self.rainbow(badge_id, *args, **kwargs)

    @asyncio.coroutine
    def set_lights_one(self, badge_id, r, g, b):
        #debug(badge_id, "Setting lights!")
        yield from self.rainbow(badge_id, 5000, 32, 128, 64)
        #executor.submit(self.send_packet, badge_id, bytes((LED_CONTROL, 0, 0, 0) + (g, r, b) * 4))

    @asyncio.coroutine
    def set_lights(self, badge_id, *colors):
        r1, g1, b1, r2, g2, b2, r3, g3, b3, r4, g4, b4 = colors
        #debug(badge_id, 'setting lights')
        executor.submit(self.send_packet, badge_id, bytes((LED_CONTROL, 0, 0, 0, g1, r1, b1, g2, r2, b2, g3, r3, b3, g4, r4, b4)))

    def rssi(self, badge_id, min=30, max=45, intensity=96):
        self.send_packet(badge_id, struct.pack('BbbB', LED_RSSI_MODE, min, max, intensity))

    def rssi_all(self, min=30, max=45, intensity=96):
        self.send_packet_all(b"\x03" + struct.pack('bbB', min, max, intensity))

    @asyncio.coroutine
    def set_lights_nogame(self, *args):
        for badge in DEBUG_BADGES:
            if not self.game_map[badge]:
                yield from self.set_lights(badge, *args)

    def save(self):
        print("DO NOT KILL, WRITING...")
        with open('state.json', 'w') as f:
            json.dump({
                'badge_ips': self.badge_ips,
                'join_codes': list(self.join_codes.items()),
                'game_map': self.game_map,
                'konami_players': list(self.konami.players)
            }, f)
        print("DONE!")

    @asyncio.coroutine
    def morse_code(self, text):
        print("morsing")
        morse = ' '.join([MORSE_CODE.get(c, '') for c in text.upper()])
        for char in morse:
            if char == '.':
                print("dot")
                yield from self.set_lights_nogame(*MORSE_ON)
                yield from asyncio.sleep(MORSE_DIT)
                yield from self.set_lights_nogame(*MORSE_OFF)
            elif char == '-':
                print("dash")
                yield from self.set_lights_nogame(*MORSE_ON)
                yield from asyncio.sleep(MORSE_DAH)
                yield from self.set_lights_nogame(*MORSE_OFF)
            elif char == ' ':
                print("space")
                yield from asyncio.sleep(MORSE_SPACE)

            if char != ' ':
                yield from asyncio.sleep(MORSE_CHAR)

    @asyncio.coroutine
    def onJoin(self, details):
        yield from self.subscribe(self.set_lights_one, u'me.magbadge.badge.lights')
        yield from self.subscribe(self.konami_button, u'me.magbadge.app.konami.user.button.down')
        yield from self.subscribe(self.konami_join, u'me.magbadge.app.konami.user.join')
        yield from self.subscribe(self.set_lights_nogame, u'me.magbadge.idle.lights')
        yield from self.subscribe(self.morse_code, u'me.magbadge.idle.morse_code')
        yield from self.register(self.request_joincode, u'me.magbadge.joincode.request')

        try:
            with open('state.json') as f:
                res = json.load(f)
                self.join_codes = dict(res.get('join_codes', {}))
                self.badge_ips = res.get('badge_ips', {})
                self.game_map = res.get('game_map', {})
                self.konami.players = set(res.get('konami_players', []))

            print("Pre-loaded {} players".format(len(self.badge_ips)))
        except OSError:
            pass

        counter = 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 8000))

        next_scan = time.time() - 1
        next_rssi = time.time() + 10000

        our_ip = socket.gethostbyname_ex(socket.gethostname())[2]

        threading.Thread(target=self.ping_all_the_things, daemon=True).start()
        threading.Thread(target=self.save_thread, daemon=True).start()

        self.socket = sock
        while True:
            try:
                data, (ip, port) = sock.recvfrom(1024)
                if ip in our_ip:
                    continue

                badge_id = format_mac(data[0:6])
                msg_type = data[6]
                packet = data[7:]
                status_count = int.from_bytes(packet[14:16], 'big') # update_id

                debug(badge_id, "STATUS: ", status_count)

                if badge_id not in self.badge_ips:
                    if not len(self.badge_ips) % 10:
                        print("{} clients".format(len(self.badge_ips)))
                    self.badge_ips[badge_id] = ip
                    self.game_map[badge_id] = None

                if badge_id not in self.badges:
                    self.badges[badge_id] = Badge(badge_id)

                badge = self.badges[badge_id]

                if msg_type == STATUS_UPDATE:
                    gpio_state, gpio_trigger, gpio_direction = packet[8], packet[9], packet[10]

                    if gpio_trigger:
                        button = BUTTON_NAMES[gpio_trigger]
                        if not gpio_direction:
                            badge.pings = 200
                            badge.buttons.append(gpio_trigger)

                        if self.game_map[badge_id]:
                            self.send_button_updates(self.game_map[badge_id], badge, button, gpio_direction)
                        else:
                            if not gpio_direction:
                                yield from self.check_joincode(badge)
                            else:
                                yield from self.rainbow(badge_id, 100, 32, 32, 0)

                    elif not gpio_state and not self.game_map[badge_id]:
                        debug(badge_id, 'no gpio received and game map is', self.game_map[badge_id])
                        yield from self.set_lights(badge_id, *self.default_color)

                elif msg_type == WIFI_UPDATE_REPLY and False:
                    print("Got wifi reply: ".format(packet))
                    scan_id = int.from_bytes(packet[0:4], 'big')
                    scan_len = packet[4]

                    if scan_id not in self.wifi_scans:
                        self.wifi_scans[scan_id] = []

                    print("Got scan of {} SSIDs from {}".format(scan_len, badge_id))

                    if scan_len:
                        for i in range(scan_len):
                            self.wifi_scans[scan_id].append((packet[5+8*i:11+8*i], packet[12+8*i]-128))
                    if scan_len == 0 or scan_len <= 47:
                        if scan_id in self.wifi_scans:
                            self.scan_complete(badge_id, scan_id)
                        else:
                            print("[WARN]: Got WIFI UPDATE END for nonexistent scan ID")

                if time.time() > next_scan:
                    next_scan = time.time() + SCAN_INTERVAL
                    try:
                        self.scan_all()
                    except:
                        traceback.print_exc()
            except KeyboardInterrupt:
                self.save()
                break
            except:
                traceback.print_exc()
            yield from asyncio.sleep(.001)

    def scan_complete(self, badge_id, scan_id):
        print("Sending off scan with #{} SSIDs".format(len(self.wifi_scans[scan_id])))
        if len(self.wifi_scans[scan_id]):
            self.publish(u'me.magbadge.badge.scan', badge_id, [{"mac": format_mac(mac), "rssi": rssi} for mac, rssi in self.wifi_scans[scan_id]])
        del self.wifi_scans[scan_id]

runner = ApplicationRunner(u"ws://badges.magevent.net:8080/ws", u"MAGBadges",)
runner.run(Component)

