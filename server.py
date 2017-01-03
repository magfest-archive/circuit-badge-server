from os import environ

import asyncio
from autobahn.asyncio.wamp import ApplicationSession, ApplicationRunner
import socket
import struct
import time

BUTTON_RIGHT = 1
BUTTON_DOWN = 2
BUTTON_LEFT = 4
BUTTON_UP = 8
BUTTON_SELECT = 16
BUTTON_START = 32
BUTTON_B = 64
BUTTON_A = 128

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

STATUS_UPDATE = 1
WIFI_UPDATE = 2
WIFI_UPDATE_END = 3


class BadgeState:
    @classmethod
    def from_bytes(cls, packet):
        res = cls(
            packet[0], # wifi_power
            packet[1], # gpio_state
            packet[2], # gpio_trigger
            packet[3], # trigger_direction
            packet[4], # led_power
            int.from_bytes(packet[5:7], 'big'), # battery_voltage
            int.from_bytes(packet[7:9], 'big'), # status_count (sequence number)
        )

        return res

    def __init__(self, wifi_power, gpio_state, gpio_trigger, trigger_direction, led_power, battery_voltage, status_count):
        self.wifi_power = wifi_power
        self.gpio_state = gpio_state
        self.gpio_trigger = gpio_trigger
        self.trigger_direction = trigger_direction
        self.led_power = led_power
        self.battery_voltage = battery_voltage
        self.status_count = status_count
        self.last_update = time.time()

    def newer_than(self, other):
        return self.status_count > other.status_count \
               or (self.status_count < 64 and other.status_count >= 2 ** 16 - 64)


def format_mac(mac):
    return ':'.join(('%02X' % d for d in mac))


class Component(ApplicationSession):
    wifi_scans = {}
    badge_states = {}

    def send_button_updates(self, badge_id, state):
        if state.gpio_trigger:
            for i in range(8):
                if state.gpio_trigger & (1<<i):
                    if state.trigger_direction & (1<<i):
                        self.publish(u'me.magbadge.badge.button.down', format_mac(badge_id), BUTTON_NAMES[1<<i])
                    else:
                        self.publish(u'me.magbadge.badge.button.up', format_mac(badge_id), BUTTON_NAMES[1<<i])

    async def onJoin(self, details):
        counter = 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 8000))
        while True:
            data, addr = sock.recvfrom(1024)
            if addr[0] in socket.gethostbyname_ex(socket.gethostname())[2]:
                continue
            print("Received udp message from {0}: {1}".format(addr, data))

            badge_id = data[0:6]
            msg_type = data[6]
            packet = data[7:]

            if msg_type == STATUS_UPDATE:
                next_state = BadgeState.from_bytes(packet)

                if badge_id not in self.badge_states or next_state.newer_than(self.badge_states[badge_id]):
                    self.badge_states[badge_id] = next_state

                self.send_button_updates(badge_id, next_state)

            elif msg_type == WIFI_UPDATE:
                scan_id = int.from_bytes(packet[0:6], 'big')
                scan_len = int.from_bytes(packet[6:8], 'big')

                if scan_id not in self.wifi_scans:
                    self.wifi_scans[scan_id] = []

                for i in range(scan_len):
                    self.wifi_scans[scan_id].append((packet[8+7*i:15+7*i], struct.unpack('b', packet[16+7*i:17+7*i])[0]))

            elif msg_type == WIFI_UPDATE_END:
                if scan_id in self.wifi_scans:
                    self.scan_complete(badge_id, scan_id)
                else:
                    print("[WARN]: Got WIFI UPDATE END for nonexistent scan ID")

    def scan_complete(self, badge_id, scan_id):
        self.publish(u'me.magbadge.badge.scan', format_mac(badge_id), [{"mac": format_mac(mac), "rssi": rssi} for mac, rssi in self.wifi_scans[scan_id]])
        del self.wifi_scans[scan_id]

runner = ApplicationRunner(u"ws://badges.magevent.net:8080/ws", u"MAGBadges",)
runner.run(Component)

