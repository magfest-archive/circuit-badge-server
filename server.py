from os import environ

import asyncio
from autobahn.asyncio.wamp import ApplicationSession, ApplicationRunner
import socket
import struct
from autobahn import wamp
import time

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

STATUS_UPDATE = 1
LED_CONTROL = 2
LED_RSSI_MODE = 3
WIFI_UPDATE = 4
WIFI_UPDATE_REPLY = 5
LED_RAINBOW_MODES = 7
CONFIGURE = 8
DEEP_SLEEP = 9

class BadgeState:
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
            int.from_bytes(packet[14:16], 'big'), # update_id
            int.from_bytes(packet[16:18], 'big'), # heap_free
            packet[18], # sleep_performance
            int.from_bytes(packet[20:24], 'big'), # status_count
        )

        return res

    def __init__(self, wifi_power, connected_bssid, gpio_state, gpio_trigger, trigger_direction, led_power, battery_voltage, update_id, heap_free, sleep_performance, status_count):
        self.wifi_power = wifi_power
        self.connected_bssid = connected_bssid
        self.gpio_state = gpio_state
        self.gpio_trigger = gpio_trigger
        self.trigger_direction = trigger_direction
        self.led_power = led_power
        self.battery_voltage = battery_voltage
        self.update_id = update_id
        self.heap_free = heap_free
        self.sleep_performance = sleep_performance
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
        print(state)
        if state.gpio_trigger:
            print(state.trigger_direction)

            if state.trigger_direction:
                self.publish(u'me.magbadge.badge.button.down', format_mac(badge_id), BUTTON_NAMES[state.gpio_trigger])
            else:
                self.publish(u'me.magbadge.badge.button.up', format_mac(badge_id), BUTTON_NAMES[state.gpio_trigger])

    @asyncio.coroutine
    def onJoin(self, details):
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
                print("Got status update: ".format(packet))
                next_state = BadgeState.from_bytes(packet)

                if badge_id not in self.badge_states or next_state.newer_than(self.badge_states[badge_id]):
                    self.badge_states[badge_id] = next_state

                self.send_button_updates(badge_id, next_state)

            elif msg_type == WIFI_UPDATE_REPLY:
                print("Got wifi reply: ".format(packet))
                scan_id = int.from_bytes(packet[0:4], 'big')
                scan_len = int.from_bytes(packet[4], 'big')

                if scan_id not in self.wifi_scans:
                    self.wifi_scans[scan_id] = []

                print("Got scan of {} SSIDs from {}".format(scan_len, badge_id))

                if scan_len:
                    for i in range(scan_len):
                        self.wifi_scans[scan_id].append((packet[5+8*i:11+8*i], packet[12+8*i]-128))
                else:
                    if scan_id in self.wifi_scans:
                        self.scan_complete(badge_id, scan_id)
                    else:
                        print("[WARN]: Got WIFI UPDATE END for nonexistent scan ID")

    @wamp.subscribe(u'me.magbadge.badge.led_update', )

    def scan_complete(self, badge_id, scan_id):
        self.publish(u'me.magbadge.badge.scan', format_mac(badge_id), [{"mac": format_mac(mac), "rssi": rssi} for mac, rssi in self.wifi_scans[scan_id]])
        del self.wifi_scans[scan_id]

runner = ApplicationRunner(u"ws://badges.magevent.net:8080/ws", u"MAGBadges",)
runner.run(Component)

