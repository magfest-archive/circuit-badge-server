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

SCAN_INTERVAL = 600
WIFI_INTERVAL = 10000

executor = concurrent.futures.ThreadPoolExecutor(max_workers=32)

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
        self.ip = None

    def newer_than(self, other):
        return self.status_count > other.status_count \
               or (self.status_count < 64 and other.status_count >= 2 ** 16 - 64)


def format_mac(mac):
    return ':'.join(('%02X' % d for d in mac))


class Component(ApplicationSession):
    wifi_scans = {}
    badge_states = {}
    socket = None

    def send_button_updates(self, badge_id, gpio_trigger, trigger_direction):
        if gpio_trigger:

            if trigger_direction:
                print(BUTTON_NAMES[gpio_trigger] + " down")
                self.publish(u'me.magbadge.badge.button.down', format_mac(badge_id), BUTTON_NAMES[gpio_trigger])
            else:
                self.publish(u'me.magbadge.badge.button.up', format_mac(badge_id), BUTTON_NAMES[gpio_trigger])

    def send_packet(self, badge_id, packet):
        print("SENDING", packet)
        if badge_id in self.badge_states:
            ip = self.badge_states[badge_id]
            self.socket.sendto(b'\x00\x00\x00\x00\x00\x00' + packet, (ip, 8001))

    def request_scan(self, badge_id):
        print("Requesting scan from {}".format(badge_id))
        self.send_packet(badge_id, b'\x04')

    def scan_all(self):
        for badge_id in set(self.badge_states.keys()):
            self.request_scan(badge_id)

    def send_packet_all(self, packet):
        for badge_id in set(self.badge_states.keys()):
            self.send_packet(badge_id, packet)

    @asyncio.coroutine
    def set_lights_one(self, badge_id, r, g, b):
        print("Setting lights!")
        self.rssi(badge_id)
        #executor.submit(self.send_packet, badge_id, bytes((LED_CONTROL, 0, 0, 0) + (g, r, b) * 4))

    @asyncio.coroutine
    def set_lights(self, badge_id, *colors):
        r1, g1, b1, r2, g2, b2, r3, g3, b3, r4, g4, b4 = colors
        self.send_packet(badge_id, bytes((LED_CONTROL, 0, 0, 0, g1, r1, b1, g2, r2, b2, g3, r3, b3, g4, r4, b4)))

    def rssi(self, badge_id, min=30, max=45, intensity=96):
        self.send_packet(badge_id, struct.pack('BbbB', LED_RSSI_MODE, min, max, intensity))

    def rssi_all(self, min=30, max=45, intensity=96):
        self.send_packet_all(b"\x03" + struct.pack('bbB', min, max, intensity))

    @asyncio.coroutine
    def onJoin(self, details):
        yield from self.subscribe(self.set_lights_one, u'me.magbadge.badge.lights')

        counter = 0
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 8000))

        next_scan = time.time() - 1
        next_rssi = time.time() - 1

        our_ip = socket.gethostbyname_ex(socket.gethostname())[2]

        self.socket = sock
        while True:
            try:
                data, (ip, port) = sock.recvfrom(1024)
                if ip in our_ip:#socket.gethostbyname_ex(socket.gethostname())[2]:
                    continue
                #print("Received udp message from {0}: {1}".format(addr, data))

                badge_id = data[0:6]
                msg_type = data[6]
                packet = data[7:]

                if msg_type == STATUS_UPDATE:
                    #print("Got status update: ".format(packet))
                    gpio_state, gpio_trigger, gpio_direction = packet[8], packet[9], packet[10]

                    if badge_id not in self.badge_states:# or next_state.newer_than(self.badge_states[badge_id]):
                        #print("{} clients".format(len(self.badge_states)))
                        self.badge_states[badge_id] = ip

                    self.send_button_updates(badge_id, gpio_trigger, gpio_direction)

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
                if time.time() > next_rssi:
                    MESSAGE = [LED_CONTROL, 0x0, 0x00, 0, ]
                    leds = [[0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0]]
                    for i in leds:
                        MESSAGE.extend(i)

                    self.send_packet(badge_id, bytes(MESSAGE))
                                #b"\x00\x00\x00" + struct.pack("bbbbbbbbbbbb", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
                    next_rssi = time.time() + WIFI_INTERVAL
                    #self.rssi_all(30, 45, 96)
            except KeyboardInterrupt:

                break
            except:
                traceback.print_exc()
            yield from asyncio.sleep(.01)

    def scan_complete(self, badge_id, scan_id):
        print("Sending off scan with #{} SSIDs".format(len(self.wifi_scans[scan_id])))
        if len(self.wifi_scans[scan_id]):
            self.publish(u'me.magbadge.badge.scan', format_mac(badge_id), [{"mac": format_mac(mac), "rssi": rssi} for mac, rssi in self.wifi_scans[scan_id]])
        del self.wifi_scans[scan_id]

runner = ApplicationRunner(u"ws://badges.magevent.net:8080/ws", u"MAGBadges",)
runner.run(Component)

