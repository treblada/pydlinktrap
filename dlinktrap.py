#!/usr/bin/env python3

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import base64
import configparser
import logging
import os
import re
import signal
import socket
import subprocess
import syslog
import typing
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum, unique

logging.basicConfig(level=logging.ERROR)


@dataclass
class ALevel:
    logging: int
    syslog: int


@unique
class Level(Enum):
    """
    Available logging levels, combining the values for logging and syslog
    module.
    """
    DEBUG = ALevel(logging.DEBUG, syslog.LOG_DEBUG)
    INFO = ALevel(logging.INFO, syslog.LOG_INFO)
    WARNING = ALevel(logging.WARNING, syslog.LOG_WARNING)
    ERROR = ALevel(logging.ERROR, syslog.LOG_ERR)


@dataclass()
class Config:
    """
    Internal configuration built from config file and command line arguments.
    """
    port: int
    log_level: Level
    bind_addr: str
    max_threads: int
    use_syslog: bool
    dump_payload: bool
    dump_on_error: bool
    timeout: int
    program: str = None


class MacAddress:
    """
    A MAC address built from 6 bytes.
    """

    def __init__(self, data: bytes):
        assert len(data) == 6, f"MAC consists of 6 octets, not {len(data)}"
        self.__data = data

    def __repr__(self) -> str:
        return ":".join("%02x" % b for b in self.__data)


class IpAddress:
    """A IP address build from 4 bytes"""

    def __init__(self, data: bytes):
        assert len(data) == 4, f"MAC consists of 4 octets, not {len(data)}"
        self.__data = data

    def __repr__(self) -> str:
        return ".".join("%d" % b for b in self.__data)


@dataclass
class SmartConsoleMessage:
    """
    Information extracted from the received message
    """
    src_mac: MacAddress = None
    src_address: str = None
    src_port: int = -1
    dst_address: IpAddress = None
    device_type: str = None
    msg: str = None
    msg_code: str = None
    dst_mac: MacAddress = None

    def as_environment_dict(self) -> dict:
        environment = {
            "DLINKTRAP_SRC_MAC": str(self.src_mac),
            "DLINKTRAP_SRC_ADDR": str(self.src_address),
            "DLINKTRAP_SRC_PORT": str(self.src_port),
            "DLINKTRAP_DST_ADDR": str(self.dst_address),
            "DLINKTRAP_DEVICE_TYPE": str(self.device_type),
            "DLINKTRAP_MSG": self.msg
        }
        if self.dst_mac:
            environment["DLINKTRAP_DST_MAC"] = str(self.dst_mac)
        if self.msg_code:
            environment["DLINKTRAP_MSG_CODE"] = str(self.msg_code)
        return environment


DEFAULT_PORT = 64514
DEFAULT_CONFIG_PATH = "/etc/dlinktrap.ini"
DEFAULT_LOG_LEVEL = Level.ERROR.name
DEFAULT_MAX_THREADS = 3
DEFAULT_EXEC_TIMEOUT = 10
VALID_LOG_LEVELS=["ERROR", "WARNING", "INFO", "DEBUG"]
SECTION_MAIN = "main"

CONFIG: typing.Optional[Config] = None
LOGGER: typing.Optional[logging.Logger] = None


def build_config(cli_config: argparse.Namespace, file_config: configparser.ConfigParser) -> Config:
    """
    Builds a resulting config from pre-parsed CLI and config file components.
    :param cli_config: pre-parsed CLI configuration.
    :param file_config: parsed file configuration (may be empty)
    :return: program configuration
    """
    return Config(
        port=cli_config.port or file_config.getint(SECTION_MAIN, "port", fallback=DEFAULT_PORT),
        log_level=Level[
            (cli_config.log_level or file_config.get(SECTION_MAIN, "loglevel", fallback=DEFAULT_LOG_LEVEL)).upper()
        ],
        bind_addr=cli_config.bind_addr or file_config.get(SECTION_MAIN, "bind", fallback=""),
        max_threads=cli_config.max_threads or
                    file_config.getint(SECTION_MAIN, "max-threads", fallback=DEFAULT_MAX_THREADS),
        timeout=cli_config.timeout or file_config.getint(SECTION_MAIN, "timeout", fallback=DEFAULT_EXEC_TIMEOUT),
        use_syslog=cli_config.use_syslog or file_config.getboolean(SECTION_MAIN, "syslog", fallback=False),
        dump_payload=cli_config.dump_payload or file_config.getboolean(SECTION_MAIN, "dump-payload", fallback=False),
        dump_on_error=cli_config.dump_on_error or file_config.getboolean(SECTION_MAIN, "dump-on-error", fallback=False),
        program=cli_config.program or file_config.get(SECTION_MAIN, "execute", fallback=None)
    )


def log(level: Level, msg_format: str, *format_args, exc_info=None) -> None:
    if CONFIG.use_syslog:
        syslog.syslog(level.value.syslog, str(exc_info) if exc_info else msg_format % format_args)
    else:
        LOGGER.log(level.value.logging, msg_format, *format_args, exc_info=exc_info)


def dump_payload(level: Level, payload: bytes) -> None:
    msg = "UDP:" + base64.standard_b64encode(payload).decode("ascii")
    if CONFIG.use_syslog:
        syslog.syslog(level.value.syslog, msg)
    else:
        LOGGER.log(level.value.logging, msg)


def process(payload: bytes, src_addr: str, src_port: int):
    log(Level.INFO, "Processing message from %s:%d", src_addr, src_port)
    if CONFIG.dump_payload:
        dump_payload(Level.DEBUG, payload)

    try:
        process_internal(payload, src_addr, src_port)
    except Exception as exception:
        log(Level.ERROR, "Error processing message from %s:%s", src_addr, src_port, exc_info=exception)
        if CONFIG.dump_on_error:
            dump_payload(Level.ERROR, payload)


def process_internal(payload: bytes, src_addr: str, src_port: int):
    result = parse_payload(payload, src_addr, src_port)

    environment = {k: v for k, v in os.environ.items()}
    environment.update(result.as_environment_dict())

    log(Level.INFO, str(result))

    if CONFIG.program:
        log(Level.DEBUG, "Calling external program %s", CONFIG.program)
        result = subprocess.run(
            [CONFIG.program],
            env=environment,
            capture_output=True,
            timeout=CONFIG.timeout,
            text=True
        )
        if result.returncode != 0:
            raise Exception(
                "%s exit code %d: [%s] [%s]",
                CONFIG.program,
                result.returncode,
                result.stdout.strip(),
                result.stderr.strip()
            )


def parse_payload(payload, src_addr: str, src_port: int):
    result = SmartConsoleMessage()
    result.src_address = src_addr
    result.src_port = src_port
    result.src_mac = MacAddress(cut(payload, 4, 6))
    magic_byte = payload[0xb]  # 3 for DGS-1224T, 4 for DGS-1100-08

    if magic_byte == 4:
        result.dst_mac = MacAddress(cut(payload, 0x14, 6))  # only for magic_byte = 4
        result.dst_address = IpAddress(cut(payload, 0x2c, 4))
        raw_msg = payload[0x49:len(payload)]
        result.msg = raw_msg.decode("iso-8859-1")
        raw_type = payload[0x34:payload.index(b'\x00', 0x34)]
        result.device_type = raw_type.decode("iso-8859-1")
    else:
        result.dst_address = IpAddress(cut(payload, 0x28, 4))
        raw_msg = payload[0x2c:len(payload)]
        raw_msg_str = raw_msg.decode("iso-8859-1")
        matcher = re.match("^(\\S+)\\s+\\((\\d+)\\)(.+)$", raw_msg_str)
        if matcher:
            result.device_type = matcher.group(1)
            result.msg_code = int(matcher.group(2))
            result.msg = matcher.group(3)
    result.device_type = remove_unprintable_chars(result.device_type)
    result.msg = remove_unprintable_chars(result.msg)
    return result


def cut(chunk: bytes, offset: int, length: int) -> bytes:
    assert offset >= 0
    assert length >= 0
    assert len(chunk) >= offset + length
    return chunk[offset:offset + length]


def remove_unprintable_chars(string: str) -> str:
    return string.translate({i: None for i in range(0, 32)})


def parse_cli_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="""This program is intended to be run as a daemon.
It will listen to a UDP port (64514 by default) expecting messages for D-Link
SmartConsole application. From there different actions can be triggered.""")
    parser.add_argument("-p", "--port", dest="port", type=int,
                        help=f"UDP port to listen to (default: {DEFAULT_PORT})")
    parser.add_argument("-c", "--config", dest="config", type=str, metavar="CONFIG_PATH", default=DEFAULT_CONFIG_PATH,
                        help="Path to the configuration file (default: %(default)s)")
    parser.add_argument("-l", "--loglevel", dest="log_level", type=str, metavar="LEVEL", choices=VALID_LOG_LEVELS,
                        help=f"The loglevel to use. Valid levels are: %(choices)s. (default: {DEFAULT_LOG_LEVEL})")
    parser.add_argument("-b", "--bind", dest="bind_addr", type=str,
                        help="Optional IP address to bind to. By default, we bind to all available addresses.")
    parser.add_argument("-e", "--execute", dest="program", type=str, metavar="PROGRAM",
                        help="Executes an external program. "
                             "The message's contents are passed as environment variables. "
                             "DLINKTRAP_SRC_MAC - Source MAC address; "
                             "DLINKTRAP_SRC_ADDR - Source address; "
                             "DLINKTRAP_SRC_PORT - Source port; "
                             "DLINKTRAP_DST_MAC - Destination MAC address (optional); "
                             "DLINKTRAP_DST_ADDR - Original destination IP address; "
                             "DLINKTRAP_DEVICE_TYPE - Device type; "
                             "DLINKTRAP_MSG - The transmitted message; "
                             "DLINKTRAP_MSG_CODE: "
                             "1001 - System bootup, "
                             "1002 - WEB authenticate error, "
                             "3003 - Port *X* copper link up, "
                             "3004 - Port *X* copper link down, "
                             "5001 -  Firmware upgraded success, "
                             "5002 - Firmware upgraded failure, "
                             "5005 - Wrong file checksum causes firmware upgrade failure"
                        )
    parser.add_argument("-m", "--max-threads", dest="max_threads", type=int,
                        help=f"Maximal number of processing threads. (default: {DEFAULT_MAX_THREADS})")
    parser.add_argument("-t", "--timeout", dest="timeout", type=int,
                        help="Timeout (ins seconds) for the external command to complete. "
                             f"(default: {DEFAULT_EXEC_TIMEOUT})")
    parser.add_argument("-s", "--syslog", dest="use_syslog", default=False, action="store_true",
                        help="Use syslog to log incoming messages.")
    parser.add_argument("--dump-payload", dest="dump_payload", default=False, action="store_true",
                        help="Always dump the received message(base64 encoded).")
    parser.add_argument("--dump-on-error", dest="dump_on_error", default=False, action="store_true",
                        help="Dump the received message if there were errors (base64 encoded).")
    return parser.parse_args()


def parse_config_file(config_file_name: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.default_section = SECTION_MAIN

    if config_file_name is None:
        pass
    elif not os.path.isfile(config_file_name):
        LOGGER.warning("Configuration '%s' not found", config_file_name)
    else:
        parser.read(config_file_name)

    return parser


if __name__ == '__main__':
    LOGGER = logging.getLogger("dlinktrap")
    LOGGER.setLevel(logging.WARNING)

    cli_config = parse_cli_args()
    file_config = parse_config_file(cli_config.config)
    CONFIG = build_config(cli_config, file_config)

    LOGGER.setLevel(CONFIG.log_level.value.logging)

    do_run = True


    def signal_handler(signum, frame):
        global do_run
        if signum == signal.SIGTERM:
            logging.info("Received SIGTERM")
            do_run = False


    syslog.openlog(facility=syslog.LOG_DAEMON)
    signal.signal(signal.SIGTERM, signal_handler)

    log(Level.DEBUG, "Configuring socket ...")
    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    sock.settimeout(1)
    sock.bind((CONFIG.bind_addr, CONFIG.port))

    executor = ThreadPoolExecutor(max_workers=CONFIG.max_threads)
    log(Level.DEBUG, "Starting listening on %s:%d ...", CONFIG.bind_addr if CONFIG.bind_addr else "(all)", CONFIG.port)
    while do_run:
        try:
            data, (src_addr, src_port) = sock.recvfrom(2048)
            executor.submit(process, data, src_addr, src_port)
        except KeyboardInterrupt:
            do_run = False
        except socket.timeout:
            pass

    log(Level.INFO, "Shutting down")
    executor.shutdown()
    log(Level.DEBUG, "Closing socket")
    sock.close()
