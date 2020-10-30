# Copyright 2020 Damien Braillard
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import logging
from binascii import hexlify
from enum import IntEnum
from functools import reduce
from typing import Tuple, Type, Union

log = logging.getLogger(__name__)

# CRC-8-CCIT polynomial table. Source: https://gist.github.com/hypebeast/3833758
# fmt: off
__CRC_TABLE = [
    0x00, 0x07, 0x0e, 0x09, 0x1c, 0x1b, 0x12, 0x15, 0x38, 0x3f, 0x36, 0x31, 0x24, 0x23, 0x2a, 0x2d,
    0x70, 0x77, 0x7e, 0x79, 0x6c, 0x6b, 0x62, 0x65, 0x48, 0x4f, 0x46, 0x41, 0x54, 0x53, 0x5a, 0x5d,
    0xe0, 0xe7, 0xee, 0xe9, 0xfc, 0xfb, 0xf2, 0xf5, 0xd8, 0xdf, 0xd6, 0xd1, 0xc4, 0xc3, 0xca, 0xcd,
    0x90, 0x97, 0x9e, 0x99, 0x8c, 0x8b, 0x82, 0x85, 0xa8, 0xaf, 0xa6, 0xa1, 0xb4, 0xb3, 0xba, 0xbd,
    0xc7, 0xc0, 0xc9, 0xce, 0xdb, 0xdc, 0xd5, 0xd2, 0xff, 0xf8, 0xf1, 0xf6, 0xe3, 0xe4, 0xed, 0xea,
    0xb7, 0xb0, 0xb9, 0xbe, 0xab, 0xac, 0xa5, 0xa2, 0x8f, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9d, 0x9a,
    0x27, 0x20, 0x29, 0x2e, 0x3b, 0x3c, 0x35, 0x32, 0x1f, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0d, 0x0a,
    0x57, 0x50, 0x59, 0x5e, 0x4b, 0x4c, 0x45, 0x42, 0x6f, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7d, 0x7a,
    0x89, 0x8e, 0x87, 0x80, 0x95, 0x92, 0x9b, 0x9c, 0xb1, 0xb6, 0xbf, 0xb8, 0xad, 0xaa, 0xa3, 0xa4,
    0xf9, 0xfe, 0xf7, 0xf0, 0xe5, 0xe2, 0xeb, 0xec, 0xc1, 0xc6, 0xcf, 0xc8, 0xdd, 0xda, 0xd3, 0xd4,
    0x69, 0x6e, 0x67, 0x60, 0x75, 0x72, 0x7b, 0x7c, 0x51, 0x56, 0x5f, 0x58, 0x4d, 0x4a, 0x43, 0x44,
    0x19, 0x1e, 0x17, 0x10, 0x05, 0x02, 0x0b, 0x0c, 0x21, 0x26, 0x2f, 0x28, 0x3d, 0x3a, 0x33, 0x34,
    0x4e, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5c, 0x5b, 0x76, 0x71, 0x78, 0x7f, 0x6a, 0x6d, 0x64, 0x63,
    0x3e, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2c, 0x2b, 0x06, 0x01, 0x08, 0x0f, 0x1a, 0x1d, 0x14, 0x13,
    0xae, 0xa9, 0xa0, 0xa7, 0xb2, 0xb5, 0xbc, 0xbb, 0x96, 0x91, 0x98, 0x9f, 0x8a, 0x8d, 0x84, 0x83,
    0xde, 0xd9, 0xd0, 0xd7, 0xc2, 0xc5, 0xcc, 0xcb, 0xe6, 0xe1, 0xe8, 0xef, 0xfa, 0xfd, 0xf4, 0xf3
]


# fmt: on


def _crc8(buffer: memoryview):
    """Calculates the CRC8 checksum for an array of bytes

    :param buffer: The bytes for which to calculate the checksum
    :return byte A byte that is the CRC8 checksum value of the specified buffer.
    """
    return reduce(lambda s, v: __CRC_TABLE[s ^ v], buffer, 0x00)


class Esp3ParseResult(IntEnum):
    Success = 1
    BadCRC = 2
    NotEnoughData = 3
    NoPacket = 4


class Esp3PacketType(IntEnum):
    Unknown = 0x00
    RadioERP1 = 0x01
    Response = 0x02
    RadioSubTel = 0x03
    Event = 0x04
    CommonCommand = 0x05
    SmartAckCommand = 0x06
    RemoteManCommand = 0x07
    RadioMessage = 0x09
    RadioERP2 = 0x0A
    ConfigCommand = 0x0B
    CommandAccepted = 0x0C
    Radio802_15_4 = 0x10
    Radio2_4 = 0x11


class Esp3Packet:
    """
    Processes and stores a raw ESP3 packet

    For details about the packet structure and encoding, refer to the EnOcean ERP3 documentation:
    https://www.enocean.com/fileadmin/redaktion/pdf/tec_docs/EnOceanSerialProtocol3.pdf
    """

    data: bytes
    optional_data: bytes
    raw_packet_type: int
    packet_type: Esp3PacketType

    def __init__(
        self,
        packet_type: Union[int, Esp3PacketType],
        data: Union[bytes, None],
        optional_data: Union[bytes, None],
    ) -> None:
        """
        Initialize a new instance of the class

        :param bytes data: The data bytes from the "data" section of the ESP3 packet
        :param bytes optional_data: The data bytes from the "optional data" section of the ESP3 packet.
        :param int packet_type: The type of the ESP3 packet as defined in the protocol document
        """

        self.data = data if data is not None else b""
        self.optional_data = optional_data if optional_data is not None else b""
        self.raw_packet_type = int(packet_type)
        try:
            self.packet_type = Esp3PacketType(self.raw_packet_type)
        except ValueError:
            self.packet_type = Esp3PacketType.Unknown

    @classmethod
    def try_decode(
        cls, buffer: bytearray
    ) -> Tuple[Esp3ParseResult, int, Union[Type["Esp3Packet"], None]]:
        """
        Attempts to parse an ESP3 packet from the specified buffer
        and remove the parsed bytes form the buffer if the operation was successful.

        The method searches for the first synchronization byte 0x55 in the buffer and then
        tries to parse the packet from here.

        If the 0x55 synchronization byte is not the first byte of the buffer,
        all the bytes before the packet are also removed. This is to avoid a failed
        parse attempt because of garbage data

        Beware that, when the method returns and a packet was found and parsed,
        the content of buffer is modified so that the data used for parsing is removed.

        :param bytearray buffer: The buffer of bytes to examine and to modify in case of successful parse
        :returns (int, Esp3Packet): A tuple that contains:
                                    parse_result, consumed_bytes_count, parsed_packet
                                    The parsed_packet is None if parse_result is anything else than
                                    Esp3ParseResult.Success
        """

        log.debug(f"Processing raw ESP3 buffer: {hexlify(buffer)}")

        # Searches the start of the packet and uses all bytes before the sync byte
        # If we can't find a sync byte, we consume the whole data. We can't do anything with this garbage.
        used_len = buffer.find(0x55)
        if used_len < 0:
            if logging.INFO >= log.level:
                log.info(
                    f"No start byte 0x55 found. No ESP3 packet found in buffer: {hexlify(buffer)} "
                )
            return Esp3ParseResult.NoPacket, len(buffer), None

        # From there, we'll use a memory view to avoid data copy
        buffer_view = memoryview(buffer)

        # Parse/check the header. Except if result is not enough data, we consume the header
        (
            parse_result,
            packet_type,
            data_len,
            optional_len,
        ) = Esp3Packet.__try_decode_header(buffer_view[used_len:])
        if parse_result != Esp3ParseResult.NotEnoughData:
            used_len += 6

        # Now parse the data and construct the packet if successful
        packet = None
        if parse_result == Esp3ParseResult.Success:
            # Parse/check the data. Except if result is not enough data, we consume the data, optional data and CRC
            parse_result, data, optional = Esp3Packet.__try_decode_data(
                buffer_view[used_len:], data_len, optional_len
            )
            if parse_result != Esp3ParseResult.NotEnoughData:
                used_len += data_len + optional_len + 1

            # Create the packet if we have a success
            if parse_result == Esp3ParseResult.Success:
                packet = Esp3Packet(packet_type, data, optional)
                log.info(f"Packet parse successful: {str(packet)}")
            else:
                log.info(f"Packet body decoding inconclusive: {str(parse_result)}")
        else:
            log.info(f"Packet header decoding inconclusive: {str(parse_result)}")

        # Done, we now extend the used data up-to the next sync byte (we skip all the garbage after the used data)
        used_len = buffer.find(0x55, used_len)
        if used_len < 0:
            used_len = len(buffer)
        log.debug(f"Parse outcome is {str(parse_result)} with {used_len} used bytes")
        return parse_result, used_len, packet

    @staticmethod
    def __try_decode_header(
        buffer: memoryview,
    ) -> Tuple[Esp3ParseResult, int, int, int]:
        """
        Attempts to decode a packet header at the start of the specified buffer

        :param buffer: The buffer that starts with the sync byte 0x55
        :returns (Esp3ParseResult, int, int, int): A tuple that contains:
                                       result, packet_type, data_length, optional_length.
                                       If parsing failed, packet_type, data_length, and optional_length
                                       are all set to -1
        """

        # Check that the buffer is at least 6 bytes and starts with the sync byte
        if len(buffer) < 6:
            return Esp3ParseResult.NotEnoughData, -1, -1, -1

        # Parse the header
        data_len = buffer[1] << 8 | buffer[2]
        optional_len = buffer[3]
        packet_type = buffer[4]
        crc = buffer[5]

        # Verify the CRC
        crc_data = buffer[1:5]
        expected_crc = _crc8(crc_data)
        if crc != expected_crc:
            if logging.DEBUG >= log.level:
                log.debug(
                    f"Expected header CRC {hex(expected_crc)} but got {crc} "
                    f"for data {hexlify(bytes(crc_data))}"
                )
            return Esp3ParseResult.BadCRC, -1, -1, -1

        log.debug(
            f"Header decoded for packet type {packet_type}: {data_len} bytes of data and {optional_len} bytes of "
            f"optional data"
        )
        return Esp3ParseResult.Success, packet_type, data_len, optional_len

    @staticmethod
    def __try_decode_data(
        buffer: memoryview, data_len, optional_len
    ) -> Tuple[Esp3ParseResult, bytes, bytes]:
        """
        Attempts to extract the packet data at the start of the specified buffer

        :param buffer: The buffer that starts with the sync byte 0x55
        :param data_len: The length of the packet data section
        :param optional_len: The length of the optional packet data section
        :returns (Esp3ParseResult, bytearray, bytearray): A tuple that contains:
                                       used_bytes, data_buffer, optional_buffer.
                                       If parsing failed, data_buffer and optional_buffer are all empty
        """

        # Check that the buffer contains at least the two data sections and an extra CRC bytes
        if len(buffer) < data_len + optional_len + 1:
            return Esp3ParseResult.NotEnoughData, b"", b""

        # Verify the CRC
        crc = buffer[data_len + optional_len]
        crc_data = buffer[: data_len + optional_len]
        expected_crc = _crc8(crc_data)
        if crc != expected_crc:
            if logging.DEBUG >= log.level:
                log.debug(
                    f"Expected body CRC {hex(expected_crc)} but got {crc} "
                    f"for data {hexlify(bytes(crc_data))}"
                )
            return Esp3ParseResult.BadCRC, b"", b""

        data = bytes(buffer[:data_len])
        optional = bytes(buffer[data_len : data_len + optional_len])

        return Esp3ParseResult.Success, data, optional

    def __repr__(self) -> str:
        return (
            f"ESP3: "
            f"Type={self.raw_packet_type} ({str(self.packet_type)}), "
            f"Data({len(self.data)})={hexlify(self.data)}, "
            f"Optional({len(self.optional_data)})={hexlify(self.optional_data)}"
        )
