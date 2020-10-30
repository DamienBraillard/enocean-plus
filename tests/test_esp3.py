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

import pytest
from assertpy import *

from enoceanplus.esp3 import Esp3Packet, Esp3PacketType, Esp3ParseResult


class TestEsp3Packet:
    def test_data__created_with_0_1_2__contains_0_1_2(self):
        # Arrange
        target = Esp3Packet(99, b"\x00\x01\x02", b"\xFF")

        # Act
        result = target.data

        # Assert
        assert_that(result).contains_only(0, 1, 2)

    def test_data__created_with_none__is_empty(self):
        # Arrange
        target = Esp3Packet(99, None, b"\xFF")

        # Act
        result = target.data

        # Assert
        assert_that(result).is_not_none()
        assert_that(result).is_empty()

    def test_optional_data__created_with_0_1_2__contains_0_1_2(self):
        # Arrange
        target = Esp3Packet(99, b"\xFF", b"\x00\x01\x02")

        # Act
        result = target.optional_data

        # Assert
        assert_that(result).contains_only(0, 1, 2)

    def test_optional_data__created_with_none__is_empty(self):
        # Arrange
        target = Esp3Packet(99, b"\xFF", None)

        # Act
        result = target.optional_data

        # Assert
        assert_that(result).is_not_none()
        assert_that(result).is_empty()

    def test_raw_packet_type__created_with_123__contains_123(self):
        # Arrange
        target = Esp3Packet(123, b"", b"")

        # Act
        result = target.raw_packet_type

        # Assert
        assert_that(result).is_equal_to(123)

    def test_raw_packet_type__created_with_known_packet_type__contains_type_value(self):
        # Arrange
        target = Esp3Packet(Esp3PacketType.Response, b"", b"")

        # Act
        result = target.raw_packet_type

        # Assert
        assert_that(result).is_type_of(int)
        assert_that(result).is_equal_to(int(Esp3PacketType.Response))

    @pytest.mark.parametrize(
        "raw_type,expected_type",
        [
            pytest.param(0x00, Esp3PacketType.Unknown),
            pytest.param(0x01, Esp3PacketType.RadioERP1),
            pytest.param(0x02, Esp3PacketType.Response),
            pytest.param(0x03, Esp3PacketType.RadioSubTel),
            pytest.param(0x04, Esp3PacketType.Event),
            pytest.param(0x05, Esp3PacketType.CommonCommand),
            pytest.param(0x06, Esp3PacketType.SmartAckCommand),
            pytest.param(0x07, Esp3PacketType.RemoteManCommand),
            pytest.param(0x08, Esp3PacketType.Unknown),
            pytest.param(0x09, Esp3PacketType.RadioMessage),
            pytest.param(0x0A, Esp3PacketType.RadioERP2),
            pytest.param(0x0B, Esp3PacketType.ConfigCommand),
            pytest.param(0x0C, Esp3PacketType.CommandAccepted),
            pytest.param(0x0D, Esp3PacketType.Unknown),
            pytest.param(0x0E, Esp3PacketType.Unknown),
            pytest.param(0x0F, Esp3PacketType.Unknown),
            pytest.param(0x10, Esp3PacketType.Radio802_15_4),
            pytest.param(0x11, Esp3PacketType.Radio2_4),
        ],
    )
    def test_packet_type__created_with_raw_packet_type__contains_known_type_value_or_unknown(
        self, raw_type, expected_type
    ):
        # Arrange
        target = Esp3Packet(raw_type, b"", b"")

        # Act
        result = target.packet_type

        # Assert
        assert_that(result).is_type_of(Esp3PacketType)
        assert_that(result).is_equal_to(expected_type)

    def test_packet_type__created_with_known_packet_type__contains_known_type(self):
        # Arrange
        target = Esp3Packet(Esp3PacketType.Response, b"", b"")

        # Act
        result = target.packet_type

        # Assert
        assert_that(result).is_type_of(Esp3PacketType)
        assert_that(result).is_equal_to(Esp3PacketType.Response)

    def test_try_decode__no_sync_byte__returns_result_no_packet(self):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(bytearray(b"\x01\x02\x03"))

        # Assert
        assert_that(result).is_equal_to(Esp3ParseResult.NoPacket)

    def test_try_decode__no_sync_byte__consumes_all_bytes(self):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(bytearray(b"\x01\x02\x03"))

        # Assert
        assert_that(count).is_equal_to(3)

    def test_try_decode__no_sync_byte__returns_no_packet(self):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(bytearray(b"\x01\x02\x03"))

        # Assert
        assert_that(packet).is_none()

    def test_try_decode__incomplete_packet__returns_result_not_enough_data(self):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(bytearray(b"\x55\x01"))

        # Assert
        assert_that(result).is_equal_to(Esp3ParseResult.NotEnoughData)

    @pytest.mark.parametrize(
        "buffer,expected_count",
        [
            pytest.param(b"\x55\x01", 0, id="no data before sync byte"),
            pytest.param(b"\xAA\xBB\x55\x01", 2, id="data before sync byte"),
        ],
    )
    def test_try_decode__incomplete_packet__consumes_bytes_before_the_sync_byte(
        self, buffer, expected_count
    ):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(buffer)

        # Assert
        assert_that(count).is_equal_to(expected_count)

    def test_try_decode__incomplete_packet__returns_no_packet(self):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(bytearray(b"\x55\x01"))

        # Assert
        assert_that(packet).is_none()

    def test_try_decode__bad_header_checksum__returns_result_bad_crc(self):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(
            bytearray(b"\x55\x00\x01\x01\x01\xFF\xAA\xBB\xB2")
        )
        # Assert
        assert_that(result).is_equal_to(Esp3ParseResult.BadCRC)

    @pytest.mark.parametrize(
        "buffer,expected_count",
        [
            pytest.param(
                b"\x55\x00\x01\x01\x01\xFF\xAA\xBB\xB2", 9, id="no other sync byte"
            ),
            pytest.param(
                b"--\x55\x00\x01\x01\x01\xFF\xAA\xBB\xB2--",
                13,
                id="no other sync byte + extra bytes",
            ),
            pytest.param(
                b"\x55\x00\x01\x01\x55\xFF\xAA\xBB\xB2",
                9,
                id="other sync byte in header",
            ),
            pytest.param(
                b"--\x55\x00\x01\x01\x55\xFF\xAA\xBB\xB2--",
                13,
                id="other sync byte in header + extra bytes",
            ),
            pytest.param(
                b"\x55\x00\x01\x01\x55\xFF\xAA\xBB\xB2\x55",
                9,
                id="other sync byte in and after header",
            ),
            pytest.param(
                b"--\x55\x00\x01\x01\x55\xFF\xAA\xBB\xB2--\x55",
                13,
                id="other sync byte in and after header + extra bytes",
            ),
            pytest.param(
                b"\x55\x00\x01\x01\x01\xFF\xAA\xBB\xB2\x55",
                9,
                id="other sync byte after header",
            ),
            pytest.param(
                b"--\x55\x00\x01\x01\x01\xFF\xAA\xBB\xB2--\x55",
                13,
                id="other sync byte after header + extra bytes",
            ),
        ],
    )
    def test_try_decode__bad_header_checksum__consumes_bytes_up_to_the_next_sync_byte_after_header_or_buffer_end(
        self, buffer, expected_count
    ):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(buffer)

        # Assert
        assert_that(count).is_equal_to(expected_count)

    def test_try_decode__bad_header_checksum__returns_no_packet(self):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(
            bytearray(b"\x55\x00\x01\x01\x01\xFF\xAA\xBB\xB2")
        )

        # Assert
        assert_that(packet).is_none()

    def test_try_decode__bad_data_checksum__returns_result_bad_crc(self):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(
            bytearray(b"\x55\x00\x01\x01\x01\x79\xAA\xBB\xFF")
        )

        # Assert
        assert_that(result).is_equal_to(Esp3ParseResult.BadCRC)

    @pytest.mark.parametrize(
        "buffer,expected_count",
        [
            pytest.param(
                b"\x55\x00\x01\x01\x01\x79\xAA\xBB\xFF", 9, id="no other sync byte"
            ),
            pytest.param(
                b"--\x55\x00\x01\x01\x01\x79\xAA\xBB\xFF--",
                13,
                id="no other sync byte + extra bytes",
            ),
            pytest.param(
                b"\x55\x00\x01\x01\x01\x79\xAA\x55\xFF",
                9,
                id="other sync byte in packet",
            ),
            pytest.param(
                b"--\x55\x00\x01\x01\x01\x79\xAA\x55\xFF--",
                13,
                id="other sync byte in packet + extra bytes",
            ),
            pytest.param(
                b"\x55\x00\x01\x01\x01\x79\xAA\x55\xFF\x55",
                9,
                id="other sync byte in and after packet",
            ),
            pytest.param(
                b"--\x55\x00\x01\x01\x01\x79\xAA\x55\xFF--\x55",
                13,
                id="other sync byte in and after packet + extra bytes",
            ),
            pytest.param(
                b"\x55\x00\x01\x01\x01\x79\xAA\xBB\xFF\x55",
                9,
                id="other sync byte after packet",
            ),
            pytest.param(
                b"--\x55\x00\x01\x01\x01\x79\xAA\xBB\xFF--\x55",
                13,
                id="other sync byte after packet + extra bytes",
            ),
        ],
    )
    def test_try_decode__bad_data_checksum__consumes_bytes_up_to_the_next_sync_byte_after_data_or_buffer_end(
        self, buffer, expected_count
    ):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(buffer)

        # Assert
        assert_that(count).is_equal_to(expected_count)

    def test_try_decode__bad_data_checksum__returns_no_packet(self):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(
            bytearray(b"\x55\x00\x01\x01\x01\x79\xAA\xBB\xFF")
        )

        # Assert
        assert_that(packet).is_none()

    def test_try_decode__valid_packet__returns_result_success(self):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(
            bytearray(b"\x55\x00\x02\x00\x05\xCD\xA0\xA1\x76")
        )

        # Assert
        assert_that(result).is_equal_to(Esp3ParseResult.Success)

    @pytest.mark.parametrize(
        "buffer,expected_count",
        [
            pytest.param(
                b"\x55\x00\x01\x01\x01\x79\x44\x55\xA3", 9, id="no other data"
            ),
            pytest.param(
                b"-\x55\x00\x01\x01\x01\x79\x44\x55\xA3", 10, id="garbage before"
            ),
            pytest.param(
                b"\x55\x00\x01\x01\x01\x79\x44\x55\xA3-", 10, id="garbage after"
            ),
            pytest.param(
                b"-\x55\x00\x01\x01\x01\x79\x44\x55\xA3-",
                11,
                id="garbage before and after",
            ),
            pytest.param(
                b"\x55\x00\x01\x01\x01\x79\x44\x55\xA3\x55", 9, id="sync byte after"
            ),
            pytest.param(
                b"-\x55\x00\x01\x01\x01\x79\x44\x55\xA3\x55",
                10,
                id="sync byte after and garbage before",
            ),
        ],
    )
    def test_try_decode__valid_packet__consumes_bytes_up_to_the_next_sync_byte_after_packet_or_buffer_end(
        self, buffer, expected_count
    ):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(buffer)

        # Assert
        assert_that(count).is_equal_to(expected_count)

    @pytest.mark.parametrize(
        "buffer,expected_data,expected_optional_data,expected_type",
        [
            pytest.param(
                b"\x55\x00\x02\x00\x05\xCD\xA0\xA1\x76",
                b"\xA0\xA1",
                b"",
                5,
                id="data only",
            ),
            pytest.param(
                b"\x55\x01\x00\x00\x05\x0D\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11"
                b"\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29"
                b"\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40\x41"
                b"\x42\x43\x44\x45\x46\x47\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59"
                b"\x5A\x5B\x5C\x5D\x5E\x5F\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71"
                b"\x72\x73\x74\x75\x76\x77\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89"
                b"\x8A\x8B\x8C\x8D\x8E\x8F\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1"
                b"\xA2\xA3\xA4\xA5\xA6\xA7\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9"
                b"\xBA\xBB\xBC\xBD\xBE\xBF\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1"
                b"\xD2\xD3\xD4\xD5\xD6\xD7\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9"
                b"\xEA\xEB\xEC\xED\xEE\xEF\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF\x14",
                b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17"
                b"\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
                b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40\x41\x42\x43\x44\x45\x46\x47"
                b"\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F"
                b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77"
                b"\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"
                b"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7"
                b"\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"
                b"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7"
                b"\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF"
                b"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF",
                b"",
                5,
                id="data longer than 256",
            ),
            pytest.param(
                b"\x55\x00\x02\x03\x05\xF2\xA0\xA1\xB0\xB1\xB2\xBD",
                b"\xA0\xA1",
                b"\xB0\xB1\xB2",
                5,
                id="data and optional data",
            ),
        ],
    )
    def test_try_decode__valid_packet__returns_packet(
        self, buffer, expected_data, expected_optional_data, expected_type
    ):
        # Arrange

        # Act
        result, count, packet = Esp3Packet.try_decode(buffer)

        # Assert
        assert_that(packet).is_not_none()
        assert_that(packet.data).is_equal_to(expected_data)
        assert_that(packet.optional_data).is_equal_to(expected_optional_data)
        assert_that(packet.packet_type).is_equal_to(expected_type)

    def test_encode__no_optional_data__returns_encoded_packet(self):
        # Arrange
        packet_type = 0x1
        packet_data = b"\x02\x03\x04"
        packet_opt = b""

        packet = Esp3Packet(
            packet_type=packet_type, data=packet_data, optional_data=packet_opt
        )

        # Act
        actual = packet.encode()

        # Assert
        expected = (
            b"\x55"  # sync
            + b"\x00\x03"  # data length
            + b"\x00"  # optional data length
            + bytes([packet_type])
            + b"\xBA"  # header CRC
            + packet_data
            + packet_opt
            + b"\xF5"  # body CRC
        )
        assert_that(actual).is_equal_to(expected)

    def test_encode__optional_data__returns_encoded_packet(self):
        # Arrange
        packet_type = 0x1
        packet_data = b"\x02\x03\x04"
        packet_opt = b"\xFE\xFF"

        packet = Esp3Packet(
            packet_type=packet_type, data=packet_data, optional_data=packet_opt
        )

        # Act
        actual = packet.encode()

        # Assert
        expected = (
            b"\x55"  # sync
            + b"\x00\x03"  # data length
            + b"\x02"  # optional data length
            + bytes([packet_type])
            + b"\x90"  # header CRC
            + packet_data
            + packet_opt
            + b"\x64"  # body CRC
        )
        assert_that(actual).is_equal_to(expected)

    def test_encode__more_than_255_bytes_of_data__returns_encoded_packet(self):
        # Arrange
        packet_type = 0x10
        packet_data = (
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17"
            b"\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
            b"\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\x40\x41\x42\x43\x44\x45\x46\x47"
            b"\x48\x49\x4A\x4B\x4C\x4D\x4E\x4F\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5A\x5B\x5C\x5D\x5E\x5F"
            b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70\x71\x72\x73\x74\x75\x76\x77"
            b"\x78\x79\x7A\x7B\x7C\x7D\x7E\x7F\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8A\x8B\x8C\x8D\x8E\x8F"
            b"\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9A\x9B\x9C\x9D\x9E\x9F\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7"
            b"\xA8\xA9\xAA\xAB\xAC\xAD\xAE\xAF\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7\xB8\xB9\xBA\xBB\xBC\xBD\xBE\xBF"
            b"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF\xD0\xD1\xD2\xD3\xD4\xD5\xD6\xD7"
            b"\xD8\xD9\xDA\xDB\xDC\xDD\xDE\xDF\xE0\xE1\xE2\xE3\xE4\xE5\xE6\xE7\xE8\xE9\xEA\xEB\xEC\xED\xEE\xEF"
            b"\xF0\xF1\xF2\xF3\xF4\xF5\xF6\xF7\xF8\xF9\xFA\xFB\xFC\xFD\xFE\xFF"
        )
        packet_opt = b"\xF0\xF1"

        packet = Esp3Packet(
            packet_type=packet_type, data=packet_data, optional_data=packet_opt
        )

        # Act
        actual = packet.encode()

        # Assert
        expected = (
            b"\x55"  # sync
            + b"\x01\x00"  # data length
            + b"\x02"  # optional data length
            + bytes([packet_type])
            + b"\x4C"  # header CRC
            + packet_data
            + packet_opt
            + b"\xCE"  # body CRC
        )
        assert_that(actual).is_equal_to(expected)
