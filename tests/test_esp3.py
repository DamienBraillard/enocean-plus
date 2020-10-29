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

from enoceanplus.esp3 import Esp3Packet, PacketType


class TestEsp3Packet:
    def test_data__created_with_0_1_2__contains_0_1_2(self):
        # Arrange
        target = Esp3Packet(b"\x00\x01\x02", b"\xFF", 99)

        # Act
        result = target.data

        # Assert
        assert_that(result).contains_only(0, 1, 2)

    def test_data__created_with_none__is_empty(self):
        # Arrange
        target = Esp3Packet(None, b"\xFF", 99)

        # Act
        result = target.data

        # Assert
        assert_that(result).is_not_none()
        assert_that(result).is_empty()

    def test_optional_data__created_with_0_1_2__contains_0_1_2(self):
        # Arrange
        target = Esp3Packet(b"\xFF", b"\x00\x01\x02", 99)

        # Act
        result = target.optional_data

        # Assert
        assert_that(result).contains_only(0, 1, 2)

    def test_optional_data__created_with_none__is_empty(self):
        # Arrange
        target = Esp3Packet(b"\xFF", None, 99)

        # Act
        result = target.optional_data

        # Assert
        assert_that(result).is_not_none()
        assert_that(result).is_empty()

    def test_raw_packet_type__created_with_123__contains_123(self):
        # Arrange
        target = Esp3Packet(b"", b"", 123)

        # Act
        result = target.raw_packet_type

        # Assert
        assert_that(result).is_equal_to(123)

    def test_raw_packet_type__created_with_known_packet_type__contains_type_value(self):
        # Arrange
        target = Esp3Packet(b"", b"", PacketType.Response)

        # Act
        result = target.raw_packet_type

        # Assert
        assert_that(result).is_type_of(int)
        assert_that(result).is_equal_to(int(PacketType.Response))

    @pytest.mark.parametrize(
        "raw_type,expected_type",
        [
            pytest.param(0x00, PacketType.Unknown),
            pytest.param(0x01, PacketType.RadioERP1),
            pytest.param(0x02, PacketType.Response),
            pytest.param(0x03, PacketType.RadioSubTel),
            pytest.param(0x04, PacketType.Event),
            pytest.param(0x05, PacketType.CommonCommand),
            pytest.param(0x06, PacketType.SmartAckCommand),
            pytest.param(0x07, PacketType.RemoteManCommand),
            pytest.param(0x08, PacketType.Unknown),
            pytest.param(0x09, PacketType.RadioMessage),
            pytest.param(0x0A, PacketType.RadioERP2),
            pytest.param(0x0B, PacketType.ConfigCommand),
            pytest.param(0x0C, PacketType.CommandAccepted),
            pytest.param(0x0D, PacketType.Unknown),
            pytest.param(0x0E, PacketType.Unknown),
            pytest.param(0x0F, PacketType.Unknown),
            pytest.param(0x10, PacketType.Radio802_15_4),
            pytest.param(0x11, PacketType.Radio2_4),
        ],
    )
    def test_packet_type__created_with_raw_packet_type__contains_known_type_value_or_unknown(
        self, raw_type, expected_type
    ):
        # Arrange
        target = Esp3Packet(b"", b"", raw_type)

        # Act
        result = target.packet_type

        # Assert
        assert_that(result).is_type_of(PacketType)
        assert_that(result).is_equal_to(expected_type)

    def test_packet_type__created_with_known_packet_type__contains_known_type(self):
        # Arrange
        target = Esp3Packet(b"", b"", PacketType.Response)

        # Act
        result = target.packet_type

        # Assert
        assert_that(result).is_type_of(PacketType)
        assert_that(result).is_equal_to(PacketType.Response)
