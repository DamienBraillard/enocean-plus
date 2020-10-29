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
from enum import IntEnum
from typing import Union


class PacketType(IntEnum):
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
    packet_type: PacketType

    def __init__(
        self,
        data: Union[bytes, None],
        optional_data: Union[bytes, None],
        packet_type: Union[int, PacketType],
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
            self.packet_type = PacketType(self.raw_packet_type)
        except ValueError:
            self.packet_type = PacketType.Unknown
