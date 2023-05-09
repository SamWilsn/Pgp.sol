// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

library Pgp {
    uint8 private constant HEADER_MASK = 0xC0;

    error InvalidHeader(uint256 offset);
    error InvalidPacket(uint256 offset);
    error PartialBody(uint256 offset);

    struct Parser {
        uint256 offset;
        bytes raw;
    }

    function header(Parser memory self) internal pure returns (uint256 tag, uint256 length) {
        /* [4.2] Packet Headers */

        // Extract first octet.
        uint8 first = uint8(self.raw[self.offset++]);

        // Check for new packet format.
        if ((first & HEADER_MASK) != HEADER_MASK) {
            revert InvalidHeader(self.offset);
        }

        // Extract packet tag.
        tag = first & ~HEADER_MASK;

        /* [4.2.2] New Format Packet Lengths */
        uint256 second = uint8(self.raw[self.offset++]);

        /* [4.2.2.1] One-Octet Lengths */
        if (second < 192) {
            length = second;
            return (tag, length);
        }

        /* [4.2.2.4] Partial Body Lengths */
        if (second >= 224 && second < 255) {
            // Only permitted for data packets.
            revert PartialBody(self.offset);
        }

        /* [4.2.2.2] Two-Octet Lengths */
        uint256 third = uint8(self.raw[self.offset++]);
        if (second != 255) {
            length = ((second - 192) << 8) + (third) + 192;
            return (tag, length);
        }

        /* [4.2.2.3] Five-Octet Lengths */
        uint256 fourth = uint8(self.raw[self.offset++]);
        uint256 fifth = uint8(self.raw[self.offset++]);
        uint256 sixth = uint8(self.raw[self.offset++]);

        length = (third << 24) | (fourth << 16) | (fifth << 8) | sixth;
    }

    function skip(Parser memory self, uint256 length) internal pure {
        self.offset += length;
    }

    function eof(Parser memory self) internal pure returns (bool) {
        return self.offset >= self.raw.length;
    }

    function packetPublicKey(Parser memory self, uint256 length) internal pure {
        /* [5.5.2] Public-Key Packet Formats */

        if (6 > length) {
            revert InvalidPacket(self.offset);
        }

        uint8 version = uint8(self.raw[self.offset++]);
        if (4 != version) {
            revert InvalidPacket(self.offset);
        }

        self.offset += 4; // Creation time
        revert();
    }
}
