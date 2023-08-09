// OpenPGP Implementation in Solidity
// Copyright (C) 2023 Sam Wilson
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// SPDX-License-Identifier: AGPL-3.0-or-later

pragma solidity ^0.8.19;

import "solidity-bytes-utils/BytesLib.sol";

// References from:
// https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/08/

//-----------------------------------------------------------------------------
// User Defined Types
//-----------------------------------------------------------------------------

//
// Offsets
//
type PgpPacketOffset is uint256;

type PgpSubpacketsOffset is uint256;

type PgpSubpacketOffset is uint256;

//
// Packet Tags
//
type PgpPacketTag is uint256;

using {packetTagEq as ==} for PgpPacketTag global;

function packetTagEq(PgpPacketTag a, PgpPacketTag b) pure returns (bool) {
    return PgpPacketTag.unwrap(a) == PgpPacketTag.unwrap(b);
}

library PgpPacketTags {
    PgpPacketTag internal constant PUBLIC_KEY_ENCRYPTED_SESSION_KEY =
        PgpPacketTag.wrap(0x01);

    PgpPacketTag internal constant SIGNATURE = PgpPacketTag.wrap(0x02);

    PgpPacketTag internal constant SYMMETRIC_KEY_ENCRYPTED_SESSION_KEY =
        PgpPacketTag.wrap(0x03);

    PgpPacketTag internal constant ONE_PASS_SIGNATURE = PgpPacketTag.wrap(0x04);

    PgpPacketTag internal constant SECRET_KEY = PgpPacketTag.wrap(0x05);

    PgpPacketTag internal constant PUBLIC_KEY = PgpPacketTag.wrap(0x06);

    PgpPacketTag internal constant SECRET_SUBKEY = PgpPacketTag.wrap(0x07);

    PgpPacketTag internal constant COMPRESSED_DATA = PgpPacketTag.wrap(0x08);

    PgpPacketTag internal constant SYMMETRICALLY_ENCRYPTED_DATA =
        PgpPacketTag.wrap(0x09);

    PgpPacketTag internal constant MARKER = PgpPacketTag.wrap(0x0a);

    PgpPacketTag internal constant LITERAL_DATA = PgpPacketTag.wrap(0x0b);

    PgpPacketTag internal constant TRUST = PgpPacketTag.wrap(0x0c);

    PgpPacketTag internal constant USER_ID = PgpPacketTag.wrap(0x0d);

    PgpPacketTag internal constant PUBLIC_SUBKEY = PgpPacketTag.wrap(0x0e);

    PgpPacketTag internal constant USER_ATTRIBUTE = PgpPacketTag.wrap(0x11);

    PgpPacketTag internal constant
        SYMMETRICALLY_ENCRYPTED_INTEGRITY_PROTECTED_DATA =
            PgpPacketTag.wrap(0x12);

    PgpPacketTag internal constant PADDING = PgpPacketTag.wrap(0x15);
}

//
// Signature Subpacket Tags
//
type PgpSigSubpacketTag is uint256;

using {sigSubpacketTagEq as ==} for PgpSigSubpacketTag global;

function sigSubpacketTagEq(PgpSigSubpacketTag a, PgpSigSubpacketTag b)
    pure
    returns (bool)
{
    return PgpSigSubpacketTag.unwrap(a) == PgpSigSubpacketTag.unwrap(b);
}

library PgpSigSubpacketTags {
    PgpSigSubpacketTag internal constant SIGNATURE_CREATION_TIME =
        PgpSigSubpacketTag.wrap(2);

    PgpSigSubpacketTag internal constant SIGNATURE_EXPIRATION_TIME =
        PgpSigSubpacketTag.wrap(3);

    PgpSigSubpacketTag internal constant EXPORTABLE_CERTIFICATION =
        PgpSigSubpacketTag.wrap(4);

    PgpSigSubpacketTag internal constant TRUST_SIGNATURE =
        PgpSigSubpacketTag.wrap(5);

    PgpSigSubpacketTag internal constant REGULAR_EXPRESSION =
        PgpSigSubpacketTag.wrap(6);

    PgpSigSubpacketTag internal constant REVOCABLE = PgpSigSubpacketTag.wrap(7);

    PgpSigSubpacketTag internal constant KEY_EXPIRATION_TIME =
        PgpSigSubpacketTag.wrap(9);

    PgpSigSubpacketTag internal constant
        PLACEHOLDER_FOR_BACKWARD_COMPATIBILITY = PgpSigSubpacketTag.wrap(10);

    PgpSigSubpacketTag internal constant
        PREFERRED_SYMMETRIC_CIPHERS_FOR_V1_SEIPD = PgpSigSubpacketTag.wrap(11);

    PgpSigSubpacketTag internal constant REVOCATION_KEY =
        PgpSigSubpacketTag.wrap(12);

    PgpSigSubpacketTag internal constant ISSUER_KEY_ID =
        PgpSigSubpacketTag.wrap(16);

    PgpSigSubpacketTag internal constant NOTATION_DATA =
        PgpSigSubpacketTag.wrap(20);

    PgpSigSubpacketTag internal constant PREFERRED_HASH_ALGORITHMS =
        PgpSigSubpacketTag.wrap(21);

    PgpSigSubpacketTag internal constant PREFERRED_COMPRESSION_ALGORITHMS =
        PgpSigSubpacketTag.wrap(22);

    PgpSigSubpacketTag internal constant KEY_SERVER_PREFERENCES =
        PgpSigSubpacketTag.wrap(23);

    PgpSigSubpacketTag internal constant PREFERRED_KEY_SERVER =
        PgpSigSubpacketTag.wrap(24);

    PgpSigSubpacketTag internal constant PRIMARY_USER_ID =
        PgpSigSubpacketTag.wrap(25);

    PgpSigSubpacketTag internal constant POLICY_URI =
        PgpSigSubpacketTag.wrap(26);

    PgpSigSubpacketTag internal constant KEY_FLAGS = PgpSigSubpacketTag.wrap(27);

    PgpSigSubpacketTag internal constant SIGNERS_USER_ID =
        PgpSigSubpacketTag.wrap(28);

    PgpSigSubpacketTag internal constant REASON_FOR_REVOCATION =
        PgpSigSubpacketTag.wrap(29);

    PgpSigSubpacketTag internal constant FEATURES = PgpSigSubpacketTag.wrap(30);

    PgpSigSubpacketTag internal constant SIGNATURE_TARGET =
        PgpSigSubpacketTag.wrap(31);

    PgpSigSubpacketTag internal constant EMBEDDED_SIGNATURE =
        PgpSigSubpacketTag.wrap(32);

    PgpSigSubpacketTag internal constant ISSUER_FINGERPRINT =
        PgpSigSubpacketTag.wrap(33);

    PgpSigSubpacketTag internal constant INTENDED_RECIPIENT_FINGERPRINT =
        PgpSigSubpacketTag.wrap(35);

    PgpSigSubpacketTag internal constant PREFERRED_AEAD_CIPHERSUITES =
        PgpSigSubpacketTag.wrap(39);
}

//
// Object Identifier (OID)
//
type PgpOid is bytes32;

using {oidEq as ==} for PgpOid global;

function oidEq(PgpOid a, PgpOid b) pure returns (bool) {
    return PgpOid.unwrap(a) == PgpOid.unwrap(b);
}

library PgpOids {
    PgpOid internal constant SECP256K1 = PgpOid.wrap(
        hex"0000000000000000000000000000000000000000000000000000002b8104000a"
    );
}

//-----------------------------------------------------------------------------
// PGP Parser
//-----------------------------------------------------------------------------

library Pgp {
    struct Parser {
        uint256 offset;
        bytes raw;
    }
}

library PgpParser {
    error InvalidHeader(uint256 offset);
    error InvalidPacket(uint256 offset);
    error PartialBody(uint256 offset);

    function readPacket(Pgp.Parser memory self)
        internal
        pure
        returns (PgpPacketTag tag, PgpPacketOffset end)
    {
        /* [4.2] Packet Headers */

        // Extract first octet.
        uint8 first = uint8(self.raw[self.offset++]);

        // Check for header bit.
        if (0 == (first & 0x80)) {
            revert InvalidHeader(self.offset);
        }

        if (0 == (first & 0x40)) {
            tag = PgpPacketTag.wrap((first & 0x3C) >> 2);

            /* [4.2.2] Legacy Format Packet Lengths */

            uint256 lengthType = first & 0x03;

            uint256 length;

            if (0 == lengthType) {
                length = uint8(self.raw[self.offset++]);
            } 
            
            if (1 == lengthType) {
                length = BytesLib.toUint16(self.raw, self.offset);
                self.offset += 2;
            } 
            
            if (2 == lengthType) {
                length = BytesLib.toUint32(self.raw, self.offset);
                self.offset += 4;
            } 
            
            if (3 == lengthType) {
                revert PartialBody(self.offset);
            } else {
                assert(false);
            }

            end = PgpPacketOffset.wrap(self.offset + length);
        } else {
            tag = PgpPacketTag.wrap(first & 0x3F);

            /* [4.2.1] OpenPGP Format Packet Lengths */

            uint256 second = uint8(self.raw[self.offset++]);

            /* [4.2.1.1] One-Octet Lengths */
            if (second < 192) {
                end = PgpPacketOffset.wrap(self.offset + second);
                return (tag, end);
            }

            /* [4.2.1.4] Partial Body Lengths */

            if (second >= 224 && second < 255) {
                // Only permitted for data packets.
                revert PartialBody(self.offset);
            }

            /* [4.2.1.2] Two-Octet Lengths */

            uint256 third = uint8(self.raw[self.offset++]);
            if (second != 255) {
                end = PgpPacketOffset.wrap(
                    self.offset + ((second - 192) << 8) + (third) + 192
                );
                return (tag, end);
            }

            /* [4.2.1.3] Five-Octet Lengths */
            uint256 fourth = uint8(self.raw[self.offset++]);
            uint256 fifth = uint8(self.raw[self.offset++]);
            uint256 sixth = uint8(self.raw[self.offset++]);

            end = PgpPacketOffset.wrap(
                self.offset + (third << 24) | (fourth << 16) | (fifth << 8)
                    | sixth
            );
        }
    }

    function skipTo(Pgp.Parser memory self, PgpSubpacketOffset end)
        internal
        pure
    {
        skipTo(self, PgpSubpacketOffset.unwrap(end));
    }

    function skipTo(Pgp.Parser memory self, PgpPacketOffset end)
        internal
        pure
    {
        skipTo(self, PgpPacketOffset.unwrap(end));
    }

    function skipTo(Pgp.Parser memory self, uint256 end) internal pure {
        self.offset = end;
    }

    function hasPackets(Pgp.Parser memory self) internal pure returns (bool) {
        return self.offset < self.raw.length;
    }

    function hasSubpackets(Pgp.Parser memory self, PgpSubpacketsOffset end)
        internal
        pure
        returns (bool)
    {
        return self.offset < PgpSubpacketsOffset.unwrap(end);
    }

    //-------------------------------------------------------------------------
    // Packet Readers
    //-------------------------------------------------------------------------

    function readPacketPublicKey(Pgp.Parser memory self, PgpPacketOffset end)
        internal
        pure
        returns (uint256 created, uint256 algorithm)
    {
        return readPacketKey(self, PgpPacketOffset.unwrap(end));
    }

    function readPacketPublicSubkey(Pgp.Parser memory self, PgpPacketOffset end)
        internal
        pure
        returns (uint256 created, uint256 algorithm)
    {
        /* [5.5.1.2] Public-Subkey Packet (Tag 14) */

        return readPacketKey(self, PgpPacketOffset.unwrap(end));
    }

    function readPacketUserId(Pgp.Parser memory self, PgpPacketOffset end)
        internal
        pure
        returns (string memory)
    {
        /* [5.11] User ID Packet (Tag 13) */

        uint256 _end = PgpPacketOffset.unwrap(end);

        uint256 start = self.offset;
        assert(_end >= start);

        self.offset = _end;
        return string(BytesLib.slice(self.raw, start, _end - start));
    }

    function readPacketSignature(Pgp.Parser memory self, PgpPacketOffset end)
        internal
        pure
        returns (uint256 sigType, uint256 pkAlgo, uint256 hashAlgo)
    {
        /* [5.2.3] Version 4 and 6 Signature Packet Formats */

        uint256 _end = PgpPacketOffset.unwrap(end);
        uint256 version = readUint8(self, _end);

        if (4 != version) {
            revert InvalidPacket(self.offset);
        }

        sigType = readUint8(self, _end);
        pkAlgo = readUint8(self, _end);
        hashAlgo = readUint8(self, _end);
    }

    function readPacketSignatureTail(
        Pgp.Parser memory self,
        PgpPacketOffset end
    ) internal pure returns (bytes2) {
        /* [5.2.3] Version 4 and 6 Signature Packet Formats */

        return bytes2(uint16(readUint16(self, PgpPacketOffset.unwrap(end))));
    }

    //-------------------------------------------------------------------------
    // Subpacket Readers
    //-------------------------------------------------------------------------

    function readSignatureV4Subpackets(
        Pgp.Parser memory self,
        PgpPacketOffset end
    ) internal pure returns (PgpSubpacketsOffset subEnd) {
        /* [5.2.3] Version 4 and 6 Signature Packet Formats */

        uint256 _end = PgpPacketOffset.unwrap(end);
        uint256 subLen = readUint16(self, _end);
        subEnd = PgpSubpacketsOffset.wrap(self.offset + subLen);
        checkEnd(self, subLen, _end);
    }

    function readSignatureV4Subpacket(
        Pgp.Parser memory self,
        PgpSubpacketsOffset end
    )
        internal
        pure
        returns (PgpSigSubpacketTag tag, PgpSubpacketOffset subEnd)
    {
        /* [5.2.3.7] Signature Subpacket Specification */

        uint256 _end = PgpSubpacketsOffset.unwrap(end);

        uint256 length;
        uint256 first = readUint8(self, _end);
        if (first < 192) {
            length = first;
        } else if (first < 255) {
            uint256 second = readUint8(self, _end);
            length = ((first - 192) << 8) + second + 192;
        } else {
            length = readUint32(self, _end);
        }

        subEnd = PgpSubpacketOffset.wrap(self.offset + length);
        tag = PgpSigSubpacketTag.wrap(readUint8(self, _end));
    }

    //-------------------------------------------------------------------------
    // Signature Subpacket Readers
    //-------------------------------------------------------------------------

    function readSignatureV4Fingerprint(
        Pgp.Parser memory self,
        PgpSubpacketOffset end
    ) internal pure returns (bytes memory fingerprint) {
        /* [5.2.3.35] Issuer Fingerprint */
        /* [5.2.3.36] Intended Recipient Fingerprint */

        uint256 _end = PgpSubpacketOffset.unwrap(end);

        uint256 version = readUint8(self, _end);
        if (4 != version) {
            revert InvalidPacket(self.offset);
        }

        checkEnd(self, 20, _end);

        fingerprint = BytesLib.slice(self.raw, self.offset, 20);
        self.offset += 20;
    }

    //-------------------------------------------------------------------------
    // Signature Readers
    //-------------------------------------------------------------------------

    function readSignatureEcdsaSecp256k1(
        Pgp.Parser memory self,
        PgpPacketOffset end
    ) internal pure returns (bytes32 todo0, bytes32 todo1) {
        todo0 = bytes32(
            readMultiprecisionInteger(self, PgpPacketOffset.unwrap(end))
        );
        todo1 = bytes32(
            readMultiprecisionInteger(self, PgpPacketOffset.unwrap(end))
        );
    }

    //-------------------------------------------------------------------------
    // Key Readers
    //-------------------------------------------------------------------------

    function readKeyEcdhSecp256k1(Pgp.Parser memory self, PgpPacketOffset end)
        internal
        pure
        returns (bytes memory key, bytes memory kdf)
    {
        /* [5.5.5.6] Algorithm-Specific Part for ECDH Keys */

        uint256 _end = PgpPacketOffset.unwrap(end);

        key = readMultiprecisionInteger(self, _end);

        uint256 size = readUint8(self, _end);

        checkEnd(self, size, _end);

        kdf = BytesLib.slice(self.raw, self.offset, size);
        self.offset += size;
    }

    function readKeyEcdsaSecp256k1(Pgp.Parser memory self, PgpPacketOffset end)
        internal
        pure
        returns (bytes memory)
    {
        /* [5.5.5.4] Algorithm-Specific Part for ECDSA Keys */

        return readMultiprecisionInteger(self, PgpPacketOffset.unwrap(end));
    }

    //-------------------------------------------------------------------------
    // Miscellaneous Readers
    //-------------------------------------------------------------------------

    function readOid(Pgp.Parser memory self, PgpPacketOffset end)
        internal
        pure
        returns (PgpOid)
    {
        /* [5.5.5.4] Algorithm-Specific Part for ECDSA Keys */

        uint256 _end = PgpPacketOffset.unwrap(end);

        uint256 size = readUint8(self, _end);

        if (0 == size || 32 < size) {
            revert InvalidPacket(self.offset);
        }

        checkEnd(self, size, _end);

        uint256 oid = 0;

        unchecked {
            for (uint256 ii = size; ii > 0; --ii) {
                oid <<= 8;
                oid |= uint8(self.raw[self.offset++]);
            }
        }

        return PgpOid.wrap(bytes32(oid));
    }

    //-------------------------------------------------------------------------
    // Private Functions
    //-------------------------------------------------------------------------

    function checkEnd(Pgp.Parser memory self, uint256 length, uint256 end)
        private
        pure
    {
        if (length > (end - self.offset)) {
            revert InvalidPacket(self.offset);
        }
    }

    function readUint8(Pgp.Parser memory self, uint256 end)
        private
        pure
        returns (uint256)
    {
        checkEnd(self, 1, end);
        return uint8(self.raw[self.offset++]);
    }

    function readUint16(Pgp.Parser memory self, uint256 end)
        private
        pure
        returns (uint256)
    {
        checkEnd(self, 2, end);
        uint256 value = BytesLib.toUint16(self.raw, self.offset);
        self.offset += 2;
        return value;
    }

    function readUint32(Pgp.Parser memory self, uint256 end)
        private
        pure
        returns (uint256)
    {
        checkEnd(self, 4, end);
        uint256 value = BytesLib.toUint32(self.raw, self.offset);
        self.offset += 4;
        return value;
    }

    function readPacketKey(Pgp.Parser memory self, uint256 end)
        private
        pure
        returns (uint256 created, uint256 algorithm)
    {
        /* [5.5.2] Public-Key Packet Formats */

        uint256 version = readUint8(self, end);

        if (4 != version) {
            revert InvalidPacket(self.offset);
        }

        created = readUint32(self, end);
        algorithm = readUint8(self, end);
    }

    function readMultiprecisionInteger(Pgp.Parser memory self, uint256 end)
        private
        pure
        returns (bytes memory key)
    {
        /* [3.2] Multiprecision Integers */

        uint256 bits = readUint16(self, end);
        uint256 size = (bits + 7) / 8;

        // TODO: The length field of an MPI describes the length starting from
        //       its most significant non-zero bit. Thus, the MPI [00 02 01] is
        //       not formed correctly.

        // TODO: Unused bits of an MPI MUST be zero.

        checkEnd(self, size, end);

        key = BytesLib.slice(self.raw, self.offset, size);
        self.offset += size;
    }
}
