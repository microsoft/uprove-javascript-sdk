// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/// #region JSCop/JsHint

/* global operations */
/* jshint -W016 */
/* jshint -W052 */

/// <reference path="operations.js" />

/// <dictionary>msrcrypto, der, sha</dictionary>

/// <disable>JS3057.AvoidImplicitTypeCoercion</disable>

/// #endregion JSCop/JsHint

var msrcryptoSha256 = (function () {

    var hashFunction = function (name, der, h, k, truncateTo) {

        var blockBytes = 64;
        var hv = h.slice();
        var w = new Array(blockBytes);
        var buffer = [];
        var blocksProcessed = 0;

        function hashBlocks(/*@type(Array)*/message) {

            var blockCount = Math.floor(message.length / blockBytes);

            var ra, rb, rc, rd, re, rf, rg, rh;
            var t, block, i, temp, x1, x0, index;

            // Process each 64-byte block of the message
            for (block = 0; block < blockCount; block++) {

                // 0 ≤ t ≤ 15
                for (i = 0; i < 16; i++) {
                    index = block * blockBytes + i * 4;
                    // Convert 4 bytes to 32-bit integer
                    w[i] = (message[index] << 24) |
                           (message[index + 1] << 16) |
                           (message[index + 2] << 8) |
                            message[index + 3];
                }

                // 16 ≤ t ≤ 63
                for (t = 16; t < 64; t++) {

                    x0 = w[t - 15];
                    x1 = w[t - 2];

                    w[t] = (((x1 >>> 17) | (x1 << 15)) ^ ((x1 >>> 19) | (x1 << 13)) ^ (x1 >>> 10));
                    w[t] += w[t - 7];
                    w[t] += (((x0 >>> 7) | (x0 << 25)) ^ ((x0 >>> 18) | (x0 << 14)) ^ (x0 >>> 3));
                    w[t] += w[t - 16];
                }

                ra = hv[0];
                rb = hv[1];
                rc = hv[2];
                rd = hv[3];
                re = hv[4];
                rf = hv[5];
                rg = hv[6];
                rh = hv[7];

                for (i = 0; i < 64; i++) {

                    temp =
                        rh +
                            ((re >>> 6 | re << 26) ^ (re >>> 11 | re << 21) ^ (re >>> 25 | re << 7)) +
                            ((re & rf) ^ ((~re) & rg)) +
                            k[i] + w[i];

                    rd += temp;

                    temp +=
                    ((ra >>> 2 | ra << 30) ^ (ra >>> 13 | ra << 19) ^ (ra >>> 22 | ra << 10)) +
                        ((ra & (rb ^ rc)) ^ (rb & rc));

                    rh = rg; // 'h' = g
                    rg = rf; // 'g' = f
                    rf = re; // 'f' = e
                    re = rd; // 'e' = d
                    rd = rc; // 'd' = c
                    rc = rb; // 'c' = b
                    rb = ra; // 'b' = a
                    ra = temp; // 'a' = temp

                }

                // Need to mask 32-bits when using regular arrays
                hv[0] += ra & 0xFFFFFFFF;
                hv[1] += rb & 0xFFFFFFFF;
                hv[2] += rc & 0xFFFFFFFF;
                hv[3] += rd & 0xFFFFFFFF;
                hv[4] += re & 0xFFFFFFFF;
                hv[5] += rf & 0xFFFFFFFF;
                hv[6] += rg & 0xFFFFFFFF;
                hv[7] += rh & 0xFFFFFFFF;
            }

            // Keep track of the number of blocks processed.
            // We have to put the total message size into the padding.
            blocksProcessed += blockCount;

            // Return the unprocessed data.
            return message.slice(blockCount * blockBytes);
        }

        function hashToBytes() {

            var hash = new Array(256);

            // Copy the 32-bit values to a byte array
            for (var i = 0, byteIndex = 0; i < 8; i += 1, byteIndex += 4) {
                hash[byteIndex] = hv[i] >>> 24;
                hash[byteIndex + 1] = hv[i] >>> 16 & 0xFF;
                hash[byteIndex + 2] = hv[i] >>> 8 & 0xFF;
                hash[byteIndex + 3] = hv[i] & 0xFF;
            }

            return hash.slice(0, truncateTo / 8);
        }

        // This can be optimized.
        // Currently the amount of padding is computed. Then a new array, big enough
        // to hold the message + padding is created.  The message is copied to the
        // new array and the padding is placed at the end.
        // We don't really need to create an entire new array and copy to it.
        // We can just build the last padded block and store it.
        // Then when computing the hash, substitute it for the last message block.
        function padBlock( /*@type(Array)*/ message) {

            var padLen = blockBytes - message.length;

            // If there is 8 or less bytes of padding, pad an additional block.
            if (padLen <= 8) {
                padLen += blockBytes;
            }

            // Create a new Array that will contain the message + padding
            var paddedMessage = message.slice();

            // Set the 1 bit at the end of the message data
            paddedMessage.push(128);

            // Pad the array with zero. Leave 4 bytes for the message size.
            for (var i = 1; i < padLen - 4; i++) {
                paddedMessage.push(0);
            }

            // Set the length equal to the previous data len + the new data len
            var messageLenBits = (message.length + blocksProcessed * blockBytes) * 8;

            // Set the message length in the last 4 bytes
            paddedMessage.push(messageLenBits >>> 24 & 255);
            paddedMessage.push(messageLenBits >>> 16 & 255);
            paddedMessage.push(messageLenBits >>> 8 & 255);
            paddedMessage.push(messageLenBits & 255);

            return paddedMessage;
        }

        function bufferToArray(buffer) {

            // Checking for slice method to determine if this a regular array.
            if (buffer.pop) {
                return buffer;
            }

            return (buffer.length === 1) ? [buffer[0]] : Array.apply(null, buffer);
        }

        function /*@type(Array)*/ computeHash(messageBytes) {

            // Convert the input to an Array - it could be a typed array
            buffer = hashBlocks(bufferToArray(messageBytes));

            return finish();
        }

        function process(messageBytes) {

            // Append the new data to the buffer (previous unprocessed data)
            // Convert the input to an Array - it could be a typed array
            buffer = buffer.concat(bufferToArray(messageBytes));

            // If there is at least one block of data, hash it
            if (buffer.length >= 64) {
                // The remaining unprocessed data goes back into the buffer
                buffer = hashBlocks(buffer);
            }

            return;
        }

        function finish() {

            // All the full blocks of data have been processed. Now we pad the rest and hash.
            // Buffer should be empty now.
            if (hashBlocks(padBlock(buffer)).length !== 0) {
                throw new Error("buffer.length !== 0");
            }

            var result = hashToBytes();

            // Clear the hash values so this instance can be reused
            buffer = [];
            hv = h.slice();
            blocksProcessed = 0;

            return result;
        }

        return {
            name: name,
            computeHash: computeHash,
            process: process,
            finish: finish,
            der: der,
            hashLen: truncateTo,
            maxMessageSize: 0xFFFFFFFF // (2^32 - 1 is max array size in JavaScript)
        };

    };

    var k256, h224, h256, der224, der256, upd = msrcryptoUtilities.unpackData;

    h224 = upd("wQWe2DZ81QcwcN0X9w5ZOf/ACzFoWBURZPmPp776T6Q", 4, 1);

    h256 = upd("agnmZ7tnroU8bvNypU/1OlEOUn+bBWiMH4PZq1vgzRk", 4, 1);

    k256 = upd("QoovmHE3RJG1wPvP6bXbpTlWwltZ8RHxkj+CpKscXtXYB6qYEoNbASQxhb5VDH3Dcr5ddIDesf6b3AanwZvxdOSbacHvvkeGD8GdxiQMocwt6SxvSnSEqlywqdx2+YjamD5RUqgxxm2wAyfIv1l/x8bgC/PVp5FHBspjURQpKWcntwqFLhshOE0sbfxTOA0TZQpzVHZqCruBwskuknIshaK/6KGoGmZLwkuLcMdsUaPRkugZ1pkGJPQONYUQaqBwGaTBFh43bAgnSHdMNLC8tTkcDLNO2KpKW5zKT2gub/N0j4LueKVjb4TIeBSMxwIIkL7/+qRQbOu++aP3xnF48g", 4, 1);

    // DER encoding
    der224 = upd("MDEwDQYJYIZIAWUDBAIEBQAEIA");
    der256 = upd("MDEwDQYJYIZIAWUDBAIBBQAEIA");

    return {
        sha224: hashFunction("SHA-224", der224, h224, k256, 224),
        sha256: hashFunction("SHA-256", der256, h256, k256, 256)
    };
})();

if (typeof operations !== "undefined") {

    msrcryptoSha256.hash256 = function (/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha256.sha256.process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoSha256.sha256.finish();
        }

        return msrcryptoSha256.sha256.computeHash(p.buffer);

    };

    msrcryptoSha256.hash224 = function (/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha256.sha224.process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoSha256.sha224.finish();
        }

        return msrcryptoSha256.sha224.computeHash(p.buffer);

    };

    operations.register("digest", "sha-224", msrcryptoSha256.hash224);
    operations.register("digest", "sha-256", msrcryptoSha256.hash256);
}

msrcryptoHashFunctions["sha-224"] = msrcryptoSha256.sha224;
msrcryptoHashFunctions["sha-256"] = msrcryptoSha256.sha256;
