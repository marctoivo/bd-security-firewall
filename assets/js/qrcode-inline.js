/**
 * Minimal QR Code Generator (client-side, no dependencies)
 *
 * Generates QR codes as inline SVG strings. Used by BestDid Security
 * for TOTP 2FA setup so that the TOTP secret never leaves the browser.
 *
 * Supports Byte mode encoding, error correction level L.
 * Handles QR versions 1-10 (up to ~271 bytes), sufficient for otpauth:// URIs.
 *
 * @package BestDid_Security
 */
var bdsecQR = (function() {
    'use strict';

    // -- GF(256) arithmetic for Reed-Solomon --
    var GF_EXP = new Array(256);
    var GF_LOG = new Array(256);
    (function() {
        var x = 1;
        for (var i = 0; i < 256; i++) {
            GF_EXP[i] = x;
            GF_LOG[x] = i;
            x <<= 1;
            if (x & 256) x ^= 0x11d;
        }
        GF_LOG[0] = 255; // undefined, but set to 255 for safety
    })();

    function gfMul(a, b) {
        if (a === 0 || b === 0) return 0;
        return GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 255];
    }

    // Generate Reed-Solomon error correction codewords
    function rsEncode(data, ecCount) {
        // Build generator polynomial
        var gen = [1];
        for (var i = 0; i < ecCount; i++) {
            var newGen = new Array(gen.length + 1);
            for (var k = 0; k < newGen.length; k++) newGen[k] = 0;
            for (var j = 0; j < gen.length; j++) {
                newGen[j] ^= gen[j];
                newGen[j + 1] ^= gfMul(gen[j], GF_EXP[i]);
            }
            gen = newGen;
        }
        // Polynomial division
        var msg = new Array(data.length + ecCount);
        for (var i = 0; i < data.length; i++) msg[i] = data[i];
        for (var i = data.length; i < msg.length; i++) msg[i] = 0;
        for (var i = 0; i < data.length; i++) {
            var coef = msg[i];
            if (coef !== 0) {
                for (var j = 1; j < gen.length; j++) {
                    msg[i + j] ^= gfMul(gen[j], coef);
                }
            }
        }
        return msg.slice(data.length);
    }

    // -- QR Code constants --
    // Error correction level L capacities (byte mode) and EC codewords per block for versions 1-10
    var VERSION_CAPACITY = [0, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271];
    var VERSION_SIZE = [0, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57];

    // Total codewords per version
    var TOTAL_CODEWORDS = [0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346];

    // EC codewords per block for level L
    var EC_CODEWORDS_PER_BLOCK = [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18];

    // Number of EC blocks for level L
    var NUM_EC_BLOCKS = [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4];

    // Alignment pattern positions per version
    var ALIGNMENT_PATTERNS = [
        [], [], [6,18], [6,22], [6,26], [6,30], [6,34],
        [6,22,38], [6,24,42], [6,26,46], [6,28,50]
    ];

    function getVersion(dataLen) {
        for (var v = 1; v <= 10; v++) {
            if (dataLen <= VERSION_CAPACITY[v]) return v;
        }
        return -1; // too large
    }

    // Encode data into QR code bit stream (Byte mode, ECC level L)
    function encodeData(text) {
        var data = [];
        // Convert to UTF-8 bytes
        var utf8 = unescape(encodeURIComponent(text));
        for (var i = 0; i < utf8.length; i++) {
            data.push(utf8.charCodeAt(i));
        }

        var version = getVersion(data.length);
        if (version < 0) return null;

        var totalCodewords = TOTAL_CODEWORDS[version];
        var ecPerBlock = EC_CODEWORDS_PER_BLOCK[version];
        var numBlocks = NUM_EC_BLOCKS[version];
        var dataCodewords = totalCodewords - ecPerBlock * numBlocks;

        // Build data stream: mode indicator (0100 = byte), char count, data, terminator, padding
        var bits = [];
        function addBits(val, len) {
            for (var i = len - 1; i >= 0; i--) {
                bits.push((val >> i) & 1);
            }
        }

        addBits(4, 4); // Byte mode
        var ccLen = version <= 9 ? 8 : 16;
        addBits(data.length, ccLen); // Character count
        for (var i = 0; i < data.length; i++) {
            addBits(data[i], 8);
        }
        // Terminator
        var maxBits = dataCodewords * 8;
        var termLen = Math.min(4, maxBits - bits.length);
        addBits(0, termLen);
        // Pad to byte boundary
        while (bits.length % 8 !== 0) bits.push(0);
        // Pad codewords
        var padBytes = [0xEC, 0x11];
        var padIdx = 0;
        while (bits.length < maxBits) {
            addBits(padBytes[padIdx], 8);
            padIdx = (padIdx + 1) % 2;
        }

        // Convert bits to bytes
        var codewords = [];
        for (var i = 0; i < bits.length; i += 8) {
            var b = 0;
            for (var j = 0; j < 8; j++) b = (b << 1) | (bits[i + j] || 0);
            codewords.push(b);
        }

        // Split into blocks and add EC
        var dataPerBlock = Math.floor(dataCodewords / numBlocks);
        var extraBlocks = dataCodewords % numBlocks;
        var blocks = [];
        var ecBlocks = [];
        var offset = 0;

        for (var b = 0; b < numBlocks; b++) {
            var blockLen = dataPerBlock + (b >= numBlocks - extraBlocks ? 1 : 0);
            var blockData = codewords.slice(offset, offset + blockLen);
            offset += blockLen;
            blocks.push(blockData);
            ecBlocks.push(rsEncode(blockData, ecPerBlock));
        }

        // Interleave data blocks
        var result = [];
        var maxDataLen = dataPerBlock + (extraBlocks > 0 ? 1 : 0);
        for (var i = 0; i < maxDataLen; i++) {
            for (var b = 0; b < numBlocks; b++) {
                if (i < blocks[b].length) result.push(blocks[b][i]);
            }
        }
        // Interleave EC blocks
        for (var i = 0; i < ecPerBlock; i++) {
            for (var b = 0; b < numBlocks; b++) {
                result.push(ecBlocks[b][i]);
            }
        }

        return { version: version, data: result };
    }

    // -- Matrix placement --
    function createMatrix(version) {
        var size = VERSION_SIZE[version];
        var matrix = [];
        var reserved = [];
        for (var i = 0; i < size; i++) {
            matrix[i] = new Array(size);
            reserved[i] = new Array(size);
            for (var j = 0; j < size; j++) {
                matrix[i][j] = 0;
                reserved[i][j] = false;
            }
        }
        return { matrix: matrix, reserved: reserved, size: size };
    }

    function placeFinderPattern(m, row, col) {
        for (var r = -1; r <= 7; r++) {
            for (var c = -1; c <= 7; c++) {
                var rr = row + r, cc = col + c;
                if (rr < 0 || rr >= m.size || cc < 0 || cc >= m.size) continue;
                var val;
                if (r === -1 || r === 7 || c === -1 || c === 7) {
                    val = 0; // separator
                } else if (r === 0 || r === 6 || c === 0 || c === 6) {
                    val = 1;
                } else if (r >= 2 && r <= 4 && c >= 2 && c <= 4) {
                    val = 1;
                } else {
                    val = 0;
                }
                m.matrix[rr][cc] = val;
                m.reserved[rr][cc] = true;
            }
        }
    }

    function placeAlignmentPattern(m, row, col) {
        for (var r = -2; r <= 2; r++) {
            for (var c = -2; c <= 2; c++) {
                var rr = row + r, cc = col + c;
                if (rr < 0 || rr >= m.size || cc < 0 || cc >= m.size) continue;
                if (m.reserved[rr][cc]) continue;
                var val = (Math.abs(r) === 2 || Math.abs(c) === 2 || (r === 0 && c === 0)) ? 1 : 0;
                m.matrix[rr][cc] = val;
                m.reserved[rr][cc] = true;
            }
        }
    }

    function placeTimingPatterns(m) {
        for (var i = 8; i < m.size - 8; i++) {
            var val = (i % 2 === 0) ? 1 : 0;
            if (!m.reserved[6][i]) {
                m.matrix[6][i] = val;
                m.reserved[6][i] = true;
            }
            if (!m.reserved[i][6]) {
                m.matrix[i][6] = val;
                m.reserved[i][6] = true;
            }
        }
    }

    function reserveFormatArea(m) {
        // Around top-left finder
        for (var i = 0; i <= 8; i++) {
            if (i < m.size) { m.reserved[8][i] = true; m.reserved[i][8] = true; }
        }
        // Around top-right finder
        for (var i = 0; i <= 7; i++) {
            m.reserved[8][m.size - 1 - i] = true;
        }
        // Around bottom-left finder
        for (var i = 0; i <= 7; i++) {
            m.reserved[m.size - 1 - i][8] = true;
        }
        // Dark module
        m.matrix[m.size - 8][8] = 1;
        m.reserved[m.size - 8][8] = true;
    }

    function placeData(m, data) {
        var bits = [];
        for (var i = 0; i < data.length; i++) {
            for (var j = 7; j >= 0; j--) {
                bits.push((data[i] >> j) & 1);
            }
        }
        // Remainder bits (for versions 2-6: 7 bits, v1: 0, v7+: varies but we handle up to 10)
        // Versions 2-6 need 7 remainder bits, version 7-10 need 0 remainder bits, version 1 needs 0
        // Actually: v1=0, v2-6=7, v7-13=0, v14-20=3, v21-27=4, v28-34=3
        // For our range (1-10):
        var version = (m.size - 17) / 4;
        if (version >= 2 && version <= 6) {
            for (var i = 0; i < 7; i++) bits.push(0);
        }

        var bitIdx = 0;
        var upward = true;
        for (var col = m.size - 1; col >= 1; col -= 2) {
            if (col === 6) col = 5; // skip timing column
            var rows = upward
                ? (function(s) { var a=[]; for(var i=s-1;i>=0;i--) a.push(i); return a; })(m.size)
                : (function(s) { var a=[]; for(var i=0;i<s;i++) a.push(i); return a; })(m.size);
            for (var ri = 0; ri < rows.length; ri++) {
                var row = rows[ri];
                for (var dc = 0; dc < 2; dc++) {
                    var c = col - dc;
                    if (c < 0) continue;
                    if (m.reserved[row][c]) continue;
                    m.matrix[row][c] = (bitIdx < bits.length) ? bits[bitIdx] : 0;
                    bitIdx++;
                }
            }
            upward = !upward;
        }
    }

    // Mask patterns (0-7)
    var MASK_FNS = [
        function(r,c) { return (r+c)%2===0; },
        function(r,c) { return r%2===0; },
        function(r,c) { return c%3===0; },
        function(r,c) { return (r+c)%3===0; },
        function(r,c) { return (Math.floor(r/2)+Math.floor(c/3))%2===0; },
        function(r,c) { return ((r*c)%2+(r*c)%3)===0; },
        function(r,c) { return (((r*c)%2+(r*c)%3)%2)===0; },
        function(r,c) { return (((r+c)%2+(r*c)%3)%2)===0; }
    ];

    function applyMask(m, maskIdx) {
        var fn = MASK_FNS[maskIdx];
        for (var r = 0; r < m.size; r++) {
            for (var c = 0; c < m.size; c++) {
                if (!m.reserved[r][c] && fn(r, c)) {
                    m.matrix[r][c] ^= 1;
                }
            }
        }
    }

    // Format info (ECC level L = 01, mask 0-7)
    // Precomputed format strings for level L (01), masks 0-7
    var FORMAT_BITS = [
        0x77c4, 0x72f3, 0x7daa, 0x789d, 0x662f, 0x6318, 0x6c41, 0x6976
    ];

    function placeFormatInfo(m, maskIdx) {
        var bits = FORMAT_BITS[maskIdx];
        // Place format info around the finder patterns
        var positions = [
            // Around top-left (horizontal, columns 0-7 then 8)
            [8,0],[8,1],[8,2],[8,3],[8,4],[8,5],[8,7],[8,8],
            // Around top-left (vertical, rows 8 down to 0)
            [7,8],[5,8],[4,8],[3,8],[2,8],[1,8],[0,8]
        ];
        for (var i = 0; i < 15; i++) {
            var val = (bits >> (14 - i)) & 1;
            var r, c;
            if (i < 8) {
                r = positions[i][0]; c = positions[i][1];
            } else {
                r = positions[i][0]; c = positions[i][1];
            }
            m.matrix[r][c] = val;
        }

        // Vertical: bottom-left going up
        var vPositions = [
            [m.size-1,8],[m.size-2,8],[m.size-3,8],[m.size-4,8],
            [m.size-5,8],[m.size-6,8],[m.size-7,8]
        ];
        for (var i = 0; i < 7; i++) {
            m.matrix[vPositions[i][0]][vPositions[i][1]] = (bits >> (14 - i)) & 1;
        }

        // Horizontal: top-right going left
        var hPositions = [
            [8,m.size-8],[8,m.size-7],[8,m.size-6],[8,m.size-5],
            [8,m.size-4],[8,m.size-3],[8,m.size-2],[8,m.size-1]
        ];
        for (var i = 0; i < 8; i++) {
            m.matrix[hPositions[i][0]][hPositions[i][1]] = (bits >> (7 - i)) & 1;
        }
    }

    // Scoring penalty for mask selection
    function scoreMask(matrix, size) {
        var score = 0;

        // Rule 1: Consecutive same-color modules in row/column
        for (var r = 0; r < size; r++) {
            var count = 1;
            for (var c = 1; c < size; c++) {
                if (matrix[r][c] === matrix[r][c-1]) {
                    count++;
                    if (count === 5) score += 3;
                    else if (count > 5) score += 1;
                } else {
                    count = 1;
                }
            }
        }
        for (var c = 0; c < size; c++) {
            var count = 1;
            for (var r = 1; r < size; r++) {
                if (matrix[r][c] === matrix[r-1][c]) {
                    count++;
                    if (count === 5) score += 3;
                    else if (count > 5) score += 1;
                } else {
                    count = 1;
                }
            }
        }

        // Rule 2: 2x2 blocks of same color
        for (var r = 0; r < size - 1; r++) {
            for (var c = 0; c < size - 1; c++) {
                var val = matrix[r][c];
                if (val === matrix[r][c+1] && val === matrix[r+1][c] && val === matrix[r+1][c+1]) {
                    score += 3;
                }
            }
        }

        // Rule 3: Finder-like patterns (simplified)
        // Rule 4: Proportion of dark modules
        var dark = 0;
        for (var r = 0; r < size; r++) {
            for (var c = 0; c < size; c++) {
                if (matrix[r][c]) dark++;
            }
        }
        var pct = Math.abs(Math.round(dark * 100 / (size * size)) - 50);
        score += Math.floor(pct / 5) * 10;

        return score;
    }

    function deepCopyMatrix(matrix, size) {
        var copy = [];
        for (var r = 0; r < size; r++) {
            copy[r] = matrix[r].slice();
        }
        return copy;
    }

    function generate(text) {
        var encoded = encodeData(text);
        if (!encoded) return null;

        var version = encoded.version;
        var size = VERSION_SIZE[version];

        // Build matrix with fixed patterns
        var m = createMatrix(version);
        placeFinderPattern(m, 0, 0);
        placeFinderPattern(m, 0, m.size - 7);
        placeFinderPattern(m, m.size - 7, 0);
        placeTimingPatterns(m);

        // Alignment patterns
        var aligns = ALIGNMENT_PATTERNS[version];
        if (aligns.length > 0) {
            for (var i = 0; i < aligns.length; i++) {
                for (var j = 0; j < aligns.length; j++) {
                    // Skip if overlapping with finder patterns
                    if (i === 0 && j === 0) continue;
                    if (i === 0 && j === aligns.length - 1) continue;
                    if (i === aligns.length - 1 && j === 0) continue;
                    placeAlignmentPattern(m, aligns[i], aligns[j]);
                }
            }
        }

        reserveFormatArea(m);

        // Place data codewords
        placeData(m, encoded.data);

        // Try all 8 masks, pick the one with the lowest penalty score
        var bestMask = 0;
        var bestScore = Infinity;
        var bestMatrix = null;

        for (var mask = 0; mask < 8; mask++) {
            // Copy matrix
            var testMatrix = deepCopyMatrix(m.matrix, size);
            var testM = { matrix: testMatrix, reserved: m.reserved, size: size };
            applyMask(testM, mask);
            placeFormatInfo(testM, mask);
            var s = scoreMask(testMatrix, size);
            if (s < bestScore) {
                bestScore = s;
                bestMask = mask;
                bestMatrix = testMatrix;
            }
        }

        return { matrix: bestMatrix, size: size };
    }

    function generateSVG(text, pixelSize) {
        var qr = generate(text);
        if (!qr) return '<p style="color:red;">QR code generation failed. Please enter the secret manually.</p>';

        var size = qr.size;
        var quiet = 4; // quiet zone
        var total = size + quiet * 2;
        var cellSize = pixelSize / total;

        var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' + pixelSize + '" height="' + pixelSize +
            '" viewBox="0 0 ' + total + ' ' + total + '" shape-rendering="crispEdges">';
        svg += '<rect width="' + total + '" height="' + total + '" fill="#fff"/>';

        for (var r = 0; r < size; r++) {
            for (var c = 0; c < size; c++) {
                if (qr.matrix[r][c]) {
                    svg += '<rect x="' + (c + quiet) + '" y="' + (r + quiet) + '" width="1" height="1" fill="#000"/>';
                }
            }
        }

        svg += '</svg>';
        return svg;
    }

    return {
        generate: generate,
        generateSVG: generateSVG
    };
})();
