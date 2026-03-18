<?php
/**
 * Minimal QR Code Generator — pure PHP, outputs inline SVG.
 *
 * Supports Byte-mode encoding, ECC level L, versions 1–10.
 * Sufficient for otpauth:// URIs (up to ~271 bytes).
 *
 * @package BestDid_Security
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class BDSEC_QR {

    // EC level L capacities (byte mode) for versions 1-10.
    private static $CAPACITY   = array( 0, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271 );
    private static $SIZE       = array( 0, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57 );
    private static $TOTAL_CW   = array( 0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346 );
    private static $EC_PER_BLK = array( 0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18 );
    private static $NUM_BLKS   = array( 0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4 );
    private static $ALIGN      = array(
        array(), array(), array(6,18), array(6,22), array(6,26), array(6,30), array(6,34),
        array(6,22,38), array(6,24,42), array(6,26,46), array(6,28,50),
    );

    // Pre-computed format info bits (EC level L, masks 0-7).
    private static $FORMAT = array( 0x77c4, 0x72f3, 0x7daa, 0x789d, 0x662f, 0x6318, 0x6c41, 0x6976 );

    // GF(256) tables for Reed-Solomon.
    private static $gf_exp = null;
    private static $gf_log = null;

    private static function init_gf() {
        if ( self::$gf_exp !== null ) return;
        self::$gf_exp = array();
        self::$gf_log = array();
        $x = 1;
        for ( $i = 0; $i < 256; $i++ ) {
            self::$gf_exp[ $i ] = $x;
            self::$gf_log[ $x ] = $i;
            $x <<= 1;
            if ( $x & 256 ) $x ^= 0x11d;
        }
        self::$gf_log[0] = 255;
    }

    private static function gf_mul( $a, $b ) {
        if ( $a === 0 || $b === 0 ) return 0;
        return self::$gf_exp[ ( self::$gf_log[ $a ] + self::$gf_log[ $b ] ) % 255 ];
    }

    private static function rs_encode( $data, $ec_count ) {
        // Build generator polynomial.
        $gen = array( 1 );
        for ( $i = 0; $i < $ec_count; $i++ ) {
            $new = array_fill( 0, count( $gen ) + 1, 0 );
            for ( $j = 0; $j < count( $gen ); $j++ ) {
                $new[ $j ]     ^= $gen[ $j ];
                $new[ $j + 1 ] ^= self::gf_mul( $gen[ $j ], self::$gf_exp[ $i ] );
            }
            $gen = $new;
        }
        // Polynomial division.
        $msg = array_merge( $data, array_fill( 0, $ec_count, 0 ) );
        for ( $i = 0; $i < count( $data ); $i++ ) {
            $coef = $msg[ $i ];
            if ( $coef !== 0 ) {
                for ( $j = 1; $j < count( $gen ); $j++ ) {
                    $msg[ $i + $j ] ^= self::gf_mul( $gen[ $j ], $coef );
                }
            }
        }
        return array_slice( $msg, count( $data ) );
    }

    /**
     * Generate an inline SVG QR code for the given text.
     *
     * @param string $text     Data to encode.
     * @param int    $px_size  SVG width/height in pixels.
     * @return string SVG markup, or empty string on failure.
     */
    public static function svg( $text, $px_size = 200 ) {
        self::init_gf();

        // UTF-8 bytes.
        $data = array_values( unpack( 'C*', $text ) );
        $len  = count( $data );

        // Find minimum version.
        $ver = 0;
        for ( $v = 1; $v <= 10; $v++ ) {
            if ( $len <= self::$CAPACITY[ $v ] ) { $ver = $v; break; }
        }
        if ( ! $ver ) return '';

        $total_cw   = self::$TOTAL_CW[ $ver ];
        $ec_per_blk = self::$EC_PER_BLK[ $ver ];
        $num_blks   = self::$NUM_BLKS[ $ver ];
        $data_cw    = $total_cw - $ec_per_blk * $num_blks;
        $size       = self::$SIZE[ $ver ];

        // --- Encode bit stream ---
        $bits = array();
        $add  = function( $val, $n ) use ( &$bits ) {
            for ( $i = $n - 1; $i >= 0; $i-- ) $bits[] = ( $val >> $i ) & 1;
        };

        $add( 4, 4 ); // Byte mode indicator.
        $add( $len, $ver <= 9 ? 8 : 16 ); // Character count.
        foreach ( $data as $b ) $add( $b, 8 );

        // Terminator.
        $max_bits = $data_cw * 8;
        $term     = min( 4, $max_bits - count( $bits ) );
        $add( 0, $term );
        while ( count( $bits ) % 8 !== 0 ) $bits[] = 0;
        $pad_bytes = array( 0xEC, 0x11 );
        $pi = 0;
        while ( count( $bits ) < $max_bits ) {
            $add( $pad_bytes[ $pi ], 8 );
            $pi = ( $pi + 1 ) % 2;
        }

        // Bits → codewords.
        $codewords = array();
        for ( $i = 0; $i < count( $bits ); $i += 8 ) {
            $b = 0;
            for ( $j = 0; $j < 8; $j++ ) $b = ( $b << 1 ) | ( $bits[ $i + $j ] ?? 0 );
            $codewords[] = $b;
        }

        // --- Split into blocks + RS EC ---
        $dpb = intdiv( $data_cw, $num_blks );
        $extra = $data_cw % $num_blks;
        $blocks = array();
        $ec_blocks = array();
        $off = 0;
        for ( $b = 0; $b < $num_blks; $b++ ) {
            $bl = $dpb + ( $b >= $num_blks - $extra ? 1 : 0 );
            $bd = array_slice( $codewords, $off, $bl );
            $off += $bl;
            $blocks[] = $bd;
            $ec_blocks[] = self::rs_encode( $bd, $ec_per_blk );
        }

        // Interleave.
        $result = array();
        $max_dl = $dpb + ( $extra > 0 ? 1 : 0 );
        for ( $i = 0; $i < $max_dl; $i++ ) {
            for ( $b = 0; $b < $num_blks; $b++ ) {
                if ( $i < count( $blocks[ $b ] ) ) $result[] = $blocks[ $b ][ $i ];
            }
        }
        for ( $i = 0; $i < $ec_per_blk; $i++ ) {
            for ( $b = 0; $b < $num_blks; $b++ ) {
                $result[] = $ec_blocks[ $b ][ $i ];
            }
        }

        // --- Build matrix ---
        $matrix   = array_fill( 0, $size, array_fill( 0, $size, 0 ) );
        $reserved = array_fill( 0, $size, array_fill( 0, $size, false ) );

        // Finder patterns.
        $place_finder = function( $row, $col ) use ( &$matrix, &$reserved, $size ) {
            for ( $r = -1; $r <= 7; $r++ ) {
                for ( $c = -1; $c <= 7; $c++ ) {
                    $rr = $row + $r; $cc = $col + $c;
                    if ( $rr < 0 || $rr >= $size || $cc < 0 || $cc >= $size ) continue;
                    if ( $r === -1 || $r === 7 || $c === -1 || $c === 7 ) {
                        $val = 0;
                    } elseif ( $r === 0 || $r === 6 || $c === 0 || $c === 6 ) {
                        $val = 1;
                    } elseif ( $r >= 2 && $r <= 4 && $c >= 2 && $c <= 4 ) {
                        $val = 1;
                    } else {
                        $val = 0;
                    }
                    $matrix[ $rr ][ $cc ]   = $val;
                    $reserved[ $rr ][ $cc ] = true;
                }
            }
        };
        $place_finder( 0, 0 );
        $place_finder( 0, $size - 7 );
        $place_finder( $size - 7, 0 );

        // Timing patterns.
        for ( $i = 8; $i < $size - 8; $i++ ) {
            $val = ( $i % 2 === 0 ) ? 1 : 0;
            if ( ! $reserved[6][ $i ] ) { $matrix[6][ $i ] = $val; $reserved[6][ $i ] = true; }
            if ( ! $reserved[ $i ][6] ) { $matrix[ $i ][6] = $val; $reserved[ $i ][6] = true; }
        }

        // Alignment patterns.
        $aligns = self::$ALIGN[ $ver ];
        $ac = count( $aligns );
        for ( $ai = 0; $ai < $ac; $ai++ ) {
            for ( $aj = 0; $aj < $ac; $aj++ ) {
                if ( $ai === 0 && $aj === 0 ) continue;
                if ( $ai === 0 && $aj === $ac - 1 ) continue;
                if ( $ai === $ac - 1 && $aj === 0 ) continue;
                $ar = $aligns[ $ai ]; $acl = $aligns[ $aj ];
                for ( $r = -2; $r <= 2; $r++ ) {
                    for ( $c = -2; $c <= 2; $c++ ) {
                        $rr = $ar + $r; $cc = $acl + $c;
                        if ( $rr < 0 || $rr >= $size || $cc < 0 || $cc >= $size ) continue;
                        if ( $reserved[ $rr ][ $cc ] ) continue;
                        $val = ( abs( $r ) === 2 || abs( $c ) === 2 || ( $r === 0 && $c === 0 ) ) ? 1 : 0;
                        $matrix[ $rr ][ $cc ]   = $val;
                        $reserved[ $rr ][ $cc ] = true;
                    }
                }
            }
        }

        // Reserve format info areas.
        for ( $i = 0; $i <= 8; $i++ ) {
            if ( $i < $size ) { $reserved[8][ $i ] = true; $reserved[ $i ][8] = true; }
        }
        for ( $i = 0; $i <= 7; $i++ ) $reserved[8][ $size - 1 - $i ] = true;
        for ( $i = 0; $i <= 7; $i++ ) $reserved[ $size - 1 - $i ][8] = true;
        // Dark module.
        $matrix[ $size - 8 ][8] = 1;
        $reserved[ $size - 8 ][8] = true;

        // --- Place data ---
        $dbits = array();
        foreach ( $result as $byte ) {
            for ( $j = 7; $j >= 0; $j-- ) $dbits[] = ( $byte >> $j ) & 1;
        }
        // Remainder bits for versions 2-6.
        if ( $ver >= 2 && $ver <= 6 ) {
            for ( $i = 0; $i < 7; $i++ ) $dbits[] = 0;
        }

        $bi = 0;
        $upward = true;
        for ( $col = $size - 1; $col >= 1; $col -= 2 ) {
            if ( $col === 6 ) $col = 5;
            $rows = array();
            if ( $upward ) { for ( $r = $size - 1; $r >= 0; $r-- ) $rows[] = $r; }
            else            { for ( $r = 0; $r < $size; $r++ ) $rows[] = $r; }
            foreach ( $rows as $row ) {
                for ( $dc = 0; $dc < 2; $dc++ ) {
                    $c = $col - $dc;
                    if ( $c < 0 || $reserved[ $row ][ $c ] ) continue;
                    $matrix[ $row ][ $c ] = ( $bi < count( $dbits ) ) ? $dbits[ $bi ] : 0;
                    $bi++;
                }
            }
            $upward = ! $upward;
        }

        // --- Masking ---
        $mask_fns = array(
            function( $r, $c ) { return ( $r + $c ) % 2 === 0; },
            function( $r, $c ) { return $r % 2 === 0; },
            function( $r, $c ) { return $c % 3 === 0; },
            function( $r, $c ) { return ( $r + $c ) % 3 === 0; },
            function( $r, $c ) { return ( intdiv( $r, 2 ) + intdiv( $c, 3 ) ) % 2 === 0; },
            function( $r, $c ) { return ( ( $r * $c ) % 2 + ( $r * $c ) % 3 ) === 0; },
            function( $r, $c ) { return ( ( ( $r * $c ) % 2 + ( $r * $c ) % 3 ) % 2 ) === 0; },
            function( $r, $c ) { return ( ( ( $r + $c ) % 2 + ( $r * $c ) % 3 ) % 2 ) === 0; },
        );

        $best_mask   = 0;
        $best_score  = PHP_INT_MAX;
        $best_matrix = null;

        for ( $mask = 0; $mask < 8; $mask++ ) {
            // Deep copy matrix.
            $test = array();
            for ( $r = 0; $r < $size; $r++ ) $test[ $r ] = $matrix[ $r ];

            // Apply mask.
            for ( $r = 0; $r < $size; $r++ ) {
                for ( $c = 0; $c < $size; $c++ ) {
                    if ( ! $reserved[ $r ][ $c ] && $mask_fns[ $mask ]( $r, $c ) ) {
                        $test[ $r ][ $c ] ^= 1;
                    }
                }
            }

            // Place format info.
            self::place_format( $test, $size, $mask );

            // Score.
            $score = self::score_mask( $test, $size );
            if ( $score < $best_score ) {
                $best_score  = $score;
                $best_mask   = $mask;
                $best_matrix = $test;
            }
        }

        // --- Render SVG ---
        $quiet = 4;
        $total = $size + $quiet * 2;
        $svg   = '<svg xmlns="http://www.w3.org/2000/svg" width="' . $px_size . '" height="' . $px_size
               . '" viewBox="0 0 ' . $total . ' ' . $total . '" shape-rendering="crispEdges">'
               . '<rect width="' . $total . '" height="' . $total . '" fill="#fff"/>';
        for ( $r = 0; $r < $size; $r++ ) {
            for ( $c = 0; $c < $size; $c++ ) {
                if ( $best_matrix[ $r ][ $c ] ) {
                    $svg .= '<rect x="' . ( $c + $quiet ) . '" y="' . ( $r + $quiet ) . '" width="1" height="1" fill="#000"/>';
                }
            }
        }
        $svg .= '</svg>';
        return $svg;
    }

    /**
     * Place format info bits in the matrix (both copies).
     */
    private static function place_format( &$m, $size, $mask_idx ) {
        $bits = self::$FORMAT[ $mask_idx ];

        // First copy — around top-left finder.
        // Horizontal (row 8): columns 0-5, 7, 8 (skip col 6 = timing).
        $h_cols = array( 0, 1, 2, 3, 4, 5, 7, 8 );
        for ( $i = 0; $i < 8; $i++ ) {
            $m[8][ $h_cols[ $i ] ] = ( $bits >> ( 14 - $i ) ) & 1;
        }
        // Vertical (col 8): rows 7, 5, 4, 3, 2, 1, 0 (skip row 6 = timing).
        $v_rows = array( 7, 5, 4, 3, 2, 1, 0 );
        for ( $i = 0; $i < 7; $i++ ) {
            $m[ $v_rows[ $i ] ][8] = ( $bits >> ( 6 - $i ) ) & 1;
        }

        // Second copy — bottom-left vertical + top-right horizontal.
        // Bottom-left: rows size-1 down to size-7, col 8. Bits 0..6 (MSB-first).
        for ( $i = 0; $i < 7; $i++ ) {
            $m[ $size - 1 - $i ][8] = ( $bits >> ( 14 - $i ) ) & 1;
        }
        // Top-right: row 8, cols size-8 to size-1. Bits 7..14 (MSB-first).
        for ( $i = 0; $i < 8; $i++ ) {
            $m[8][ $size - 8 + $i ] = ( $bits >> ( 7 - $i ) ) & 1;
        }
    }

    /**
     * Penalty score for mask evaluation.
     */
    private static function score_mask( $matrix, $size ) {
        $score = 0;

        // Rule 1: runs of same colour in rows/columns.
        for ( $r = 0; $r < $size; $r++ ) {
            $cnt = 1;
            for ( $c = 1; $c < $size; $c++ ) {
                if ( $matrix[ $r ][ $c ] === $matrix[ $r ][ $c - 1 ] ) {
                    $cnt++;
                    if ( $cnt === 5 ) $score += 3;
                    elseif ( $cnt > 5 ) $score += 1;
                } else {
                    $cnt = 1;
                }
            }
        }
        for ( $c = 0; $c < $size; $c++ ) {
            $cnt = 1;
            for ( $r = 1; $r < $size; $r++ ) {
                if ( $matrix[ $r ][ $c ] === $matrix[ $r - 1 ][ $c ] ) {
                    $cnt++;
                    if ( $cnt === 5 ) $score += 3;
                    elseif ( $cnt > 5 ) $score += 1;
                } else {
                    $cnt = 1;
                }
            }
        }

        // Rule 2: 2×2 blocks.
        for ( $r = 0; $r < $size - 1; $r++ ) {
            for ( $c = 0; $c < $size - 1; $c++ ) {
                $v = $matrix[ $r ][ $c ];
                if ( $v === $matrix[ $r ][ $c + 1 ] && $v === $matrix[ $r + 1 ][ $c ] && $v === $matrix[ $r + 1 ][ $c + 1 ] ) {
                    $score += 3;
                }
            }
        }

        // Rule 4: proportion of dark modules.
        $dark = 0;
        for ( $r = 0; $r < $size; $r++ ) {
            for ( $c = 0; $c < $size; $c++ ) {
                if ( $matrix[ $r ][ $c ] ) $dark++;
            }
        }
        $pct = abs( round( $dark * 100 / ( $size * $size ) ) - 50 );
        $score += intdiv( $pct, 5 ) * 10;

        return $score;
    }
}
