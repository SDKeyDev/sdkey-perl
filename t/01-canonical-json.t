#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";

use JSON::PP ();
use Sdkey::Crypto::CanonicalJson qw(canonical_json canonicalize);

is(canonicalize({ b => 1, a => 2 }), '{"a":2,"b":1}', 'sorts object keys lexicographically');

is(canonicalize({ a => 1, b => undef }), '{"a":1,"b":null}', 'encodes null fields');

is(
  canonicalize({ z => [$JSON::PP::true, undef, 'x'], m => { k => 0 } }),
  '{"m":{"k":0},"z":[true,null,"x"]}',
  'encodes nested structures without whitespace'
);

is(canonical_json({ a => 1 }), '{"a":1}', 'returns utf8 bytes (as string octets)');

done_testing;
