#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";

use Crypt::PRNG qw(random_bytes);
use Sdkey::Crypto::Encoding qw(bytes_to_base64);
use Sdkey::Crypto::Seal qw(derive_session_aes_key open_aes_gcm seal_aes_gcm);

subtest 'aes_gcm_round_trips_plaintext' => sub {
  my $aes_key   = random_bytes(32);
  my $plaintext = '{"ok":true}';
  my $sealed    = seal_aes_gcm($aes_key, $plaintext);
  my $opened    = open_aes_gcm($aes_key, $sealed);
  is($opened, $plaintext, 'round-trip');
};

subtest 'derive_session_aes_key_is_deterministic' => sub {
  my $client_nonce = random_bytes(32);
  my $server_nonce = random_bytes(32);
  my $salt_b64     = bytes_to_base64(random_bytes(16));
  my $app_id       = '11111111-2222-3333-4444-555555555555';

  my $a = derive_session_aes_key(
    client_nonce => $client_nonce,
    server_nonce => $server_nonce,
    salt_b64     => $salt_b64,
    app_id       => $app_id,
  );
  my $b = derive_session_aes_key(
    client_nonce => $client_nonce,
    server_nonce => $server_nonce,
    salt_b64     => $salt_b64,
    app_id       => $app_id,
  );
  is(bytes_to_base64($a), bytes_to_base64($b), 'deterministic');
  is(length($a), 32, '32-byte key');
};

subtest 'derive_session_aes_key_changes_when_app_id_changes' => sub {
  my $client_nonce = "\x01" x 32;
  my $server_nonce = "\x02" x 32;
  my $salt_b64     = bytes_to_base64("\x03" x 16);

  my $a = derive_session_aes_key(
    client_nonce => $client_nonce,
    server_nonce => $server_nonce,
    salt_b64     => $salt_b64,
    app_id       => 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  );
  my $b = derive_session_aes_key(
    client_nonce => $client_nonce,
    server_nonce => $server_nonce,
    salt_b64     => $salt_b64,
    app_id       => 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
  );
  isnt(bytes_to_base64($a), bytes_to_base64($b), 'different app_id → different key');
};

done_testing;
