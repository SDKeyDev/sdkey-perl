package Sdkey::Crypto::Constants;

use strict;
use warnings;

use Exporter qw(import);

our @EXPORT_OK = qw(
  PROTOCOL_VERSION
  CLOCK_SKEW_SECONDS
  CLIENT_NONCE_BYTES
  SERVER_NONCE_BYTES
  VALIDATE_NONCE_BYTES
  AES_GCM_IV_BYTES
  AES_GCM_TAG_BITS
  AES_GCM_TAG_BYTES
  SESSION_AES_KEY_BYTES
  SESSION_HKDF_INFO_PREFIX
  VALIDATE_FAILURE_CODES
);

use constant PROTOCOL_VERSION       => 1;
use constant CLOCK_SKEW_SECONDS     => 60;
use constant CLIENT_NONCE_BYTES     => 32;
use constant SERVER_NONCE_BYTES     => 32;
use constant VALIDATE_NONCE_BYTES   => 16;
use constant AES_GCM_IV_BYTES       => 12;
use constant AES_GCM_TAG_BITS       => 128;
use constant AES_GCM_TAG_BYTES      => 16;
use constant SESSION_AES_KEY_BYTES  => 32;
use constant SESSION_HKDF_INFO_PREFIX => 'sdkey-session-v1';

use constant VALIDATE_FAILURE_CODES => [
  'SESSION_EXPIRED',
  'CLOCK_SKEW',
  'REPLAY',
  'LICENSE_NOT_FOUND',
  'APP_MISMATCH',
  'BANNED',
  'EXPIRED',
  'HWID_MISMATCH',
  'DECRYPT_FAIL',
  'APP_DISABLED',
  'APP_OUTDATED',
  'HWID_BANNED',
  'IP_BANNED',
];

1;

__END__

=head1 NAME

Sdkey::Crypto::Constants - Wire-protocol constants (protocol v1)

=cut
