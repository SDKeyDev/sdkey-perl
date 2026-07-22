package Sdkey;

use strict;
use warnings;

use Sdkey::Client;
use Sdkey::Error;
use Sdkey::Types;
use Sdkey::Crypto::Constants qw(
  PROTOCOL_VERSION
  CLOCK_SKEW_SECONDS
  CLIENT_NONCE_BYTES
  SERVER_NONCE_BYTES
  VALIDATE_NONCE_BYTES
  AES_GCM_IV_BYTES
  SESSION_AES_KEY_BYTES
  SESSION_HKDF_INFO_PREFIX
  VALIDATE_FAILURE_CODES
);
use Sdkey::Crypto::Encoding qw(bytes_to_base64 base64_to_bytes);
use Sdkey::Crypto::CanonicalJson qw(canonical_json canonicalize);
use Sdkey::Crypto::Seal qw(
  import_public_key
  verify_signature
  derive_session_aes_key
  seal_aes_gcm
  open_aes_gcm
);

our $VERSION = '0.2.0';

use Exporter qw(import);

our @EXPORT_OK = qw(
  PROTOCOL_VERSION
  CLOCK_SKEW_SECONDS
  CLIENT_NONCE_BYTES
  SERVER_NONCE_BYTES
  VALIDATE_NONCE_BYTES
  AES_GCM_IV_BYTES
  SESSION_AES_KEY_BYTES
  SESSION_HKDF_INFO_PREFIX
  VALIDATE_FAILURE_CODES
  bytes_to_base64
  base64_to_bytes
  canonical_json
  canonicalize
  import_public_key
  verify_signature
  derive_session_aes_key
  seal_aes_gcm
  open_aes_gcm
);

sub new {
  my ($class, @args) = @_;
  return Sdkey::Client->new(@args);
}

1;

__END__

=head1 NAME

Sdkey - Official Perl client for the SDKey license authentication protocol

=head1 VERSION

0.2.0

=head1 SYNOPSIS

  use Sdkey;

  my $client = Sdkey->new(
    api_base_url       => 'https://api.sdkey.dev',
    app_id             => 'YOUR_APP_ID',
    app_version        => '1.0.0',
    app_public_key_b64 => 'YOUR_APP_PUBLIC_KEY_BASE64',
  );

  my $result = $client->validate('SDKY-XXXX-XXXX-XXXX-XXXX');

=head1 DESCRIPTION

Implements the sealed session protocol (Ed25519 hello verify, HKDF session
keys, AES-256-GCM validate) plus plaintext client auth (register / login /
upgrade). See L<PROTOCOL.md> in this distribution.

=head1 SEE ALSO

L<https://github.com/SDKeyDev/sdkey-perl>

=head1 LICENSE

MIT

=cut
