package Sdkey::Crypto::Seal;

use strict;
use warnings;

use Exporter qw(import);
use Carp qw(croak);
use Crypt::AuthEnc::GCM ();
use Crypt::KeyDerivation qw(hkdf);
use Crypt::PK::Ed25519 ();
use Crypt::PRNG qw(random_bytes);

use Sdkey::Crypto::CanonicalJson qw(canonical_json);
use Sdkey::Crypto::Constants qw(
  AES_GCM_IV_BYTES
  AES_GCM_TAG_BYTES
  SESSION_AES_KEY_BYTES
  SESSION_HKDF_INFO_PREFIX
);
use Sdkey::Crypto::Encoding qw(base64_to_bytes bytes_to_base64);

our @EXPORT_OK = qw(
  import_public_key
  verify_signature
  derive_session_aes_key
  seal_aes_gcm
  open_aes_gcm
  sealed_as_wire
);

sub import_public_key {
  my ($public_key_b64) = @_;
  my $raw = base64_to_bytes($public_key_b64);
  my $pk = Crypt::PK::Ed25519->new;
  $pk->import_key_raw($raw, 'public');
  return $pk;
}

sub verify_signature {
  my ($public_key, $payload, $signature_b64) = @_;
  my $ok = eval {
    $public_key->verify_message(base64_to_bytes($signature_b64), canonical_json($payload));
  };
  return $ok ? 1 : 0;
}

sub derive_session_aes_key {
  my (%args) = @_;
  my $client_nonce = $args{client_nonce} // croak('client_nonce required');
  my $server_nonce = $args{server_nonce} // croak('server_nonce required');
  my $salt_b64     = $args{salt_b64}     // croak('salt_b64 required');
  my $app_id       = $args{app_id}       // croak('app_id required');

  my $ikm  = $client_nonce . $server_nonce;
  my $salt = base64_to_bytes($salt_b64);
  my $info = SESSION_HKDF_INFO_PREFIX . $app_id;
  return hkdf($ikm, $salt, 'SHA256', SESSION_AES_KEY_BYTES, $info);
}

sub seal_aes_gcm {
  my ($aes_key, $plaintext) = @_;
  my $iv = random_bytes(AES_GCM_IV_BYTES);
  my $ae = Crypt::AuthEnc::GCM->new('AES', $aes_key);
  $ae->iv_add($iv);
  my $ciphertext = $ae->encrypt_add($plaintext);
  my $tag = $ae->encrypt_done();
  # CryptX returns the full tag; protocol uses 16-byte (128-bit) tags.
  $tag = substr($tag, 0, AES_GCM_TAG_BYTES) if length($tag) > AES_GCM_TAG_BYTES;
  return {
    iv_b64         => bytes_to_base64($iv),
    ciphertext_b64 => bytes_to_base64($ciphertext),
    tag_b64        => bytes_to_base64($tag),
    ivB64          => bytes_to_base64($iv),
    ciphertextB64  => bytes_to_base64($ciphertext),
    tagB64         => bytes_to_base64($tag),
  };
}

sub sealed_as_wire {
  my ($sealed) = @_;
  return {
    ivB64         => $sealed->{ivB64}         // $sealed->{iv_b64},
    ciphertextB64 => $sealed->{ciphertextB64} // $sealed->{ciphertext_b64},
    tagB64        => $sealed->{tagB64}        // $sealed->{tag_b64},
  };
}

sub open_aes_gcm {
  my ($aes_key, $envelope) = @_;
  my $iv_b64 = $envelope->{ivB64} // $envelope->{iv_b64}
    // croak('ivB64 required');
  my $ciphertext_b64 = $envelope->{ciphertextB64} // $envelope->{ciphertext_b64}
    // croak('ciphertextB64 required');
  my $tag_b64 = $envelope->{tagB64} // $envelope->{tag_b64}
    // croak('tagB64 required');

  my $iv         = base64_to_bytes($iv_b64);
  my $ciphertext = base64_to_bytes($ciphertext_b64);
  my $tag        = base64_to_bytes($tag_b64);

  my $ae = Crypt::AuthEnc::GCM->new('AES', $aes_key);
  $ae->iv_add($iv);
  my $plain = $ae->decrypt_add($ciphertext);
  my $ok = $ae->decrypt_done($tag);
  croak 'AES-GCM authentication failed' unless $ok;
  return $plain;
}

1;

__END__

=head1 NAME

Sdkey::Crypto::Seal - Ed25519, HKDF session keys, and AES-GCM seal helpers

=cut
