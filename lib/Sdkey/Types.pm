package Sdkey::Types;

use strict;
use warnings;

# Lightweight hashref constructors mirroring the Python dataclasses.
# Callers may treat returned hashrefs as immutable by convention.

sub session_state {
  my (%args) = @_;
  return {
    session_id      => $args{session_id},
    aes_key         => $args{aes_key},
    server_nonce_b64 => $args{server_nonce_b64},
    hkdf_salt_b64   => $args{hkdf_salt_b64},
  };
}

sub validate_result {
  my (%args) = @_;
  return {
    success           => $args{success} ? 1 : 0,
    code              => $args{code},
    message           => $args{message},
    status            => $args{status},
    expires_at        => $args{expires_at},
    subscription_tier => $args{subscription_tier},
    timestamp         => $args{timestamp},
  };
}

sub client_auth_user {
  my (%args) = @_;
  return {
    id             => $args{id},
    username       => $args{username},
    email          => $args{email},
    application_id => $args{application_id},
  };
}

sub client_auth_license {
  my (%args) = @_;
  return {
    id                => $args{id},
    status            => $args{status},
    expires_at        => $args{expires_at},
    subscription_tier => $args{subscription_tier} // 0,
  };
}

sub client_auth_session_info {
  my (%args) = @_;
  return {
    ip   => $args{ip},
    hwid => $args{hwid},
  };
}

sub client_auth_result {
  my (%args) = @_;
  return {
    success       => $args{success} ? 1 : 0,
    code          => $args{code},
    error         => $args{error},
    session_token => $args{session_token},
    expires_at    => $args{expires_at},
    user          => $args{user},
    license       => $args{license},
    session       => $args{session},
  };
}

1;

__END__

=head1 NAME

Sdkey::Types - Public result types for the SDKey client

=cut
