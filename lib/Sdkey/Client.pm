package Sdkey::Client;

use 5.016;
use strict;
use warnings;

use Carp qw(croak);
use Encode qw(decode encode);
use HTTP::Tiny;
use JSON::PP qw(encode_json decode_json);
use Time::HiRes qw(time);
use Crypt::PRNG qw(random_bytes);

use Sdkey::Crypto::Constants qw(
  CLIENT_NONCE_BYTES
  CLOCK_SKEW_SECONDS
  PROTOCOL_VERSION
  VALIDATE_NONCE_BYTES
);
use Sdkey::Crypto::Encoding qw(base64_to_bytes bytes_to_base64);
use Sdkey::Crypto::Seal qw(
  derive_session_aes_key
  import_public_key
  open_aes_gcm
  seal_aes_gcm
  sealed_as_wire
  verify_signature
);
use Sdkey::Error;
use Sdkey::Types;

sub new {
  my ($class, %args) = @_;
  my $api_base_url        = $args{api_base_url}        // croak('api_base_url required');
  my $app_id              = $args{app_id}              // croak('app_id required');
  my $app_version         = $args{app_version}         // croak('app_version required');
  my $app_public_key_b64  = $args{app_public_key_b64}  // croak('app_public_key_b64 required');

  $api_base_url =~ s{/\z}{};

  return bless {
    api_base_url       => $api_base_url,
    app_id             => $app_id,
    app_version        => $app_version,
    app_public_key_b64 => $app_public_key_b64,
    http_post          => $args{http_post} // \&_default_http_post,
    public_key         => undef,
    session            => undef,
  }, $class;
}

sub get_session {
  my ($self) = @_;
  return $self->{session};
}

sub clear_session {
  my ($self) = @_;
  $self->{session} = undef;
  return;
}

sub init {
  my ($self) = @_;
  $self->{public_key} = import_public_key($self->{app_public_key_b64});
  my $client_nonce = random_bytes(CLIENT_NONCE_BYTES);

  my ($status, $body) = eval {
    $self->{http_post}->(
      $self->{api_base_url} . '/api/v1/session/init',
      {
        appId          => $self->{app_id},
        clientNonceB64 => bytes_to_base64($client_nonce),
        clientVersion  => $self->{app_version},
      },
    );
  };
  if ($@) {
    die Sdkey::Error->new('NETWORK', 'session init request failed', $@);
  }

  if ($status < 200 || $status >= 300 || !$body->{success}) {
    die Sdkey::Error->new(
      ($body->{code} // 'INIT_FAILED'),
      ($body->{error} // 'session init failed'),
    );
  }

  my $hello = {
    appId          => $self->{app_id},
    hkdfSaltB64    => $body->{hkdfSaltB64},
    serverNonceB64 => $body->{serverNonceB64},
    sessionId      => $body->{sessionId},
    timestamp      => $body->{timestamp},
    v              => PROTOCOL_VERSION,
  };

  if (!verify_signature($self->{public_key}, $hello, $body->{signatureB64})) {
    die Sdkey::Error->new('HELLO_SIGNATURE_INVALID', 'hello signature verification failed');
  }

  my $aes_key = derive_session_aes_key(
    client_nonce => $client_nonce,
    server_nonce => base64_to_bytes($body->{serverNonceB64}),
    salt_b64     => $body->{hkdfSaltB64},
    app_id       => $self->{app_id},
  );

  $self->{session} = Sdkey::Types::session_state(
    session_id       => $body->{sessionId},
    aes_key          => $aes_key,
    server_nonce_b64 => $body->{serverNonceB64},
    hkdf_salt_b64    => $body->{hkdfSaltB64},
  );
  return $self->{session};
}

sub validate {
  my ($self, $license_key, $hwid) = @_;
  croak 'license_key required' unless defined $license_key;

  if (!defined $self->{session} || !defined $self->{public_key}) {
    $self->init;
  }
  my $session     = $self->{session};
  my $public_key  = $self->{public_key};

  my $inner = {
    licenseKey => $license_key,
    nonce      => bytes_to_base64(random_bytes(VALIDATE_NONCE_BYTES)),
    timestamp  => int(time()),
    v          => PROTOCOL_VERSION,
  };
  if (defined $hwid) {
    $inner = {
      hwid       => $hwid,
      licenseKey => $inner->{licenseKey},
      nonce      => $inner->{nonce},
      timestamp  => $inner->{timestamp},
      v          => $inner->{v},
    };
  }

  # Compact JSON (no insignificant whitespace), keys already ordered for hwid case.
  my $inner_json = encode('UTF-8', _compact_json($inner));
  my $sealed = seal_aes_gcm($session->{aes_key}, $inner_json);

  my ($status, $envelope) = eval {
    $self->{http_post}->(
      $self->{api_base_url} . '/api/v1/licenses/validate',
      {
        sessionId => $session->{session_id},
        %{ sealed_as_wire($sealed) },
      },
    );
  };
  if ($@) {
    die Sdkey::Error->new('NETWORK', 'validate request failed', $@);
  }

  if (
    !$envelope->{ivB64}
    || !$envelope->{ciphertextB64}
    || !$envelope->{tagB64}
    || !$envelope->{signatureB64}
  ) {
    if (($envelope->{code} // '') eq 'SESSION_EXPIRED') {
      $self->clear_session;
    }
    die Sdkey::Error->new(
      ($envelope->{code} // 'VALIDATE_RESPONSE_INVALID'),
      ($envelope->{error} // 'invalid validate response'),
    );
  }

  my $plain_bytes = open_aes_gcm(
    $session->{aes_key},
    {
      ivB64         => $envelope->{ivB64},
      ciphertextB64 => $envelope->{ciphertextB64},
      tagB64        => $envelope->{tagB64},
    },
  );
  my $plaintext = decode_json(decode('UTF-8', $plain_bytes));

  if (!verify_signature($public_key, $plaintext, $envelope->{signatureB64})) {
    die Sdkey::Error->new('RESPONSE_SIGNATURE_INVALID', 'response signature verification failed');
  }

  if (($plaintext->{sessionId} // '') ne $session->{session_id}) {
    die Sdkey::Error->new('SESSION_MISMATCH', 'sessionId mismatch');
  }
  if (abs(int(time()) - int($plaintext->{timestamp})) > CLOCK_SKEW_SECONDS) {
    die Sdkey::Error->new('CLOCK_SKEW', 'response clock skew');
  }

  if (($plaintext->{code} // '') eq 'SESSION_EXPIRED') {
    $self->clear_session;
  }

  my $tier_raw = $plaintext->{subscriptionTier};
  my $subscription_tier = defined $tier_raw ? int($tier_raw) : undef;

  return Sdkey::Types::validate_result(
    success           => $plaintext->{success},
    code              => '' . $plaintext->{code},
    message           => '' . $plaintext->{message},
    status            => $plaintext->{status},
    expires_at        => $plaintext->{expiresAt},
    subscription_tier => $subscription_tier,
    timestamp         => int($plaintext->{timestamp}),
  );
}

sub register {
  my ($self, %args) = @_;
  my $body = {
    appId         => $self->{app_id},
    username      => $args{username} // croak('username required'),
    password      => $args{password} // croak('password required'),
    clientVersion => $self->{app_version},
  };
  $body->{email}      = $args{email}       if defined $args{email};
  $body->{licenseKey} = $args{license_key} if defined $args{license_key};
  $body->{hwid}       = $args{hwid}        if defined $args{hwid};
  return $self->_client_auth('register', $body);
}

sub login {
  my ($self, %args) = @_;
  my $body = {
    appId         => $self->{app_id},
    username      => $args{username} // croak('username required'),
    password      => $args{password} // croak('password required'),
    clientVersion => $self->{app_version},
  };
  $body->{hwid} = $args{hwid} if defined $args{hwid};
  return $self->_client_auth('login', $body);
}

sub upgrade {
  my ($self, %args) = @_;
  my $body = {
    appId         => $self->{app_id},
    username      => $args{username}    // croak('username required'),
    licenseKey    => $args{license_key} // croak('license_key required'),
    clientVersion => $self->{app_version},
  };
  $body->{hwid} = $args{hwid} if defined $args{hwid};
  return $self->_client_auth('upgrade', $body);
}

sub _client_auth {
  my ($self, $action, $body) = @_;
  my ($status, $response) = eval {
    $self->{http_post}->(
      $self->{api_base_url} . "/api/v1/client/$action",
      $body,
    );
  };
  if ($@) {
    die Sdkey::Error->new('NETWORK', "$action request failed", $@);
  }
  if (ref $response ne 'HASH') {
    die Sdkey::Error->new('UNKNOWN', "invalid $action response");
  }
  return _parse_auth_result($response);
}

sub _parse_auth_result {
  my ($body) = @_;
  if (!$body->{success}) {
    return Sdkey::Types::client_auth_result(
      success => 0,
      code    => defined $body->{code}  ? '' . $body->{code}  : undef,
      error   => defined $body->{error} ? '' . $body->{error} : undef,
    );
  }

  my $user;
  if (ref $body->{user} eq 'HASH') {
    my $u = $body->{user};
    $user = Sdkey::Types::client_auth_user(
      id             => '' . $u->{id},
      username       => '' . $u->{username},
      email          => $u->{email},
      application_id => '' . $u->{applicationId},
    );
  }

  my $license;
  if (ref $body->{license} eq 'HASH') {
    my $l = $body->{license};
    $license = Sdkey::Types::client_auth_license(
      id                => '' . $l->{id},
      status            => '' . $l->{status},
      expires_at        => $l->{expiresAt},
      subscription_tier => int($l->{subscriptionTier} // 0),
    );
  }

  my $session;
  if (ref $body->{session} eq 'HASH') {
    my $s = $body->{session};
    $session = Sdkey::Types::client_auth_session_info(
      ip   => '' . $s->{ip},
      hwid => $s->{hwid},
    );
  }

  return Sdkey::Types::client_auth_result(
    success       => 1,
    session_token => defined $body->{sessionToken} ? '' . $body->{sessionToken} : undef,
    expires_at    => $body->{expiresAt},
    user          => $user,
    license       => $license,
    session       => $session,
  );
}

sub _default_http_post {
  my ($url, $body) = @_;
  my $http = HTTP::Tiny->new(timeout => 30);
  my $payload = encode_json($body);
  # HTTP::Tiny + JSON::PP may produce UTF-8 bytes already; ensure octets.
  $payload = encode('UTF-8', $payload) if utf8::is_utf8($payload);

  my $res = $http->request(
    'POST',
    $url,
    {
      headers => { 'Content-Type' => 'application/json' },
      content => $payload,
    },
  );

  my $parsed = {};
  if (defined $res->{content} && length $res->{content}) {
    my $decoded = eval { decode_json($res->{content}) };
    $parsed = (ref $decoded eq 'HASH') ? $decoded : {};
  }
  return (int($res->{status}), $parsed);
}

# Compact JSON with stable key order for known validate-inner shapes.
# Prefer JSON::PP with sorted keys for general objects.
sub _compact_json {
  my ($value) = @_;
  state $json = JSON::PP->new->utf8(0)->canonical(1)->allow_nonref;
  # canonical(1) sorts object keys lexicographically — good for seal payload.
  my $s = $json->encode($value);
  return $s;
}

1;

__END__

=head1 NAME

Sdkey::Client - SDKey license client (sealed session + plaintext client auth)

=head1 SYNOPSIS

  my $client = Sdkey::Client->new(
    api_base_url       => 'https://api.sdkey.dev',
    app_id             => $app_id,
    app_version        => '1.0.0',
    app_public_key_b64 => $pubkey_b64,
  );
  my $result = $client->validate($license_key, $hwid);  # hwid optional

=cut
