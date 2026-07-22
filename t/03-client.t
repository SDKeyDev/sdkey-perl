#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use FindBin;
use lib "$FindBin::Bin/../lib";

use JSON::PP qw(encode_json decode_json);
use Crypt::PK::Ed25519;
use Crypt::PRNG qw(random_bytes);
use Time::HiRes qw(time);

use Sdkey;
use Sdkey::Client;
use Sdkey::Error;
use Sdkey::Crypto::Constants qw(PROTOCOL_VERSION);
use Sdkey::Crypto::CanonicalJson qw(canonical_json);
use Sdkey::Crypto::Encoding qw(base64_to_bytes bytes_to_base64);
use Sdkey::Crypto::Seal qw(derive_session_aes_key open_aes_gcm seal_aes_gcm sealed_as_wire);

sub generate_ed25519_pair {
  my $sk = Crypt::PK::Ed25519->new;
  $sk->generate_key;
  my $public_key_b64 = bytes_to_base64($sk->export_key_raw('public'));
  return ($sk, $public_key_b64);
}

sub sign_payload {
  my ($private_key, $payload) = @_;
  return bytes_to_base64($private_key->sign_message(canonical_json($payload)));
}

sub make_client {
  my ($public_key_b64, $http_post, %opts) = @_;
  return Sdkey::Client->new(
    api_base_url       => 'https://api.example.test',
    app_id             => $opts{app_id} // 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    app_version        => $opts{app_version} // '1.0.0',
    app_public_key_b64 => $public_key_b64,
    http_post          => $http_post,
  );
}

subtest 'inits_session_and_validates_sealed_license_response' => sub {
  my ($private_key, $public_key_b64) = generate_ed25519_pair();
  my $app_id      = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  my $app_version = '1.2.3';
  my $session_id  = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
  my $server_nonce = random_bytes(32);
  my $hkdf_salt    = random_bytes(16);
  my $timestamp    = int(time());

  my $captured_client_nonce;
  my $captured_validate_inner;
  my $call_count = 0;

  my $http_post = sub {
    my ($url, $body) = @_;
    $call_count++;

    if ($url =~ m{/api/v1/session/init\z}) {
      is($body->{clientVersion}, $app_version, 'init sends clientVersion');
      $captured_client_nonce = base64_to_bytes($body->{clientNonceB64});
      my $hello = {
        appId          => $app_id,
        hkdfSaltB64    => bytes_to_base64($hkdf_salt),
        serverNonceB64 => bytes_to_base64($server_nonce),
        sessionId      => $session_id,
        timestamp      => $timestamp,
        v              => PROTOCOL_VERSION,
      };
      return (200, {
        success => JSON::PP::true,
        %$hello,
        signatureB64 => sign_payload($private_key, $hello),
      });
    }

    if ($url =~ m{/api/v1/licenses/validate\z}) {
      ok(defined $captured_client_nonce, 'client nonce captured');
      my $aes_key = derive_session_aes_key(
        client_nonce => $captured_client_nonce,
        server_nonce => $server_nonce,
        salt_b64     => bytes_to_base64($hkdf_salt),
        app_id       => $app_id,
      );
      my $plain_bytes = open_aes_gcm($aes_key, {
        ivB64         => $body->{ivB64},
        ciphertextB64 => $body->{ciphertextB64},
        tagB64        => $body->{tagB64},
      });
      $captured_validate_inner = decode_json($plain_bytes);
      my $plaintext = {
        success          => JSON::PP::true,
        code             => 'OK',
        message          => 'validated',
        status           => 'active',
        expiresAt        => undef,
        subscriptionTier => 2,
        sessionId        => $session_id,
        timestamp        => int(time()),
        v                => PROTOCOL_VERSION,
      };
      my $sealed = seal_aes_gcm($aes_key, encode_json($plaintext));
      # encode_json may add spaces depending on version — seal the compact form:
      my $compact = JSON::PP->new->utf8->canonical(0)->encode($plaintext);
      $sealed = seal_aes_gcm($aes_key, $compact);
      return (200, {
        sessionId => $session_id,
        %{ sealed_as_wire($sealed) },
        signatureB64 => sign_payload($private_key, $plaintext),
      });
    }

    return (404, { error => 'not found' });
  };

  my $client = make_client($public_key_b64, $http_post, app_id => $app_id, app_version => $app_version);
  my $result = $client->validate('SDKY-TEST-TEST-TEST-TEST', 'hwid-1');

  ok($result->{success}, 'validate success');
  is($result->{code}, 'OK');
  is($result->{message}, 'validated');
  is($result->{subscription_tier}, 2);
  ok(defined $captured_validate_inner);
  is($captured_validate_inner->{hwid}, 'hwid-1');
  ok(defined $client->get_session);
  is($client->get_session->{session_id}, $session_id);
  is($call_count, 2);
};

subtest 'validate_omits_hwid_json_key_when_absent' => sub {
  my ($private_key, $public_key_b64) = generate_ed25519_pair();
  my $app_id       = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
  my $session_id   = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
  my $server_nonce = random_bytes(32);
  my $hkdf_salt    = random_bytes(16);
  my $captured_client_nonce;
  my $captured_inner;

  my $http_post = sub {
    my ($url, $body) = @_;
    if ($url =~ m{/api/v1/session/init\z}) {
      $captured_client_nonce = base64_to_bytes($body->{clientNonceB64});
      my $hello = {
        appId          => $app_id,
        hkdfSaltB64    => bytes_to_base64($hkdf_salt),
        serverNonceB64 => bytes_to_base64($server_nonce),
        sessionId      => $session_id,
        timestamp      => int(time()),
        v              => PROTOCOL_VERSION,
      };
      return (200, {
        success => JSON::PP::true,
        %$hello,
        signatureB64 => sign_payload($private_key, $hello),
      });
    }

    my $aes_key = derive_session_aes_key(
      client_nonce => $captured_client_nonce,
      server_nonce => $server_nonce,
      salt_b64     => bytes_to_base64($hkdf_salt),
      app_id       => $app_id,
    );
    my $plain_bytes = open_aes_gcm($aes_key, {
      ivB64         => $body->{ivB64},
      ciphertextB64 => $body->{ciphertextB64},
      tagB64        => $body->{tagB64},
    });
    $captured_inner = decode_json($plain_bytes);
    my $plaintext = {
      success          => JSON::PP::true,
      code             => 'OK',
      message          => 'validated',
      status           => 'active',
      expiresAt        => undef,
      subscriptionTier => 0,
      sessionId        => $session_id,
      timestamp        => int(time()),
      v                => PROTOCOL_VERSION,
    };
    my $compact = JSON::PP->new->utf8->canonical(0)->encode($plaintext);
    my $sealed  = seal_aes_gcm($aes_key, $compact);
    return (200, {
      sessionId => $session_id,
      %{ sealed_as_wire($sealed) },
      signatureB64 => sign_payload($private_key, $plaintext),
    });
  };

  my $client = make_client($public_key_b64, $http_post, app_id => $app_id);
  my $result = $client->validate('SDKY-TEST-TEST-TEST-TEST');
  ok($result->{success});
  is($result->{subscription_tier}, 0);
  ok(defined $captured_inner);
  ok(!exists $captured_inner->{hwid}, 'hwid key omitted');
};

subtest 'init_surfaces_server_error_and_code' => sub {
  my (undef, $public_key_b64) = generate_ed25519_pair();
  my $http_post = sub {
    my ($url, $body) = @_;
    is($body->{clientVersion}, '9.9.9');
    return (403, {
      success => JSON::PP::false,
      error   => 'Client version outdated',
      code    => 'APP_OUTDATED',
    });
  };
  my $client = make_client($public_key_b64, $http_post, app_version => '9.9.9');
  eval { $client->init; 1 };
  my $err = $@;
  ok(ref $err && $err->isa('Sdkey::Error'), 'throws Sdkey::Error');
  is($err->code, 'APP_OUTDATED');
  is($err->message, 'Client version outdated');
};

subtest 'throws_sdkey_error_when_hello_signature_is_wrong' => sub {
  my (undef, $public_key_b64) = generate_ed25519_pair();
  my ($other_private, undef) = generate_ed25519_pair();
  my $http_post = sub {
    my $hello = {
      appId          => 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
      hkdfSaltB64    => bytes_to_base64("\0" x 16),
      serverNonceB64 => bytes_to_base64("\0" x 32),
      sessionId      => 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
      timestamp      => int(time()),
      v              => PROTOCOL_VERSION,
    };
    return (200, {
      success => JSON::PP::true,
      %$hello,
      signatureB64 => sign_payload($other_private, $hello),
    });
  };
  my $client = make_client($public_key_b64, $http_post);
  eval { $client->init; 1 };
  my $err = $@;
  ok(ref $err && $err->isa('Sdkey::Error'));
  is($err->code, 'HELLO_SIGNATURE_INVALID');
};

subtest 'register_login_upgrade_plaintext_auth' => sub {
  my (undef, $public_key_b64) = generate_ed25519_pair();
  my $app_version = '1.0.0';
  my @captured;

  my $http_post = sub {
    my ($url, $body) = @_;
    push @captured, [$url, $body];
    if ($url =~ m{/register\z}) {
      return (201, {
        success      => JSON::PP::true,
        sessionToken => 'tok-reg',
        expiresAt    => '2026-01-01T00:00:00.000Z',
        user => {
          id            => 'u1',
          username      => 'player1',
          email         => 'a@example.com',
          applicationId => 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        },
        license => {
          id               => 'l1',
          status           => 'active',
          expiresAt        => undef,
          subscriptionTier => 1,
        },
        session => { ip => '203.0.113.1', hwid => 'hw-1' },
      });
    }
    if ($url =~ m{/login\z}) {
      return (200, {
        success      => JSON::PP::true,
        sessionToken => 'tok-login',
        expiresAt    => '2026-01-01T00:00:00.000Z',
        user => {
          id            => 'u1',
          username      => 'player1',
          email         => undef,
          applicationId => 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        },
        license => undef,
        session => { ip => '203.0.113.1', hwid => undef },
      });
    }
    if ($url =~ m{/upgrade\z}) {
      ok(!exists $body->{password}, 'upgrade has no password');
      return (200, {
        success      => JSON::PP::true,
        sessionToken => 'tok-up',
        expiresAt    => '2026-01-01T00:00:00.000Z',
        user => {
          id            => 'u1',
          username      => 'player1',
          email         => undef,
          applicationId => 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        },
        license => {
          id               => 'l2',
          status           => 'active',
          expiresAt        => undef,
          subscriptionTier => 3,
        },
        session => { ip => '203.0.113.1', hwid => 'hw-2' },
      });
    }
    return (404, { success => JSON::PP::false, error => 'not found', code => 'UNKNOWN' });
  };

  my $client = make_client($public_key_b64, $http_post, app_version => $app_version);

  my $reg = $client->register(
    username    => 'player1',
    password    => 'password1',
    email       => 'a@example.com',
    license_key => 'SDKY-AAAA',
    hwid        => 'hw-1',
  );
  ok($reg->{success});
  is($reg->{session_token}, 'tok-reg');
  is($reg->{user}{username}, 'player1');
  is($reg->{license}{subscription_tier}, 1);
  is($reg->{session}{hwid}, 'hw-1');
  is($captured[0][1]{clientVersion}, $app_version);
  is($captured[0][1]{licenseKey}, 'SDKY-AAAA');

  my $login = $client->login(username => 'player1', password => 'password1');
  ok($login->{success});
  is($login->{session_token}, 'tok-login');
  ok(!defined $login->{license});
  ok(!exists $captured[1][1]{hwid});

  my $up = $client->upgrade(username => 'player1', license_key => 'SDKY-BBBB', hwid => 'hw-2');
  ok($up->{success});
  is($up->{license}{subscription_tier}, 3);
  ok(!exists $captured[2][1]{password});
  is($captured[2][1]{licenseKey}, 'SDKY-BBBB');
};

subtest 'auth_failure_exposes_server_error_and_code' => sub {
  my (undef, $public_key_b64) = generate_ed25519_pair();
  my $http_post = sub {
    return (403, {
      success => JSON::PP::false,
      error   => 'License tier must be higher than the current tier',
      code    => 'TIER_NOT_HIGHER',
    });
  };
  my $client = make_client($public_key_b64, $http_post);
  my $result = $client->upgrade(username => 'player1', license_key => 'SDKY-LOW');
  ok(!$result->{success});
  is($result->{code}, 'TIER_NOT_HIGHER');
  is($result->{error}, 'License tier must be higher than the current tier');
  ok(!defined $result->{session_token});
};

done_testing;
