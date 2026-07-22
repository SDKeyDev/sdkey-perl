#!/usr/bin/env perl
# Minimal usage example. Replace placeholders with values from the SDKey dashboard.
#
#   cpanm --installdeps .
#   perl -Ilib examples/basic.pl

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../lib";

use Sdkey;
use Sdkey::Error;

my $client = Sdkey->new(
  api_base_url       => $ENV{SDKEY_API_BASE_URL} // 'https://api.sdkey.dev',
  app_id             => $ENV{SDKEY_APP_ID} // '00000000-0000-0000-0000-000000000000',
  app_version        => $ENV{SDKEY_APP_VERSION} // '1.0.0',
  app_public_key_b64 => $ENV{SDKEY_APP_PUBLIC_KEY_B64} // '',
);

my $license_key = $ENV{SDKEY_LICENSE_KEY} // 'SDKY-XXXX-XXXX-XXXX-XXXX';
my $hwid        = $ENV{SDKEY_HWID};  # optional; omit for web-style clients

eval {
  my $result = $client->validate($license_key, $hwid);
  if ($result->{success}) {
    print join(' ',
      'OK',
      $result->{status} // '',
      $result->{expires_at} // '',
      $result->{subscription_tier} // '',
      $result->{message} // '',
    ), "\n";
  } else {
    print "denied $result->{code} $result->{message}\n";
  }
  1;
} or do {
  my $err = $@;
  if (ref $err && $err->isa('Sdkey::Error')) {
    warn "[@{[$err->code]}] @{[$err->message]}\n";
  } else {
    warn "$err\n";
  }
  exit 1;
};
