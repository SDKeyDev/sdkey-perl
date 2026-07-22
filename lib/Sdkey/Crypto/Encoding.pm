package Sdkey::Crypto::Encoding;

use strict;
use warnings;

use Exporter qw(import);
use MIME::Base64 qw(encode_base64 decode_base64);

our @EXPORT_OK = qw(bytes_to_base64 base64_to_bytes);

sub bytes_to_base64 {
  my ($data) = @_;
  my $b64 = encode_base64($data // '', '');
  $b64 =~ s/\s+//g;
  return $b64;
}

sub base64_to_bytes {
  my ($b64) = @_;
  $b64 //= '';
  $b64 =~ s/-/+/g;
  $b64 =~ s/_/\//g;
  my $pad = length($b64) % 4 == 0 ? '' : '=' x (4 - (length($b64) % 4));
  return decode_base64($b64 . $pad);
}

1;

__END__

=head1 NAME

Sdkey::Crypto::Encoding - Base64 helpers (standard and URL-safe)

=cut
