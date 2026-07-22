package Sdkey::Error;

use strict;
use warnings;

use overload
  '""'     => sub { $_[0]->message },
  fallback => 1;

sub new {
  my ($class, $code, $message, $cause) = @_;
  return bless {
    code    => $code // 'UNKNOWN',
    message => $message // '',
    cause   => $cause,
  }, $class;
}

sub code    { $_[0]->{code} }
sub message { $_[0]->{message} }
sub cause   { $_[0]->{cause} }

# Known SDK-local codes. Init / plaintext failures may also use server codes.
our @KNOWN_CODES = qw(
  INIT_FAILED
  HELLO_SIGNATURE_INVALID
  VALIDATE_RESPONSE_INVALID
  RESPONSE_SIGNATURE_INVALID
  SESSION_MISMATCH
  CLOCK_SKEW
  NETWORK
  UNKNOWN
);

1;

__END__

=head1 NAME

Sdkey::Error - Protocol and transport errors for the SDKey client

=head1 SYNOPSIS

  die Sdkey::Error->new('APP_OUTDATED', 'Client version outdated');

=cut
