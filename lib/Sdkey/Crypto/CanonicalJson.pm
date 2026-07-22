package Sdkey::Crypto::CanonicalJson;

use strict;
use warnings;

use Exporter qw(import);
use Encode qw(encode);
use JSON::PP ();

our @EXPORT_OK = qw(canonical_json canonicalize);

my $JSON = JSON::PP->new->allow_nonref->ascii(0)->canonical(0);

sub canonical_json {
  my ($value) = @_;
  return encode('UTF-8', canonicalize($value));
}

sub canonicalize {
  my ($value) = @_;

  if (!defined $value) {
    return 'null';
  }

  my $ref = ref $value;
  if (!$ref) {
    # Scalar: distinguish string / number / boolean via dualvar-safe heuristics.
    # JSON::PP boolean objects are handled below via $JSON->is_bool when available.
    if (JSON::PP::is_bool($value)) {
      return $value ? 'true' : 'false';
    }
    # Plain numbers (no leading zeros except 0 / 0.x)
    if (_looks_like_number($value)) {
      return $JSON->encode(0 + $value);
    }
    return $JSON->encode("$value");
  }

  if ($ref eq 'ARRAY') {
    return '[' . join(',', map { canonicalize($_) } @$value) . ']';
  }

  if ($ref eq 'HASH') {
    my @keys = sort keys %$value;
    my $body = join(',', map {
      $JSON->encode("$_") . ':' . canonicalize($value->{$_})
    } @keys);
    return '{' . $body . '}';
  }

  # JSON::PP::Boolean blessing
  if (JSON::PP::is_bool($value)) {
    return $value ? 'true' : 'false';
  }

  die "canonicalJson: unsupported type $ref";
}

sub _looks_like_number {
  my ($v) = @_;
  return 0 if !defined $v;
  # Reject empty and pure string forms that B::sv_2iv would coerce.
  return 0 if ref $v;
  # Match JSON number shape (integer or float, optional exponent)
  return $v =~ /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\z/;
}

1;

__END__

=head1 NAME

Sdkey::Crypto::CanonicalJson - Deterministic JSON encoding for Ed25519 signing

=head1 DESCRIPTION

Object keys sorted lexicographically, no insignificant whitespace.
Matches the TypeScript / Python SDKey canonical JSON rules.

=cut
