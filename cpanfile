requires 'perl', '5.016';
requires 'CryptX', '0.080';
requires 'HTTP::Tiny';
requires 'JSON::PP';
requires 'MIME::Base64';
requires 'Encode';

on test => sub {
  requires 'Test::More', '0.98';
};
