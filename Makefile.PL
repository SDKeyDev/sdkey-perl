use ExtUtils::MakeMaker;

WriteMakefile(
  NAME             => 'Sdkey',
  VERSION_FROM     => 'lib/Sdkey.pm',
  ABSTRACT         => 'Official Perl client for the SDKey license authentication protocol',
  AUTHOR           => 'SDKeyDev <dev@sdkey.dev>',
  LICENSE          => 'mit',
  MIN_PERL_VERSION => '5.016',
  PREREQ_PM        => {
    'CryptX'     => '0.080',
    'HTTP::Tiny' => '0',
    'JSON::PP'   => '0',
    'MIME::Base64' => '0',
    'Encode'     => '0',
  },
  TEST_REQUIRES => {
    'Test::More' => '0.98',
  },
  META_MERGE => {
    'meta-spec' => { version => 2 },
    resources => {
      homepage   => 'https://github.com/SDKeyDev/sdkey-perl',
      bugtracker => {
        web => 'https://github.com/SDKeyDev/sdkey-perl/issues',
      },
      repository => {
        type => 'git',
        url  => 'https://github.com/SDKeyDev/sdkey-perl.git',
        web  => 'https://github.com/SDKeyDev/sdkey-perl',
      },
    },
  },
);
