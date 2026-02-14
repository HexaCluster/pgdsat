use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

use strict;

my @ALLOWED_ARGS = ('INSTALLDIRS','DESTDIR');

# Parse command line arguments and store them as environment variables
while ($_ = shift) {
	my ($k,$v) = split(/=/, $_, 2);
	if (grep(/^$k$/, @ALLOWED_ARGS)) {
		$ENV{$k} = $v;
	}
}
$ENV{DESTDIR} =~ s/\/$//;

# Default install path
my $DESTDIR = $ENV{DESTDIR} || '';
my $INSTALLDIRS = $ENV{INSTALLDIRS} || 'site';
my %merge_compat = ();

if ($ExtUtils::MakeMaker::VERSION >= 6.46) {
	%merge_compat = (
		'META_MERGE'   => {
			resources  => {
				homepage => 'https://github.com/hexacluster/pgdsat',
				repository  => {
					type => 'git',
					git => 'git@github.com:hexacluster/pgdsat.git',
					web => 'https://github.com/hexacluster/pgdsat',
				},
			},
		}
	);
}

WriteMakefile(
	'DISTNAME'	=> 'pgdsat',
	'NAME'		=> 'pgdsat',
	'VERSION'	=> '1.2',
	'LICENSE'      => 'gpl_3',
	'dist'  => {
			'COMPRESS'=>'gzip -9f', 'SUFFIX' => 'gz',
			'ZIP'=>'/usr/bin/zip','ZIPFLAGS'=>'-rl'
		   },
	'AUTHOR'       => 'Gilles Darold (gilles@darold.net)',
	'ABSTRACT'     => 'pgdsat - PostgreSQL Database Security Assessment Tool',
	'EXE_FILES'    => [ qw(pgdsat) ],
	'MAN1PODS'     => { 'doc/pgdsat.pod' => 'blib/man1/pgdsat.1p' },
	'DESTDIR'      => $DESTDIR,
	'INSTALLDIRS'  => $INSTALLDIRS,
	'clean'	       => {FILES => 'lib/blib/'},
	%merge_compat
);
