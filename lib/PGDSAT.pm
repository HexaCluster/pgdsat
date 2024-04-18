package PGDSAT;

#------------------------------------------------------------------------------
# Project  : PostgreSQL Database Security Assement Tool
# Name     : PGDSAT.pm
# Language : Perl
# Authors  : Gilles Darold
# Copyright: Copyright (c) 2024 HexaCluster Corp
# Function : Module containing the security checks methods
#------------------------------------------------------------------------------
use vars qw($VERSION);
use strict;

$VERSION = '1.0';

use PGDSAT::Labels;
use PGDSAT::Messages;
use PGDSAT::Netmask;
use PGDSAT::Report;

use POSIX qw(locale_h _exit strftime);
use bignum;

$| = 1;

####
# Create an instance of the module
####
sub new
{
	my ($class, %options) = @_;

	# This create an OO perl object
	my $self = {};
	bless ($self, $class);

	# Initialize this object
	$self->_init(%options);

	# Return the instance
	return($self);
}

####
# Initialize the object
####
sub _init
{
	my ($self, %options) = @_;

	# Object variables
	$self->{use_ssl} = 0;
	$self->{use_gssenc} = 0;
	$self->{use_host} = 0;
	$self->{use_pwd_enforcement} = 0;
	$self->{results} = ();
	$self->{current_indent} = 1;
	$self->{collapse_id} = 0;
	$self->{content} = '';
	$self->{details} = '';
	$self->{pkg_ver} = ();

	####
	# From command line options
	####
	# Output format (html or text)
	$self->{format} = $options{format} || '';
	# Language to use
	$self->{lang} = $options{lang} || 'en_US';
	# Cluster to scan if there are several ones running
	$self->{cluster} = $options{cluster} || '';
	# No check for PG version
	$self->{no_check_pg_version} = $options{no_check_pg_version} || 0;
	# Output file
	$self->{output} = $options{output} || '-';
	# Label to use in the title of the report
	$self->{title} = $options{title} || '';

	# variables to store psql options provided at command line
	$self->{host} = $options{host} || '';
	$self->{port} = $options{port} || 0;
	$self->{user} = $options{user} || '';
	$self->{database} = $options{database} || '';
	$self->{psql} = $options{psql} || 'psql';
	$self->{pgdata} = $options{pgdata} || '';

	# Database to allow/exclude from the report
	$self->{allow}   = ();
	push(@{ $self->{allow} }, @{$options{allow}}) if ($#{$options{allow}} >= 0);
	$self->{exclude} = ();
	push(@{ $self->{exclude} }, @{$options{exclude}}) if ($#{$options{exclude}} >= 0);

	# Compose the psql system command call
	$self->{pgdb}     ||= $ENV{PGDATABASE};
	$self->{$self->{host}}   ||= $ENV{PGHOST};
	$self->{$self->{port}}   ||= $ENV{PGPORT};
	$self->{$self->{user}}   ||= $ENV{PGUSER};
	$self->{pgdata}   ||= $ENV{PGDATA};
	$self->{psql} .= " -U $self->{user}" if ($self->{user});
	$self->{psql} .= " -h $self->{host}" if ($self->{host});
	$self->{psql} .= " -p $self->{port}" if ($self->{port});
	$self->{psql} .= " -d $self->{database}" if ($self->{database});
	# We want the default language for psql messages and no look at .psqlrc
	$self->{psql} = 'LANG=C ' . $self->{psql} . ' -X';

	# Verify that the connection user is really superuser
	my $is_superuwser = `$self->{psql} -Atc "select 1 from pg_roles where rolname = current_user and rolsuper;"`;
	chomp($is_superuwser);
	die "FATAL: this program must be run as PostgreSQL superuser: $self->{psql} -Atc ...\n" if (!$is_superuwser);

        # Check that the PostgreSQL have the version specified by --cluster
        my $ver = `$self->{psql} -Atc "SELECT version();"`;
        chomp($ver);
	if ($self->{cluster} and $ver !~ /$self->{cluster}/) {
		die "FATAL: cluster version $self->{cluster} doesn't match the PostgreSQL version: $ver.\n";
	}

}

####
# Run security tests according to CIS PostgreSQL Benchmark 16
# with additionals checks by HexaCluster Corp
####
sub run
{
	my $self = shift;

	$self->logmsg(1, 'head1', 'Installation and Patches');

	# Check the PostgreSQL packages installed and set the list of PG version
	$self->check_package();

	# limit the check to the running cluster
	@{ $self->{pkg_ver} } = ($self->{cluster}) if ($self->{cluster});

	# Check if PG is started at boot time
	$self->check_systemd();

	# Check if the PGDATA is well initialized
	$self->check_cluster_init();
	# Check if the PostgreSQL minor version are up-to-date
	$self->check_version();
	# Check the installed extensions
	$self->check_extensions();
	# Check that tablespaces are not inside PGDATA
	$self->check_tablespaces();

	$self->logmsg(2, 'head1', 'Directory and File Permissions');
	$self->check_permissions();

	$self->logmsg(3, 'head1', 'Logging And Auditing');
	$self->check_log_settings();

	$self->logmsg(4, 'head1', 'User Access and Authorization');
	my @super = $self->check_user_access();

	$self->logmsg(5, 'head1', 'Connection and Login');
	$self->check_connection(@super);

	$self->logmsg(6, 'head1', 'PostgreSQL Settings');
	$self->check_pg_settings();

	$self->logmsg(7, 'head1', 'Replication');
	$self->check_replication();

	$self->logmsg(8, 'head1', 'Special Configuration Considerations');
	$self->check_special_conf();

	PGDSAT::Report::generate_report($self);

	PGDSAT::Report::save_report($self);
}

#------------------------------------------------------------------------------
# Utility methods
#------------------------------------------------------------------------------

####
# Print messages following the output format, the
# level of message and the current indentation.
####
sub logmsg
{
	my ($self, $level, $indent, $str, @params) = @_;

	my $msg = $PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'title'} || $str;
	my $manual = '';
	$manual = ' (Manual)' if ($PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'manual'});

	# Set default value for resulting checklist, this only concern some level
	if ($indent eq 'head2' || $indent eq 'head3') {
		$self->{results}{$level} = 'SUCCESS';
	}

	if ($self->{format} eq 'text')
	{
		if ($indent eq 'head1')
		{
			$self->{current_indent} = 1;
			$self->{details} .= "#" . "-"x80 . "\n";
			$self->{details} .= "# $level - $msg$manual\n";
			$self->{details} .= "#" . "-"x80 . "\n";
			if (exists $PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'description'}) {
				$self->{details} .= "$PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'description'}\n\n";
			}
		}
		elsif ($indent eq 'head2')
		{
			$self->{current_indent} = 2;
			$self->{details} .= "    # $level - $msg$manual\n";
			if (exists $PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'description'}) {
				$self->{details} .= "    $PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'description'}\n\n";
			}
		}
		elsif ($indent eq 'head3')
		{
			$self->{current_indent} = 3;
			$self->{details} .= "        # $level - $msg$manual\n";
			if (exists $PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'description'}) {
				$self->{details} .= "        $PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'description'}\n\n";
			}
		}
		elsif (grep(/^$indent$/i, 'WARNING', 'ERROR', 'CRITICAL', 'INFO', 'SUCCESS'))
		{
			$msg = $PGDSAT::Messages::AUDIT_MSG{$self->{lang}}{$level}{'errmsg'} || $str;
			$self->{details} .= sprintf("    "x$self->{current_indent} . "\U$indent\E: $msg\n\n", @params);
		}
	}
	elsif ($self->{format} eq 'html')
	{
		if ($indent eq 'head1')
		{
			$self->{details} .= "<h2 id=\"$level\">$level - $msg$manual</h2>\n";
			if (exists $PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'description'}) {
				$self->{details} .= "<p>$PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'description'}</p>\n";
			}
		}
		elsif ($indent eq 'head2')
		{
			$self->{details} .= "<h3 id=\"$level\">$level - $msg$manual</h3>\n";
			if (exists $PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'description'}) {
				$self->{details} .= "<p>$PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'description'}</p>\n";
			}
		}
		elsif ($indent eq 'head3')
		{
			my $collapse = '';
			if ($self->{collapse_id} > 0) {
				$collapse = qq{ <a href="javascript:return false;" onclick="collapseme('collapse-$self->{collapse_id}');"><i class="fa fa-caret-down"></i></a>};
			}
			$self->{details} .= "<h4 id=\"$level\">$level - $msg$manual$collapse</h4>\n";
			if (exists $PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'description'}) {
				$self->{details} .= "<p>$PGDSAT::Labels::AUDIT_LBL{$self->{lang}}{$level}{'description'}</p>\n";
			}
		}
		elsif (grep(/^$indent$/i, 'WARNING', 'ERROR', 'CRITICAL', 'INFO', 'SUCCESS'))
		{
			$msg = $PGDSAT::Messages::AUDIT_MSG{$self->{lang}}{$level}{'errmsg'} || $str;
			$self->{details} .= sprintf("<div class=\"alert \L$indent\E\"><strong>$indent</strong> - $msg</div>", @params);
		}
	}
}

####
# Print raw data following the output format and the current indentation
# level. The lines to print must have the new line character at the end.
####
sub logdata
{
	my ($self, @lines) = @_;

	if ($self->{format} eq 'text')
	{
		foreach my $l (@lines) {
			$self->{details} .= "    "x$self->{current_indent} . "DATA: $l";
		}
		$self->{details} .= "\n";
	}
	elsif ($self->{format} eq 'html')
	{
		if ($lines[0] !~ /\|/)
		{
			$self->{details} .= "<pre>\n";
			$self->{details} .= join('', @lines);
			$self->{details} .= "</pre>\n";
		}
		else
		{
			$self->{details} .= "<table>\n";
			for (my $i = 0; $i <= $#lines; $i++) {
				my @cols = split(/\|/, $lines[$i]);
				if ($i == 0) {
					$self->{details} .= "<tr><th>" . join('</th><th>', @cols) . "</th></tr>\n";
				} else {
					$self->{details} .= "<tr><td>" . join('</td><td>', @cols) . "</td></tr>\n";
				}
			}
			$self->{details} .= "</table>\n";
		}
	}
}

####
# Parse the pg_hba.conf file and return an array of hash for each entry
####
sub load_pg_hba_file
{
	my ($self, $file) = @_;
	my $fh = undef;

	open($fh, '<', $file);
	if (not defined $fh)
	{
		$self->logmsg('5.2', 'CRITICAL', 'Can not read pg_hba.conf file "%s", reason: "%s".', $file, $!);
		return;
	}

	my @entries = ();
	my $line = 0;
	while (my $l = <$fh>)
	{
		chomp($l);
		$line++;
		$l =~ s/^\s+//; # remove space or tabulation at start of a line
		next if (!$l || $l =~ /^#/); # skip commented or empty lines
		my @data = split(/\s+/, $l);

		# Read included files if any
		if ($data[0] =~ /^include(_if_exists)?$/)
		{
			push(@entries, $self->load_pg_hba_file($data[1]));
			next;
		}
		elsif ($data[0] =~ /^include_dir$/)
		{
			unless(opendir(DIR, "$data[1]"))
			{
				$self->logmsg('5.3', 'CRITICAL', 'Can not open directory "%s", reason: "%s".', $data[1], $!);
				return;
			}
			my @conf_files = grep { $_ =~ /\.conf$/ } readdir(DIR);
			closedir DIR;
			foreach my $f (sort { $a <=> $b } @conf_files)
			{
				push(@entries, $self->load_pg_hba_file($f));
			}
			next;
		}

		# skip unknown lines
		next if ($data[0] !~ /^(local|host(ssl|nossl|gssenc|nogssenc)?)$/);

		# Store information about SSL or GSS presence in the pg_hba.conf file
		$self->{use_ssl} = 1 if ($data[0] eq 'hostssl');
		$self->{use_gssenc} = 1 if ($data[0] eq 'hostgssenc');
		$self->{use_host} = 1 if ($data[0] =~ /^(host|hostnossl|hostnogssenc)$/);

		# Build the pg_hba entry struct
		my %hba_entry = (
			'source' => $l,
			'type' => $data[0],
			'database' => $data[1],
			'user' => $data[2],
			'file' => $file,
			'line' => $line
		);
		my $idx = 3;
		if ($data[0] eq 'local') {
			$hba_entry{address} = '';
		} elsif ($data[3] =~ s#/(\d+)$##) {
			$hba_entry{address} = $data[$idx++],
			$hba_entry{netmask} = $1;
		} else {
			$hba_entry{address} = $data[$idx++];
			$hba_entry{netmask} = $data[$idx++];
		}
		$hba_entry{method} = $data[$idx++];
		my $len = $#data;
		$hba_entry{options} = join(' ', @data[$idx..$len]);
		push(@entries, \%hba_entry);
	}
	close($fh);

	return @entries;
}

#------------------------------------------------------------------------------
# Security check methods
#------------------------------------------------------------------------------

sub check_package
{
	my $self = shift;

	$self->logmsg('1.1', 'head2', 'Ensure packages are obtained from authorized repositories');

	$self->logmsg('1.1.1', 'head3', "PostgreSQL packages installed.");
	my @packages = `rpm -qa 2>/dev/null| grep -E "postgresql[1-9\.]{1,2}-server"`;
	if ($#packages < 0) {
		@packages = `dpkg -l 2>/dev/null | grep -E "postgresql-[1-9]{1,2}" | sed 's/^ii //'`;
	}
	if ($#packages < 0) {
		$self->logmsg('1.1', 'CRITICAL', 'No PostgreSQL packages found.');
		$self->{results}{'1.1.1'} = 'FAILURE';
	}
	$self->logdata(@packages);

	$self->logmsg('1.1.2', 'head3', 'Ensure packages are obtained from PGDG');

	@{ $self->{pkg_ver} } = `rpm -qa 2>/dev/null| grep -E "postgresql[1-9\.]{1,2}-server" | grep -i PGDG | awk -F "-" '{print \$3}' | sort -u`;
	if ($#{ $self->{pkg_ver} } < 0) {
		@{ $self->{pkg_ver} } = `dpkg -l 2>/dev/null | grep -E "postgresql-[1-9]{1,2} .*pgdg" | awk '{print \$3}' | sed 's/-.*//' | sort -u`;
	}
	chomp(@{ $self->{pkg_ver} });
	if ($#{ $self->{pkg_ver} } < 0) {
		$self->logmsg('1.2', 'WARNING', 'PostgreSQL packages are not from the PGDG repository.');
		$self->{results}{'1.1.2'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}
	chomp(@{ $self->{pkg_ver} });

}

sub check_systemd
{
	my $self = shift;

	$self->logmsg('1.2', 'head2', 'Ensure systemd Service Files Are Enabled');

	my $patroni = `rpm -qa 2>/dev/null| grep "patroni"`;
	if (!$patroni) {
		$patroni = `dpkg -l 2>/dev/null | grep -E "patroni"`;
	}
	chomp($patroni);

	my $running = '';
	foreach my $ver (@{ $self->{pkg_ver} })
	{
		my ($major, $minor) = split(/\./, $ver);
		my $ret = `systemctl is-enabled postgresql-$major.service 2>/dev/null`;
		if (!$ret) {
			$ret = `systemctl is-enabled postgresql\@$major-main.service 2>/dev/null`;
		}
		chomp($ret);
		if ($ret ne 'enabled')
		{
			if (!$patroni)
			{
				$self->logmsg('1.7', 'WARNING', 'PostgreSQL version %s, is not enabled as a systemd service.', $major);
				$self->{results}{'1.2'} = 'FAILURE';
			}
		}
		$ret = `systemctl status postgresql-$major.service 2>/dev/null | grep "active (running)"`;
		if (!$ret) {
			$ret = `systemctl status postgresql\@$major-main.service 2>/dev/null | grep "active (running)"`;
		}
		if ($ret) {
			$running = "$major.$minor";
		}
	}

	if ($patroni && $running) {
		$self->logmsg('1.8', 'WARNING', "PostgreSQL systemd service must not be enabled when patroni is used.");
		$self->{results}{'1.2'} = 'FAILURE';
	}

	if ($running && $self->{results}{'1.2'} ne 'FAILURE')
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	return $self->{cluster} || $running;
}

sub check_cluster_init
{
	my $self = shift;

	$self->logmsg('1.3', 'head2', 'Ensure Data Cluster Initialized Successfully');

	foreach my $ver (@{ $self->{pkg_ver} })
	{
		my ($major, $minor) = split(/\./, $ver);

		# Verify that the PGDATA exists and that permissions are correct
		my $data_dir = $self->{pgdata} || `$self->{psql} -Atc "SHOW data_directory"`;
		chomp($data_dir);
		return if (!$data_dir);

		# Verify that the PGDATA is initialized
		$self->logmsg('1.3.1', 'head3', 'Check initialization of the PGDATA');
		my $base_ver = `find "$data_dir/base/" -name PG_VERSION 2>/dev/null | xargs -i cat {} | sort -u`;
		chomp($base_ver);
		if (!$base_ver) {
			$self->logmsg('1.9', 'CRITICAL', 'Wrong or no base directory found, the PGDATA (%s) must be initialized first (see initdb).', $data_dir);
			$self->{results}{'1.3.1'} = 'FAILURE';
		}
		else
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
		# Verify that we have the right PG_VERSION
		$self->logmsg('1.3.2', 'head3', 'Check version in PGDATA');
		my $ver = `cat "$data_dir/PG_VERSION"`;
		chomp($ver);
		if ($ver ne $major) {
			$self->logmsg('1.10', 'CRITICAL', 'The version of the PGDATA (%s) does not correspond to the PostgreSQL cluster version; You need to upgrade the PGDATA v%s to v%s first.', $data_dir, $ver, $major);
			$self->{results}{'1.3.2'} = 'FAILURE';
		}
		else
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}

		$self->logmsg('1.3.3', 'head3', 'Ensure Data Cluster have checksum enabled');
		# Verify that checksum are enabled (HexaCluster)
		my $controldata_output = `pg_controldata "$data_dir" 2>&1`;
		my $controldata_exit_status = $? >> 8;  # Correctly shift to get the actual exit status
		# chomp($checksum);
		if ($controldata_exit_status != 0) {
			# Handle errors such as 'Permission denied'
			$self->logmsg('1.11', 'CRITICAL', 'Failed to execute pg_controldata. Error: %s', $controldata_output);
			$self->{results}{'1.3.3'} = 'FAILURE';
		}
		else
		{
			my $checksum = $controldata_output =~ /Data page checksum version: (\d+)/ ? $1 : undef;
			if (defined $checksum and $checksum ne '0')
			{
				$self->logmsg('0.1', 'SUCCESS', 'Test passed');
				# Show stats about checksum failure if any
				my @checksum_fail = `$self->{psql} -Atc "SELECT datname,checksum_failures,checksum_last_failure FROM pg_catalog.pg_stat_database WHERE checksum_failures > 0"`;
				if ($#checksum_fail > 0)
				{
					unshift(@checksum_fail, "datname|checksum_failures|checksum_last_failure\n");
					$self->logdata(@checksum_fail);
				}
			}
			elsif (defined $checksum and $checksum eq '0')
			{
				$self->logmsg('1.11', 'CRITICAL', 'Checksum are not enabled in PGDATA %s.', $data_dir);
				$self->{results}{'1.3.3'} = 'FAILURE';
			}
			else
			{
				$self->logmsg('1.11', 'CRITICAL', "Checksum data could not be parsed from pg_controldata output.");
				$self->{results}{'1.3.3'} = 'FAILURE';
			}
		}

		$self->logmsg('1.3.4', 'head3', 'Ensure WALs and temporary files are not on the same partition as the PGDATA');
		my $temp_tbsp = `$self->{psql} -Atc "SHOW temp_tablespaces"`;
		chomp($temp_tbsp);

		my $wal_links = `ls -la "$data_dir/pg_wal" | grep "^l" | sed 's/.* -> //'`;
		chomp($wal_links);

		# FIXME: We assume that a symlink that doesn't point into the PGDATA
		# which could obviously not be the case.
		$data_dir =~ s#/$##;
		if (!$wal_links || $wal_links !~ m#^/# || $wal_links =~ m#^$data_dir/#)
		{
			$self->logmsg('1.12', 'WARNING', 'Subdirectory pg_wal is not on a separate partition than the PGDATA %s.');
			$self->{results}{'1.3.4'} = 'FAILURE';
		}
		if (!$temp_tbsp || $temp_tbsp !~ m#^/# || $temp_tbsp =~ m#^$data_dir/#)
		{
			$self->logmsg('1.13', 'WARNING', 'Subdirectory for temporary file is not on a separate partition than the PGDATA.');
			$self->{results}{'1.3.4'} = 'FAILURE';
		}
		if ($self->{results}{'1.3.4'} ne 'FAILURE')
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
	}

	$self->logmsg('1.3.5', 'head3', 'Ensure that the PGDATA partition is encrypted');
	# Verify manually that the PGDATA is on an encrypted partition
	my @encrypted = `lsblk -f 2>/dev/null | grep -v "^loop"`;
	if ($#encrypted < 0) {
		$self->logmsg('1.14', 'CRITICAL', 'Can not get information about encrypted partition, command lsblk is missing on this host.');
		$self->{results}{'1.3.5'} = 'FAILURE';
	}
	$self->logdata(@encrypted);
}

sub check_version
{
	my $self = shift;

	$self->logmsg('1.4', 'head2', 'Ensure PostgreSQL versions are up-to-date');

	if ($self->{no_check_pg_version})
	{
		$self->logmsg('1.15', 'WARNING', 'PostgreSQL version check was disabled (--no-pg-version-check) can not look for minor version upgrade.');
		$self->{results}{'1.4'} = 'FAILURE';
	}
	else
	{
		# Get all PostgreSQL version from
		my @versions = `curl https://www.postgresql.org/ftp/source/ 2>/dev/null | grep 'href="v' | awk -F '"' '{print \$2}' | grep -E "^v[1-9]"`;
		chomp(@versions);
		map { s/[^\d\.]//g; } @versions;
		if ($#versions < 0)
		{
			$self->logmsg('1.3', 'ERROR', 'No internet access to https://www.postgresql.org/.');
			$self->{results}{'1.4'} = 'FAILURE';
			return;
		}

		# Why upgrade https://why-upgrade.depesz.com/show?from=16.1&to=16.2
		my $current = `curl https://www.postgresql.org/ 2>/dev/null | grep 'href="/about/news/postgresql-' | awk -F '"' '{print \$2}' | grep "^/" | sort -u`;
		chomp($current);

		# ex: /about/news/postgresql-162-156-1411-1314-and-1218-released-2807/
		$current =~ s/-released.*//;
		$current =~ s/.*postgresql-//;
		$current =~ s/and-//;

		my @cur_version = split(/\-/, $current);
		map { s/^(\d{2})(.*)/$1.$2/; } @cur_version;
		foreach my $ver (@{ $self->{pkg_ver} })
		{
			my ($major, $minor) = split(/\./, $ver);
			my @cur = grep(/^$major\./, @cur_version);
			if ($#cur < 0) {
				$self->logmsg('1.4', 'CRITICAL', 'This PostgreSQL version, v%s, is no more supported.', $ver);
				$self->{results}{'1.4'} = 'FAILURE';
			} elsif ($cur[0] > $ver) {
				$self->logmsg('1.5', 'CRITICAL', 'This PostgreSQL version, v%s, is not the last one of this branch (%s)', $ver, $cur[0]);
				$self->logmsg('1.6', 'INFO', 'See [Why upgrade](https://why-upgrade.depesz.com/show?from=%s&to=%s).', $ver, $cur[0]);
				$self->{results}{'1.4'} = 'FAILURE';
			}
		}
		if ($self->{results}{'1.4'} ne 'FAILURE')
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
	}
}

sub check_extensions
{
	my $self = shift;

	# Get the list of the database in the PostgreSQL cluster
	my @dbs = `$self->{psql} -Atc "SELECT datname FROM pg_database WHERE datallowconn ORDER BY 1;"`;
	chomp(@dbs);

	$self->logmsg('1.5', 'head2', 'Ensure unused PostgreSQL extensions are removed');
	my $i = 1;
	$self->{collapse_id}++;
	foreach my $db (@dbs)
	{
		# apply the filter on database to include in the report
		next if ($#{ $self->{allow} } >= 0 && !grep(/^$db$/i, @{ $self->{allow} }));
		next if ($#{ $self->{exclude} } >= 0 && grep(/^$db$/i, @{ $self->{exclude} }));

		my @extdef = `$self->{psql} -d $db -Atc "\\dx"`;
		if ($#extdef >= 0)
		{
			$self->logmsg('1.5.' . $i, 'head3', $db);
			if ($self->{format} eq 'html') {
				$self->{details} .= "<div id=\"collapse-$self->{collapse_id}\" class=\"collapse\">\n";
			}
			unshift(@extdef, "Name|Version|Schema|Description\n");
			$self->logdata(@extdef);
			if ($self->{format} eq 'html') {
				$self->{details} .= "</div>\n";
			}
			$i++;
			$self->{collapse_id}++;
		}
	}
}

sub check_tablespaces
{
	my $self = shift;

	$self->logmsg('1.6', 'head2', 'Ensure tablespace location is not inside the PGDATA');
	my @dest = `ls -la /var/lib/postgresql/15/main/pg_tblspc/ 2>/dev/null | sed 's/.* -> //'`;
	chomp(@dest);
	my $data_dir = $self->{pgdata} || `$self->{psql} -Atc "SHOW data_directory"`;
	chomp($data_dir);
	$data_dir =~ s#/$##;
	foreach my $d (@dest)
	{
		if ($d =~ m#$data_dir\/#) {
			$self->logmsg('1.16', 'WARNING', 'Tablespace location %s should not be inside the data directory.', $d);
			$self->{results}{'1.6'} = 'FAILURE';
		}
	}
	if ($self->{results}{'1.6'} ne 'FAILURE')
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}
}

sub check_permissions
{
	my $self = shift;


	# Verify the postgres umask
	$self->logmsg('2.1', 'head2', 'Ensure the file permissions mask is correct');
	my $umask = `sh -c "umask"`;
	chomp($umask);
	if ($umask ne '0077') {
		$self->logmsg('2.1', 'CRITICAL', 'The umask must be 0077 or more restrictive for the postgres user. Currently it is set to %s.', $umask);
		$self->{results}{'2.1'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}
	foreach my $ver (@{ $self->{pkg_ver} })
	{
		my ($major, $minor) = split(/\./, $ver);

		# Verify that the PGDATA exists and that permissions are correct
		my $data_dir = $self->{pgdata} || `$self->{psql} -Atc "SHOW data_directory"`;
		chomp($data_dir);
		return if (!$data_dir);

		# Verify that the PGDATA permissions are correct
		$self->logmsg('2.2', 'head2', 'Check permissions of PGDATA');
		my $perm = `ls -la "$data_dir" | grep " \\.\$" | awk '{print \$1}'`;
		chomp($perm);
		$perm =~ s/\.$//;
		if ($perm ne 'drwx------') {
			$self->logmsg('2.2', 'CRITICAL', 'Permissions of the PGDATA (%s) are not secure: %s, must be drwx------.', $data_dir, $perm);
			$self->{results}{'2.2'} = 'FAILURE';
		}
		else
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}

		# Have a look to the PGDATA to check for symlink or unwanted files
		$self->logmsg('2.3', 'head2', 'List content of PGDATA to check unwanted files and symlinks');
		my @content = `ls -la "$data_dir/"`;
		$self->logdata(@content);

		# Verify that the pg_hba.conf file have the right permissions when outside the PGDATA
		$self->logmsg('2.4', 'head2', 'Check permissions of pg_hba.conf');
		my $pg_hba = `$self->{psql} -Atc "SHOW hba_file"`;
		chomp($pg_hba);
		$pg_hba = "$data_dir/$pg_hba" if ($pg_hba !~ m#^/#);
		$perm = `ls -la "$pg_hba" | awk '{print \$1}'`;
		chomp($perm);
		$perm =~ s/\.$//;
		if ($perm ne '-rw-r-----' and $perm ne '-rw-------')
		{
			my $parent_dir = $pg_hba;
			$parent_dir =~ s/\/[^\/]+$//;
			# check the permission of the parent directory to avoid firing false positive
			my $dperm = `ls -la "$parent_dir" | grep " \\.\$" | awk '{print \$1}'`;
			chomp($perm);
			$perm =~ s/\.$//;
			if ($perm ne 'drwx------')
			{
				$self->logmsg('2.4', 'CRITICAL', 'Permissions of the pg_hba.conf file (%s) are not secure: %s, must be -rw-r----- or -rw-------.', $pg_hba, $perm);
				$self->{results}{'2.4'} = 'FAILURE';
			}
		}
		if ($self->{results}{'2.4'} ne 'FAILURE') {
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
	}

	$self->logmsg('2.5', 'head2', 'Check permissions on Unix Socket');
	my @perm_sock = `$self->{psql} -Atc "SHOW unix_socket_permissions;SHOW unix_socket_directories;SHOW port;"`;
	chomp(@perm_sock);
	if ($perm_sock[1])
	{
		my @sock_dirs = split(/,/, $perm_sock[1]);
		map { s/\@//; } @sock_dirs;
		foreach my $d (@sock_dirs)
		{
			my $perm = `ls -la "$d/.s.PGSQL.$perm_sock[2]" | awk '{print \$1}'`;
			if ($perm eq 'srwxrwxrwx' || $perm_sock[0] eq '0777')
			{
				$self->logmsg('2.5', 'WARNING', 'Permission on Unix socket %s should be more restrictive, for example: 0770 or 0700. Currently it is set to 0777.', "$d/.s.PGSQL.$perm_sock[2]");
				$self->{results}{'2.5'} = 'FAILURE';
			}
		}

		if ($self->{results}{'2.5'} ne 'FAILURE')
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

}

sub check_log_settings
{
	my $self = shift;

	$self->logmsg('3.1', 'head2', 'PostgreSQL Logging');

	$self->logmsg('3.1.1', 'head3', 'Logging Rationale');

	$self->logmsg('3.1.2', 'head3', 'Ensure the log destinations are set correctly');
	my $log_dest = `$self->{psql} -Atc "SHOW log_destination"`;
	chomp($log_dest);
	if (!$log_dest) {
		$self->logmsg('3.1', 'CRITICAL', 'Setting \'log_destination\' is not set, logging will be lost.');
		$self->{results}{'3.1.2'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.3', 'head3', 'Ensure the logging collector is enabled');
	my $log_collector = `$self->{psql} -Atc "SHOW logging_collector"`;
	chomp($log_collector);
	if ($log_collector ne 'on' and $log_dest eq 'syslog') {
		$self->logmsg('3.2', 'WARNING', 'Setting \'logging_collector\' should be enabled instead of using syslog.');
		$self->{results}{'3.1.3'} = 'FAILURE';
	}
	if ($log_collector ne 'on' and ($log_dest ne 'syslog' or $log_dest ne 'stderr')) {
		$self->logmsg('3.3', 'CRITICAL', 'Setting \'logging_collector\' must be enabled when \'log_destination\' is not set to syslog or stderr, logging will be lost.');
		$self->{results}{'3.1.3'} = 'FAILURE';
	}
	if ($self->{results}{'3.1.3'} ne 'FAILURE')
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.4', 'head3', 'Ensure the log file destination directory is set correctly');
	if ($log_dest ne 'syslog' && $log_collector eq 'on')
	{
		my $log_dir = `$self->{psql} -Atc "SHOW log_directory"`;
		chomp($log_dir);
		if (!$log_dir) {
			$self->logmsg('3.4', 'CRITICAL', 'Setting \'log_directory\' must be set, currently writes will be done in / and logging will be lost.');
			$self->{results}{'3.1.4'} = 'FAILURE';
		}
		else
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.5', 'head3', 'Ensure the filename pattern for log files is set correctly');
	if ($log_dest ne 'syslog' && $log_collector eq 'on')
	{
		my $log_filename = `$self->{psql} -Atc "SHOW log_filename"`;
		chomp($log_filename);
		if (!$log_filename) {
			$self->logmsg('3.5', 'CRITICAL', 'Setting \'log_filename\' must be set, currently logging will be lost.');
			$self->{results}{'3.1.5'} = 'FAILURE';
		}
		$self->logdata("log_filename = '" . $log_filename . "' # Please check with your security policy");
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.6', 'head3', 'Ensure the log file permissions are set correctly');
	if ($log_dest ne 'syslog' && $log_collector eq 'on')
	{
		my $log_mode = `$self->{psql} -Atc "SHOW log_file_mode"`;
		chomp($log_mode);
		if ($log_mode ne '0600') {
			$self->logmsg('3.6', 'WARNING', 'Setting \'log_file_mode\' should be set to \'0600\', current value is %s.', $log_mode);
			$self->{results}{'3.1.6'} = 'FAILURE';
		}
		else
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.7', 'head3', 'Ensure \'log_truncate_on_rotation\' is enabled');
	if ($log_dest ne 'syslog' && $log_collector eq 'on')
	{
		my $log_truncate = `$self->{psql} -Atc "SHOW log_truncate_on_rotation"`;
		chomp($log_truncate);
		if ($log_truncate ne 'on') {
			$self->logmsg('3.7', 'WARNING', 'Setting \'log_truncate_on_rotation\' should be enabled.');
			$self->{results}{'3.1.7'} = 'FAILURE';
		}
		else
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.8', 'head3', 'Ensure the maximum log file lifetime is set correctly');
	if ($log_dest ne 'syslog' && $log_collector eq 'on')
	{
		my $log_age = `$self->{psql} -Atc "SHOW log_rotation_age"`;
		chomp($log_age);
		$self->logdata("log_rotation_age = '" . $log_age . "' # Please check with your security policy");
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.9', 'head3', 'Ensure the maximum log file size is set correctly');
	if ($log_dest ne 'syslog' && $log_collector eq 'on')
	{
		my $log_size = `$self->{psql} -Atc "SHOW log_rotation_size"`;
		chomp($log_size);
		$self->logdata("log_rotation_size = '" . $log_size . "' # Please check with your security policy");
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.10', 'head3', 'Ensure the correct syslog facility is selected (Manual)');
	if ($log_dest eq 'syslog')
	{
		my $log_facility = `$self->{psql} -Atc "SHOW syslog_facility"`;
		chomp($log_facility);
		$self->logdata("syslog_facility = '" . $log_facility . "' # Please check with your security policy");
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.11', 'head3', 'Ensure syslog messages are not suppressed');
	if ($log_dest eq 'syslog')
	{
		my $log_seq = `$self->{psql} -Atc "SHOW syslog_sequence_numbers"`;
		chomp($log_seq);
		if ($log_seq ne 'on') {
			$self->logmsg('3.11', 'WARNING', 'Setting \'syslog_sequence_numbers\' should be enabled, some messages can be lost.');
			$self->{results}{'3.1.11'} = 'FAILURE';
		}
		else
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.12', 'head3', 'Ensure syslog messages are not lost due to size');
	if ($log_dest eq 'syslog')
	{
		my $log_split = `$self->{psql} -Atc "SHOW syslog_split_messages"`;
		chomp($log_split);
		if ($log_split ne 'on') {
			$self->logmsg('3.12', 'WARNING', 'Setting \'syslog_split_messages\' should be enabled, some messages can be truncated.');
			$self->{results}{'3.1.12'} = 'FAILURE';
		}
		else
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.13', 'head3', 'Ensure the program name for PostgreSQL syslog messages is correct');
	if ($log_dest eq 'syslog')
	{
		my $log_ident = `$self->{psql} -Atc "SHOW syslog_ident"`;
		chomp($log_ident);
		$self->logdata("syslog_ident = '" . $log_ident . "' # Please check with your security policy");
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.14', 'head3', 'Ensure the correct messages are written to the server log');
	my $log_min_messages = `$self->{psql} -Atc "SHOW log_min_messages"`;
	chomp($log_min_messages);
	if ($log_min_messages ne 'warning') {
		$self->logmsg('3.14', 'WARNING', 'Setting \'log_min_messages\' should be set to \'warning\' to avoid tracing too many or too few messages.');
		$self->{results}{'3.1.14'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.15', 'head3', 'Ensure the correct SQL statements generating errors are recorded');
	my $log_min_error_statement = `$self->{psql} -Atc "SHOW log_min_error_statement"`;
	chomp($log_min_error_statement);
	if ($log_min_error_statement ne 'error') {
		$self->logmsg('3.15', 'WARNING', 'Setting \'log_min_error_statement\' should be set to \'error\' to avoid tracing too many or too few messages.');
		$self->{results}{'3.1.15'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.16', 'head3', 'Ensure \'debug_print_parse\' is disabled');
	my $debug_print_parse = `$self->{psql} -Atc "SHOW debug_print_parse"`;
	chomp($debug_print_parse);
	if ($debug_print_parse ne 'off') {
		$self->logmsg('3.16', 'WARNING', 'Setting \'debug_print_parse\' should be disabled.');
		$self->{results}{'3.1.16'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.17', 'head3', 'Ensure \'debug_print_rewritten\' is disabled');
	my $debug_print_rewritten = `$self->{psql} -Atc "SHOW debug_print_rewritten"`;
	chomp($debug_print_rewritten);
	if ($debug_print_rewritten ne 'off') {
		$self->logmsg('3.17', 'WARNING', 'Setting \'debug_print_rewritten\' should be disabled.');
		$self->{results}{'3.1.17'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.18', 'head3', 'Ensure \'debug_print_plan\' is disabled');
	my $debug_print_plan = `$self->{psql} -Atc "SHOW debug_print_plan"`;
	chomp($debug_print_plan);
	if ($debug_print_plan ne 'off') {
		$self->logmsg('3.18', 'WARNING', 'Setting \'debug_print_plan\' should be disabled.');
		$self->{results}{'3.1.18'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.19', 'head3', 'Ensure \'debug_pretty_print\' is enabled');
	my $debug_pretty_print = `$self->{psql} -Atc "SHOW debug_pretty_print"`;
	chomp($debug_pretty_print);
	if ($debug_pretty_print eq 'off') {
		$self->logmsg('3.19', 'WARNING', 'Setting \'debug_pretty_print\' should be enabled.');
		$self->{results}{'3.1.19'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.20', 'head3', 'Ensure \'log_connections\' is enabled');
	my $log_connections = `$self->{psql} -Atc "SHOW log_connections"`;
	chomp($log_connections);
	if ($log_connections eq 'off') {
		$self->logmsg('3.20', 'WARNING', 'Setting \'log_connections\' should be enabled.');
		$self->{results}{'3.1.20'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.21', 'head3', 'Ensure \'log_disconnections\' is enabled');
	my $log_disconnections = `$self->{psql} -Atc "SHOW log_disconnections"`;
	chomp($log_disconnections);
	if ($log_disconnections eq 'off') {
		$self->logmsg('3.21', 'WARNING', 'Setting \'log_disconnections\' should be enabled.');
		$self->{results}{'3.1.21'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.22', 'head3', 'Ensure \'log_error_verbosity\' is set correctly');
	my $log_error_verbosity = `$self->{psql} -Atc "SHOW log_error_verbosity"`;
	chomp($log_error_verbosity);
	if ($log_error_verbosity ne 'verbose') {
		$self->logmsg('3.22', 'WARNING', 'Setting \'log_error_verbosity\' should be set to \'verbose\'.');
		$self->{results}{'3.1.22'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.23', 'head3', 'Ensure \'log_hostname\' is set correctly');
	my $log_hostname = `$self->{psql} -Atc "SHOW log_hostname"`;
	chomp($log_hostname);
	if ($log_hostname ne 'off') {
		$self->logmsg('3.23', 'WARNING', 'Setting \'log_hostname\' should be disabled.');
		$self->{results}{'3.1.23'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.24', 'head3', 'Ensure \'log_line_prefix\' is set correctly');
	my $log_line_prefix = `$self->{psql} -Atc "SHOW log_line_prefix"`;
	chomp($log_line_prefix);
	if ($log_dest ne 'syslog')
	{
		my $all_found = 1;
		$all_found = 0 if ($log_line_prefix !~ /\%[tmn]/ or $log_line_prefix !~ /\%[pc]/
				or $log_line_prefix !~ /\%d/ or $log_line_prefix !~ /\%u/
				or $log_line_prefix !~ /\%a/ or $log_line_prefix !~ /\%h/);
		if (!$all_found)
		{
			$self->logmsg('3.24', 'WARNING', 'Setting \'log_line_prefix\' should containt at least \'%%m [%%p]: db=%%d,user=%%u,app=%%a,client=%%h \' (for stderr logging). For syslog logging, the prefix should include \'user=%%u,db=%%d,app=%%a,client=%%h \'.');
			$self->{results}{'3.1.24'} = 'FAILURE';
		}
		else
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.25', 'head3', 'Ensure \'log_statement\' is set correctly');
	my $log_statement = `$self->{psql} -Atc "SHOW log_statement"`;
	chomp($log_statement);
	if ($log_statement eq 'none') {
		$self->logmsg('3.25', 'WARNING', 'Setting \'log_statement\' should at least be set to \'ddl\'.');
		$self->{results}{'3.1.25'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.26', 'head3', 'Ensure \'log_timezone\' is set correctly');
	my $log_timezone = `$self->{psql} -Atc "SHOW log_timezone"`;
	chomp($log_timezone);
	if (!grep(/^$log_timezone$/i, 'GMT', 'UTC')) {
		$self->logmsg('3.26', 'WARNING', 'Setting \'log_timezone\' should be set to \'GMT\' or \'UTC\'.');
		$self->{results}{'3.1.26'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.1.27', 'head3', 'Ensure that log_directory is outside the PGDATA');
	if ($log_dest ne 'syslog' and $log_collector eq 'on')
	{
		my $data_dir = $self->{pgdata} || `$self->{psql} -Atc "SHOW data_directory"`;
		chomp($data_dir);
		$data_dir =~ s#/$##;
		my $log_dir = `$self->{psql} -Atc "SHOW log_directory"`;
		chomp($log_dir);
		if ($log_dir !~ m#^/# or $log_dir =~ m#^$data_dir/#) {
			$self->logmsg('3.4', 'WARNING', 'Setting \'log_directory\' should use a location that is not in the PGDATA.');
			$self->{results}{'3.1.27'} = 'FAILURE';
		}
		else
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('3.2', 'head2', 'Ensure the PostgreSQL Audit Extension (pgAudit) is enabled');
	my $pgaudit = `$self->{psql} -Atc "SHOW shared_preload_libraries;"`;
	chomp($pgaudit);
	if ($pgaudit !~ m#pgaudit#) {
		$self->logmsg('3.28', 'WARNING', 'PostgreSQL extension pgAudit should be used.');
		$self->{results}{'3.1.28'} = 'FAILURE';
	}
	else
	{
		my $pgaudit_conf = `$self->{psql} -Atc "SHOW pgaudit.log;"`;
		chomp($pgaudit_conf);
		if ($pgaudit_conf !~ /ddl/ || $pgaudit_conf !~ /write/) {
			$self->logmsg('3.29', 'WARNING', 'PostgreSQL extension pgAudit is not well configured, \'pgaudit.log\' setting shoud contain \'ddl\' and \'write\'.');
			$self->{results}{'3.1.29'} = 'FAILURE';
		}
		else
		{
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
	}
}

sub check_user_access
{
	my $self = shift;

	#$self->logmsg('4.1', 'head2', 'Ensure sudo is configured correctly (Manual)');
	$self->logmsg('4.2', 'head2', 'Ensure excessive administrative privileges are revoked');
	my @privs = `$self->{psql} -Atc "\\du+"`;
	my @superusers = grep(/superuser/i, @privs);
	if ($#superusers > 0)
	{
		$self->logmsg('4.2', 'WARNING', 'There are more than one PostgreSQL superuser.');
		$self->{results}{'4.2'} = 'FAILURE';
	}
	unshift(@superusers, "Role|Attributs|Description\n");
	$self->logdata(@superusers);

	# Get the list of the database in the PostgreSQL cluster
	my @dbs = `$self->{psql} -Atc "SELECT datname FROM pg_database WHERE datallowconn ORDER BY 1;"`;
	chomp(@dbs);

	$self->logmsg('4.3', 'head2', 'Ensure excessive function privileges are revoked');
	my $i = 1;
	$self->{collapse_id}++;
	foreach my $db (@dbs)
	{
		# apply the filter on database to include in the report
		next if ($#{ $self->{allow} } >= 0 && !grep(/^$db$/i, @{ $self->{allow} }));
		next if ($#{ $self->{exclude} } >= 0 && grep(/^$db$/i, @{ $self->{exclude} }));

		my @secdef = `$self->{psql} -d $db -Atc "SELECT p.oid, nspname, proname, rolname, prosecdef, proconfig, proacl FROM pg_proc p JOIN pg_namespace n ON p.pronamespace = n.oid JOIN pg_authid a ON a.oid = p.proowner WHERE proname NOT LIKE 'pgaudit%' AND (prosecdef OR NOT proconfig IS NULL) AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.refclassid = 'pg_catalog.pg_extension'::pg_catalog.regclass AND d.objid = p.oid AND d.deptype = 'e');"`;
		if ($#secdef >= 0)
		{
			$self->logmsg('4.3.' . $i, 'head3', $db);
			unshift(@secdef, join('|', qw/oid nspname proname rolname prosecdef proconfig proacl/) . "\n");
			if ($self->{format} eq 'html') {
				$self->{details} .= "<div id=\"collapse-$self->{collapse_id}\" class=\"collapse\">\n";
			}
			$self->logdata(@secdef);
			if ($self->{format} eq 'html') {
				$self->{details} .= "</div>\n";
			}
			$i++;
			$self->{collapse_id}++;
		}
	}

	$self->logmsg('4.4', 'head2', 'Ensure excessive DML privileges are revoked');
	$i = 1;
	$self->{collapse_id}++;
	foreach my $db (@dbs)
	{
		# apply the filter on database to include in the report
		next if ($#{ $self->{allow} } >= 0 && !grep(/^$db$/i, @{ $self->{allow} }));
		next if ($#{ $self->{exclude} } >= 0 && grep(/^$db$/i, @{ $self->{exclude} }));

		my @secdef = `$self->{psql} -d $db -Atc "SELECT t.schemaname, t.tablename, u.usename,
has_table_privilege(u.usename, '\\"'||t.schemaname||'\\".\\"'||t.tablename||'\\"', 'select') as select,
has_table_privilege(u.usename, '\\"'||t.schemaname||'\\".\\"'||t.tablename||'\\"', 'insert') as insert,
has_table_privilege(u.usename, '\\"'||t.schemaname||'\\".\\"'||t.tablename||'\\"', 'update') as update,
has_table_privilege(u.usename, '\\"'||t.schemaname||'\\".\\"'||t.tablename||'\\"', 'delete') as delete
FROM pg_tables t, pg_user u WHERE t.schemaname NOT IN ('information_schema','pg_catalog') AND (
has_table_privilege(u.usename, '\\"'||t.schemaname||'\\".\\"'||t.tablename||'\\"', 'select') OR
has_table_privilege(u.usename, '\\"'||t.schemaname||'\\".\\"'||t.tablename||'\\"', 'insert') OR
has_table_privilege(u.usename, '\\"'||t.schemaname||'\\".\\"'||t.tablename||'\\"', 'update') OR
has_table_privilege(u.usename, '\\"'||t.schemaname||'\\".\\"'||t.tablename||'\\"', 'delete')
) AND NOT usesuper;"`;
		if ($#secdef >= 0)
		{
			$self->logmsg('4.4.' . $i, 'head3', $db);
			if ($self->{format} eq 'html') {
				$self->{details} .= "<div id=\"collapse-$self->{collapse_id}\" class=\"collapse\">\n";
			}
			unshift(@secdef, join('|', qw/schema table user select insert update delete/) . "\n");
			$self->logdata(@secdef);
			if ($self->{format} eq 'html') {
				$self->{details} .= "</div>\n";
				$self->{collapse_id}++;
			}
			$i++;
		}
	}

	$self->logmsg('4.5', 'head2', 'Ensure Row Level Security (RLS) is configured correctly');
	my @bypassrls = grep(!/Superuser/, grep(/Bypass RLS/i, @privs));
	if ($#bypassrls > 0)
	{
		$self->logmsg('4.5', 'WARNING', 'Some PostgreSQL user have Bypass RLS enabled.');
		$self->{results}{'4.5'} = 'FAILURE';
		$self->logdata(@bypassrls);
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$i = 1;
	$self->{collapse_id}++;
	foreach my $db (@dbs)
	{
		# apply the filter on database to include in the report
		next if ($#{ $self->{allow} } >= 0 && !grep(/^$db$/i, @{ $self->{allow} }));
		next if ($#{ $self->{exclude} } >= 0 && grep(/^$db$/i, @{ $self->{exclude} }));

		my @rls = `$self->{psql} -d $db -Atc "SELECT oid, relname, relrowsecurity FROM pg_class WHERE relrowsecurity IS TRUE;"`;
		if ($#rls >= 0)
		{
			$self->logmsg('4.5.' . $i, 'head3', $db);
			if ($self->{format} eq 'html') {
				$self->{details} .= "<div id=\"collapse-$self->{collapse_id}\" class=\"collapse\">\n";
			}
			unshift(@rls, join('|', qw/oid relname relrowsecurity/) . "\n");
			$self->logdata(@rls);
			if ($self->{format} eq 'html') {
				$self->{details} .= "</div>\n";
				$self->{collapse_id}++;
			}
			$i++;
		}
	}

	$self->logmsg('4.6', 'head2', 'Ensure the set_user extension is installed');
	my $set_user = `$self->{psql} -Atc "SHOW shared_preload_libraries;"`;
	chomp($set_user);
	if ($set_user !~ m#set_user#) {
		$self->logmsg('4.6', 'WARNING', 'PostgreSQL extension set_user should be used.');
		$self->{results}{'4.6'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	#  Create the pgdsat_roletree audit view
	`$self->{psql} -Atc "DROP VIEW IF EXISTS pgdsat_roletree;" 2>/dev/null`;
	`$self->{psql} -Atc "CREATE OR REPLACE VIEW pgdsat_roletree AS WITH RECURSIVE roltree AS ( SELECT u.rolname AS rolname, u.oid AS roloid, u.rolcanlogin, u.rolsuper, '{}'::name[] AS rolparents, NULL::oid AS parent_roloid, NULL::name AS parent_rolname FROM pg_catalog.pg_authid u LEFT JOIN pg_catalog.pg_auth_members m on u.oid = m.member LEFT JOIN pg_catalog.pg_authid g on m.roleid = g.oid WHERE g.oid IS NULL UNION ALL SELECT u.rolname AS rolname, u.oid AS roloid, u.rolcanlogin, u.rolsuper, t.rolparents || g.rolname AS rolparents, g.oid AS parent_roloid, g.rolname AS parent_rolname FROM pg_catalog.pg_authid u JOIN pg_catalog.pg_auth_members m on u.oid = m.member JOIN pg_catalog.pg_authid g on m.roleid = g.oid JOIN roltree t on t.roloid = g.oid) SELECT r.rolname, r.roloid, r.rolcanlogin, r.rolsuper, r.rolparents FROM roltree r ORDER BY 1;"`;
	# Verify there are no unexpected unprivileged roles that can login directly
	my @canlogin = `$self->{psql} -Atc "SELECT ro.rolname, ro.roloid, ro.rolcanlogin, ro.rolsuper, ro.rolparents FROM pgdsat_roletree ro WHERE (ro.rolcanlogin AND ro.rolsuper) OR ( ro.rolcanlogin AND EXISTS ( SELECT TRUE FROM pgdsat_roletree ri WHERE ri.rolname = ANY (ro.rolparents) AND ri.rolsuper)) ORDER BY 1;"`;
	unshift(@canlogin, join('|', qw/rolname roloid rolcanlogin rolsuper rolparents/) . "\n");
	$self->logdata(@canlogin);

	$self->logmsg('4.7', 'head2', 'Make use of predefined roles');
	my @pgrole = `$self->{psql} -Atc "SELECT r.rolname, r.roloid, r.rolcanlogin, r.rolsuper, r.rolparents FROM pgdsat_roletree r WHERE r.rolparents::text ~ 'pg_*' ORDER BY 1;"`;
	unshift(@pgrole, join('|', qw/rolname roloid rolcanlogin rolsuper rolparents/) . "\n");
	$self->logdata(@pgrole);

	# Drop our audit view
	`$self->{psql} -Atc "DROP VIEW pgdsat_roletree;"`;

	$self->logmsg('4.8', 'head2', 'Ensuse the public schema is protected');

	$self->{collapse_id}++;
	foreach my $db (@dbs)
	{
		# apply the filter on database to include in the report
		next if ($#{ $self->{allow} } >= 0 && !grep(/^$db$/i, @{ $self->{allow} }));
		next if ($#{ $self->{exclude} } >= 0 && grep(/^$db$/i, @{ $self->{exclude} }));

		my @public = `$self->{psql} -d $db -Atc "SELECT nspname, nspowner, nspacl FROM pg_catalog.pg_namespace WHERE nspname='public';"`;
		if ($public[0] =~ m#,=U[C]?/#s)
		{
			$self->logmsg('4.8.' . $i, 'head3', $db);
			if ($self->{format} eq 'html') {
				$self->{details} .= "<div id=\"collapse-$self->{collapse_id}\" class=\"collapse\">\n";
			}
			$self->logmsg('4.8.' . $i, 'WARNING', 'Schema public can be used by anyone in database %s.', $db);
			unshift(@public, "nspname|nspowner|nspacl\n");
			$self->logdata(@public);
			$self->{results}{'4.8'} = 'FAILURE';
			if ($self->{format} eq 'html') {
				$self->{details} .= "</div>\n";
				$self->{collapse_id}++;
			}
			$i++;
		}
	}
	if ($self->{results}{'4.8'} ne 'FAILURE')
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	return @superusers;
}

sub check_connection
{
	my ($self, @superusers) = @_;

	map { s/\|.*//; } @superusers;

	my $hba_file = `$self->{psql} -Atc "SHOW hba_file;"`;
	chomp($hba_file);
	if (!$hba_file || !-e $hba_file) {
		$self->logmsg('5.1', 'CRITICAL', 'Can not find pg_hba.conf file "%s".', $hba_file);
		$self->{results}{'5.1'} = 'FAILURE';
		return 0;
	}

	my @hba_entries = $self->load_pg_hba_file($hba_file);

	$self->logmsg('5.1', 'head2', 'Ensure login via "local" UNIX Domain Socket is configured correctly');
	my $num_err = 0;
	foreach my $hba_entry (@hba_entries)
	{
		next if ($hba_entry->{type} ne 'local');
		$num_err += $self->check_auth_method($hba_entry);
	}
	if (!$num_err)
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('5.2', 'head2', 'Ensure login via "host" TCP/IP Socket is configured correctly');
	$num_err = 0;
	foreach my $hba_entry (@hba_entries)
	{
		next if ($hba_entry->{type} eq 'local');
		$num_err += $self->check_auth_method($hba_entry);
	}

	$self->logmsg('5.3', 'head2', 'Ensure Password Complexity is configured');

	# Check that a library to password complexity enforcement is loaded (not that it is well configured)
	# Only useful if the authentication method is md5 or scram
	if ($self->{use_pwd_enforcement})
	{
		my @auth_lib = `$self->{psql} -Atc "select setting from pg_settings where name like '%_preload_libraries' and setting != ''"`;
		chomp(@auth_lib);

		if (!grep(/(credcheck|passwordcheck)/, @auth_lib)) {
			$self->logmsg('5.8', 'CRITICAL', "no password difficulty enforcement library used. Consider using the credcheck or passwordcheck PostgreSQL extension.");
			$self->{results}{'5.3'} = 'FAILURE';
		}
		else
		{
			# FIXME: Show the passwordcheck and credcheck settings
			$self->logmsg('0.1', 'SUCCESS', 'Test passed');
		}
	}

	$self->logmsg('5.4', 'head2', 'Ensure authentication timeout and delay are well configured');

	# Check timeout in the authentication process.
	my $auth_timeout = `$self->{psql} -Atc "select setting from pg_settings where name='authentication_timeout'"`;
	chomp($auth_timeout);
	if ($auth_timeout > 60) {
		$self->logmsg('5.9', 'WARNING', "setting 'authentication_timeout' should be <= 60s.");
		$self->{results}{'5.4'} = 'FAILURE';
	}
	# Search if an auth delay is set, auth_delay causes the server
	# to pause briefly before reporting authentication failure
	my @auth_delay = `$self->{psql} -Atc "SHOW auth_delay.milliseconds; SHOW credcheck.auth_delay_ms;" 2>/dev/null`;
	chomp(@auth_delay);
	if (!grep(/\d+/, @auth_delay)) {
		$self->logmsg('5.10', 'WARNING', 'you should add an authentication failure delay to prevent brute force attack. See PostgreSQL extension credcheck or auth_delay.');
		$self->{results}{'5.4'} = 'FAILURE';
	}
	if ($self->{results}{'5.4'} ne 'FAILURE')
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('5.5', 'head2', 'Ensure SSL is used for client connection');
	my @ssl_msg = ();
	foreach my $hba_entry (@hba_entries)
	{
		next if ($hba_entry->{type} eq 'local');
		my $msg = $self->check_ssl_conn($hba_entry);
		push(@ssl_msg, $msg) if ($msg);
	}

	# Show SSL warning if any
	if ($#ssl_msg >= 0)
	{
		$self->logmsg('5.11', 'WARNING', 'The use of the "host" connection type should be rejected when "hostssl" or "hostgssenc" is used. See line(s) %s in pg_hba.conf.',  join(', ', @ssl_msg));
		$self->{results}{'5.5'} = 'FAILURE';
	}
	elsif (!$self->{use_ssl} && !$self->{use_gssenc} && $self->{use_host})
	{
		$self->logmsg('5.12', 'CRITICAL', 'Use of ssl encryption for all remote connection should be used, see "hostssl" and "hostgssenc" connection type.');
		$self->{results}{'5.5'} = 'FAILURE';
	}
	if ($self->{results}{'5.5'} ne 'FAILURE')
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('5.6', 'head2', 'Ensure authorized Ip addresses ranges are not too large');
	foreach my $hba_entry (@hba_entries)
	{
		$self->check_ip_address($hba_entry);
	}

	$self->logmsg('5.7', 'head2', 'Ensure specific database and users are used');
	$num_err = 0;
	foreach my $hba_entry (@hba_entries)
	{
		next if ($hba_entry->{type} eq 'local');
		$num_err += $self->check_all_conn($hba_entry);
	}
	if (!$num_err)
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('5.8', 'head2', 'Ensure superusers are not allowed to connect remotely');
	$num_err = 0;
	foreach my $hba_entry (@hba_entries)
	{
		next if ($hba_entry->{type} eq 'local');
		$num_err += $self->check_superuser($hba_entry, @superusers);
	}
	if (!$num_err)
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('5.9', 'head2', 'Ensure that \'password_encryption\' is correctly set');
	my $pwd_enc_type = `$self->{psql} -Atc "SHOW password_encryption;"`;
	chomp($pwd_enc_type);
	if ($pwd_enc_type ne 'scram-sha-256') {
		$self->logmsg('5.17', 'CRITICAL', 'parameter \'password_encryption\' should be set to \'scram-sha-256\', not \'%s\'.', $pwd_enc_type);
		$self->{results}{'5.9'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}


}

sub check_auth_method
{
	my ($self, $entry) = @_;

	my $found = 0;
	if ($entry->{method} eq 'trust' or $entry->{method} eq 'password')
	{
		$self->logmsg('5.4', 'CRITICAL', 'The use of the "%s" authentication method must not be used. See line %s in file %s.', $entry->{method}, $entry->{line}, $entry->{file});
		$found = 1;
	}
	elsif ($entry->{method} eq 'md5')
	{
		$self->logmsg('5.5', 'WARNING', 'The use of the "md5" authentication method is vulnerable to packet replay attacks. See line %s in file %s.', $entry->{line}, $entry->{file});
		$found = 1;
	}
	elsif ($entry->{method} eq 'ident')
	{
		$self->logmsg('5.6', 'WARNING', 'The use of the "ident" authentication method is insecure, the client running the ident server should be considered as untrust. See line %s in file %s.', $entry->{line}, $entry->{file});
		$found = 1;
	}

	if (grep(/^$entry->{method}$/, 'md5', 'scram-sha-256')) {
		$self->{use_pwd_enforcement} = 1;
	}

	if ($found)
	{
		$self->{results}{'5.1'} = 'FAILURE';
		$self->logdata("$entry->{source}\n");

		my $method = 'peer';
		$method = 'scram-sha-256' if ($entry->{type} ne 'local');
		$self->logmsg('5.7', 'INFO', 'Use %s authentication method or any of the external methods (gss, sspi, pam, ldap, radius or cert) instead.', $method);
	}

	return $found;
}

sub check_ssl_conn
{
	my ($self, $entry) = @_;

	if ($self->{use_ssl} and $entry->{type} =~ /^host(nossl)?$/ and $entry->{method} ne 'reject')
	{
		return $entry->{line};
	}
	elsif ($self->{use_gssenc} and $entry->{type} =~ /^host(nogssenc)?$/ and $entry->{method} ne 'reject')
	{
		return $entry->{line};
	}
}

sub check_ip_address
{
	my ($self, $entry) = @_;

	next if (!$entry->{address});

	# Voir nom à la place de IPs
	my $found = 0;

	my $netmask_lbl = 'netmask';
	my $mask = '';
	my $size = 0;
	if ($entry->{netmask} =~ /^\d+$/)
	{
		$netmask_lbl = 'cidr';
		my $block = PGDSAT::Netmask->new2( $entry->{address} . '/' . $entry->{netmask} ) or die $Net::Netmask::error;
		$mask = $block->mask;
		$size = $block->size;
	}
	else
	{
		$netmask_lbl = 'netmask';
		my $block = PGDSAT::Netmask->new2( $entry->{address}, $entry->{netmask} ) or die $Net::Netmask::error;
		$mask = $block->mask;
		$size = $block->size;
	}

	if ($mask eq '0.0.0.0' or $mask eq '::')
	{
		$self->logmsg('5.13', 'CRITICAL', 'the use of %s \'%s\' correspond to any source. See line %s in file %s.', $netmask_lbl, $entry->{netmask}, $entry->{line}, $entry->{file});
		$self->{results}{'5.6'} = 'FAILURE';
	}
	#elsif ($mask eq '255.0.0.0' or $size >= 18446744073709551616)
	elsif ($mask eq '255.0.0.0' or $size > 65536)
	{
		$self->logmsg('5.14', 'WARNING', 'the use of %s \'%s\' correspond to a too huge Ip range. See line %s in file %s.', $netmask_lbl, $entry->{netmask}, $entry->{line}, $entry->{file});
		$self->{results}{'5.6'} = 'FAILURE';
	}
}

sub check_all_conn
{
	my ($self, $entry) = @_;

	my $found = 0;
	if ($entry->{database} eq 'all' or $entry->{user} eq 'all')
	{
		$self->logmsg('5.15', 'WARNING', 'You should be more specific and give the database and users allowed to connect, not "all". See line %s in file %s.', $entry->{method}, $entry->{line}, $entry->{file});
		$found = 1;
	}

	if ($found)
	{
		$self->{results}{'5.7'} = 'FAILURE';
		$self->logdata("$entry->{source}\n");
	}

	return $found;
}

sub check_superuser
{
	my ($self, $entry, @superusers) = @_;

	my $found = 0;
	my $regexp = join('|', @superusers) || '';
	if ($entry->{user} =~ /^($regexp)$/)
	{
		$self->logmsg('5.16', 'CRITICAL', 'You should not allow superusers to connect remotely, only from local and peer authentication. See line %s in file %s.', $entry->{method}, $entry->{line}, $entry->{file});
		$found = 1;
	}

	if ($found)
	{
		$self->{results}{'5.8'} = 'FAILURE';
		$self->logdata("$entry->{source}\n");
	}

	return $found;
}


sub check_pg_settings
{
	my $self = shift;

	#$self->logmsg('6.1', 'head2', 'Understanding attack vectors and runtime parameters');

	$self->logmsg('6.2', 'head2', 'Ensure \'backend\' runtime parameters are configured correctly');
	my @ret = `$self->{psql} -Atc "SELECT name, setting FROM pg_settings WHERE context IN ('backend','superuser-backend') ORDER BY 1;"`;
	chomp(@ret);
	my %backend_settings =();
	foreach my $s (@ret)
	{
		my ($k, $v) = split(/\|/, $s);
		$backend_settings{$k} = $v;
	}

	foreach my $s ('ignore_system_indexes', 'jit_debugging_support', 'jit_profiling_support')
	{
		if ($backend_settings{$s} ne 'off') {
			$self->logmsg('6.2', 'CRITICAL', 'Setting \'%s\' must be disabled.', $s);
			$self->{results}{'6.2'} = 'FAILURE';
		}
	}

	foreach my $s ('log_connections', 'log_disconnections')
	{
		if ($backend_settings{$s} ne 'on') {
			$self->logmsg('6.3', 'CRITICAL', 'Setting \'%s\' must be enabled.', $s);
			$self->{results}{'6.2'} = 'FAILURE';
		}
	}

	if ($backend_settings{'post_auth_delay'} ne '0') {
		$self->logmsg('6.4', 'CRITICAL', 'Setting \'post_auth_delay\' must be set to 0.');
		$self->{results}{'6.2'} = 'FAILURE';
	}

	if ($self->{results}{'6.2'} ne 'FAILURE')
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('6.3', 'head2', 'Ensure \'Postmaster\' runtime parameters are configured correctly');
	@ret = `$self->{psql} -Atc "SELECT name, setting FROM pg_settings WHERE context = 'postmaster' ORDER BY 1;"`;
	unshift(@ret, "name|setting\n");
	$self->logdata(@ret);

	$self->logmsg('6.4', 'head2', 'Ensure \'SIGHUP\' runtime parameters are configured correctly');
	@ret = `$self->{psql} -Atc "SELECT name, setting FROM pg_settings WHERE context = 'sighup' ORDER BY 1;"`;
	unshift(@ret, "name|setting\n");
	$self->logdata(@ret);

	$self->logmsg('6.5', 'head2', 'Ensure \'Superser\' runtime parameters are configured correctly');
	@ret = `$self->{psql} -Atc "SELECT name, setting FROM pg_settings WHERE context = 'superuser' ORDER BY 1;"`;
	unshift(@ret, "name|setting\n");
	$self->logdata(@ret);

	$self->logmsg('6.6', 'head2', 'Ensure \'User\' runtime parameters are configured correctly');
	@ret = `$self->{psql} -Atc "SELECT name, setting FROM pg_settings WHERE context = 'user' ORDER BY 1;"`;
	unshift(@ret, "name|setting\n");
	$self->logdata(@ret);

	$self->logmsg('6.7', 'head2', 'Ensure FIPS 140-2 OpenSSL cryptography is used');
	@ret = `fips-mode-setup --check 2>/dev/null`;
	if (!grep(/FIPS mode is enabled/, @ret))
	{
		$self->logmsg('6.5', 'CRITICAL', 'Installation of FIPS modules is not completed.');
		$self->logmsg('6.6', 'INFO', 'See https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening#switching-the-system-to-fips-mode_using-the-system-wide-cryptographic-policies to enable FIPS mode');
		$self->{results}{'6.7'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}
	# Show SSL version
	@ret = `openssl version`;
	$self->logdata(@ret);

	$self->logmsg('6.8', 'head2', 'Ensure TLS is enabled and configured correctly');
	my $ssl = `$self->{psql} -Atc "SHOW ssl;"`;
	chomp($ssl);
	if ($ssl ne 'on') {
		$self->logmsg('6.7', 'CRITICAL', 'TLS is not enabled. Setting \'ssl\' should be activated.');
		$self->{results}{'6.8'} = 'FAILURE';
	}
	else
	{
		my $ssl_ver = `$self->{psql} -Atc "select setting from pg_settings where name='ssl_min_protocol_version'"`;
		chomp($ssl_ver);
		$ssl_ver =~ s/[^0-9\.]+//g;
		if ($ssl_ver < 1.3) {
			$self->logmsg('6.8', 'WARNING', 'Setting \'ssl_min_protocol_version\' should be TLS v1.3 or newer.');
			$self->{results}{'6.8'} = 'FAILURE';
		}
		my $ssl_passphrase = `$self->{psql} -Atc "select setting from pg_settings where name='ssl_passphrase_command'"`;
		chomp($ssl_passphrase);
		if (!$ssl_passphrase) {
			$self->logmsg('6.9', 'WARNING', 'The SSL certificate should have a passphrase and setting \'ssl_passphrase_command\' should be set.');
			$self->{results}{'6.8'} = 'FAILURE';
		}

		if (!$self->{use_ssl} && !$self->{use_gssenc})
		{
			$self->logmsg('6.10', 'CRITICAL', 'To enforce TLS authentication for the server, appropriate "hostssl" or "hostgssenc" records must be added to the pg_hba.conf file and "host" connections rejected.');
			$self->{results}{'6.8'} = 'FAILURE';
		}
	}
	if ($self->{results}{'6.8'} ne 'FAILURE')
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('6.9', 'head2', 'Ensure a cryptographic extension is installed');
	my @has_crypto = `$self->{psql} -Atc "select * from pg_available_extensions where name='pgcrypto' or name='pgsodium'"`;
	chomp(@has_crypto);
	if ($#has_crypto < 0) {
		$self->logmsg('6.11', 'WARNING', 'Extensions pgcrypto or pgsodium are not installed.');
		$self->{results}{'6.9'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('6.10', 'head2', 'Ensure a data anonymization extension is installed');
	my $has_anon = `$self->{psql} -Atc "SHOW session_preload_libraries;"`;
	chomp($has_anon);
	my @libs = split(/,/, $has_anon);
	if (!grep(/^(anon|pg_anonymize)$/, @libs)) {
		$self->logmsg('6.12', 'WARNING', 'Extensions pg_anonymize or anon are not installed.');
		$self->{results}{'6.10'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}
}

sub check_replication
{
	my $self = shift;

	$self->logmsg('7.1', 'head2', 'Ensure a replication-only user is created and used for streaming replication');
	my @repusers = `$self->{psql} -Atc "select rolname from pg_roles where rolreplication is true;"`;
	chomp(@repusers);
	# Check if there's any replication user outside the postgres superuser
	if ($#repusers < 1) {
		$self->logmsg('7.1', 'WARNING', 'A replication-only user should be created.');
		$self->{results}{'7.1'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('7.2', 'head2', 'Ensure logging of replication commands is configured');
	my $log_rep = `$self->{psql} -Atc "SHOW log_replication_commands;"`;
	chomp($log_rep);
	if ($log_rep eq 'off') {
		$self->logmsg('7.2', 'WARNING', 'Setting \'log_replication_commands\' should be enabled.');
		$self->{results}{'7.2'} = 'FAILURE';
	}
	else
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('7.3', 'head2', 'Ensure base backups are configured and functional');

	$self->logmsg('7.4', 'head2', 'Ensure WAL archiving is configured and functional');
	my @ret = `$self->{psql} -Atc "SELECT name, setting FROM pg_settings WHERE name ~ '^archive' ORDER BY 1;"`;
	chomp(@ret);
	my %archive_settings = ();
	foreach my $s (@ret)
	{
		my ($k, $v) = split(/\|/, $s);
		$archive_settings{$k} = $v;
	}

	if ($archive_settings{'archive_mode'} eq 'off') {
		$self->logmsg('7.4', 'CRITICAL', 'WAL archiving is not activated. Setting \'archive_mode\' must be enabled.');
		$self->{results}{'7.4'} = 'FAILURE';
	}
	else
	{
		if ($archive_settings{'archive_command'} eq '' and $archive_settings{'archive_library'} eq '') {
			$self->logmsg('7.5', 'CRITICAL', 'Settings \'archive_command\' or \'archive_library\' must be set.');
			$self->{results}{'7.4'} = 'FAILURE';
		}
	}
	if ($self->{results}{'7.4'} ne 'FAILURE')
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('7.5', 'head2', 'Ensure streaming replication parameters are configured correctly');
	my $ret = `$self->{psql} -Atc "SHOW primary_conninfo;"`;
	chomp($ret);
	if ($ret !~ /sslmode=require/) {
		$self->logmsg('7.6', 'CRITICAL', 'Setting \'primary_conninfo\' must enforce TLS encryption of the replication (sslmode=required).');
		$self->{results}{'7.5'} = 'FAILURE';
	}
	else
	{
		if ($ret !~ /sslcompression=1/) {
			$self->logmsg('7.7', 'WARNING', 'Setting \'primary_conninfo\' should enable SSL compression (sslcompression=1).');
			$self->{results}{'7.5'} = 'FAILURE';
		}
	}
	if ($self->{results}{'7.5'} ne 'FAILURE')
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}
}

sub check_special_conf
{
	my $self = shift;

	$self->logmsg('8.1', 'head2', 'Ensure PostgreSQL subdirectory locations are outside the data cluster');

	$self->logmsg('8.2', 'head2', 'Ensure the backup and restore tool, \'pgBackRest\', is installed and configured');
	my @ret = `pgbackrest info 2>/dev/null`;
	if ($#ret < 0) {
		$self->logmsg('8.2', 'WARNING', 'The backup tool \'pgBackRest\' is not installed.');
		$self->{results}{'8.2'} = 'FAILURE';
	} elsif ($#ret == 0) {
		$self->logmsg('8.3', 'WARNING', 'No stanzas exist for \'pgBackRest\'.');
		$self->{results}{'8.2'} = 'FAILURE';
	}
	if ($self->{results}{'8.2'} ne 'FAILURE')
	{
		$self->logmsg('0.1', 'SUCCESS', 'Test passed');
	}

	$self->logmsg('8.3', 'head2', 'Ensure miscellaneous configuration settings are correct');
	@ret = `$self->{psql} -Atc "select name, setting from pg_settings where name in ('external_pid_file', 'unix_socket_directories','shared_preload_libraries','dynamic_library_path','local_preload_libraries','session_preload_libraries');"`;
	unshift(@ret, "name|setting\n");
	$self->logdata(@ret);
}

1;
