## NAME

pgdsat - PostgreSQL Database Security Assessment Tool

## DESCRIPTION

PGDSAT is a security assessment tool that checks around 80 PostgreSQL security
controls of your PostgreSQL clusters including all recommendations from the
[CIS compliance benchmark](https://www.cisecurity.org/cis-benchmarks/)
but not only.

This tool is a single command that must be run on the PostgreSQL server
to collect all necessaries system and PostgreSQL information to compute a
security assessment report. A report consist in a summary of all tests status
and a second part with all detailed information.
See [sample report](https://www.darold.net/sample_pgdsat/report.html).

This PostgreSQL Security Assessment Tool allow assessments to be carried out
in an automated manner to verify the security policies established inside
the company. It also gives understanding of the security issued that your
cluster can be faced.

Although the default text output format can be read directly from a terminal
the use of the HTML output format is recommended for better reading as you
can see in the sample report above.

## SECURITY CHECKS

All checks recommended by the CIS Benchmark for PostgreSQL 16 are implemented
but not only. Some additional tests not part of the CIS document are marked with
the "(\*)" mention in the description.

Here is the list all checks performed on a PostgreSQL cluster. Some must be
checked manually but most of them are check automatically by the tool.

        1 - Installation and Patches
          1.1 - Ensure packages are obtained from authorized repositories => SUCCESS
            1.1.1 - PostgreSQL packages installed. (Manual)
            1.1.2 - Ensure packages are obtained from PGDG => SUCCESS
          1.2 - Ensure systemd Service Files Are Enabled => SUCCESS
          1.3 - Ensure Data Cluster Initialized Successfully => SUCCESS
            1.3.1 - Check initialization of the PGDATA => SUCCESS
            1.3.2 - Check version in PGDATA => SUCCESS
            1.3.3 - Ensure Data Cluster have checksum enabled => FAILURE
            1.3.4 - Ensure WALs and temporary files are not on the same partition as the PGDATA => FAILURE
            1.3.5 - Ensure that the PGDATA partition is encrypted (Manual)
          1.4 - Ensure PostgreSQL versions are up-to-date => FAILURE
          1.5 - Ensure unused PostgreSQL extensions are removed (Manual)
	  1.6 - Ensure tablespace location is not inside the PGDATA
        2 - Directory and File Permissions
          2.1 - Ensure the file permissions mask is correct => FAILURE
          2.2 - Check permissions of PGDATA => SUCCESS
          2.3 - List content of PGDATA to check unwanted files and symlinks (Manual)
          2.4 - Check permissions of pg_hba.conf => SUCCESS
          2.5 - Check permissions on Unix Socket => FAILURE
        3 - Logging And Auditing
          3.1 - PostgreSQL Logging => SUCCESS
            3.1.1 - Logging Rationale => SUCCESS
            3.1.2 - Ensure the log destinations are set correctly => SUCCESS
            3.1.3 - Ensure the logging collector is enabled => FAILURE
            3.1.4 - Ensure the log file destination directory is set correctly => SUCCESS
            3.1.5 - Ensure the filename pattern for log files is set correctly (Manual)
            3.1.6 - Ensure the log file permissions are set correctly => SUCCESS
            3.1.7 - Ensure 'log_truncate_on_rotation' is enabled => SUCCESS
            3.1.8 - Ensure the maximum log file lifetime is set correctly (Manual)
            3.1.9 - Ensure the maximum log file size is set correctly (Manual)
            3.1.10 - Ensure the correct syslog facility is selected (Manual)
            3.1.11 - Ensure syslog messages are not suppressed => SUCCESS
            3.1.12 - Ensure syslog messages are not lost due to size => SUCCESS
            3.1.13 - Ensure the program name for PostgreSQL syslog messages is correct (Manual)
            3.1.14 - Ensure the correct messages are written to the server log => SUCCESS
            3.1.15 - Ensure the correct SQL statements generating errors are recorded => SUCCESS
            3.1.16 - Ensure 'debug_print_parse' is disabled => SUCCESS
            3.1.17 - Ensure 'debug_print_rewritten' is disabled => SUCCESS
            3.1.18 - Ensure 'debug_print_plan' is disabled => SUCCESS
            3.1.19 - Ensure 'debug_pretty_print' is enabled => SUCCESS
            3.1.20 - Ensure 'log_connections' is enabled => FAILURE
            3.1.21 - Ensure 'log_disconnections' is enabled => FAILURE
            3.1.22 - Ensure 'log_error_verbosity' is set correctly => FAILURE
            3.1.23 - Ensure 'log_hostname' is set correctly => SUCCESS
            3.1.24 - Ensure 'log_line_prefix' is set correctly => FAILURE
            3.1.25 - Ensure 'log_statement' is set correctly => FAILURE
            3.1.26 - Ensure 'log_timezone' is set correctly => FAILURE
            3.1.27 - Ensure that log_directory is outside the PGDATA => SUCCESS
          3.2 - Ensure the PostgreSQL Audit Extension (pgAudit) is enabled => SUCCESS
        4 - User Access and Authorization
          4.1 - Ensure sudo is configured correctly (Manual)
          4.2 - Ensure excessive administrative privileges are revoked => FAILURE
          4.3 - Ensure excessive function privileges are revoked (Manual)
          4.4 - Ensure excessive DML privileges are revoked (Manual)
          4.5 - Ensure Row Level Security (RLS) is configured correctly (Manual)
          4.6 - Ensure the set_user extension is installed (Manual) => FAILURE
          4.7 - Make use of predefined roles (Manual)
          4.8 - Ensuse the public schema is protected
        5 - Connection and Login
          5.1 - Ensure login via "local" UNIX Domain Socket is configured correctly => FAILURE
          5.2 - Ensure login via "host" TCP/IP Socket is configured correctly => SUCCESS
          5.3 - Ensure Password Complexity is configured => SUCCESS
          5.4 - Ensure authentication timeout and delay are well configured => FAILURE
          5.5 - Ensure SSL is used for client connection => FAILURE
          5.6 - Ensure authorized Ip addresses ranges are not too large => SUCCESS
          5.7 - Ensure specific database and users are used => FAILURE
          5.8 - Ensure superusers are not allowed to connect remotely => SUCCESS
          5.9 - Ensure that 'password_encryption' is correctly set => SUCCESS
        6 - PostgreSQL Settings
          6.1 - Understanding attack vectors and runtime parameters
          6.2 - Ensure 'backend' runtime parameters are configured correctly => FAILURE
          6.3 - Ensure 'Postmaster' runtime parameters are configured correctly (Manual)
          6.4 - Ensure 'SIGHUP' runtime parameters are configured correctly (Manual)
          6.5 - Ensure 'Superuser' runtime parameters are configured correctly (Manual)
          6.6 - Ensure 'User' runtime parameters are configured correctly (Manual)
          6.7 - Ensure FIPS 140-2 OpenSSL cryptography is used => FAILURE
          6.8 - Ensure TLS is enabled and configured correctly => FAILURE
          6.9 - Ensure a cryptographic extension is installed => SUCCESS
        7 - Replication
          7.1 - Ensure a replication-only user is created and used for streaming replication => FAILURE
          7.2 - Ensure logging of replication commands is configured => FAILURE
          7.3 - Ensure base backups are configured and functional => SUCCESS
          7.4 - Ensure WAL archiving is configured and functional => FAILURE
          7.5 - Ensure streaming replication parameters are configured correctly => FAILURE
        8 - Special Configuration Considerations
          8.1 - Ensure PostgreSQL subdirectory locations are outside the data cluster => SUCCESS
          8.2 - Ensure the backup and restore tool, 'pgBackRest', is installed and configured => FAILURE
          8.3 - Ensure miscellaneous configuration settings are correct (Manual)

## REQUIREMENT

PGDSAT is a standalone program that can be run on any Linux server, it doesn't require
any additional package installation except if your system do not have the following
requirements:

- Ensure that PostgreSQL binaries are reachable from the '$PATH' environment variable.
- Ensure PostgreSQL >= 10.
- Ensure that 'PGHOST', 'PGUSER', 'PGPASSWORD' and 'PGDATA' environment variables are defined or use the dedicated command line options (except for 'PGPASSWORD'). Or set a '.pgpass' file in the postgres system account.
- Ensure 'sudo apt install crypto-policies' have been run for the FIPS test.
- Ensure the 'curl' command is available and the server have access to Internet. It is used to check the PostgreSQL version online. If this is not possible, use command line option --no-pg-version-check to disable this check.
- To view the HTML report you also need an Internet access to obtain the FontAwesome icons used in the Summary Table of security checks.

## INSTALLATION

The PostgreSQL command psql is used to query the PostgreSQL cluster.

To install PGDSAT:

        perl Makefile.PL
        make
        sudo make install

If you don't want to install PGDSAT on your system but just want to execute
it from the source directory, follow the instruction at end of next chapter.

## USAGE

PGSAT use commands to look at the system and especially to the PostgreSQL
installation. It means that it requires the privilege of owner of these
repository to be executed. Run it as postgres system user.

Usage: pgdsat \[options\]

    PostgreSQL Database Security Assessment Tool.

Options:

    -a | --allow   : database to include into the report in parts 4.3 to 4.5.
                     Can be used multiple time and regexp are supported.
    -d | --database: name of the database to connect to PostgreSQL.
    -D | --pgdata  : path to the PostgreSQL cluster PGDATA to analyze.
    -e | --exclude : database to exclude from the report in parts 4.3 to 4.5.
                     Can be used multiple time and regexp are supported.
    -f | --format  : output format, can be: text or html. Default: html.
    -h | --host    : PostgreSQL serveur ip address if not listening on localhost
    -l | --lang    : language used for the output (en_US, fr_FR). Default: en_US
    -o | --output  : output file where to write the report. Default stdout.
    -p | --port    : port where PostgreSQL is listening, default: 5432.
    -P | --psql    : full path to the psql command if not found in PATH.
    -T | --title   : set title to use to differentiate the reports. Default is
                     to use "on `hostname`".
    -U | --user    : PostgreSQL user to use with the psql command.
    -v | --version : show version of pgdsat and exist.
    -V | --cluster : PostgreSQL Cluster version, ex: 15.4.
    --help         : show usage and exit.

    --no-pg-version-check : disable check for PostgreSQL minor versions. Useful
                     when connecting to Internet is not permitted.
Example:

    pgdsat -U postgres -h localhost -d postgres -o report.html
or
    pgdsat -U postgres -h localhost -d postgres -f html > report.html

If you have several PostgreSQL cluster installed you must give the running
version that you want to test:

    pgdsat -U postgres -h localhost -d postgres -f html -V 15.4 > report.html

To execute the pgdsat command locally without installation, use:

    sudo perl -I ./lib ./pgdsat ...

## AUTHORS

- Gilles Darold.

## LICENSE

pgdsat is free software distributed under the GPLv3 license. See LICENCE file for more information.

Copyright (c) 2024 HexaCluster Corp

Some parts are copied from the [CIS Benchmark](https://www.cisecurity.org/cis-benchmarks)
licensed under the [Creative Common Version 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode)
terms of use.
