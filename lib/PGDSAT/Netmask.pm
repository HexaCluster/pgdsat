####
# Formally Net::Netmask, embedded here just to avoid install of extra packages
#
# Copyright (C) 1998-2006 David Muir Sharnoff <muir@idiom.org>
# Copyright (C) 2011-2013 Google, Inc.
# Copyright (C) 2018-2021 Joelle Maslak <jmaslak@antelope.net>
####

package PGDSAT::Netmask;
$PGDSAT::Netmask::VERSION = '2.0001';
use 5.006_001;

# ABSTRACT: Understand and manipulate IP netmasks

# Disable one-arg bless to preserve the existing interface.
## no critic (ClassHierarchies::ProhibitOneArgBless)

require Exporter;
@ISA    = qw(Exporter);
@EXPORT = qw(findNetblock findOuterNetblock findAllNetblock
  cidrs2contiglists range2cidrlist sort_by_ip_address
  dumpNetworkTable sort_network_blocks cidrs2cidrs
  cidrs2inverse);
@EXPORT_OK = (
    @EXPORT, qw(ascii2int int2quad quad2int %quadmask2bits
      %quadhostmask2bits imask i6mask int2ascii sameblock cmpblocks contains)
);

my $remembered = {};
my %imask2bits;
my %size2bits;
my @imask;
my @i6mask;

our $SHORTNET_DEFAULT = undef;

use vars qw($error $debug %quadmask2bits %quadhostmask2bits);
$debug = 1;

use strict;
use warnings;
use Carp;
use Math::BigInt;
use POSIX qw(floor);
use overload
  '""'       => \&desc,
  '<=>'      => \&cmp_net_netmask_block,
  'cmp'      => \&cmp_net_netmask_block,
  'fallback' => 1;

sub new {
    my ( $package, $net, @params) = @_;

    my $mask = '';
    if (@params % 2) {
        $mask = shift(@params);
        $mask = '' if !defined($mask);
    }
    my (%options) = @params;
    my $shortnet = ( ( exists($options{shortnet}) && $options{shortnet} ) || $SHORTNET_DEFAULT );

    my $base;
    my $bits;
    my $ibase;
    my $proto = 'IPv4';
    undef $error;

    if ( $net =~ m,^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]+)$, ) {
        ( $base, $bits ) = ( $1, $2 );
    } elsif ( $net =~ m,^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[:/]([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$, ) {
        $base = $1;
        my $quadmask = $2;
        if ( exists $quadmask2bits{$quadmask} ) {
            $bits = $quadmask2bits{$quadmask};
        } else {
            $error = "illegal netmask: $quadmask";
        }
    } elsif ( $net =~ m,^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)[#]([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$, ) {
        $base = $1;
        my $hostmask = $2;
        if ( exists $quadhostmask2bits{$hostmask} ) {
            $bits = $quadhostmask2bits{$hostmask};
        } else {
            $error = "illegal hostmask: $hostmask";
        }
    } elsif ( ( $net =~ m,^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$, )
        && ( $mask =~ m,[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$, ) )
    {
        $base = $net;
        if ( exists $quadmask2bits{$mask} ) {
            $bits = $quadmask2bits{$mask};
        } else {
            $error = "illegal netmask: $mask";
        }
    } elsif ( ( $net =~ m,^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$, )
        && ( $mask =~ m,0x[a-f0-9]+,i ) )
    {
        $base = $net;
        my $imask = hex($mask);
        if ( exists $imask2bits{$imask} ) {
            $bits = $imask2bits{$imask};
        } else {
            $error = "illegal netmask: $mask ($imask)";
        }
    } elsif ( $net =~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && !$mask ) {
        ( $base, $bits ) = ( $net, 32 );
    } elsif ( $net =~ /^[0-9]+\.[0-9]+\.[0-9]+$/ && !$mask && $shortnet ) {
        ( $base, $bits ) = ( "$net.0", 24 );
    } elsif ( $net =~ /^[0-9]+\.[0-9]+$/ && !$mask && $shortnet ) {
        ( $base, $bits ) = ( "$net.0.0", 16 );
    } elsif ( $net =~ /^[0-9]+$/ && !$mask && $shortnet ) {
        ( $base, $bits ) = ( "$net.0.0.0", 8 );
    } elsif ( $net =~ m,^([0-9]+\.[0-9]+\.[0-9]+)/([0-9]+)$, && $shortnet ) {
        ( $base, $bits ) = ( "$1.0", $2 );
    } elsif ( $net =~ m,^([0-9]+\.[0-9]+)/([0-9]+)$, && $shortnet ) {
        ( $base, $bits ) = ( "$1.0.0", $2 );
    } elsif ( $net =~ m,^([0-9]+)/([0-9]+)$, && $shortnet ) {
        ( $base, $bits ) = ( "$1.0.0.0", $2 );
    } elsif ( $net eq 'default' || $net eq 'any' ) {
        ( $base, $bits ) = ( "0.0.0.0", 0 );
    } elsif ( $net =~ m,^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s*-\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$, )
    {
        # whois format
        $ibase = quad2int($1);
        my $end = quad2int($2);
        $error = "illegal dotted quad: $net"
          unless defined($ibase) && defined($end);
        my $diff = ( $end || 0 ) - ( $ibase || 0 ) + 1;
        $bits  = $size2bits{$diff};
        $error = "could not find exact fit for $net"
          if !defined $error
          && ( !defined $bits
            || ( $ibase & ~$imask[$bits] ) );
    } elsif ( $net =~ m,^([0-9a-f]*:[0-9a-f]*:[0-9a-f:]*)/([0-9]+)$, ) {
        # IPv6 with netmask - ex: 2001:db8::/32
        if ( $mask ne '' ) { $error = "mask ignored for IPv6 address" }
        ( $base, $bits, $proto ) = ( $1, $2, 'IPv6' );
    } elsif ( $net =~ m,^([0-9a-f]*:[0-9a-f]*:[0-9a-f:]*)$, ) {
        # IPv6 without netmask - ex: 2001:db8::1234
        if ( $mask ne '' ) { $error = "mask ignored for IPv6 address" }
        ( $base, $bits, $proto ) = ( $1, 128, 'IPv6' );
    } elsif ( $net eq 'default6' || $net eq 'any6' ) {
        if ( $mask ne '' ) { $error = "mask ignored for IPv6 address" }
        ( $base, $bits, $proto ) = ( "::", 0, 'IPv6' );
    } else {
        $error = "could not parse $net";
        $error .= " $mask" if $mask;
    }

    carp $error if $error && $debug;

    $bits = 0 unless $bits;
    if ( ( $proto eq 'IPv4' ) && ( $bits > 32 ) ) {
        $error = "illegal number of bits: $bits"
          unless $error;
        $bits = 32;
    } elsif ( ( $proto eq 'IPv6' ) && ( $bits > 128 ) ) {
        $error = "illegal number of bits: $bits"
          unless $error;
        $bits = 128;
    }

    $ibase = ascii2int( ( $base || '::' ), $proto ) unless (defined $ibase or $error);
    unless ( defined($ibase) || defined($error) ) {
        $error = "could not parse $net";
        $error .= " $mask" if $mask;
    }

    if ($error) {
        $ibase = 0;
        $bits  = 0;
    }

    $ibase = i_getnet_addr( $ibase, $bits, $proto );

    return bless {
        'IBASE'    => $ibase,
        'BITS'     => $bits,
        'PROTOCOL' => $proto,
        ( $error ? ( 'ERROR' => $error ) : () ),
    };
}

sub i_getnet_addr {
    my ( $ibase, $bits, $proto ) = @_;

    if ( !defined($ibase) ) { return; }

    if ( $proto eq 'IPv4' ) {
        return $ibase & $imask[$bits];
    } else {
        return $ibase & $i6mask[$bits];
    }
}

sub new2 {
    goto &safe_new;
}

sub safe_new {
    local ($debug) = 0;
    my $net = new(@_);
    return if $error;
    return $net;
}

sub errstr { return $error; }
sub debug { my $this = shift; return ( @_ ? $debug = shift : $debug ) }

sub base { my ($this) = @_; return int2ascii( $this->{IBASE}, $this->{PROTOCOL} ); }
sub bits { my ($this) = @_; return $this->{'BITS'}; }
sub protocol { my ($this) = @_; return $this->{'PROTOCOL'}; }

sub size {
    my ($this) = @_;

    if ( $this->{PROTOCOL} eq 'IPv4' ) {
        return 2**( 32 - $this->{'BITS'} );
    } else {
        return Math::BigInt->new(2)->bpow( 128 - $this->{'BITS'} );
    }
}

sub next {    ## no critic: (Subroutines::ProhibitBuiltinHomonyms)
    my ($this) = @_;
    # TODO: CONSOLIDATE
    if ( $this->{PROTOCOL} eq 'IPv4' ) {
        return int2quad( $this->{'IBASE'} + $this->size() );
    } else {
        return $this->_ipv6next( $this->size );
    }
}

sub broadcast {
    my ($this) = @_;

    return int2ascii( $this->{'IBASE'} + $this->size() - 1, $this->{PROTOCOL} );
}

*first = \&base;
*last  = \&broadcast;

sub desc {
    return int2ascii( $_[0]->{IBASE}, $_[0]->{PROTOCOL} ) . '/' . $_[0]->{BITS};
}

sub imask {
    return ( 2**32 - ( 2**( 32 - $_[0] ) ) );
}

sub i6mask {
    my $bits = shift;
    return Math::BigInt->new(2)->bpow(128) - Math::BigInt->new(2)->bpow( 128 - $bits );
}

sub mask {
    my ($this) = @_;

    if ( $this->{PROTOCOL} eq 'IPv4' ) {
        return int2quad( $imask[ $this->{'BITS'} ] );
    } else {
        return int2ascii( $i6mask[ $this->{'BITS'} ], $this->{PROTOCOL} );
    }
}

sub hostmask {
    my ($this) = @_;

    if ( $this->{PROTOCOL} eq 'IPv4' ) {
        return int2quad( ~$imask[ $this->{BITS} ] );
    } else {
        return int2ascii( $i6mask[ $this->{BITS} ] ^ $i6mask[128], $this->{PROTOCOL} );
    }
}

sub nth {
    my ( $this, $index, $bitstep ) = @_;

    my $maxbits = $this->{PROTOCOL} eq 'IPv4' ? 32 : 128;

    my $size  = $this->size();
    my $ibase = $this->{'IBASE'};
    $bitstep = $maxbits unless $bitstep;
    my $increment = 2**( $maxbits - $bitstep );
    $index *= $increment;
    $index += $size if $index < 0;
    return if $index < 0;
    return if $index >= $size;

    my $i = $ibase + $index;
    return int2ascii( $i, $this->{PROTOCOL} );
}

sub enumerate {
    my ( $this, $bitstep ) = @_;
    my $proto = $this->{PROTOCOL};

    # Set default step size by protocol
    $bitstep = ( $proto eq 'IPv4' ? 32 : 128 ) unless $bitstep;

    my $size = $this->size();

    my @ary;
    ### We should be able to consolidate this
    if ( $proto eq 'IPv4' ) {
        my $increment = 2**( 32 - $bitstep );
        my $ibase     = $this->{'IBASE'};
        for ( my $i = 0; $i < $size; $i += $increment ) {
            push( @ary, int2quad( $ibase + $i ) );
        }
    } else {
        my $increment = Math::BigInt->new(2)->bpow( 128 - $bitstep );

        if ( ( $size / $increment ) > 1_000_000_000 ) {
            # Let's help the user out and catch really obvious issues.
            # Asking for a billion IP addresses is probably one of them.
            #
            # That said, please contact the author if this number causes
            # you issues!
            confess("More than 1,000,000,000 results would be returned, dieing");
        }

        for ( my $i = Math::BigInt->new(0); $i < $size; $i += $increment ) {
            push( @ary, $this->_ipv6next($i) );
        }
    }
    return @ary;
}

sub _ipv6next {
    my ( $this, $bitstep ) = @_;

    my $istart = $this->{IBASE};
    my $val    = $istart + $bitstep;

    return ipv6Cannonical( int2ascii( $val, $this->{PROTOCOL} ) );
}

sub inaddr {
    my ($this) = @_;

    if ( $this->{PROTOCOL} eq 'IPv4' ) {
        return $this->inaddr4();
    } else {
        return $this->inaddr6();
    }
}

sub inaddr4 {
    my ($this) = @_;
    my $ibase  = $this->{'IBASE'};
    my $blocks = floor( $this->size() / 256 );
    return (
        join( '.', unpack( 'xC3', pack( 'V', $ibase ) ) ) . ".in-addr.arpa",
        $ibase % 256,
        $ibase % 256 + $this->size() - 1
    ) if $blocks == 0;
    my @ary;
    for ( my $i = 0; $i < $blocks; $i++ ) {
        push( @ary,
            join( '.', unpack( 'xC3', pack( 'V', $ibase + $i * 256 ) ) ) . ".in-addr.arpa",
            0, 255 );
    }
    return @ary;
}

sub inaddr6 {
    my ($this) = @_;

    my (@digits) = split //, $this->{IBASE}->to_hex;

    my $static    = floor( $this->{BITS} / 4 );
    my $len       = floor( ( $static + 3 ) / 4 );
    my $remainder = $this->{BITS} % 4;
    my $blocks    = $remainder ? ( 2**( 4 - $remainder ) ) : 1;

    my @tail;
    if ( !$len ) {
        # Specal case: 0 len
        return ('ip6.arpa');
    }
    push @tail, reverse( @digits[ 0 .. ( $static - 1 ) ] ), 'ip6.arpa';

    if ( !$remainder ) {
        # Special case - at nibble boundary already
        return ( join '.', @tail );
    }

    my $last = hex $digits[$static];
    my @ary;
    for ( my $i = 0; $i < $blocks; $i++ ) {
        push @ary, join( '.', sprintf( "%x", $last ), @tail );
        $last++;
    }

    return @ary;
}

sub tag {
    my $this = shift;
    my $tag  = shift;
    my $val  = $this->{ 'T' . $tag };
    $this->{ 'T' . $tag } = $_[0] if @_;
    return $val;
}

sub quad2int {
    my @bytes = split( /\./, $_[0] );

    return unless @bytes == 4;
    return unless !grep { !( /^(([0-9])|([1-9][0-9]*))$/ && $_ < 256 ) } @bytes;

    return unpack( "N", pack( "C4", @bytes ) );
}

sub int2quad {
    return join( '.', unpack( 'C4', pack( "N", $_[0] ) ) );
}

# Uses the internal "raw" representation (such as IBASE).
# For IPv4, this is an integer
# For IPv6, this is a raw bit string.
sub int2ascii {
    if ( $_[1] eq 'IPv4' ) {
        return join( '.', unpack( 'C4', pack( "N", $_[0] ) ) );
    } elsif ( $_[1] eq 'IPv6' ) {
        my $addr = ( ref $_[0] ) ne '' ? $_[0]->to_hex : Math::BigInt->new( $_[0] )->to_hex;
        return ipv6Cannonical($addr);
    } else {
        confess("Incorrect call");
    }
}

# Produces the internal "raw" representation (such as IBASE).
# For IPv4, this is an integer
# For IPv6, this is a raw bit string.
sub ascii2int {
    if ( $_[1] eq 'IPv4' ) {
        return quad2int( $_[0] );
    } elsif ( $_[1] eq 'IPv6' ) {
        return ipv6ascii2int( $_[0] );
    } else {
        confess("Incorrect call");
    }
}

# Take an IPv6 ASCII address and produce a raw value
sub ipv6ascii2int {
    my $addr = shift;

    $addr = ipv6NonCompacted($addr);
    $addr = join '', map { sprintf( "%04x", hex($_) ) } split( /:/, $addr );

    return Math::BigInt->from_hex($addr);
}

# Takes an IPv6 address and produces a standard version seperated by
# colons (without compacting)
sub ipv6NonCompacted {
    my $addr = shift;

    if ( $addr !~ /:/ ) {
        if ( length($addr) < 32 ) {
            $addr = ( "0" x ( 32 - length($addr) ) ) . $addr;
        }
        $addr =~ s/(....)(?=....)/$1:/gsx;
    }

    # Handle address format with trailing IPv6
    # Ex: 0:0:0:0:1.2.3.4
    if ( $addr =~ m/^[0-9a-f:]+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/i ) {
        my ( $l, $r1, $r2, $r3, $r4 ) =
          $addr =~ m/^([0-9a-f:]+)([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)$/i;
        $addr = sprintf( "%s%02x%02x:%02x%02x", $l, $r1, $r2, $r3, $r4 );
    }

    my ( $left, $right ) = split /::/, $addr;
    if ( !defined($right) ) { $right = '' }
    my (@lparts) = split /:/, $left;
    my (@rparts) = split /:/, $right;

    # Strip leading 0's & lowercase
    @lparts = map { $_ =~ s/^0+([0-9a-f]+)/$1/; lc($_) } @lparts;
    @rparts = map { $_ =~ s/^0+([0-9a-f]+)/$1/; lc($_) } @rparts;

    # Expand ::
    my $missing = 8 - ( @lparts + @rparts );
    if ($missing) {
        $addr = join ':', @lparts, ( 0, 0, 0, 0, 0, 0, 0, 0 )[ 0 .. $missing - 1 ], @rparts;
    } else {
        $addr = join ':', @lparts, @rparts;
    }

    return $addr;
}

# Compacts an IPv6 address (reduces successive :0: runs)
sub ipv6AsciiCompact {
    my $addr = shift;

    # Compress, per RFC5952
    if ( $addr =~ s/^0:0:0:0:0:0:0:0$/::/ ) {
        return $addr;
    } elsif ( $addr =~ s/(:?^|:)0:0:0:0:0:0:0(:?:|$)/::/ ) {
        return $addr;
    } elsif ( $addr =~ s/(:?^|:)0:0:0:0:0:0(:?:|$)/::/ ) {
        return $addr;
    } elsif ( $addr =~ s/(:?^|:)0:0:0:0:0(:?:|$)/::/ ) {
        return $addr;
    } elsif ( $addr =~ s/(:?^|:)0:0:0:0(:?:|$)/::/ ) {
        return $addr;
    } elsif ( $addr =~ s/(:?^|:)0:0:0(:?:|$)/::/ ) {
        return $addr;
    } elsif ( $addr =~ s/(:?^|:)0:0(:?:|$)/::/ ) {
        return $addr;
    } elsif ( $addr =~ s/(:?^|:)0(:?:|$)/::/ ) {
        return $addr;
    }
    return $addr;
}
# Cannonicalize IPv6 addresses in ascii format
sub ipv6Cannonical {
    my $addr = shift;

    $addr = ipv6NonCompacted($addr);
    $addr = ipv6AsciiCompact($addr);

    return $addr;
}

# IPv6 addresses are stored with a leading zero.
sub storeNetblock {
    my ( $this, $t ) = @_;
    $t = $remembered unless $t;

    my $base = $this->{'IBASE'};
    if ( $this->{PROTOCOL} eq 'IPv6' ) {
        $base = "0$base";
    }

    $t->{$base} = [] unless exists $t->{$base};

    my $mb   = maxblock($this);
    my $bits = $this->{'BITS'};
    my $i    = $bits - $mb;

    return ( $t->{$base}[$i] = $this );
}

sub deleteNetblock {
    my ( $this, $t ) = @_;
    $t = $remembered unless $t;

    my $base = $this->{'IBASE'};
    if ( $this->{PROTOCOL} eq 'IPv6' ) {
        $base = "0$base";
    }

    my $mb   = maxblock($this);
    my $bits = $this->{'BITS'};
    my $i    = $bits - $mb;

    return unless defined $t->{$base};

    undef $t->{$base}->[$i];

    for my $x ( @{ $t->{$base} } ) {
        return if $x;
    }
    return delete $t->{$base};
}

sub findNetblock {
    my ( $ascii, $t ) = @_;
    $t = $remembered unless $t;

    my $proto = ( $ascii =~ m/:/ ) ? 'IPv6' : 'IPv4';

    my $ip = ascii2int( $ascii, $proto );
    return unless defined $ip;
    my %done;

    my $maxbits = $proto eq 'IPv6' ? 128 : 32;
    for ( my $bits = $maxbits; $bits >= 0; $bits-- ) {
        my $nb = i_getnet_addr( $ip, $bits, $proto );
        if ( $proto eq 'IPv6' ) {
            $nb = "0$nb";
        }
        next unless exists $t->{$nb};
        my $mb = imaxblock( $nb, $maxbits, $proto );
        next if $done{$mb}++;
        my $i = $bits - $mb;
        while ( $i >= 0 ) {
            return $t->{$nb}->[$i]
              if defined $t->{$nb}->[$i];
            $i--;
        }
    }
    return;
}

sub findOuterNetblock {
    my ( $ipstr, $t ) = @_;
    $t = $remembered unless $t;

    my $proto;
    my $maxbits;

    my $ip;
    my $len;
    if ( ref($ipstr) ) {
        $proto   = $ipstr->{PROTOCOL};
        $maxbits = $proto eq 'IPv4' ? 32 : 128;
        $ip      = $ipstr->{IBASE};
        $len     = $ipstr->{BITS};
    } else {
        $proto   = ( $ipstr =~ m/:/ ) ? 'IPv6' : 'IPv4';
        $maxbits = $proto eq 'IPv4'   ? 32     : 128;
        $ip = ascii2int( $ipstr, $proto );
        $len = $maxbits;
    }

    for ( my $bits = 0; $bits <= $len; $bits++ ) {
        my $nb = $ip & ( $proto eq 'IPv4' ? $imask[$bits] : $i6mask[$bits] );
        if ( $proto eq 'IPv6' ) {
            $nb = "0$nb";
        }
        next unless exists $t->{$nb};
        my $mb = imaxblock( $nb, $len, $proto );
        my $i = $bits - $mb;
        confess "$mb, $bits, $ipstr, $nb" if $i < 0;
        confess "$mb, $bits, $ipstr, $nb" if $i > $maxbits;
        while ( $i >= 0 ) {
            return $t->{$nb}->[$i]
              if defined $t->{$nb}->[$i];
            $i--;
        }
    }
    return;
}

sub findAllNetblock {
    my ( $ipstr, $t ) = @_;
    $t = $remembered unless $t;

    my $proto   = ( $ipstr =~ m/:/ ) ? 'IPv6' : 'IPv4';
    my $maxbits = $proto eq 'IPv4'   ? 32     : 128;

    my $ip = ascii2int( $ipstr, $proto );

    my %done;
    my @ary;
    for ( my $bits = $maxbits; $bits >= 0; $bits-- ) {
        my $nb = $ip & ( $proto eq 'IPv4' ? $imask[$bits] : $i6mask[$bits] );
        if ( $proto eq 'IPv6' ) {
            $nb = "0$nb";
        }
        next unless exists $t->{$nb};
        my $mb = imaxblock( $nb, $maxbits, $proto );
        next if $done{$mb}++;
        my $i = $bits - $mb;
        confess "$mb, $bits, $ipstr, $nb" if $i < 0;
        confess "$mb, $bits, $ipstr, $nb" if $i > $maxbits;
        while ( $i >= 0 ) {
            push( @ary, $t->{$nb}->[$i] )
              if defined $t->{$nb}->[$i];
            $i--;
        }
    }
    return @ary;
}

sub dumpNetworkTable {
    my ($t) = @_;
    $t = $remembered unless $t;

    my @ary;
    foreach my $base ( keys %$t ) {
        push @ary, grep { defined($_) } @{ $t->{base} };
        for my $x ( @{ $t->{$base} } ) {
            push( @ary, $x )
              if defined $x;
        }
    }

    return ( sort @ary );
}

sub checkNetblock {
    my ( $this, $t ) = @_;
    $t = $remembered unless $t;

    my $base = $this->{'IBASE'};

    my $mb   = maxblock($this);
    my $bits = $this->{'BITS'};
    my $i    = $bits - $mb;

    return defined $t->{$base}->[$i];
}

sub match {
    my ( $this, $ip ) = @_;
    my $proto = $this->{PROTOCOL};

    # Two different protocols: return undef
    if ( $ip =~ /:/ ) {
        if ( $proto ne 'IPv6' ) { return }
    } else {
        if ( $proto ne 'IPv4' ) { return }
    }

    my $i = ascii2int( $ip, $this->{PROTOCOL} );
    my $ia = i_getnet_addr( $i, $this->{BITS}, $proto );

    if ( $proto eq 'IPv4' ) {
        if ( $ia == $this->{IBASE} ) {
            return ( ( $i & ~( $this->{IBASE} ) ) || "0 " );
        } else {
            return 0;
        }
    } else {
        if ( $ia == $this->{IBASE} ) {
            return ( ( $i - $this->{IBASE} ) || "0 " );
        } else {
            return 0;
        }
    }
}

sub maxblock {
    my ($this) = @_;
    return ( !defined $this->{ERROR} )
      ? imaxblock( $this->{IBASE}, $this->{BITS}, $this->{PROTOCOL} )
      : undef;
}

sub nextblock {
    my ( $this, $index ) = @_;
    $index = 1 unless defined $index;
    my $ibase = $this->{IBASE};
    if ( $this->{PROTOCOL} eq 'IPv4' ) {
        $ibase += $index * 2**( 32 - $this->{BITS} );
    } else {
        $ibase += $index * Math::BigInt->new(2)->bpow( 128 - $this->{BITS} );
    }

    my $newblock = bless {
        IBASE    => $ibase,
        BITS     => $this->{BITS},
        PROTOCOL => $this->{PROTOCOL},
    };

    if ( $this->{PROTOCOL} eq 'IPv4' ) {
        return if $newblock->{IBASE} >= 2**32;
    } else {
        return if $newblock->{IBASE} >= Math::BigInt->new(2)->bpow(128);
    }

    return if $newblock->{IBASE} < 0;
    return $newblock;
}

sub imaxblock {
    my ( $ibase, $tbit, $proto ) = @_;
    confess unless defined $ibase;

    if ( !defined($proto) ) { $proto = 'IPv4'; }

    while ( $tbit > 0 ) {
        my $ia = i_getnet_addr( $ibase, $tbit - 1, $proto );
        last if ( $ia != $ibase );
        $tbit--;
    }
    return $tbit;
}

sub range2cidrlist {
    my ( $startip, $endip ) = @_;

    my $proto;
    if ( $startip =~ m/:/ ) {
        if ( $endip =~ m/:/ ) { $proto = 'IPv6'; }
    } else {
        if ( $endip !~ m/:/ ) { $proto = 'IPv4'; }
    }
    if ( !defined($proto) ) { confess("Cannot mix IPv4 and IPv6 in range2cidrlist()"); }

    my $start = ascii2int( $startip, $proto );
    my $end   = ascii2int( $endip,   $proto );

    ( $start, $end ) = ( $end, $start )
      if $start > $end;
    return irange2cidrlist( $start, $end, $proto );
}

sub irange2cidrlist {
    my ( $start, $end, $proto ) = @_;
    if ( !defined($proto) ) { $proto = 'IPv4' }

    my $bits = $proto eq 'IPv4' ? 32 : 128;

    my @result;
    while ( $end >= $start ) {
        my $maxsize = imaxblock( $start, $bits, $proto );
        my $maxdiff;
        if ( $proto eq 'IPv4' ) {
            $maxdiff = $bits - _log2( $end - $start + 1 );
        } else {
            $maxdiff = $bits - ( $end - $start + 1 )->blog(2);
        }
        $maxsize = $maxdiff if $maxsize < $maxdiff;
        push(
            @result,
            bless {
                'IBASE'    => $start,
                'BITS'     => $maxsize,
                'PROTOCOL' => $proto,
            }
        );
        if ( $proto eq 'IPv4' ) {
            $start += 2**( 32 - $maxsize );
        } else {
            $start += Math::BigInt->new(2)->bpow( $bits - $maxsize );
        }
    }
    return @result;
}

sub cidrs2contiglists {
    my (@cidrs) = sort_network_blocks(@_);
    my @result;
    while (@cidrs) {
        my (@r) = shift(@cidrs);
        my $max = $r[0]->{IBASE} + $r[0]->size;
        while ( $cidrs[0] && $cidrs[0]->{IBASE} <= $max ) {
            my $nm = $cidrs[0]->{IBASE} + $cidrs[0]->size;
            $max = $nm if $nm > $max;
            push( @r, shift(@cidrs) );
        }
        push( @result, [@r] );
    }
    return @result;
}

sub cidrs2cidrs {
    my (@cidrs) = sort_network_blocks(@_);
    my @result;

    my $proto;
    if ( scalar(@cidrs) ) {
        $proto = $cidrs[0]->{PROTOCOL};
        if ( grep { $proto ne $_->{PROTOCOL} } @cidrs ) {
            confess("Cannot call cidrs2cidrs with mixed protocol arguments");
        }
    }

    while (@cidrs) {
        my (@r) = shift(@cidrs);

        my $max = $r[0]->{IBASE} + $r[0]->size;
        while ( $cidrs[0] && $cidrs[0]->{IBASE} <= $max ) {
            my $nm = $cidrs[0]->{IBASE} + $cidrs[0]->size;
            $max = $nm if $nm > $max;
            push( @r, shift(@cidrs) );
        }
        my $start = $r[0]->{IBASE};
        my $end   = $max - 1;
        push( @result, irange2cidrlist( $start, $end, $proto ) );
    }
    return @result;
}

sub cidrs2inverse {
    my $outer = shift;
    $outer = __PACKAGE__->new2($outer) || croak($error) unless ref($outer);

    # cidrs2cidrs validates that everything is in the same address
    # family
    my (@cidrs) = cidrs2cidrs(@_);
    my $proto;
    if ( scalar(@cidrs) ) {
        $proto = $cidrs[0]->{PROTOCOL};
    }

    my $first = $outer->{IBASE};
    my $last  = $first + $outer->size() - 1;
    shift(@cidrs) while $cidrs[0] && $cidrs[0]->{IBASE} + $cidrs[0]->size < $first;
    my @r;
    while ( @cidrs && $first <= $last ) {

        if ( $first < $cidrs[0]->{IBASE} ) {
            if ( $last <= $cidrs[0]->{IBASE} - 1 ) {
                return ( @r, irange2cidrlist( $first, $last, $proto ) );
            }
            push( @r, irange2cidrlist( $first, $cidrs[0]->{IBASE} - 1, $proto ) );
        }
        last if $cidrs[0]->{IBASE} > $last;
        $first = $cidrs[0]->{IBASE} + $cidrs[0]->size;
        shift(@cidrs);
    }
    if ( $first <= $last ) {
        push( @r, irange2cidrlist( $first, $last, $proto ) );
    }
    return @r;
}

sub by_net_netmask_block {
    return $a->{'IBASE'} <=> $b->{'IBASE'}
      || $a->{'BITS'} <=> $b->{'BITS'};
}

sub sameblock {
    return !cmpblocks(@_);
}

sub cmpblocks {
    my $this  = shift;
    my $class = ref $this;
    my $other = ( ref $_[0] ) ? shift : $class->new(@_);
    return cmp_net_netmask_block( $this, $other );
}

sub contains {
    my $this  = shift;
    my $class = ref $this;
    my $other = ( ref $_[0] ) ? shift : $class->new(@_);
    return 0 if $this->{IBASE} > $other->{IBASE};
    return 0 if $this->{BITS} > $other->{BITS};
    return 0 if $other->{IBASE} > $this->{IBASE} + $this->size - 1;
    return 1;
}

sub cmp_net_netmask_block {
    if ( ( $_[0]->{PROTOCOL} eq 'IPv4' ) && ( $_[1]->{PROTOCOL} eq 'IPv4' ) ) {
        # IPv4
        return ( $_[0]->{IBASE} <=> $_[1]->{IBASE} || $_[0]->{BITS} <=> $_[1]->{BITS} );
    } elsif ( ( $_[0]->{PROTOCOL} eq 'IPv6' ) && ( $_[1]->{PROTOCOL} eq 'IPv6' ) ) {
        # IPv6
        return ( $_[0]->{IBASE} <=> $_[1]->{IBASE} || $_[0]->{BITS} <=> $_[1]->{BITS} );
    } else {
        # IPv4 to IPv6, order by protocol
        return ( $_[0]->{PROTOCOL} cmp $_[1]->{PROTOCOL} );
    }
}

sub sort_network_blocks {
    return map { $_->[0] }
      sort { $a->[3] cmp $b->[3] || $a->[1] <=> $b->[1] || $a->[2] <=> $b->[2] }
      map { [ $_, $_->{IBASE}, $_->{BITS}, $_->{PROTOCOL} ] } @_;
}

sub sort_by_ip_address {
    return map { $_->[0] }
      sort     { $a->[1] cmp $b->[1] }
      map { [ $_, pack( "C4", split( /\./, $_ ) ) ] } @_;

}

sub split    ## no critic: (Subroutines::ProhibitBuiltinHomonyms)
{
    my ( $self, $parts ) = @_;

    my $num_ips = $self->size;

    confess "Parts must be defined and greater than 0."
      unless defined($parts) && $parts > 0;

    confess "Netmask only contains $num_ips IPs. Cannot split into $parts."
      unless $num_ips >= $parts;

    my $log2 = _log2($parts);

    confess "Parts count must be a number of base 2. Got: $parts"
      unless ( 2**$log2 ) == $parts;

    my $new_mask = $self->bits + $log2;

    return map { PGDSAT::Netmask->new( $_ . "/" . $new_mask ) }
      map { $self->nth( ( $num_ips / $parts ) * $_ ) } ( 0 .. ( $parts - 1 ) );
}

# Implement log2 sub routine directly, to avoid precision problems with floor()
# problems with perls built with uselongdouble defined.
# Credit: xenu, on IRC
sub _log2 {
    my $n = shift;

    my $ret = 0;
    $ret++ while ( $n >>= 1 );

    return $ret;
}

BEGIN {
    for ( my $i = 0; $i <= 32; $i++ ) {
        $imask[$i]                                    = imask($i);
        $imask2bits{ $imask[$i] }                     = $i;
        $quadmask2bits{ int2quad( $imask[$i] ) }      = $i;
        $quadhostmask2bits{ int2quad( ~$imask[$i] ) } = $i;
        $size2bits{ 2**( 32 - $i ) }                  = $i;
    }

    for ( my $i = 0; $i <= 128; $i++ ) {
        $i6mask[$i] = i6mask($i);
    }
}
1;
