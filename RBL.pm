package Mail::RBL;

require 5.005_62;
use strict;
use warnings;
use Carp;

our $VERSION = '1.00';

sub new {
    my $type = shift;
    my $class = ref($type) || $type || "Hash::Filler";
    my $suffix = shift;
    
    my $self = {
	'suffix' => length $suffix ? $suffix : 
	    'maps.vix.com',
    };

    bless $self, $class;
}

sub _inverted_addresses {
    my $host = shift;
    my @addresses;
    my @ret;
    
    if ($host =~ /^\d+\.\d+\.\d+\.\d+$/) {
	push @ret, join('.', reverse split(/\./, $host));
    }
    else {
	@addresses = (gethostbyname($host))[4];
    }
    
    foreach my $addr (@addresses) {
	push @ret, join('.', reverse unpack('C4', $addr));
    }
    
    return @ret;
}

sub _do_check {
    my $self = shift;
    my $host = shift;

    ((gethostbyname($host . '.' . $self->{'suffix'}))[4])[0];
}

sub check {
    my $self = shift;
    my $host = shift;

    croak "Must call ->check() with a host to check"
	unless length $host;

    foreach my $addr (_inverted_addresses $host) {
	if ($self->_do_check($addr)) { return 1; }
    }

    return 0;
}

1;
__END__

=head1 NAME

Mail::RBL - Perl extension to access RBL-style host verification services

=head1 SYNOPSIS

  use Mail::RBL;

  my $list = new Mail::RBL('list.org');

  if ($list->check($host)) {
      print "$host is in the list";
  }

=head1 DESCRIPTION

This module eases the task of checking if a given host is in the
list. The methods available are described below:

=over

=item C<-E<gt>new(suffix)>

Creates a list handle. The C<suffix> parameter is mandatory and
specifies which suffix to append to the queries.

=item C<-E<gt>check($host)>

C<$host> can be either a hostname or an IP address. In the case of an
IP Address, any trailing netmask (anything after a '/' character) will
be ignored. In the case of a hostname, all the IP addresses will be
looked up and checked against the list. If B<any> of the addresses is
in the list, the host will be considered in the list as a whole.

=back

=head1 AUTHOR

Luis E. Munoz <lem@cantv.net>

=head1 SEE ALSO

perl(1).

=cut
