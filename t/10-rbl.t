#!/usr/bin/perl

use Test::More;

@prefixes = qw(
	       bl.spamcop.net
	       relays.ordb.org
	       list.dsbl.org
	       multihop.dsbl.org
	       unconfirmed.dsbl.org
	       );	

@rhsbls = qw(
	     postmaster.rfc-ignorant.org
	     dsn.rfc-ignorant.org
	     abuse.rfc-ignorant.org
	     bogusmx.rfc-ignorant.org
	     );	

SKIP: 
{

    if ($ENV{SKIP_RBL_TESTS})
    {
	plan tests => 2;
	diag ('');
	diag ('');
	diag('You have set $SKIP_RBL_TESTS to true, thus skipping');
	diag('testing that involves DNS queries.');
	diag ('');
	use_ok('Mail::RBL');
	skip 'User requested skipping of query tests', 1;
	diag ('');
    }

    plan  tests => @prefixes*3 + (grep {/spamcop/} @prefixes)*5 + 
	@rhsbls*8 + 1;

    diag('');
    diag('');
    diag('The following tests perform queries to some known RBLs.');
    diag('Failures do not necesarily mean that the code is broken');
    diag('If failures are seen, please insure that the relevant RBL');
    diag('Can be queried from this machine.');
    diag('');
    diag('You can skip this test by setting the environment variable');
    diag('$SKIP_RBL_TESTS to true');
    diag('');

    use_ok('Mail::RBL');

    for (@prefixes)
    {
	my $rbl = new Mail::RBL $_;
	isa_ok($rbl, 'Mail::RBL');

	ok(!$rbl->check('127.0.0.1'), 
	   "Check localhost (unblocked) against $_");
	ok($rbl->check('127.0.0.2'), 
	   "Check 127.0.0.2 (blocked) against $_");
    }

    for (grep { $_ =~ /spamcop/ } @prefixes)
    {
	my $rbl = new Mail::RBL $_;
	isa_ok($rbl, 'Mail::RBL');

	my @r = $rbl->check('127.0.0.1');
	ok(!@r, "Check localhost (unblocked) in array context against $_");
	@r = $rbl->check('127.0.0.2');
	ok(@r == 2, "Check 127.0.0.2 (blocked) in array context against $_");
	ok($r[0], "True block result");
	ok($r[1], "Non-empty message returned");
    }

    for (@rhsbls)
    {
	my $rbl = new Mail::RBL $_;
	isa_ok($rbl, 'Mail::RBL');

	ok(!$rbl->check_rhsbl('127.0.0.1'), 
	   "Check unlisted localhost rhsbl $_");
	ok($rbl->check_rhsbl('example.tld'),
	   "Check example.tld rhsbl $_");

	my @r = $rbl->check_rhsbl('127.0.0.1');
	ok(!@r, "Unlisted localhost in array context is false: $_");
	@r = $rbl->check_rhsbl('example.tld');
	ok(@r, "Listed domain in array context is true: $_");
	ok(@r == 2, "Listed domain in array context has proper count: $_");
	ok($r[0], "Listed domain in array context has true value: $_");
	ok($r[1], "Listed domain in array context has non-empty message: $_");
    }
}
