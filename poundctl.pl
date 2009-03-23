#!/usr/bin/perl

use IO::Socket::UNIX;
use Pound;
use strict;

my $path = $ARGV[0] || "poundcontrol.sock";
my $sock = new IO::Socket::UNIX(Type => SOCK_STREAM, Peer=>$path) or die "Could not connect to $path: $@ $!";

Pound::sendListCommand(*$sock);
my $lstn = new Pound::LISTENER;
my $svc = new Pound::SERVICE;
my $be = new Pound::BACKEND;
my $sess = new Pound::SESS;

my $n_lstn=0;
while (1) {
	$lstn->loadFromSock(*$sock) or die "Listener: partial read";
	if (!$lstn->isValid()) { die "Listener magic value is invalid"; }
	last if ($lstn->isLast());

	printf("%3d. %s Listener %s:%hd %s\n", $n_lstn++, $lstn->getProtocol(), $lstn->getAddress(), $lstn->getPort(), $lstn->{disabled}? "*D":"a");
	my $n_svc = 0;
	while (1) {
		$svc->loadFromSock(*$sock) or die "Service: partial read";
		if (!$svc->isValid()) { die "Service magic value is invalid"; }
		last if ($svc->isLast());

		printf("  %3d. Service %s %s\n", $n_svc++, $svc->{disabled}? "*D": "a", $svc->{name});
		my $n_be = 0;
		while (1) {
			$be->loadFromSock(*$sock) or die "Backend: Partial read";
			if (!$be->isValid()) { die "Backend has invalid magic"; }
			last if ($be->isLast());

			if($be->{domain} == PF_INET) {
				printf("    %3d. Backend PF_INET %s:%hd %s %d %f %f\n", $n_be++, $be->getAddress(), $be->getPort(),
					$be->{disabled}? "*D": "a", $be->{n_requests}, $be->{t_requests}, $be->{t_average});
			} else {
				printf("    %3d. Backend PF_UNIX %s %s %d %f %f\n", $n_be++, $be->getAddress(),
					$be->{disabled}? "*D": "", $be->{n_requests}, $be->{t_requests}, $be->{t_average});
			}
		}
		my $n_sess = 0;
		while (1) {
			sess->loadFromSock(*$sock) or die "Session: Partial read";
			if (!$sess->isValid()) { die "Session magic value is invalid"; }
			last if ($sess->isLast());

			printf("    %3d. Session %s -> %d   %s  %s %s  %d %d %d %d/%d\n", $n_sess++, $sess->{key}, $sess->{to_host}, $sess->{last_user}, $sess->{last_url},
				$sess->getAddress(), $sess->{n_requests}, $sess->{first_acc}, $sess->{last_acc}, $svc->{sess_ttl} - $sess->getIdleTime(), $svc->{sess_ttl}
			);
		}
	}
}

$n_lstn = -1;
printf(" -1. Global services\n");
my $n_svc = 0;
while (1) {
	$svc->loadFromSock(*$sock) or die "Service: partial read";
	if (!$svc->isValid()) { die "Service magic value is invalid"; }
	last if ($svc->isLast());

	printf("  %3d. Service %s %s\n", $n_svc++, $svc->{disabled}? "*D": "a", $svc->{name});
	my $n_be = 0;
	while (1) {
		$be->loadFromSock(*$sock) or die "Backend: partial read";
		if (!$be->isValid()) { die "Backend has invalid magic"; }
		last if ($be->isLast());

		if($be->{domain} == PF_INET) {
			printf("    %3d. Backend PF_INET %s:%hd %s %d %f %f\n", $n_be++, $be->getAddress(), $be->getPort(),
				$be->{disabled}? "*D": "a", $be->{n_requests}, $be->{t_requests}, $be->{t_average});
		} else {
			printf("    %3d. Backend PF_UNIX %s %s %d %f %f\n", $n_be++, $be->getAddress(),
				$be->{disabled}? "*D": "", $be->{n_requests}, $be->{t_requests}, $be->{t_average});
		}
	}
	my $n_sess = 0;
	while (1) {
		$sess->loadFromSock(*$sock);
		if (!$sess->isValid()) { die "Session: invalid magic value"; }
		last if ($sess->isLast());

		printf("    %3d. Session %s -> %d   %s  %s %s  %d %d %d %d/%d\n", $n_sess++, $sess->{key}, $sess->{to_host}, $sess->{last_user}, $sess->{last_url},
			$sess->getAddress(), $sess->{n_requests}, $sess->{first_acc}, $sess->{last_acc}, $svc->{sess_ttl} - $sess->getIdleTime(), $svc->{sess_ttl}
		);
	}
}

$sock->close();
exit;
