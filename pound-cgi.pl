#!/usr/bin/perl

#use FCGI;
#use CGI;
use CGI::Carp qw(fatalsToBrowser);
#use CGI::Pretty qw(:html3 :standard);
use IO::Socket::UNIX;
use Pound;
use POSIX;
use strict;

# Set these before running to do fastcgi
#BEGIN {
#  $ENV{FCGI_SOCKET_PATH} = ":8888";
#  $ENV{FCGI_LISTEN_QUEUE} = "5";
#}

# include after we set our listener sockets
use CGI::Fast qw(:html3 :standard);

my $path = $ENV{POUND_SOCKET_PATH}||"poundcontrol.sock";

while (my $q = CGI::Fast->new) {
  do_request($q);
}
exit;

sub do_request() {
	my $q = shift || CGI->new;

	print $q->header("text/html");
	print $q->start_html({-style=>{-type=>'text/css', -verbatim=> stylesheet()}, -title =>'Pound Status'});

	my $listurl = $q->url(-full=>1)."?action=list";
	my $refresh_s = "";
	if ($q->param("refresh")) {
		$refresh_s = "&refresh=".$q->param("refresh");
		print $q->script({-type=>"text/javascript"}, "window.setTimeout('window.location.href=\"".$listurl.$refresh_s."\"', ".($q->param('refresh')*1000).");");
		print "Auto-refreshing every ".$q->param('refresh')." seconds",$q->a({-style=>"margin-left:15px;", -href=>$listurl}, "Stop Auto-Refreshing"),$q->br();
	} else {
		print "Set auto-refresh (seconds)  ";
		foreach my $i (5,15,30,60,90,180,300) {
			print $q->a({-href=>$listurl."&refresh=$i", -style=>"margin-left:5px;"}, "$i");
		}
		print $q->br();
	}
	print "Page generated ".strftime("%Y%b%d %H:%M:%S", localtime),$q->a({-style=>"margin-left: 15px;", -href=>$listurl.$refresh_s}, "Refresh Now");
	do_action($q);
	my $sock = new IO::Socket::UNIX(Type => SOCK_STREAM, Peer=>$path) or die "Could not connect to $path: $@ $!";

	Pound::sendListCommand(*$sock);
	my $lstn = new Pound::LISTENER;
	my $svc = new Pound::SERVICE;
	my $be = new Pound::BACKEND;
	my $sess = new Pound::SESS;

	my $n_lstn=0;
	for (my $n_lstn=0; ; $n_lstn++) {
		$lstn->loadFromSock(*$sock) or die "Listener: partial read";
		if (!$lstn->isValid()) { die "Listener magic value is invalid"; }
		last if ($lstn->isLast());

		my $link = a({-href=>$q->url(-absolute=>1)."?listener=$n_lstn$refresh_s&action=".($lstn->{disabled}?"en_lstn":"dis_lstn")}, $lstn->{disabled}?"Enable":"Disable");
		print $q->div({-class=>"header"}, 
			sprintf( "%3d. Listener(%s) %s:%hd  %s", $n_lstn, $lstn->getProtocol(), $lstn->getAddress(), $lstn->getPort(), $lstn->{disabled}? "*D":"a"),
			$link
		);
		print $q->start_div({-style=>"background: #669966; border: 2px solid black; padding: 5px;"});
		for (my $n_svc = 0; ; $n_svc++) {
			$svc->loadFromSock(*$sock) or die "Service: partial read";
			if (!$svc->isValid()) { die "Service magic value is invalid"; }
			last if ($svc->isLast());

			my $link = $q->a({-style=>"margin-left:5px;",-href=>$q->url(-absolute=>1)."?listener=$n_lstn&service=$n_svc$refresh_s&action=".($svc->{disabled}?"en_svc":"dis_svc")}, $svc->{disabled}?"Enable":"Disable");
			print $q->start_div({-style=>"padding: 15px; background: #bbffbb; border: 2px solid black; margin-bottom: 2px;" });
			print $q->div({-style=>"font-size:24px; margin-left: -5px; color:black;"}, sprintf( "%3d. Service %s  %s", $n_svc, $svc->{name}, $svc->{disabled}? "*D":"a"), $link);
			print $q->start_table();
			print $q->Tr(th(["Backend","Protocol","IP","Status", "Requests","AvgTime"]));
			for (my $n_be=0; ;$n_be++) {
				$be->loadFromSock(*$sock) or die "Backend: partial read";
				if (!$be->isValid()) { die "Backend has invalid magic"; }
				last if ($be->isLast());

				my $link = $q->a({-style=>"margin-left:5px;",-href=>$q->url(-absolute=>1)."?listener=$n_lstn&service=$n_svc&backend=$n_be$refresh_s&action=".($be->{disabled}?"en_be":"dis_be")}, $be->{disabled}?"Enable":"Disable");
				
				if($be->{domain} == PF_INET) {
					print $q->Tr(td([$n_be.$link, "PF_INET", $be->getAddress().":".$be->getPort(),
						($be->{alive}?"alive":"Dead").",".($be->{disabled}? "*Disabled": "Active"), 
						$be->{n_requests}, sprintf("%4.4fms",$be->{t_average}/1000)]));
				} else {
					print $q->Tr(td([$n_be.$link, "PF_UNIX", $be->getAddress().":".$be->getPort(),
						($be->{alive}?"alive":"Dead").",".($be->{disabled}? "*Disabled": "Active"), 
						$be->{n_requests}, sprintf("%4.4fms",$be->{t_average}/1000)]));
				}
			}
			print $q->end_table();
			print $q->start_table();
			print $q->Tr(th(["ID","SessionKey","BE", "ClientIP", "User", "SessionTime", "Life", "FirstAcc", "LastAcc", "Requests", "URL"]));
			for (my $n_sess = 0; ; $n_sess++) {
				$sess->loadFromSock(*$sock);
				if (!$sess->isValid()) { die "Session: invalid magic value"; }
				last if ($sess->isLast());

				print $q->Tr(td([$n_sess, $sess->{key}, $sess->{to_host}, $sess->getAddress(), $sess->{last_user}, 
					($svc->{sess_ttl} - $sess->getIdleTime())."/".$svc->{sess_ttl}, $sess->{last_acc} - $sess->{first_acc},
					strftime("%H:%M:%S", localtime($sess->{first_acc})), strftime("%H:%M:%S", localtime($sess->{last_acc})), 
					$sess->{n_requests}, $sess->{last_url}
				]));
			}
			print $q->end_table();
			print $q->end_div();
		}
		print $q->end_div();
	}

	$n_lstn = -1;
	print $q->div({-class=>"header"}, " -1. Global Services");
	print $q->start_div({-style=>"background: #669966; border: 2px solid black; padding: 5px;"});
	for (my $n_svc = 0; ; $n_svc++) {
		$svc->loadFromSock(*$sock) or die "Service: partial read";
		if (!$svc->isValid()) { die "Service magic value is invalid"; }
		last if ($svc->isLast());

		my $link = $q->a({-style=>"margin-left:5px;",-href=>$q->url(-absolute=>1)."?listener=$n_lstn&service=$n_svc$refresh_s&action=".($svc->{disabled}?"en_svc":"dis_svc")}, $svc->{disabled}?"Enable":"Disable");
		print $q->start_div({-style=>"padding: 15px; background: #bbffbb; border: 2px solid black; margin-bottom: 2px;" });
		print $q->div({-style=>"font-size:24px; margin-left: -5px; color:black;"}, sprintf( "%3d. Service %s  %s", $n_svc, $svc->{name}, $svc->{disabled}? "*D":"a"), $link);
		print $q->start_table();
		print $q->Tr(th(["Backend","Protocol","IP","Status", "Requests","AvgTime"]));
		for (my $n_be=0; ;$n_be++) {
			$be->loadFromSock(*$sock) or die "Backend: partial read";
			if (!$be->isValid()) { die "Backend has invalid magic"; }
			last if ($be->isLast());

			my $link = $q->a({-style=>"margin-left:5px;",-href=>$q->url(-absolute=>1)."?listener=$n_lstn&service=$n_svc&backend=$n_be$refresh_s&action=".($be->{disabled}?"en_be":"dis_be")}, $be->{disabled}?"Enable":"Disable");
			
			if($be->{domain} == PF_INET) {
				print $q->Tr(td([$n_be.$link, "PF_INET", $be->getAddress().":".$be->getPort(),
					($be->{alive}?"alive":"Dead").",".($be->{disabled}? "*Disabled": "Active"), 
					$be->{n_requests}, sprintf("%4.4fms",$be->{t_average}/1000)]));
			} else {
				print $q->Tr(td([$n_be.$link, "PF_UNIX", $be->getAddress().":".$be->getPort(),
					($be->{alive}?"alive":"Dead").",".($be->{disabled}? "*Disabled": "Active"), 
					$be->{n_requests}, sprintf("%4.4fms",$be->{t_average}/1000)]));
			}
		}
		print $q->end_table();
		print $q->start_table();
		print $q->Tr(th(["ID","SessionKey","BE", "ClientIP", "User", "SessionTime", "Life", "FirstAcc", "LastAcc", "Requests", "URL"]));
		for (my $n_sess = 0; ; $n_sess++) {
			$sess->loadFromSock(*$sock);
			if (!$sess->isValid()) { die "Session: invalid magic value"; }
			last if ($sess->isLast());

			print $q->Tr(td([$n_sess, $sess->{key}, $sess->{to_host}, $sess->getAddress(), $sess->{last_user}, 
				($svc->{sess_ttl} - $sess->getIdleTime())."/".$svc->{sess_ttl}, $sess->{last_acc} - $sess->{first_acc},
				strftime("%H:%M:%S", localtime($sess->{first_acc})), strftime("%H:%M:%S", localtime($sess->{last_acc})), 
				$sess->{n_requests}, $sess->{last_url}
			]));
		}
		print $q->end_table();
		print $q->end_div();
	}
	print $q->end_div();

	$sock->close();
	print $q->end_html();
}

sub stylesheet() {
	my $css = "
	body { border: 0px; padding: 0px; margin: 0px; background: #BFBFBF; color: black; font-family: arial, helvetica, sans-serif; font-size: .9em; text-decoration: none; font-weight: normal; font-style: normal; } 
	.formbg { background: #BFBFBF; color: black; }
	.headbg { background: #EEEEEE; color: black; }
	div.header { background: #EEEEEE; color: black; clear: both; left: 0; right: 0; width: auto; border: black solid 2px; font-size: 1em; font-weight: bold; padding-left: 10px; }
	table, tr, td, th { border: 1px solid black; border-collapse: collapse; } 
	tr { background: white; color:black; }
	td { padding: 5px; margin: 0px; }
	th { background: #000099; font-weight: bold; color: white; border: 1px solid black; padding-left: 5px; padding-right: 5px; margin: 0px; }
";
	return $css;
	}

sub do_action($) {
	my $q = shift;
	my $action = $q->param("action") || "list";

	return if ($action eq 'list');

	my $sock = new IO::Socket::UNIX(Type => SOCK_STREAM, Peer=>$path) or die "Could not connect to $path: $@ $!";
	if ($action eq 'en_lstn' or $action eq 'dis_lstn') {
		my $listener = $q->param("listener");
		if ($listener eq "") { print $q->div({-class=>"message"}, "Listener missing"); return; }
		if ($action eq 'en_lstn') {
			print $q->div({-class=>"message"}, "Enabling listener ".$listener);
			Pound::enableListener($sock, $listener);
		} else {
			print $q->div({-class=>"message"}, "Disabling listener ".$listener);
			Pound::disableListener($sock, $listener);
		}
	} elsif ($action eq "en_svc" or $action eq 'dis_svc') {
		my $listener = $q->param("listener");
		if ($listener eq "") { print $q->div({-class=>"message"}, "Listener missing"); return; }
		my $service = $q->param("service");
		if ($service eq "") { print $q->div({-class=>"message"}, "Service missing"); return; }
		if ($action eq 'en_svc') {
			print $q->div({-class=>"message"}, "Enabling service ".join(":",$listener,$service));
			Pound::enableService($sock, $listener, $service);
		} else {
			print $q->div({-class=>"message"}, "Disabling service ".join(":",$listener,$service));
			Pound::disableService($sock, $listener, $service);
		}
	} elsif ($action eq "en_be" or $action eq 'dis_be') {
		my $listener = $q->param("listener");
		if ($listener eq "") { print $q->div({-class=>"message"}, "Listener missing"); return; }
		my $service = $q->param("service");
		if ($service eq "") { print $q->div({-class=>"message"}, "Service missing"); return; }
		my $backend = $q->param("backend");
		if ($backend eq "") { print $q->div({-class=>"message"}, "Backend missing"); return; }
		if ($action eq 'en_be') {
			print $q->div({-class=>"message"}, "Enabling backend ".join(":",$listener,$service,$backend));
			Pound::enableBackend($sock, $listener, $service, $backend);
		} else {
			print $q->div({-class=>"message"}, "Disabling backend ".join(":",$listener,$service,$backend));
			Pound::disableBackend($sock, $listener, $service, $backend);
		}
	}

	$sock->close();

}
