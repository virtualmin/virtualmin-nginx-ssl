#  Common functions for NginX SSL mode plugin

use strict;
use warnings;
use Socket;

BEGIN { push(@INC, ".."); };
eval "use WebminCore;";
&init_config();
our (%config, %text, %in, $module_root_directory);

# find_listen_clash(ip, port)
# Find a server listening on the given IP and port
sub find_listen_clash
{
my ($ip, $port) = @_;
my $conf = &virtualmin_nginx::get_config();
my $http = &virtualmin_nginx::find("http", $conf);
foreach my $s (&virtualmin_nginx::find("server", $http)) {
	foreach my $l (&virtualmin_nginx::find_value("listen", $s)) {
		my ($lip, $lport) = &virtualmin_nginx::split_ip_port($l);
		if ($lip && $lip eq $ip && $lport == $port) {
			return $s;
			}
		}
	}
return undef;
}

1;

