#  Common functions for NginX SSL mode plugin

use strict;
use warnings;
use Socket;

BEGIN { push(@INC, ".."); };
eval "use WebminCore;";
&init_config();
our (%config, %text, %in, $module_root_directory);

&foreign_require("nginx");

# find_listen_clash(ip, port)
# Find a server listening on the given IP and port
sub find_listen_clash
{
my ($ip, $port) = @_;
my $conf = &nginx::get_config();
my $http = &nginx::find("http", $conf);
foreach my $s (&nginx::find("server", $http)) {
	foreach my $l (&nginx::find_value("listen", $s)) {
		my ($lip, $lport) = &nginx::split_ip_port($l);
		if ($lip && $lip eq $ip && $lport == $port) {
			return $s;
			}
		}
	}
return undef;
}

1;

