
use strict;
use warnings;
use Time::Local;
require 'virtualmin-nginx-ssl-lib.pl';
our (%text, %config, $module_name, %access);

# This hack is needed so that &module::text calls work .. sorry :-(
%text = ( &load_language("virtual-server"),
	  &load_language("virtualmin-nginx"),
	  %text );

sub feature_provides_ssl
{
return 1;	# Enables SSL
}

# feature_name()
# Returns a short name for this feature
sub feature_name
{
return $text{'feat_name'};
}

# feature_losing(&domain)
# Returns a description of what will be deleted when this feature is removed
sub feature_losing
{
return $text{'feat_losing'};
}

# feature_disname(&domain)
# Returns a description of what will be turned off when this feature is disabled
sub feature_disname
{
return $text{'feat_disname'};
}

# feature_label(in-edit-form)
# Returns the name of this feature, as displayed on the domain creation and
# editing form
sub feature_label
{
my ($edit) = @_;
return $edit ? $text{'feat_label2'} : $text{'feat_label'};
}

sub feature_hlink
{
return "label";
}

# feature_check([&new-features])
# Check for Nginx plugin?
sub feature_check
{
my ($features) = @_;
no warnings "once";
$features ||= [ @virtual_server::plugins ];
use warnings "once";
if (&indexof("virtualmin-nginx", @$features) < 0) {
	return $text{'feat_eplugindep'};
	}
return undef;
}

# feature_depends(&domain)
# Nginx needs a Unix login for the domain
sub feature_depends
{
my ($d) = @_;
return $text{'feat_nginx'} if (!$d->{'virtualmin-nginx'});
return undef;
}

# feature_suitable([&parentdom], [&aliasdom], [&subdom])
# Returns 1 if some feature can be used with the specified alias and
# parent domains
sub feature_suitable
{
my ($parentdom, $aliasdom, $subdom) = @_;
return $subdom || $aliasdom ? 0 : 1;
}

# feature_import(domain-name, user-name, db-name)
# Returns 1 if this feature is already enabled for some domain being imported,
# or 0 if not
sub feature_import
{
my ($dname, $user, $db) = @_;
my $server = &virtualmin_nginx::find_domain_server({ 'dom' => $dname });
return 0 if (!$server);
foreach my $l (&nginx::find("listen", $server)) {
	return 1 if ($l->{'words'}->[0] =~ /:443$/);
	}
return 0;
}

# feature_warnings(&domain, [&old-domain])
# Check for a certificate clash, and return a warning
sub feature_warnings
{
my ($d, $oldd) = @_;
my $tmpl = &virtual_server::get_template($d->{'template'});
my $defport = $tmpl->{'web_sslport'} || 443;
my $port = $d->{'web_sslport'} || $defport;

# Check if Nginx supports SNI, which makes clashing certs not so bad
my $sni = &virtualmin_nginx::feature_supports_sni();

no warnings "once";
if ($d->{'virt'}) {
        # Has a private IP
        return undef;
	}
elsif ($port != $defport) {
        # Has a private port
        return undef;
	}
elsif ($virtual_server::config{'sni_support'}) {
	# Assume web server and clients can handle multiple SSL certs on
	# the same IP address
	return undef;
	}
else {
	# Neither .. but we can still do SSL, if there are no other domains
	# with SSL on the same IP
	if ($d->{'ip'}) {
		my ($sslclash) = grep { $_->{'ip'} eq $d->{'ip'} &&
					&virtual_server::domain_has_ssl($_) &&
					$_->{'id'} ne $d->{'id'} }
				      &virtual_server::list_domains();
		if ($sslclash &&
		    (!$oldd || !&virtual_server::domain_has_ssl($oldd))) {
			# Clash .. but is the cert OK?
			if (!&virtual_server::check_domain_certificate(
					$d->{'dom'}, $sslclash)) {
				my @certdoms =
				    &virtual_server::list_domain_certificate(
					$sslclash);
				return &virtual_server::text(
				    $sni ? 'setup_edepssl5sni'
					 : 'setup_edepssl5', $d->{'ip'},
				    join(", ", map { "<tt>$_</tt>" } @certdoms),
				    $sslclash->{'dom'});
				}
			else {
				return undef;
				}
			}
		}
	return undef;
	}
}
use warnings "once";

# feature_setup(&domain)
# Adds SSL to an Nginx website
sub feature_setup
{
my ($d) = @_;
return 1 if ($d->{'alias'});
my $tmpl = &virtual_server::get_template($d->{'template'});
$d->{'web_sslport'} = $d->{'web_sslport'} || $tmpl->{'web_sslport'} || 443;
$d->{'web_ssl_samechain'} = 1;

# Find out if this domain will share a cert with another
&virtual_server::find_matching_certificate($d);

# Create a self-signed cert and key, if needed
my $generated = &virtual_server::generate_default_certificate($d);
if (!$generated && !-r $d->{'ssl_cert'}) {
	return 0;
	}

# Add to the non-SSL server block
&$virtual_server::first_print($text{'feat_setup'});
&nginx::lock_all_config_files();
my $server = &virtualmin_nginx::find_domain_server($d);
if (!$server) {
	&nginx::unlock_all_config_files();
        &$virtual_server::second_print(
                &virtualmin_nginx::text('feat_efind', $d->{'dom'}));
        return 0;
	}

# Double-check cert and key
my $certdata = &read_file_contents($d->{'ssl_cert'});
my $keydata = &read_file_contents($d->{'ssl_key'});
my $err = &virtual_server::validate_cert_format($certdata, 'cert');
if ($err) {
        &$virtual_server::second_print(
		&virtual_server::text('setup_esslcert', $err));
        return 0;
        }
$err = &virtual_server::validate_cert_format($keydata, 'key');
if ($err) {
        &$virtual_server::second_print(
		&virtual_server::text('setup_esslkey', $err));
        return 0;
        }
if ($d->{'ssl_chain'}) {
        my $cadata = &read_file_contents($d->{'ssl_chain'});
        $err = &virtual_server::validate_cert_format($cadata, 'ca');
        if ($err) {
                &$virtual_server::second_print(
			&virtual_server::text('setup_esslca', $err));
                return 0;
                }
        }
$err = &virtual_server::check_cert_key_match($certdata, $keydata);
if ($err) {
        &$virtual_server::second_print(
		&virtual_server::text('setup_esslmatch', $err));
        return 0;
        }

# Add listen line
my @listen = &nginx::find("listen", $server);
my ($old_ip4, $old_ip6);
if ($d->{'ip'}) {
	($old_ip4) = grep { $_->{'words'}->[0] eq
			    $d->{'ip'}.":".$d->{'web_sslport'} } @listen;
	}
if ($d->{'ip6'}) {
	($old_ip6) = grep { $_->{'words'}->[0] eq
		       "[".$d->{'ip6'}."]:".$d->{'web_sslport'} } @listen;
	}
my @sslopts = ( 'ssl' );
push(@sslopts, "http2") if ($virtualmin_nginx::config{'http2'} ||
			    $tmpl->{'web_http2'});
if ($virtualmin_nginx::config{'listen_mode'} eq '0') {
	# Listen on all IPs
	if (!$old_ip4 && !$old_ip6) {
		push(@listen, { 'name' => 'listen',
				'words' => [ $d->{'web_sslport'},
					     @sslopts ] });
		push(@listen, { 'name' => 'listen',
				'words' => [ '[::]:' . $d->{'web_sslport'},
					     @sslopts ] });
		}
	}
else {
	# Add on specific IPs
	if (!$old_ip4 && $d->{'ip'}) {
		push(@listen, { 'name' => 'listen',
				'words' => [ $d->{'ip'}.":".$d->{'web_sslport'},
					     @sslopts ] });
		}
	if (!$old_ip6 && $d->{'ip6'}) {
		if ($d->{'virt6'}) {
			push(@sslopts, &nginx::get_default_server_param());
			}
		push(@listen, { 'name' => 'listen',
				'words' => [ "[".$d->{'ip6'}."]:".$d->{'web_sslport'},
					     @sslopts ]});
		}
	}
&nginx::save_directive($server, "listen", \@listen);

# Enable SSL
&nginx::save_directive($server, "ssl_certificate",
				  [ $d->{'ssl_cert'} ]);
&nginx::save_directive($server, "ssl_certificate_key",
				  [ $d->{'ssl_key'} ]);
if ($d->{'ssl_chain'}) {
	# Add chained cert to main cert file
	&virtualmin_nginx::feature_save_web_ssl_file(
		$d, 'ca', $d->{'ssl_chain'});
	}

&nginx::flush_config_file_lines();
&nginx::unlock_all_config_files();
&virtual_server::register_post_action(\&virtualmin_nginx::print_apply_nginx);

# Add cert in Webmin, Dovecot, etc..
&virtual_server::enable_domain_service_ssl_certs($d);

# Update DANE DNS records
&virtual_server::sync_domain_tlsa_records($d);

# Redirect HTTP to HTTPS
if ($tmpl->{'web_sslredirect'} || $d->{'auto_redirect'}) {
        &virtual_server::create_redirect($d, &virtual_server::get_redirect_to_ssl($d));
        }

# Try to request a Let's Encrypt cert when enabling SSL post-creation for
# the first time
if (!$d->{'creating'} && $generated && $d->{'auto_letsencrypt'} &&
    !$d->{'disabled'}) {
	&virtual_server::create_initial_letsencrypt_cert($d);
	}

&$virtual_server::second_print($virtual_server::text{'setup_done'});
}

# feature_modify(&domain, &old-domain)
sub feature_modify
{
my ($d, $oldd) = @_;
return 1 if ($d->{'alias'});

&nginx::lock_all_config_files();
my $changed = 0;

# Update port, if changed
if ($d->{'web_sslport'} != $oldd->{'web_sslport'}) {
	&$virtual_server::first_print($text{'feat_modifyport'});
	my $server = &virtualmin_nginx::find_domain_server($d);
	if (!$server) {
		&$virtual_server::second_print(
			&virtualmin_nginx::text('feat_efind', $d->{'dom'}));
		return 0;
		}
	my @listen = &nginx::find("listen", $server);
	my @newlisten;
	foreach my $l (@listen) {
		my @w = @{$l->{'words'}};
		my $p = $w[0] =~ /:(\d+)$/ ? $1 : 80;
		if ($p == $oldd->{'web_sslport'}) {
			$w[0] =~ s/:\d+$//;
			$w[0] .= ":".$d->{'web_sslport'};
			}
		elsif ($w[0] eq $oldd->{'web_sslport'}) {
			$w[0] = $d->{'web_sslport'};
			}
		push(@newlisten, { 'words' => \@w });
		}
	&nginx::save_directive($server, "listen", \@newlisten);
	&$virtual_server::second_print(
		$virtual_server::text{'setup_done'});
	$changed++;
	}

# If IP has changed, maybe clear ssl_same field for cert sharing
&virtual_server::update_ssl_link_on_domain_change($d, $oldd);

# Fix SSL cert file locations, if home has changed
if ($d->{'home'} ne $oldd->{'home'}) {
        foreach my $k ('ssl_cert', 'ssl_key', 'ssl_chain') {
                $d->{$k} =~ s/\Q$oldd->{'home'}\E\//$d->{'home'}\//
                    if ($d->{$k});
                }
	}

# If domain name has changed, re-generate self-signed cert or re-request
# let's encrypt cert
&virtual_server::rerequest_cert_on_domain_change($d, $oldd);

# If anything has changed that would impact the per-domain SSL cert for
# another server like Postfix or Webmin, re-set it up as long as it is supported
# with the new settings
&virtual_server::update_ssl_certs_on_change($d, $oldd);

# Update DANE DNS records
&virtual_server::sync_domain_tlsa_records($d);

# Flush files and restart
&nginx::flush_config_file_lines();
&nginx::unlock_all_config_files();
if ($changed) {
	&virtual_server::register_post_action(
		\&virtualmin_nginx::print_apply_nginx);
	}
}

# feature_delete(&domain)
# Turn off SSL for the domain
sub feature_delete
{
my ($d) = @_;
return 1 if ($d->{'alias'});
&$virtual_server::first_print($text{'feat_delete'});
&nginx::lock_all_config_files();
my $server = &virtualmin_nginx::find_domain_server($d);
if (!$server) {
	&nginx::unlock_all_config_files();
        &$virtual_server::second_print(
                &virtualmin_nginx::text('feat_efind', $d->{'dom'}));
        return 0;
	}

# Turn off ssl
&nginx::save_directive($server, "ssl", [ ]);
&nginx::save_directive($server, "ssl_certificate", [ ]);
&nginx::save_directive($server, "ssl_certificate_key", [ ]);

# Remove SSL port listens
my @listen = &nginx::find("listen", $server);
my @newlisten;
foreach my $l (@listen) {
	my ($lip, $lport) = &nginx::split_ip_port(
		$l->{'words'}->[0]);
	if (&indexof("ssl", @{$l->{'words'}}) >= 0 ||
	    $lip && $lport &&
	    ($d->{'ip'} && $lip eq $d->{'ip'} || $d->{'ip6'} && $lip eq $d->{'ip6'}) &&
	    $lport == $d->{'web_sslport'}) {
		# Don't add to new list of listen directives
		}
	else {
		push(@newlisten, $l);
		}
	}
&nginx::save_directive($server, "listen", \@newlisten);

&nginx::flush_config_file_lines();
&nginx::unlock_all_config_files();
&virtual_server::register_post_action(\&virtualmin_nginx::print_apply_nginx);

# If any other domains were using this one's SSL cert or key, break the linkage
foreach my $od (&virtual_server::get_domain_by("ssl_same", $d->{'id'})) {
	&virtual_server::break_ssl_linkage($od, $d);
	&virtual_server::lock_domain($od);
	&virtual_server::save_domain($od);
	&virtual_server::unlock_domain($od);
	}

# Update DANE DNS records
&virtual_server::sync_domain_tlsa_records($d);

$d->{'web_ssl_samechain'} = 0;
&$virtual_server::second_print($virtual_server::text{'setup_done'});
}

# feature_validate(&domain)
# Checks that SSL related settings are correct
sub feature_validate
{
my ($d) = @_;

# Does server exist?
my $server = &virtualmin_nginx::find_domain_server($d);
return &virtualmin_nginx::text('feat_evalidate',
	"<tt>".&virtual_server::show_domain_name($d)."</tt>") if (!$server);

# Check for IPs and port
my @listen = &nginx::find_value("listen", $server);
if ($d->{'ip'}) {
	my $found = 0;
	foreach my $l (@listen) {
		$found++ if ($l eq $d->{'ip'} &&
			      $d->{'web_sslport'} == 80 ||
			     $l =~ /^\Q$d->{'ip'}\E:(\d+)$/ &&
			      $d->{'web_sslport'} == $1);
		$found++ if ($l eq $d->{'web_sslport'} &&
			     $virtualmin_nginx::config{'listen_mode'} eq '0');
		}
	$found || return &virtualmin_nginx::text('feat_evalidateip',
						 $d->{'ip'}, $d->{'web_sslport'});
	}
if ($d->{'virt6'}) {
	my $found6 = 0;
	foreach my $l (@listen) {
		$found6++ if ($l eq "[".$d->{'ip6'}."]" &&
			       $d->{'web_sslport'} == 80 ||
			      $l =~ /^\[\Q$d->{'ip6'}\E\]:(\d+)$/ &&
			       $d->{'web_sslport'} == $1);
		$found6++ if ($l eq $d->{'web_sslport'} &&
			      $virtualmin_nginx::config{'listen_mode'} eq '0');
		}
	$found6 || return &virtualmin_nginx::text('feat_evalidateip6',
					  $d->{'ip6'}, $d->{'web_sslport'});
	}

# Make sure cert file exists
my $cert = &nginx::find_value("ssl_certificate", $server);
if (!$cert) {
        return &text('feat_esslcert');
        }
elsif (!-r $cert) {
        return &text('feat_esslcertfile', "<tt>$cert</tt>");
        }

# Make sure key exists
my $key = &nginx::find_value("ssl_certificate_key", $server);
if (!$key) {
        return &text('feat_esslkey');
        }
elsif (!-r $key) {
        return &text('feat_esslkeyfile', "<tt>$key</tt>");
        }

# Make sure this domain or www.domain matches cert
if (!&virtual_server::check_domain_certificate($d->{'dom'}, $d) &&
    !&virtual_server::check_domain_certificate("www.".$d->{'dom'}, $d)) {
        return &virtual_server::text('validate_essldom',
                     "<tt>".$d->{'dom'}."</tt>",
                     "<tt>"."www.".$d->{'dom'}."</tt>",
                     join(", ", map { "<tt>$_</tt>" }
			    &virtual_server::list_domain_certificate($d)));
        }

return undef;
}

# feature_clone(&domain, &old-domain)
# This function does almost nothing, but needs to exist so that the ssl
# feature is preserved when cloning
sub feature_clone
{
my ($d, $oldd) = @_;

# Is the linked SSL cert still valid for the new domain? If not, break the
# linkage by copying over the cert.
if ($d->{'ssl_same'} && !&virtual_server::check_domain_certificate($d->{'dom'}, $d)) {
	my $oldsame = &virtual_server::get_domain($d->{'ssl_same'});
	&virtual_server::break_ssl_linkage($d, $oldsame);
	&virtual_server::sync_combined_ssl_cert($d);
	}

return 1;
}

# Reset for SSL is done in the non-SSL feature
sub feature_can_reset
{
return 0;
}

# Nginx SSL will be activated if a regular website is
sub feature_can_chained
{
return ('virtualmin-nginx');
}

# Returns 1 if the regular website is enabled and on by default
sub feature_chained
{
my ($d, $oldd) = @_;
if (&indexof($module_name, @virtual_server::plugins_inactive) >= 0) {
	# Not in auto mode
	return undef;
	}
elsif ($d->{'alias'}) {
	return 0;
	}
elsif ($d->{'virtualmin-nginx'}) {
	if (!$oldd || !$oldd->{'virtualmin-nginx'}) {
		# Turning on a website, so enable SSL as well
		return 1;
		}
	return undef;
	}
else {
	# Always off when a website is
	return 0;
	}
}

1;
