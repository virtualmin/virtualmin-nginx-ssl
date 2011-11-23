
use strict;
use warnings;
use Time::Local;
require 'virtualmin-nginx-ssl-lib.pl';
our (%text, %config, $module_name, %access);

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
return $text{'feat_label'};
}

sub feature_hlink
{
return "label";
}

# feature_check()
# Check for Nginx plugin?
sub feature_check
{
# XXX
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
foreach my $l (&virtualmin_nginx::find("listen", $server)) {
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

if ($d->{'virt'}) {
        # Has a private IP
        return undef;
	}
elsif ($port != $defport) {
        # Has a private port
        return undef;
	}
else {
	# Neither .. but we can still do SSL, if there are no other domains
	# with SSL on the same IP
        local ($sslclash) = grep { $_->{'ip'} eq $d->{'ip'} &&
                                   $_->{'ssl'} &&
                                   $_->{'id'} ne $d->{'id'} }
			         &virtual_server::list_domains();
        if ($sslclash && (!$oldd || !$oldd->{'ssl'})) {
		# Clash .. but is the cert OK?
		if (!&check_domain_certificate($d->{'dom'}, $sslclash)) {
                        local @certdoms = &virtual_server::list_domain_certificate($sslclash);
                        return &virtual_server::text(
				'setup_edepssl5', $d->{'ip'},
                                join(", ", map { "<tt>$_</tt>" } @certdoms),
                                $sslclash->{'dom'});
                        }
                else {
                        return undef;
                        }
                }
	return undef;
	}
}

# feature_setup(&domain)
# Adds SSL to an Nginx website
sub feature_setup
{
my ($d) = @_;

# XXX check for shared cert

# XXX generate cert if needed

# XXX add listen to non-SSL server
}

1;

