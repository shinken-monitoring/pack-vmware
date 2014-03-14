#!/usr/bin/perl
 $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

# check_vmware_snapshots.pl
# Extra packages required (URL given for vMA suitable RPMs)
# * Date::Parse from http://vault.centos.org/5.2/extras/i386/RPMS/

# Copyright (C) 2012 Simon Meggle, <simon.meggle@consol.de>
# THANKS to Sebastian Kayser for the idea!

# this program Is free software; you can redistribute it And/Or
# modify it under the terms of the GNU General Public License
# As published by the Free Software Foundation; either version 2
# of the License, Or (at your Option) any later version.
#
# this program Is distributed In the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY Or FITNESS For A PARTICULAR PURPOSE. See the
# GNU General Public License For more details.
#
# You should have received a copy of the GNU General Public License
# along With this program; If Not, write To the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#
# VERSION 0.15 
#
# Version history: 
# 2013/12/24 - v0.15
# 		added parameter "match_snapshot_names" to also black/whiteliste snapshot names
# 2013/12/12 - v0.14
# 		fixed bug when there are no snapshots at all (thanks to Andreas Daubner, Christian Joy, James) 
# 2013/04/26 - v0.13 
#              	added parameter 'separator' to specify another msg separator than comma. (Thanks to Olaf Assmus).
#                    Examples: 
#                    --separator '<br>' : Nagios sees the whole output as a single line. All snapshots/VMs
#                                         are displayed as well in service overview as in service details. 
#                                         Each message gets its own line. 
#                    --separator '\n'   : Nagios sees n lines. Only the first line is displayed in the service overview.
#                                         All lines are displayed in the service details. 
#                                         Each message gets its own line. 
#              First Output line is now a summation of the badcount.
# 2013/04/18 - v0.12 added black/whitelist function to exclude/filter VMs (thanks to Andi Seemueller)
# 2012/10/29 - v0.11 initial commit
#
# command 'check_vmware_snapshots'
#define command{
#    command_name                   check_vmware_snapshots
#    command_line                   $USER1$/check_vmware_snapshots.pl --server $HOSTADDRESS$ --username $ARG1$ --password $ARG2$ --mode $ARG3$ --critical $ARG4$ --warning $ARG5$ $ARG6$
#}
#
# service
# service 'Snapshot Age'
#define service{
#    service_description            Snapshot Age
#    check_command                  check_vmware_snapshots!$USER4$!$USER5$!age!7!30
#    ...
#    }
#
# service 'Snapshot Count'
#define service{
#    service_description            Snapshot Count
#    check_command                  check_vmware_snapshots!$USER4$!$USER5$!count!1!2
#    ...
#    }
#
## service 'Snapshot Count for all DWH VMs 
#define service{
#    service_description            Snapshot Count for all DWH VMs
#    check_command                  check_vmware_snapshots!$USER4$!$USER5$!count!1!2!--whitelist 'emDWH.*'
#    ...
#    }
#
## service 'Snapshot count with Snapshot blacklist'
#define service{
#    service_description            Snapshot Count without Dev Snapshots
#    check_command                  check_vmware_snapshots!$USER4$!$USER5$!count!1!2!--blacklist 'snapshot_dev_.*' --match_snapshot_names=1
#    ...
#    }

# Example Output 1:
# CRITICAL - Snapshot "Before update" (VM: 'vmHDX03-1') is 18.2 days old
# Snapshot "20120914_rc2" (VM: 'win2k8r2') is 32.9 days old
#

use strict;
use warnings;
use VMware::VIRuntime;
use Date::Parse;
use Nagios::Plugin;

my %STATES = (
        0       => "ok",
        1       => "warning",
        2       => "critical",
        3       => "unknown",
);

{
    no warnings 'redefine';
    *Nagios::Plugin::Functions::get_shortname = sub {
        return undef;
    };
}

my $perfdata_label;
my $perfdata_uom;
my $ok_msg;
my $nok_msg;

my $np = Nagios::Plugin->new(
    shortname => "",
    usage     => "",
);

my %opts = (
    mode => {
        type     => "=s",
        variable => "mode",
        help     => "count (per VM) | age (per snapshot)",
        required => 1,
    },
    warning => {
        type     => "=i",
        variable => "warning",
        help     => "days after a snapshot is alarmed as warning.",
        required => 1,
    },
    critical => {
        type     => "=i",
        variable => "critical",
        help     => "days after a snapshot is alarmed as critical.",
        required => 1,
    },
    blacklist => {
        type     => "=s",
        variable => "blacklist",
        help     => "regex blacklist",
        required => 0,
    },
    whitelist => {
        type     => "=s",
        variable => "whitelist",
        help     => "regex whitelist",
        required => 0,
    },
    separator => {
        type     => "=s",
        variable => "separator",
        help     => "field separator for VMs/snapshots (default: ', '). ",
        required => 0,
        default => ", "
    },
    match_snapshot_names => {
	  	type => ":i",
        help     => "If set, match also names of snapshots in black/whitelist",
        required => 0,
        default => 0,
    },
);

my $badcount = 0;
my $worststate = 0;
Opts::add_options(%opts);
Opts::parse();
Opts::validate();
Util::connect();

my $warn = Opts::get_option('warning');
my $crit = Opts::get_option('critical');
my $blacklist = Opts::get_option('blacklist');
my $whitelist = Opts::get_option('whitelist');
my $separator = Opts::get_option('separator');
my $match_snapshot_names = Opts::get_option('match_snapshot_names');

$np->set_thresholds(
    warning  => $warn,
    critical => $crit,
);
my $mode = Opts::get_option('mode');

my $sc = Vim::get_service_content();

my $vms = Vim::find_entity_views(
    view_type => 'VirtualMachine',
	filter => {}
);

if ( uc($mode) eq "AGE" ) {
	$perfdata_label = "outdated_snapshots";
	$perfdata_uom   = "snapshots";
	$ok_msg         = "No outdated VM snapshots found.";
	$nok_msg         = "outdated VM snapshots found!";
} elsif ( uc($mode) eq "COUNT" ) {
	$perfdata_label = "snapshot_count";
	$perfdata_uom   = "snapshots";
	$ok_msg         = "All VMs have the allowed number of snapshots.";
	$nok_msg         = "VMs with too much snapshots!";
}


foreach my $vm_view ( @{$vms} ) {
    my $vm_name     = $vm_view->{summary}->{config}->{name};
    my $vm_snapinfo = $vm_view->{snapshot};

    next unless defined $vm_snapinfo;
    next if (isblacklisted(\$blacklist,$vm_name ));
    next if (isnotwhitelisted(\$whitelist,$vm_name));
    if ( uc($mode) eq "AGE" ) {
        check_snapshot_age( $vm_name, $vm_snapinfo->{rootSnapshotList} );
    }
    elsif ( uc($mode) eq "COUNT" ) {
        my %vm_snapshot_count;
        check_snapshot_count( $vm_name, $vm_snapinfo->{rootSnapshotList},
            \%vm_snapshot_count );
        my $status = $np->check_threshold( $vm_snapshot_count{$vm_name} );
        if ($status) {
            $np->add_message(
               $status,
                sprintf(
                    "VM \"%s\" has %d snapshots",
                    $vm_name, $vm_snapshot_count{$vm_name}
                )
            );
            $badcount++;
            $worststate = ($status > $worststate ? $status : $worststate);
        }

    }
#    elsif ( uc($mode) eq "SIZE" ) {
#        $perfdata_label = "snapshot size";
#        $perfdata_uom   = "MB";
#        $ok_msg         = "All snapshots are within allowed size bounds.";
#
#    }
    else {
        $np->nagios_die("Unknown Mode.");
    }
}

$np->add_perfdata(
    label     => $perfdata_label,
    value     => $badcount,
    uom       => $perfdata_uom,
    threshold => $np->threshold(),
);

{
    Util::disconnect();
}

if ($worststate) {
    unshift( @{$np->{messages}->{ $STATES{$worststate} } }, $badcount . " " . $nok_msg);
    $np->nagios_exit(
        $np->check_messages(
            join     => $separator,
            join_all => $separator,
        )
    );
}
else {
    $np->nagios_exit( 0, $ok_msg );
}

sub check_snapshot_age {
    my $vm_name     = shift;
    my $vm_snaplist = shift;

    foreach my $vm_snap ( @{$vm_snaplist} ) {
        if ( $vm_snap->{childSnapshotList} ) {
            check_snapshot_age( $vm_name, $vm_snap->{childSnapshotList} );
        }
		next if (isblacklisted(\$blacklist,$vm_snap->{name}) and $match_snapshot_names );
		next if (isnotwhitelisted(\$whitelist,$vm_snap->{name}) and $match_snapshot_names );

        my $epoch_snap = str2time( $vm_snap->{createTime} );
        my $days_snap  = sprintf("%0.1f", ( time() - $epoch_snap ) / 86400 );
        my $status     = $np->check_threshold($days_snap);
        if ($status) {
            $np->add_message(
                $status,
                sprintf(
                    "Snapshot \"%s\" (VM: '%s') is %d days old",
                    $vm_snap->{name}, $vm_name, $days_snap
                )
            );
            $badcount++;
            $worststate = ($status > $worststate ? $status : $worststate);
        }
    }
}

sub check_snapshot_count {
    my $vm_name      = shift;
    my $vm_snaplist  = shift;
    my $vm_snapcount = shift;

    foreach my $vm_snap ( @{$vm_snaplist} ) {
        if ( $vm_snap->{childSnapshotList} ) {
            check_snapshot_count( $vm_name, $vm_snap->{childSnapshotList},
                $vm_snapcount );
        }
		next if (isblacklisted(\$blacklist,$vm_snap->{name}) and $match_snapshot_names );
		next if (isnotwhitelisted(\$whitelist,$vm_snap->{name}) and $match_snapshot_names );
		$vm_snapcount->{$vm_name}++;
	}
}

sub isblacklisted {
        my ($blacklist_ref,@candidates) = @_;
        return 0 if (!defined $$blacklist_ref);

        my $ret;
        $ret = grep (/$$blacklist_ref/, @candidates);
        return $ret;
}
sub isnotwhitelisted {
        my ($whitelist_ref,@candidates) = @_;
        return 0 if (!defined $$whitelist_ref);

        my $ret;
        $ret = ! grep (/$$whitelist_ref/, @candidates);
        return $ret;
}
