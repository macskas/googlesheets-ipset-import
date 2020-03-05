#!/usr/bin/perl

use strict;
use warnings;

use JSON::XS;
use LWP::UserAgent;
use Getopt::Std;
use Socket;

# https://developers.google.com/sheets/api/guides/authorizing
# example ipset create: ipset create allowed_from_sheet hash:net
my $ipset_name = "allowed_from_sheet";

my $google_api_key = "";
my $google_sheet_id = "";

my $url_sheet = "";

my $sheet_ip_allowed = {};
my $iptables_ip_allowed = {};
my $p_ipset = "/sbin/ipset";
my $dry_run = 0;

my $modules_enabled = {
    'iptables'	=> 1
};

my $queue_iptables = {
    'add' => [],
    'remove' => []
};

sub reset_queues()
{
    $queue_iptables = {
        'add' => [],
        'remove' => []
    };
}

sub decode_json_eval($)
{
    my $input = shift || "";
    my $out = 0;
    eval {
        $out = decode_json($input);
        1;
    } or do {
        my $e = $@;
        $out = 0;
    };

    return $out;
}

sub do_info()
{
    my $msg = shift || "unknown";
    printf ("%s INFO  > %s\n", scalar localtime, $msg);
}

sub do_debug()
{
    my $msg = shift || "unknown";
    printf ("%s DEBUG > %s\n", scalar localtime, $msg);
}

sub do_error()
{
    my $msg = shift || "unknown";
    printf STDERR ("%s ERROR > %s\n", scalar localtime, $msg);
    exit(1);
}

sub isIpAllowedInIptables()
{
    my $ip = shift || &do_error("isIpAllowedInIptables() missing ip.");
    if (defined($iptables_ip_allowed->{"$ip"})) {
        return 1;
    }
    return 0;
}

sub isIpAllowedInSheet()
{
    my $ip = shift || &do_error("isIpAllowedInSheet() missing ip.");
    if (defined($sheet_ip_allowed->{"$ip"})) {
        return 1;
    }
    return 0;
}



sub download()
{
    my $url = shift || "";
    my $ua = LWP::UserAgent->new;
    $ua->timeout(10);
    my $response = $ua->get($url);
    if ($response->is_success) {
        return $response->decoded_content;
    } else {
        &do_error("Failed to download ($url): ". $response->status_line);
    }
}

sub sheet_get_rules()
{
    &do_info("sheet_get_rules() started.");
    my $r = {};
    my $sheet_raw = &download($url_sheet);
    my $sheet_data = &decode_json_eval($sheet_raw);

    if (!$sheet_data) {
        &do_error("Invalid JSON received for sheet. #1");
    }
    if (!defined($sheet_data->{'values'})) {
        &do_error("Invalid JSON received for sheet. Missing values #2");
    }

    my @vals = @{$sheet_data->{'values'}};
    my $items = scalar @vals;

    if ($items <= 0) {
        &do_error("Empty sheet. Exiting.");
    }

    my @row_A = @{$vals[0]};
    if (scalar @row_A <= 0) {
        &do_error("row A is empty in sheet. Exiting.");
    }
    my @users = @row_A;
    shift @vals;
    foreach my $row (@vals) {
        for (my $i=0; $i<scalar @{$row}; $i++) {
            my $ip = ${$row}[$i];
            my $username = $users[$i];
            if (length($username) < 3) {
                next;
            }
            if ($ip !~ /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/) {
                next;
            }
            my $ip_aton = inet_aton($ip);
            if (!$ip_aton) {
                &do_debug("Invalid IP $ip. Skipping.");
            }
            $sheet_ip_allowed->{"$ip"} = $username;
            $r->{"$username"}->{"$ip"} = 1;
        }
    }
    foreach my $uname (sort keys %{$r}) {
        &do_debug(" - IPs allowed for $uname: ". join(", ", keys %{$r->{"$uname"}}));
    }
}

sub queue_fill()
{
    &do_info("queue_fill() started.");
    &reset_queues();

    if ($modules_enabled->{'iptables'}) {
        # ADD ips
        foreach my $ip (keys %{$sheet_ip_allowed}) {
            if (!&isIpAllowedInIptables($ip)) {
                push(@{$queue_iptables->{'add'}}, { 'ip' => $ip, 'username' => $sheet_ip_allowed->{"$ip"} } );
            }
        }

        # DEL ips
        foreach my $ip (keys %{$iptables_ip_allowed}) {
            if (!&isIpAllowedInSheet($ip)) {
                push(@{$queue_iptables->{'remove'}}, { 'ip' => $ip, 'username' => $iptables_ip_allowed->{"$ip"} } );
            }
        }
    }
}

sub iptables_get_rules()
{
    $iptables_ip_allowed = {};
    if (!-x "$p_ipset") {
        &do_error("ipset command is missing");
    }
    local *P;
    open(P, "$p_ipset list $ipset_name -o save |") or &do_error("Unable to list ipset '$ipset_name'");
    while (<P>) {
        chomp;
        if ($_ =~ /^add\s+$ipset_name\s+([^\s]+)\s*$/) {
            my $ip = $1;
            my $ip_aton = inet_aton($ip);
            if (!$ip_aton) {
                &do_debug("ipset parse failed. invalid ip $ip.");
                next;
            }
            $iptables_ip_allowed->{"$ip"} = 1;
        }
    }
    close(P);
    my $rc = $? >> 8;
    if ($rc == 0) {
        return 1;
    } elsif ($rc == 1) {
        &do_error("ipset $ipset_name does not exist");
    } else {
        &do_error("ipset list command failed with rc=$rc");
    }
}

sub queue_run_iptables()
{
    &do_info("queue_run_iptables() started.");
    foreach my $obj (@{$queue_iptables->{'add'}}) {
        my $ip = $obj->{'ip'};
        my $cmd = "$p_ipset add $ipset_name $ip";
        if (!$dry_run) {
            system($cmd);
        }
        &do_debug(" - $cmd");
    }

    foreach my $obj (@{$queue_iptables->{'remove'}}) {
        my $ip = $obj->{'ip'};
        my $cmd = "$p_ipset del $ipset_name $ip";
        if (!$dry_run) {
            system($cmd);
        }
        &do_debug(" - $cmd");
    }
    $queue_iptables = { 'add' => [], 'remove' => [] };
}

sub do_help() {
    print "$0 [-s <sheet_id>] [-k <google-api-key>] [-h] [-i <ipset name>] [-n]\n";
    print "            -n  - dry run\n";
    print "                - sheet_id option can be replaced with SHEET_ID environment variable\n";
    print "                - google-api-key option can be replaced with GOOGLE_API_KEY environment variable\n";
    print "\n";
    exit(0);
}

sub main()
{
    my %opts = ();
    getopts("s:k:hi:n", \%opts);

    if (defined($opts{"h"})) {
        &do_help();
    }

    if (defined($opts{"n"})) {
        $dry_run = 1;
    }

    if (defined($ENV{"SHEET_ID"})) {
        $google_sheet_id = $ENV{"SHEET_ID"};
    }

    if (defined($opts{"s"})) {
        $google_sheet_id = $opts{"s"};
    }

    if (defined($ENV{"GOOGLE_API_KEY"})) {
        $google_api_key = $ENV{"GOOGLE_API_KEY"};
    }

    if (defined($opts{"k"})) {
        $google_api_key = $opts{"k"};
    }

    if (defined($opts{"i"})) {
        $ipset_name = $opts{"i"};
    }

    if (length($google_sheet_id) < 2) {
        &do_help();
    }
    if (length($google_api_key) < 2) {
        &do_help();
    }

    if ($ipset_name !~ /^[a-zA-Z0-9_+-]+$/) {
        &do_error("Ipset name is not in the right format");
    }

    $url_sheet = 'https://sheets.googleapis.com/v4/spreadsheets/'.$google_sheet_id.'/values/Sheet1?key='.$google_api_key;

    &sheet_get_rules();

    if ($dry_run) {
        return 0;
    }

    if ($modules_enabled->{'iptables'}) {
        &iptables_get_rules();
    }
    
    &queue_fill();

    if ($modules_enabled->{'iptables'}) {
        &queue_run_iptables();
    }
}

&main();
