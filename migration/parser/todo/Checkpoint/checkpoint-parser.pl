#!/usr/bin/perl

#############################################################################
# FW1r65_to_FWdoc
# 	convert Firewall-1 rules and objects (versions 3.0 - NG R65)
#	into FWdoc standard 1.0
#	Note: unsupported by Checkpoint or representatives.
#
# Copyright (C) 2006 Volker Tanger
#	initially based on FW1rules 7.3.43
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# For bug reports and suggestions or if you just want to talk to me please
# contact me at volker.tanger@wyae.de
#
# Updates will be available at  http://www.wyae.de/software/
# please check there for updates prior to submitting patches!
#
# For list of changes please refer to the README.TXT file. Thanks.
#############################################################################


#
# Used modules
#
use Getopt::Long;
use File::Basename;
use List::MoreUtils qw(uniq);

use Encode;
$SCRIPTINFORMATION = 'Securlabs Checkpoint Parser';    ###scriptinformation###
$DESCRINFORMATION  = 'Securlabs Parser (Version 3.0 up to R65)';    ###descrinformation###

$FW1rules	 = 'PolicyName.W';
$FW1objects	 = 'objects_5_0.C';

$LogFile	 = 'FW1_to_FWdoc.log';
$DebugFile	 = 'FW1_to_FWdoc.debug.log';

$FLAG_withinterface=1;

%netmasktranslation = (
	'255.255.255.255'  => '32',
	'255.255.255.254'  => '31',
	'255.255.255.252'  => '30',
	'255.255.255.248'  => '29',
	'255.255.255.240'  => '28',
	'255.255.255.224'  => '27',
	'255.255.255.192'  => '26',
	'255.255.255.128'  => '25',
	'255.255.255.0'	   => '24',
	'255.255.254.0'	   => '23',
	'255.255.252.0'	   => '22',
	'255.255.248.0'	   => '21',
	'255.255.240.0'	   => '20',
	'255.255.224.0'	   => '19',
	'255.255.192.0'	   => '18',
	'255.255.128.0'	   => '17',
	'255.255.0.0'	   => '16',
	'255.254.0.0'	   => '15',
	'255.252.0.0'	   => '14',
	'255.248.0.0'	   => '13',
	'255.240.0.0'	   => '12',
	'255.224.0.0'	   => '11',
	'255.192.0.0'	   => '10',
	'255.128.0.0'	   => '9',
	'255.0.0.0'	   => '8',
	'254.0.0.0'	   => '7',
	'252.0.0.0'	   => '6',
	'248.0.0.0'	   => '5',
	'240.0.0.0'	   => '4',
	'224.0.0.0'	   => '3',
	'192.0.0.0'	   => '2',
	'128.0.0.0'	   => '1',
	'0.0.0.0'	   => '0'  );

%NATtranslation = (
	0 => 'hide',
	1 => 'static' );

$SynDefender[0] = 'None';
$SynDefender[1] = 'SYN Relay';
$SynDefender[2] = 'SYN Gateway';
$SynDefender[3] = 'Passive SYN Gateway';

%ICMPtranslate = (
	'icmp_type=ICMP_ECHOREPLY'	=> 0,
	'icmp_type=ICMP_UNREACH',	=> 3,
	'icmp_type=ICMP_SOURCEQUENCH',	=> 4,
	'icmp_type=ICMP_REDIRECT',	=> 5,
	'icmp_type=ICMP_ECHO',		=> 8,
	'icmp_type=ICMP_TIMXCEED'	=> 11,
	'icmp_type=ICMP_PARAMPROB',	=> 12,
	'icmp_type=ICMP_TSTAMP',	=> 13,
	'icmp_type=ICMP_TSTAMPREPLY',	=> 14,
	'icmp_type=ICMP_IREQ',		=> 15,
	'icmp_type=ICMP_IREQREPLY',	=> 16,
	'icmp_type=ICMP_MASKREQ',	=> 17,
	'icmp_type=ICMP_MASKREPLY',	=> 18,
);

$l7_numner = 0;
$user_numner = 0;

##########################################################################
# print out Usage
sub Usage{
	print STDERR "

-----------------------------------------------------------------------
	Parser USAGE
-----------------------------------------------------------------------

   checkpoint-parser.pl
	[--objects=<objects file>]
	[--rules=<rules file>]
	[--merge_SP3=<FWS rules file>]  or [--merge_AI=<FWS rules file>]
	[--with_implicit_rules]
	[--verbose] [--debug] [--version]
	[--anonymizeIP]
	[--anonymizeObjects]


Parameters:
-----------

   --rules=<rule file>: Location of FireWall-1 rule file.
	Default is 'Standard.W'

   --objects=<objects file>: Location of FireWall-1 objects file.
	  Default is 'objects_5_0.C' which is good for NG versions,
	  please use 'objects.C' if you are using V4.1 or older

   --merge_SP3=<FWS rule file>  or
   --merge_AI=<FWS rule file>: Location of FireWall-1 SP3 rulebases file
	Merges <rule file> with comments of <FWS rule file>
	eg. 'rulebases_5_0.fws'

   --with_implicit_rules: include the implicit rules into the tables

   --verbose: prints debugging information to STDERR and FWrules.log

   --version: prints version and exists

   --anonymizeIP: replaces all IP addresses with 'A.N.O.N/YM'

   --anonymizeObjects: DOES NOT WORK YET

The Securlabs output, in JSON file format (.JSN) is sent to STOUT\n";
}

##########################################################################
# correct Micro$oft stuff (line end, spaces)
sub fromdos {
	$line = $_[0];
	$line =~ s/\n//g;
	$line =~ s/\r//g;
	$line =~ s/\"//g;
	$line =~ s/        /\t/g;
	$line =~ s/\\/\//g;
	return $line;
}

##########################################################################
# print out comments / errors
sub PrintLog{
	my ($msg) = $_[0];
	if ($FLAG_verbose){
		print STDERR "$msg";
		print LOGFILE "$msg";
	}
}

##########################################################################
# print out comments / errors
sub DebugLog{
	my ($msg) = $_[0];
	if ($FLAG_debug){
		print DEBUGFILE "$msg\n";
	}
}

##########################################################################
# print only if second parameter not empty
sub PrintNonempty{
	my ($FILE)   = $_[0];
	my ($first)  = $_[1];
	my ($second) = $_[2];

	if ( "$second" ne '' ) {
		printf $FILE ("$first","$second");
	}
}


#Albert Estevez Adding communities support
sub ReadCommunities{
	my ($dummy)     = '';
	my ($name)      = '';
	my ($lineparam) = '';
	my ($amember)   = '';
	my ($members)   = '';

	#$obj_number = 0;
	$mode_cluster_members = 0;
	while ( ($line = <INFILE> ) && ( fromdos("$line") ne "\t)" ) ) {
		$line = &fromdos($line);
		&DebugLog("Obj.READ1: $line");
		while ( $line !~ /\t\t\: \(/ )  {
			$line = <INFILE>;
			$line = &fromdos($line);
			&DebugLog("Obj.READ2: $line");
		}
		($dummy,$name) = split(/\(/,$line,2) ;
		$obj_if_number{$name} = 0;
		$amember = '';
		$members = '';
		while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t)" ) ) {
			$line = &fromdos($line);
			&DebugLog("Obj.READ3: $line");
			($dummy,$lineparam) = split(/\(/,$line,2) ;
			$lineparam =~ s/\)$//;
			$obj_type{$name} = "community";

			if ( $line =~ /^\t\t\t:location \(/ ){
				$obj_location{$name} = ("$lineparam" eq 'external') * 1;
			} elsif ( $line =~ /^\t\t\t:firewall \(/ ){
				$obj_is_fw1{$name} = ("$lineparam" eq 'installed') * 1;
			} elsif ( $line =~ /^\t\t\t:ipaddr \(/ ){
				if($obj_if_number{$name} == 0){
					$obj_if_number{$name} = -1;
				}
				$obj_ipaddr{$name} = "$lineparam";
			} elsif ( $line =~ /^\t\t\t:ipaddr_first \(/ ){
				$obj_ipaddr{$name} = "$lineparam";
			} elsif ( $line =~ /^\t\t\t:ipaddr_last \(/ ){
				$obj_ipaddr{$name} = "$obj_ipaddr{$name} - $lineparam";
			} elsif ( $line =~ /^\t\t\t:netmask \(/ ){
				$obj_netmask{$name} = $netmasktranslation{$lineparam};
			} elsif ( $line =~ /^\t\t\t:valid_ipaddr \(/ ){
				$obj_NATadr{$name} = $lineparam;
			} elsif ( $line =~ /^\t\t\t:netobj_adtr_method \(/ ){
				$obj_NATtype{$name} = ("$lineparam" eq 'adtr_static') * 1;
			} elsif ( $line =~ /^\t\t\t:comments \(/ ){
				$obj_comment{$name} = $lineparam;
				$obj_comment{$name} =~ s/^\"|\"$//g;		#--- remove " at beginning and end
				$obj_comment{$name} =~ s/;/ /g;
			} elsif ( $line =~ /^\t\t\t: \(ReferenceObject/ ){
				while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t\t)" ) ) {
					$line = &fromdos($line);
					&DebugLog("Obj.READ4: $line");
					if ( $line =~ /^\t\t\t\t:Name \(/) {
						($dummy,$lineparam) = split(/\(/,$line,2) ;
						$lineparam =~ s/\)$//;
						$members = "$members§$lineparam";
					}
				}
				# The 'if' clause adds the member to $members only if the current mode is 'cluster_members'.
				# This prevents the 'cluster masters' from being added to $members.
			}elsif($line =~ /^\t\t\t\t:\S+ \(ReferenceObject/){
				while(($line = <INFILE>) && (fromdos("$line") ne "\t\t\t\t)")){
					$line = fromdos($line);
					if($line =~ /^\t\t\t\t\t:Name \(/){
						if($mode_cluster_members){
							($dummy,$lineparam) = split(/\(/,$line,2);
							$lineparam =~ s/\)$//;
							$members = "$members§$lineparam";
						}
					}
				}
				# process members of 'group_with_exclusion' objects.
				# First the base members :
			}elsif($line =~ /^\t\t\t:base \(ReferenceObject/){
				while(($line = <INFILE>) && (fromdos("$line") ne "\t\t\t)")){
					$line = fromdos($line);
					if($line =~ /^\t\t\t\t:Name \(/){
						($dummy,$lineparam) = split(/\(/,$line,2);
						$lineparam =~ s/\)$//;
						$obj_members_base{$name} = $lineparam;
						last;
					}
				}
				# Now the excluded members:
			}elsif($line =~ /^\t\t\t:exception \(ReferenceObject/){
				while(($line = <INFILE>) && (fromdos("$line") ne "\t\t\t)")){
					$line = fromdos($line);
					if($line =~ /^\t\t\t\t:Name \(/){
						($dummy,$lineparam) = split(/\(/,$line,2);
						$lineparam =~ s/\)$//;
						$obj_members_exception{$name} = $lineparam;
						last;
					}
				}
			} elsif ( $line =~ /^\t\t\t: / ){
				($dummy,$amember) = split(/: /,$line,2) ;
				$members = "$members§$amember";
			} elsif ( ($line =~ /^\t\t\t:if-(.|..) \(/ ) && ($FLAG_withinterface) ){
				$obj_if_number{$name} = $1 + 1;
				while  ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t\t)" ) ) {
					$line = &fromdos($line);
					($dummy,$lineparam) = split(/\(/,$line,2) ;
					$lineparam =~ s/\)$//;
					if ( ($line =~ /^\t\t\t\t:iffullname \(/) || ($line =~ /^\t\t\t\t:officialname \(/) ){
						$obj_if_name{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
					} elsif ( $line =~ /^\t\t\t\t:ipaddr \(/ ){
						$obj_if_ipaddr{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
					} elsif ( $line =~ /^\t\t\t\t:netmask \(/ ){
						$obj_if_netmask{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
						# process anti-spoofing settings for 4.1.
					}elsif($line =~ /^\t\t\t\t:netaccess \(Others/){
						$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = "Others";
					}elsif($line =~ /^\t\t\t\t:netaccess \(\" \+ (.*)\"/){
						$accessobj = "$1";
						$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = "Others + " . $accessobj;
					}elsif($line =~ /^\t\t\t\t:netaccess \(\"This Net\"/){
						$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = "ThisNet";
					}elsif($line =~ /^\t\t\t\t\t:refname \(\"\#_(.*)\"\)/){
						$accessobj = "$1";
						$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = $accessobj;
					}
				}
			} elsif(($line =~ /^\t\t\t\t:([0-9]|[0-9][0-9]) \(/) && ($FLAG_withinterface)){
				$obj_if_number{$name} = $1 + 1;
				while(($line = <INFILE>) && (fromdos("$line") ne "\t\t\t\t)")){
					$line = fromdos($line);
					($dummy,$lineparam) = split(/\(/,$line,2);
					$lineparam =~ s/\)$//;
					if(($line =~ /^\t\t\t\t\t:iffullname \(/) || ($line =~ /^\t\t\t\t\t:officialname \(/)){
						$obj_if_name{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
					}elsif($line =~ /^\t\t\t\t\t:ipaddr \(/){
						$obj_if_ipaddr{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
					}elsif($line =~ /^\t\t\t\t\t:netmask \(/){
						$obj_if_netmask{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
						# process anti-spoofing settings for NG.
					}elsif($line =~ /^\t\t\t\t\t\t:access \(this/){
						$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = "ThisNet";
					}elsif($line =~ /^\t\t\t\t\t\t\t:Name \((.*)\)/){
						$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = $1;
					}
				}
			}
			if($line =~ /^\t\t\t:cluster_members \(/){
				$mode_cluster_members = 1;
			}elsif($line =~ /^\t\t\t:/){
				$mode_cluster_members = 0;
			}
		}
		if ( ("$obj_type{$name}" eq 'group') || ("$obj_type{$name}" eq 'gateway_cluster') ) {
			($dummy,$members) = split (/§/, $members, 2);
			$obj_members{$name} = $members;
		}
		$obj_name[$obj_number] = $name;

		$obj_number += 1;
		&PrintLog('.');
	}
	if ($FLAG_sortbytype) {
		@obj_name = sort { $obj_type{"$a"} cmp $obj_type{"$b"} or lc($a) cmp lc($b) } @obj_name;
	} else {
		@obj_name = sort { lc($a) cmp lc($b) } @obj_name;
	}
}

#=====================================================================
##########################################################################
# read all network entities/objects defined
#
# Object variables where obj_name equals the hash for each of these:
#
#	$obj_number 	= number of objects
#	@obj_name 	= names of all objects
#	%obj_type 	= host, network, gateway, group
#	%obj_location 	= 0=internal, 1=external
#	%obj_is_fw1 	= has FW1 installed? 0=false, 1=true
#	%obj_ipaddr 	= IP Address
#	%obj_netmask	= netmask
#	%obj_NATadr 	= NAT address for implicit NAT
#	%obj_NATtype 	= 0=hide, 1=static
#	%obj_members 	= members, if a group
#	%obj_comment 	= comment for the object
#       %obj_if_number	= Number of interfaces added to an object
#
# Object variables where NICinterfacenumber.obj_name equals the hash
#   %obj_if_name	= Name of the interface added
#	%obj_if_ipaddr	= IP Address of the interface added
#	%obj_if_netmask	= Netmask of the interface added
# %obj_interfaces = Interfaces inside a host
sub ReadNetworkObjects{
	my ($dummy)      = '';
	my ($name)       = '';
	my ($lineparam)  = '';
	my ($amember)    = '';
	my ($members)    = '';
	my ($interfaces) = '';
	$obj_number = 0;
	$mode_cluster_members = 0;

	while ( ($line = <INFILE> ) && ( fromdos("$line") ne "\t)" ) ) {
		$line = &fromdos($line);
		&DebugLog("Obj.READ1: $line");
		while ( $line !~ /\t\t\: \(/ )  {
			$line = <INFILE>;
			$line = &fromdos($line);
			&DebugLog("Obj.READ2: $line");
		}
		($dummy,$name) = split(/\(/,$line,2) ;
		$obj_shared{$name}="0";
		$obj_if_number{$name} = 0;
		$amember = '';
		$members = '';
		while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t)" ) ) {
			$line = &fromdos($line);
			&DebugLog("Obj.READ3: $line");
			($dummy,$lineparam) = split(/\(/,$line,2) ;
			$lineparam =~ s/\)$//;
			if ( $line =~ /^\t\t\t:type \(/ ){
				$obj_type{$name} = lc($lineparam);
			}
			elsif ( $line =~ /^\t\t\t:location \(/ ){
				$obj_location{$name} = ("$lineparam" eq 'external') * 1;
			}
			elsif ( $line =~ /^\t\t\t:firewall \(/ ){
				$obj_is_fw1{$name} = ("$lineparam" eq 'installed') * 1;
			}
			elsif ( $line =~ /^\t\t\t:ipaddr \(/ ){
				if($obj_if_number{$name} == 0){
					$obj_if_number{$name} = -1;
				}
				$obj_ipaddr{$name} = "$lineparam";
			}
			elsif ( $line =~ /^\t\t\t:ipaddr_first \(/ ){
				$obj_ipaddr{$name} = "$lineparam";
			}
			elsif ( $line =~ /^\t\t\t:ipaddr_last \(/ ){
				$obj_ipaddr{$name} = "$obj_ipaddr{$name} - $lineparam";
			}
			elsif ( $line =~ /^\t\t\t:netmask \(/ ){
				$obj_netmask{$name} = $netmasktranslation{$lineparam};
			}
			elsif ( $line =~ /^\t\t\t:valid_ipaddr \(/ ){
				$obj_NATadr{$name} = $lineparam;
			}
			elsif ( $line =~ /^\t\t\t:netobj_adtr_method \(/ ){
				$obj_NATtype{$name} = ("$lineparam" eq 'adtr_static') * 1;
			}
			elsif ( $line =~ /^\t\t\t:comments \(/ ){
				$obj_comment{$name} = $lineparam;
				$obj_comment{$name} =~ s/^\"|\"$//g;		#--- remove " at beginning and end
				$obj_comment{$name} =~ s/;/ /g;
			}
			elsif ( $line =~ /^\t\t\t: \(ReferenceObject/ ){
				while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t\t)" ) ) {
					$line = &fromdos($line);
					&DebugLog("Obj.READ4: $line");
					if ( $line =~ /^\t\t\t\t:Name \(/) {
						($dummy,$lineparam) = split(/\(/,$line,2) ;
						$lineparam =~ s/\)$//;
						$members = "$members§$lineparam";
					}
				}
				# The 'if' clause adds the member to $members only if the current mode is 'cluster_members'.
				# This prevents the 'cluster masters' from being added to $members.
			}
			elsif($line =~ /^\t\t\t\t:\S+ \(ReferenceObject/){
				while(($line = <INFILE>) && (fromdos("$line") ne "\t\t\t\t)")){
					$line = fromdos($line);
					if($line =~ /^\t\t\t\t\t:Name \(/){
						if($mode_cluster_members){
							($dummy,$lineparam) = split(/\(/,$line,2);
							$lineparam =~ s/\)$//;
							$members = "$members§$lineparam";
						}
					}
				}
				# process members of 'group_with_exclusion' objects.
				# First the base members :
			}
			elsif($line =~ /^\t\t\t:base \(ReferenceObject/){
				while(($line = <INFILE>) && (fromdos("$line") ne "\t\t\t)")){
					$line = fromdos($line);
					if($line =~ /^\t\t\t\t:Name \(/){
						($dummy,$lineparam) = split(/\(/,$line,2);
						$lineparam =~ s/\)$//;
						$obj_members_base{$name} = $lineparam;
						last;
					}
				}
				# Now the excluded members:
			}
			elsif($line =~ /^\t\t\t:exception \(ReferenceObject/){
				while(($line = <INFILE>) && (fromdos("$line") ne "\t\t\t)")){
					$line = fromdos($line);
					if($line =~ /^\t\t\t\t:Name \(/){
						($dummy,$lineparam) = split(/\(/,$line,2);
						$lineparam =~ s/\)$//;
						$obj_members_exception{$name} = $lineparam;
						last;
					}
				}
			}
			elsif ( $line =~ /^\t\t\t: / ){
				($dummy,$amember) = split(/: /,$line,2) ;
				$members = "$members§$amember";
			}
			elsif ( ($line =~ /^\t\t\t:if-(.|..) \(/ ) && ($FLAG_withinterface) ){

				$obj_if_number{$name} = $1 + 1;
				while  ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t\t)" ) ) {
					$line = &fromdos($line);
					($dummy,$lineparam) = split(/\(/,$line,2) ;
					$lineparam =~ s/\)$//;
					if ( ($line =~ /^\t\t\t\t:iffullname \(/) || ($line =~ /^\t\t\t\t:officialname \(/) ){
						$obj_if_name{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
					}
					elsif ( $line =~ /^\t\t\t\t:ipaddr \(/ ){
						$obj_if_ipaddr{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
					}
					elsif ( $line =~ /^\t\t\t\t:netmask \(/ ){
						$obj_if_netmask{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
						# process anti-spoofing settings for 4.1.
					}
					elsif($line =~ /^\t\t\t\t:netaccess \(Others/){
						$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = "Others";
					}
					elsif($line =~ /^\t\t\t\t:netaccess \(\" \+ (.*)\"/){
						$accessobj = "$1";
						$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = "Others + " . $accessobj;
					}
					elsif($line =~ /^\t\t\t\t:netaccess \(\"This Net\"/){
						$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = "ThisNet";
					}
					elsif($line =~ /^\t\t\t\t\t:refname \(\"\#_(.*)\"\)/){
						$accessobj = "$1";
						$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = $accessobj;
					}
				}
			}
			elsif($line =~ /^\t\t\t\t:([0-9]|[0-9][0-9]) \(/) {

				$obj_if_number{$name} = $1 + 1;
				while(($line = <INFILE>) && (fromdos("$line") ne "\t\t\t\t)")){
					$line = fromdos($line);
					($dummy,$lineparam) = split(/\(/,$line,2);
					$lineparam =~ s/\)$//;
					if(($line =~ /^\t\t\t\t\t:iffullname \(/) || ($line =~ /^\t\t\t\t\t:officialname \(/)){
						$obj_if_name{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
					}
					elsif($line =~ /^\t\t\t\t\t:ipaddr \(/){
						$obj_if_ipaddr{"NIC$obj_if_number{$name}\.$name"} = $lineparam;
						$myip=$lineparam;
					}
					elsif($line =~ /^\t\t\t\t\t:netmask \(/){
						$obj_if_netmask{"NIC$obj_if_number{$name}\.$name"} = $netmasktranslation{$lineparam};
						$amember= $myip.'/'.$obj_if_netmask{"NIC$obj_if_number{$name}\.$name"};
						$interfaces = "$interfaces§$amember";
						# process anti-spoofing settings for NG.
					}
					elsif($line =~ /^\t\t\t\t\t\t:access \(this/){
						$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = "ThisNet";
					}
					elsif($line =~ /^\t\t\t\t\t\t\t:Name \((.*)\)/){
						$obj_if_spoof{"NIC$obj_if_number{$name}\.$name"} = $1;
					}

				}

			}
			elsif ( $line =~ /^\t\t\t\t:global_level \(1\)/ ){
				$obj_shared{$name}="1";
			}

			if($line =~ /^\t\t\t:cluster_members \(/){
				$mode_cluster_members = 1;
			}
			elsif($line =~ /^\t\t\t:/){
				$mode_cluster_members = 0;
			}
		}

		if ($interfaces){
			($dummy,$interfaces) = split (/§/, $interfaces, 2);
			$obj_interfaces{$name}=$interfaces;
			$interfaces="";
		}

		if ( ("$obj_type{$name}" eq 'group') || ("$obj_type{$name}" eq 'gateway_cluster') ) {

			($dummy,$members) = split (/§/, $members, 2);
			$obj_members{$name} = $members;
		}
		$obj_name[$obj_number] = $name;
		$obj_number += 1;
		&PrintLog('.');
	}
	$obj_type{'any'} = 'any';
	if ($FLAG_sortbytype) {
		@obj_name = sort { $obj_type{"$a"} cmp $obj_type{"$b"} or lc($a) cmp lc($b) } @obj_name;
	}
	else {
		@obj_name = sort { lc($a) cmp lc($b) } @obj_name;
	}
}

#=====================================================================

sub ReadNetobjadtr{
	my ($dummy)     = '';
	my ($name)      = '';
	my ($lineparam) = '';
	my ($amember)   = '';
	my ($members)   = '';
	my ($eof_flag)  = 0;

	while ( ($line = <INFILE> ) && ( fromdos("$line") ne "\t)" ) ) {
		$line = &fromdos($line);
		&DebugLog("NetObj.READ1: $line");
		$eof_flag = 0;
		while ( ($line !~ /\t\t\: \(/ ) && ( ! $eof_flag ) )  {
			$eof_flag = ($line = <INFILE>);
			$line = &fromdos($line);
			&DebugLog("NetObj.READ2: $line");
		}
		($dummy,$name) = split(/\(/,$line,2) ;
		$amember = '';
		$members = '';
		while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t)" ) ) {
			$line = &fromdos($line);
			&DebugLog("NetObj.READ3: $line");
			($dummy,$lineparam) = split(/\(/,$line,2) ;
			$lineparam =~ s/\)$//;
			if ( $line =~ /^\t\t\t:type \(/ ){
				$obj_type{$name} = lc($lineparam);
			} elsif ( $line =~ /^\t\t\t:ipaddr_first \(/ ){
				$obj_netmask{$name} = "$lineparam";
			} elsif ( $line =~ /^\t\t\t:ipaddr_last \(/ ){
				$obj_netmask{$name} = "$obj_netmask{$name} - $lineparam";
			} elsif ( $line =~ /^\t\t\t:valid_ipaddr \(/ ){
				$obj_NATadr{$name} = $lineparam;
			} elsif ( $line =~ /^\t\t\t:netobj_adtr_method \(/ ){
				$obj_NATtype{$name} = ("$lineparam" eq 'adtr_static') * 1;
			} elsif ( $line =~ /^\t\t\t:comments \(/ ){
				$obj_comment{$name} = $lineparam;
				$obj_comment{$name} =~ s/^\"|\"$//g;		#--- remove " at beginning and end
				$obj_comment{$name} =~ s/;/ /g;
			} elsif ( $line =~ /^\t\t\t: \(ReferenceObject/ ){
				while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t\t)" ) ) {
					$line = &fromdos($line);
					&DebugLog("NetObj.READ4: $line");
					if ( $line =~ /^\t\t\t\t:Name \(/) {
						($dummy,$lineparam) = split(/\(/,$line,2) ;
						$lineparam =~ s/\)$//;
						$members = "$members§$lineparam";
					}
				}
			} elsif ( $line =~ /^\t\t\t: / ){
				($dummy,$amember) = split(/: /,$line,2) ;
				$members = "$members§$amember";
			}
		}
		$obj_name[$obj_number] = $name;
		$obj_number += 1;
		&PrintLog('.');
	}
	$obj_type{'any'} = 'any';
	if ($FLAG_sortbytype) {
		@obj_name = sort { $obj_type{"$a"} cmp $obj_type{"$b"} or lc($a) cmp lc($b) } @obj_name;
	} else {
		@obj_name = sort { lc($a) cmp lc($b) } @obj_name;
	}
}


##########################################################################
# read all network services defined
#
# service variables where svc_name equals the hash for each of these:
#
#	$svc_number 	= number of services read
#	@svc_name 	= names of all services
#	%svc_type 	= tcp, udp, icmp, rpc, group
#	%svc_dst_port 	= destination port
#	%svc_src_low 	= range source port from
#	%svc_src_high 	= range source port to
#	%svc_match	= if MATCH defines (for RPCs)
#	%svc_prolog	= RPC prolog
#	%svc_members 	= members, if a group
#	%svc_comment 	= comment for the service
sub ReadServices{
	my ($dummy)    = '';
	my ($name)     = '';
	my ($amember)  = '';
	my ($members)  = '';

	while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t)" ) ) {
		$line = &fromdos($line);
		&DebugLog("Svc.READ1: $line");
		while ( $line !~ /\t\t\: \(/ )  {
			$line = <INFILE>;
			$line = &fromdos($line);
			&DebugLog("Svc.READ2: $line");
		}
		($dummy,$name) = split(/\(/,$line,2) ;
		$amember  = '';
		$members  = '';
		$svc_shared{$name}="0";
		while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t)" ) ) {
			$line = &fromdos($line);
			&DebugLog("Svc.READ3: $line");
			($dummy,$lineparam) = split(/\(/,$line,2) ;
			$lineparam =~ s/\)$//;
			if ( "$lineparam" =~ /"\>(.*)\"/ ){  # this stands for ports bigger than...
				$lineparam = $1;
				$lineparam++;
				$lineparam = "$lineparam\:65535";
				$svc_dst_port{$name} = $lineparam;
			} elsif ( "$lineparam" =~ /"\<(.*)\"/ ){  # this stands for ports smaller than...
				$lineparam = $1;
				$lineparam--;
				$lineparam = "0\:$lineparam";
				$svc_dst_port{$name} = $lineparam;
			} elsif ( $line =~ /^\t\t\t:type \(/ ){
				$svc_type{$name} = lc($lineparam);
			} elsif ( $line =~ /^\t\t\t:exp \(/ ){           # ICMP extensions
				$lineparam =~ s/\"//g;
				if ($svc_type{$name} =~ /^other$/i) {	 # older CKPs store RPC program number here
					$lineparam =~ s/\"//g;
					$svc_dst_port{$name} = $lineparam;
				} else {
					$lineparam =~ s/\"//g;
					$svc_dst_port{$name} = $ICMPtranslate{$lineparam};
				}
				$svc_dst_port{$name} = $ICMPtranslate{$lineparam};
			} elsif ( $line =~ /^\t\t\t:port \(/ ){          # TCP/UDP destination port
				$lineparam =~ tr/-/:/;
				$svc_dst_port{$name} = $lineparam;
			} elsif ( $line =~ /^\t\t\t:src_port \(/ ){
				$svc_src_low{$name} = $lineparam;
				$svc_src_high{$name} = $lineparam;
			} elsif ( $line =~ /^\t\t\t:src_port_from \(/ ){
				$svc_src_low{$name} = $lineparam;
			} elsif ( $line =~ /^\t\t\t:src_port_to \(/ ){
				$svc_src_high{$name} = $lineparam;
			} elsif ( $line =~ /^\t\t\t:prematch \(/ ){
				$svc_match{$name} = $lineparam;
			} elsif ( $line =~ /^\t\t\t:prolog \(/ ){
				$svc_prolog{$name} = $lineparam;
			} elsif ( $line =~ /^\t\t\t:comments \(/ ){
				$svc_comment{$name} = $lineparam;
				$svc_comment{$name} =~ s/^\"|\"$//g;		#--- remove " at beginning and end
				$svc_comment{$name} =~ s/;/ /g;
			} elsif ( $line =~ /^\t\t\t: \(ReferenceObject/ ){
				while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t\t)" ) ) {
					$line = &fromdos($line);
					&DebugLog("Svc.READ4: $line");
					if ( $line =~ /^\t\t\t\t:Name \(/) {
						($dummy,$lineparam) = split(/\(/,$line,2) ;
						$lineparam =~ s/\)$//;
						$members = "$members§$lineparam";
					}
				}
			} elsif ( $line =~ /^\t\t\t: / ){
				($dummy,$amember) = split(/:\x20/,$line,2) ;
				$members = "$members§$amember";
			}
			elsif ( $line =~ /^\t\t\t\t:global_level \(1\)/ ){
				$svc_shared{$name}="1";
			}
		}
		$svc_name[$svc_number] = $name;
		if ( "$svc_type{$name}" eq 'group' ) {
			($dummy,$members) = split (/§/, $members, 2);
			$svc_members{$name} = $members;
		}
		&PrintLog('.');
		$svc_number += 1;
	}
	&PrintLog ("\n");
	$svc_type{'any'} = 'any';
	if ($FLAG_sortbytype) {
		@svc_name2 = sort { $svc_type{"$a"} cmp $svc_type{"$b"} or lc($a) cmp lc($b) } @svc_name;
	} else {
		@svc_name2 = sort { lc($a) cmp lc($b) } @svc_name;
	}

	@svc_name = uniq(@svc_name2);
}

##########################################################################
# register layer7  (name,service)
sub RegisterL7 {
	$name                  = $_[0];
	$l7_service{$name}     = $_[1];
	$l7_maxsize{$name}     = $_[2];
	$l7_fwd_to{$name}      = $_[3];
	$l7_fwd_with{$name}    = $_[4];
	$l7_rpc{$name}         = $_[5];
	$l7_match{$name}       = $_[6];
	$l7_matchprolog{$name} = $_[7];
	$l7_comment{$name}     = $_[8];

	$l7_name[$l7_number]   = $name;
	$l7_number += 1;
}

##########################################################################
# register user  (name)
sub RegisterUser {
	$user_name[$user_number] = $_[0];
	$user_number += 1;
}

##########################################################################
# read all network servers defined
#
# Object variables where srv_name equals the hash for each of these:
#
#	$srv_number 	= number of servers
#	@srv_name 	= names of all servers
#	%srv_type 	= radius, tacacs, ufp, cvp, group
#	%srv_members 	= members, if a group
#	%srv_priority 	= priority of the server
#	%srv_reference 	= reference of the server
#	%srv_comment 	= comment for the server
#	%srv_version	= version of the server

sub ReadServers{
	my ($dummy)     = '';
	my ($name)      = '';
	my ($lineparam) = '';
	my ($amember)   = '';
	my ($members)   = '';

	$srv_number = 0;
	while ( ($line = <INFILE> ) && ( fromdos("$line") ne "\t)" )) {
		$line = &fromdos($line);
		&DebugLog("Srv.READ1: $line");
		while ( $line !~ /\t\t\: \(/ )  {
			$line = <INFILE>;
			$line = &fromdos($line);
			&DebugLog("Srv.READ2: $line");
		}
		($dummy,$name) = split(/\(/,$line,2) ;
		$amember = '';
		$members = '';
		$srv_reference{$name} = '-';
		$priority{$name} = '';
		while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t)" )) {
			$line = &fromdos($line);
			&DebugLog("Srv.READ2: $line");
			($dummy,$lineparam) = split(/\(/,$line,2) ;
			$lineparam =~ s/\)$//;
			if ( $line =~ /^\t\t\t:type \(/ ){
				$srv_type{$name} = lc($lineparam);
			} elsif ( $line =~ /^\t\t\t:comments \(/ ){
				$srv_comment{$name} = $lineparam;
				$srv_comment{$name} =~ s/^\"|\"$//g;		#--- remove " at beginning and end
				$srv_comment{$name} =~ s/;/ /g;
			} elsif ( $line =~ /^\t\t\t:priority \(/ ){
				$srv_priority{$name} = lc($lineparam);
			} elsif ( $line =~ /^\t\t\t:version \(/ ){
				$srv_version{$name} = $lineparam;
				$srv_version{$name} =~ s/^\"|\"$//g;		#--- remove " at beginning and end
				$srv_version{$name} =~ s/;/ /g;
			} elsif ( $line =~ /^\t\t\t:server \(/ ){
				$line = &fromdos($line);
				while ( $line !~ /\t\t\t\t\:(refname|Name) \(/ )  {	# V4.1 | NG
					$line = <INFILE>;
					$line = &fromdos($line);
					&DebugLog("Srv.READ3: $line");
				}
				($dummy,$lineparam) = split(/\(/,$line,2) ;
				$srv_reference{$name} = $lineparam;
				$srv_reference{$name} =~ s/^\"|\"\)$|\)$//g;		#--- remove " at beginning and end
				$srv_reference{$name} =~ s/;/ /g;
			} elsif ( $line =~ /^\t\t\t: \(ReferenceObject/ ){
				while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t\t)" ) ) {
					$line = &fromdos($line);
					&DebugLog("Srv.READ4: $line");
					if ( $line =~ /^\t\t\t\t:Name \(/) {
						($dummy,$lineparam) = split(/\(/,$line,2) ;
						$lineparam =~ s/\)$//;
						$members = "$members§$lineparam";
					}
				}
			} elsif ( $line =~ /^\t\t\t: / ){
				($dummy,$amember) = split(/: /,$line,2) ;
				$members = "$members§$amember";
			}
		}
		if ( "$srv_type{$name}" eq 'group' ) {
			($dummy,$members) = split (/§/, $members, 2);
			$srv_members{$name} = $members;
		}
		$srv_name[$srv_number] = $name;
		$srv_number += 1;
		&PrintLog('.');
	}
	$srv_type{'any'} = 'any';
	if ($FLAG_sortbytype) {
		@srv_name = sort { $srv_type{"$a"} cmp $srv_type{"$b"} or lc($a) cmp lc($b) } @srv_name;
	} else {
		@srv_name = sort { lc($a) cmp lc($b) } @srv_name;
	}
}


##########################################################################
# read all resources defined
#
# resource variables where rsc_name equals the hash for each of these:
#
#	$rsc_number 	= number of ressources read
#	@rsc_name 	= names of all ressources
#	%rsc_maxsize 	= maximum size
#	%rsc_allowedchar= allowed characterset
#	%rsc_av_setting	= AntiVirus server handling
#	%rsc_av_server	= ...and it's server
#	%rsc_type	= smtp, http
#	%rsc_comment	= comment for the resource
#
#
sub ReadResources{
	my ($dummy)    = '';
	my ($name)     = '';
	my ($amember)  = '';
	my ($members)  = '';

	while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t)" ) ) {
		$line = &fromdos($line);
		&DebugLog("Res.READ1: $line");
		while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t\t)" ) ) {
			$line = &fromdos($line);
			&DebugLog("Res.READ2: $line");
		}
		&PrintLog('.');
		$rsc_number += 1;
	}
	&PrintLog ("\n");
}

##########################################################################
# read properties
#
#	%prop_setting{'XXX'}	= setting for XXX
#
#	of interest with respect to implicit rules:
#		rip, domain_udp, domain_tcp, established,
#		    icmpenable, fw1enable ==  true / false
#		rip_p, domain_udp_p, domain_tcp_p, established_p,
#		    icmpenable_p, fw1enable_p ==  first / "before last" / last
#
sub ReadProperties{
	my($line) = '';
	my($par)  = '';
	my($set)  = '';
	my($rest) = '';

	while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t)" ) ) {
		$line = &fromdos($line);
		&DebugLog("Prop.READ1: $line");
		&PrintLog('.');
		if ( "$line" =~ m/\t\t:.* \(.*\)$/ ){
			($par,$set) = split(/ \(/, $line, 2);
			$par =~ s/^\s+://;					#--- remove "    :" at the beginning
			$set =~ s/\)$//;					#--- remove ) at the end
			$set =~ s/^\"|\"$//g;				#--- remove " at beginning and end
			$prop_setting{"$par"} = "$set";
		}
	}
	&PrintLog("\n");
}


##########################################################################
# read NAT rules
#
#	$nat_number	 	= number of NAT rules read (array starting at zero)
#	@nat_disabled		= rule enabled=0, rule disabled=1
#	@nat_orig_from 		= ORIGINAL source object
#	@nat_orig_to 		= ORIGINAL destination object
#	@nat_orig_svc 		= ORIGINAL service object
#	@nat_transl_from 	= translated source object
#	@nat_transl_from_methd 	= translated source object method: 0=hide, 1=static
#	@nat_transl_to 		= translated destination object
#	@nat_transl_to_methd	= translated destination object method: 0=hide, 1=static
#	@nat_transl_svc 	= translated service object
#	@nat_transl_svc_methd 	= translated service object method: 0=hide, 1=static
#	@nat_install_on		= install rule on...
#	@nat_unmatched		= NAT rule does not match request
#
sub ReadNATrules{
	my ($mode)    = 'none';
	my ($param)   = '';
	my ($dummy)   = '';
	my ($wert)    = '';
	my ($user)    = '';
	my ($fileEOF) = 1;
	my ($allObjs) = '';
	my ($allSvc)  = '';
	my ($line)    = $_[0];

	while ( ( $line =~ /^\t:rule_adtr \(/ ) && ( $fileEOF ) ) {
		$line = &fromdos($line);
		&DebugLog("NAT.READ1: $line");
		$mode    = 'none';
		$nat_number  += 1;
		&PrintLog("\n\trule_adtr($nat_number)");

		while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t)" ) ) {
			$line = &fromdos($line);
			&DebugLog("NAT.READ2: $line");
			&PrintLog('.');
			if ( $line =~ /^\t\t:comments \(/ ){
				($dummy,$wert) = split(/\(/,$line,2) ;
				$wert =~ s/\)$//;			#--- remove ) at the end
				$wert =~ s/^\"|\"$//g;			#--- remove " at beginning and end
				$wert =~ s/;/ /g;
				$nat_comment[$nat_number] = $wert ;
			}
			elsif ( $line =~ /^\t\t:header_text \(/ ){
				($dummy,$wert) = split(/\(/,$line,2) ;
				$wert =~ s/\)$//;			#--- remove ) at the end
				$wert =~ s/^\"|\"$//g;			#--- remove " at beginning and end
				$wert =~ s/;/ /g;
				$nat_header[$nat_number] = $wert ;
			}
			elsif ( $line =~ /^\t\t:disabled \(true\)/ ){
				$nat_disabled[$nat_number] = 1;
			} elsif ( $line =~ /^\t\t:(src_adtr|dst_adtr|services_adtr|src_adtr_translated|dst_adtr_translated|services_adtr_translated|install) \(/ ){
				($dummy,$wert) = split(/:/,$line,2) ;
				($mode,$dummy) = split(/ /,$wert,2) ;
			} elsif ("$mode" eq 'src_adtr') {
				if ($line =~ /^\t\t\t: /) {
					($dummy,$wert) = split(/: /,$line,2) ;
					$wert=~s/^\(//;
					if ("$wert" eq "ReferenceObject") {
						while($line = <INFILE>){
							fromdos($line);
							if($line =~ /^\t\t\t\t:Name/){
								($dummy1,$wert1) = split(/:Name/,$line) ;
								($dummy2,$wert2) = split(/ /,$wert1) ;
								($dummy3,$wert3) = split(/\(/,$wert2) ;
								($dummy4,$wert4) = split(/\)/,$wert3) ;
								$nat_orig_from[$nat_number] = "$dummy4";
								$allObjs .= "$dummy4§";
							} elsif(fromdos("$line") eq "\t\t)"){
								last;
							}
						}
					} else {
						$nat_orig_from[$nat_number] = "$wert";
						$allObjs .= "$wert§";
					}

				}
			} elsif ("$mode" eq 'dst_adtr') {
				if ($line =~ /^\t\t\t: /) {
					($dummy,$wert) = split(/: /,$line,2) ;
					$wert=~s/^\(//;
					if ("$wert" eq "ReferenceObject") {
						while($line = <INFILE>){
							fromdos($line);
							if($line =~ /^\t\t\t\t:Name/){
								($dummy1,$wert1) = split(/:Name/,$line) ;
								($dummy2,$wert2) = split(/ /,$wert1) ;
								($dummy3,$wert3) = split(/\(/,$wert2) ;
								($dummy4,$wert4) = split(/\)/,$wert3) ;
								$nat_orig_to[$nat_number] = "$dummy4";
								$allObjs .= "$dummy4§";
							} elsif(fromdos("$line") eq "\t\t)"){
								last;
							}
						}
					} else {
						$nat_orig_to[$nat_number] = "$wert";
						$allObjs .= "$wert§";
					}
				}
			} elsif ("$mode" eq 'services_adtr') {
				if ($line =~ /^\t\t\t: /) {
					($dummy,$wert) = split(/: /,$line,2) ;
					$wert=~s/^\(//;
					if ("$wert" eq "ReferenceObject") {
						while($line = <INFILE>){
							fromdos($line);
							if($line =~ /^\t\t\t\t:Name/){
								($dummy1,$wert1) = split(/:Name/,$line) ;
								($dummy2,$wert2) = split(/ /,$wert1) ;
								($dummy3,$wert3) = split(/\(/,$wert2) ;
								($dummy4,$wert4) = split(/\)/,$wert3) ;
								$nat_orig_svc[$nat_number] = "$dummy4";
								$allSvc .= "$dummy4§";
							}elsif(fromdos("$line") eq "\t\t)"){
								last;
							}
						}
					}else {
						$nat_orig_svc[$nat_number] = "$wert";
						$allSvc .= "$wert§";
					}
				}
			} elsif ("$mode" eq 'src_adtr_translated') {
				if ($line =~ /^\t\t\t: /) {
					($dummy,$wert) = split(/: /,$line,2) ;
					$wert=~s/^\(//;
					if ("$wert" eq "ReferenceObject") {
						while($line = <INFILE>){
							fromdos($line);
							if($line =~ /^\t\t\t\t:Name/){
								($dummy1,$wert1) = split(/:Name/,$line) ;
								($dummy2,$wert2) = split(/ /,$wert1) ;
								($dummy3,$wert3) = split(/\(/,$wert2) ;
								($dummy4,$wert4) = split(/\)/,$wert3) ;
								if ( lc("$dummy4") eq 'any' ) { $dummy4 = 'ORIGINAL'; }
								$nat_transl_from[$nat_number] = "$dummy4";
								$allObjs .= "$dummy4§";
							}elsif(fromdos("$line") eq "\t\t)"){
								last;
							}
						}

					} else {
						if ( lc("$wert") eq 'any' ) { $wert = 'ORIGINAL'; }
						$nat_transl_from[$nat_number] = "$wert";
						$allObjs .= "$wert§";
					}

				} elsif ($line =~ /^\t\t\t:adtr_method/) {
					if ( $line =~ m/adtr_method_static/ ) {
						$nat_transl_from_methd[$nat_number] = 1;
					} else {
						$nat_transl_from_methd[$nat_number] = 0;
					}
				}
			} elsif ("$mode" eq 'dst_adtr_translated') {
				if ($line =~ /^\t\t\t: /) {
					($dummy,$wert) = split(/: /,$line,2) ;
					$wert=~s/^\(//;
					if ("$wert" eq "ReferenceObject") {
						while($line = <INFILE>){
							fromdos($line);
							if($line =~ /^\t\t\t\t:Name/){
								($dummy1,$wert1) = split(/:Name/,$line) ;
								($dummy2,$wert2) = split(/ /,$wert1) ;
								($dummy3,$wert3) = split(/\(/,$wert2) ;
								($dummy4,$wert4) = split(/\)/,$wert3) ;
								if ( lc("$dummy4") eq 'any' ) { $dummy4 = 'ORIGINAL'; }
								$nat_transl_to[$nat_number] = "$dummy4";
								$allObjs .= "$dummy4§";
								$nat_transl_to_methd[$nat_number] = 1;
							}elsif(fromdos("$line") eq "\t\t)"){
								last;
							}
						}
					} else {
						if ( lc("$wert") eq 'any' ) { $wert = 'ORIGINAL'; }
						$nat_transl_to[$nat_number] = "$wert";
						$allObjs .= "$wert§";
						$nat_transl_to_methd[$nat_number] = 1;
					}
				}
			} elsif ("$mode" eq 'services_adtr_translated') {
				if ($line =~ /^\t\t\t: /) {
					($dummy,$wert) = split(/: /,$line,2) ;
					$wert=~s/^\(//;
					if ("$wert" eq "ReferenceObject") {
						while($line = <INFILE>){
							fromdos($line);
							if($line =~ /^\t\t\t\t:Name/){
								($dummy1,$wert1) = split(/:Name/,$line) ;
								($dummy2,$wert2) = split(/ /,$wert1) ;
								($dummy3,$wert3) = split(/\(/,$wert2) ;
								($dummy4,$wert4) = split(/\)/,$wert3) ;
								if ( lc("$dummy4") eq 'any' ) { $dummy4 = 'ORIGINAL'; }
								$nat_transl_svc[$nat_number] = "$dummy4";
								$allSvc .= "$dummy4§";
								$nat_transl_svc_methd[$nat_number] = 1;
							}elsif(fromdos("$line") eq "\t\t)"){
								last;
							}
						}
					} else {
						if ( lc("$wert") eq 'any' ) { $wert = 'ORIGINAL'; }
						$nat_transl_svc[$nat_number] = "$wert";
						$allSvc .= "$wert§";
						$nat_transl_svc_methd[$nat_number] = 1;
					}
				}
			} elsif ("$mode" eq 'install') {
				if  ( $line =~ /^\t\t\t: / ) {
					($dummy,$wert) = split(/: /,$line,2) ;
					$wert=~s/^\(//;
					if ( "$wert" ne "ReferenceObject") {
						if ( "$nat_install_on[$nat_number]" eq '') {
							$nat_install_on[$nat_number] = "$wert";
						} else {
							$nat_install_on[$nat_number] = "$nat_install_on[$nat_number]§$wert";
						}
					}
				}
			}
		} #--- inner while, the complete rule
		$allObjs = '';
		$allSvc = '';
		$fileEOF = ( $line = <INFILE> );
	} #--- outer while
}


##########################################################################
# read Access rules
#
#	$access_number	 	= number of access rules read (array starting at zero)
#	@access_disabled	= rule enabled=0, rule disabled=1
#	@access_from		= list of source objects, separated by space
#	@access_from_negated	= from-list negated=1, standard=0
#	@access_to		= list of destination objects, separated by space
#	@access_to_negated	= to-list negated=1, standard=0
#	@access_services	= list of services, separated by space
#	@access_services_negated= services-list negated=1, standard=0
#	@access_action		= action deny, allow, encrypt, ...
#	@access_track		= log: long, short, account, ...
#	@access_time		= time object (not really implemented yet)
#	@access_install_on	= install rule on...
#	@access_header		= header above this particular rule
#	@access_comment		= comment on this particular rule
#	@access_clauth_to_hours = client auth timeout hours
#	@access_clauth_to_minutes       = client auth timeout minutes
#	@access_clauth_to_infinite      = client auth timeout infinity
#	@access_clauth_to       = actual client auth timeout value
#	@access_clauth_sessions = max client auth sessions
#	@access_clauth_sessions_infinite        = client auth sessions infinity
#	@access_clauth_sessions_value   = actual client auth max sessions
#
sub ReadAccessRules{
	my ($mode)    = 'none';
	my ($param)   = '';
	my ($dummy)   = '';
	my ($wert)    = '';
	my ($fileEOF) = 1;
	my ($allObjs) = '';
	my ($allSvc)  = '';
	my ($line)    = $_[0];

	&DebugLog("Access.READ1a: $line");
	$access_number = -1;

	#----------------------------	# GT: only for print, what you want to match
	$plogic = $Match_Logic;
	$plogic =~ s/com/ com=$Match_Comment /;
	$plogic =~ s/src/ src=$Match_Source /;
	$plogic =~ s/dst/ dst=$Match_Destination /;
	$plogic =~ s/svc/ svc=$Match_Service /;
	if ($Match_Case) { $plogic = $plogic . " /case sensitive"; }
	else { $plogic = $plogic . " /ignore case"; }

	$HTMLtitle_ext = " (filtered) " 				if ($FLAG_match);
	$HTMLmatch = " rules filtered by: " . $plogic	if ($FLAG_match);


	while ( ( $line =~ /^\t:rule \(/ ) && $fileEOF ) {
		&DebugLog("Access.READ1: $line");
		$mode    = 'none';
		$access_number  += 1;
		&PrintLog("\n\trule($access_number)");

		$access_from_negated[$access_number] = 0;
		$access_to_negated[$access_number] = 0;
		$access_services_negated[$access_number] = 0;
		$access_from_users[$access_number]="";

		while ( ($line = <INFILE>) && ( fromdos("$line") ne "\t)" ) ) {
			$line = &fromdos($line);
			&DebugLog("Access.READ2: $line");
			&PrintLog('.');
			if ( $line =~ /^\t\t:comments \(/ ){
				($dummy,$wert) = split(/\(/,$line,2) ;
				$wert =~ s/\)$//;			#--- remove ) at the end
				$wert =~ s/^\"|\"$//g;			#--- remove " at beginning and end
				$wert =~ s/;/ /g;
				$access_comment[$access_number] = $wert ;
				#$access_comment[$access_number] = $wert ;
			} elsif ( $line =~ /^\t\t:header_text \(/ ){
				($dummy,$wert) = split(/\(/,$line,2) ;
				$wert =~ s/\)$//;			#--- remove ) at the end
				$wert =~ s/^\"|\"$//g;			#--- remove " at beginning and end
				$wert =~ s/;/ /g;
				$access_header[$access_number] = $wert ;
			} elsif ( $line =~ /^\t\t:disabled \(true\)/ ){
				$access_disabled[$access_number] = 1;
			} elsif ( $line =~ /^\t\t:name \(/ ){     # Added for R65 compatiliby 2008-02-12 By Jacob
				($dummy,$wert) = split(/\(/,$line,2) ; # Added for R65 compatiliby 2008-02-12 By Jacob
				$wert =~ s/\)$//;                      # Added for R65 compatiliby 2008-02-12 By Jacob
				$wert =~ s/^\"|\"$//g;                 # Added for R65 compatiliby 2008-02-12 By Jacob
				$wert =~ s/;/ /g;                      # Added for R65 compatiliby 2008-02-12 By Jacob
				$wert =~ s/^##//g;                     # Added for R65 compatiliby 2008-02-12 By Jacob
				$access_name[$access_number] = $wert ; # Added for R65 compatiliby 2008-02-12 By Jacob
			} elsif ( $line =~ /^\t\t:(src|dst|services|action|track|install|time) \(/ ){
				($dummy,$wert) = split(/:/,$line,2) ;
				($mode,$dummy) = split(/ /,$wert,2) ;

			}
			elsif ( $line =~ /^\t\t:global_location \(/ ){     # Added for R65 compatiliby 2008-02-12 By Jacob
				($dummy,$wert) = split(/\(/,$line,2) ; # Added for R65 compatiliby 2008-02-12 By Jacob
				$wert =~ s/\)$//;                      # Added for R65 compatiliby 2008-02-12 By Jacob
				$wert =~ s/^\"|\"$//g;                 # Added for R65 compatiliby 2008-02-12 By Jacob
				$wert =~ s/;/ /g;                      # Added for R65 compatiliby 2008-02-12 By Jacob
				$wert =~ s/^##//g;                     # Added for R65 compatiliby 2008-02-12 By Jacob
				$access_location[$access_number] = $wert ; # Added for R65 compatiliby 2008-02-12 By Jacob
			}
			elsif ("$mode" eq 'src') {
				if ($line =~ /^\t\t\t\t?:\s/) {
					###--- not overly clean: optional TAB is good for
					###--- normal and compound objects
					($dummy,$wert) = split(/:\s+\(*/,$line,2) ;
					$wert=~s/^\(//;		#--- remove ( at the beginning of user-rules
					$wert=~s/^"|"$//g;		#--- remove \" from user-rules
					if ($wert eq "Any)"){$wert="Any";}
					if ( "$wert" ne "ReferenceObject") {
						if ( "$access_from[$access_number]" eq '') {
							$access_from[$access_number] = "$wert";
						} else {
							$access_from[$access_number] = "$access_from[$access_number]§$wert";
						}
						# split 'user@location' into 'user' and 'location' then add 'location' only to $wert
						$wert =~ s/^.*@(.*)$/$1/;
						$allObjs .= "$wert§";
					}
				}
				elsif ($line =~ /^\t\t\t\t:\s\("([^"]+)"/) { # Auth-Regel
					$wert = $1 ;
					$wert=~s/^\(//;				#--- remove ( at the beginning of user-rules
					if ( "$wert" ne "ReferenceObject") {
						if ( "$access_from[$access_number]" eq '') {
							$access_from[$access_number] = "$wert";
						} else {
							$access_from[$access_number] = "$access_from[$access_number]§$wert";
						}
						$allObjs .= "$wert§";
					}
				}
				elsif ($line =~ /^\t\t\t:op \(\"not in\"\)/) {
					$access_from_negated[$access_number] = 1;
				}
				elsif ($line =~ /^\t\t\t:op \(not in\)/) {
					$access_from_negated[$access_number] = 1;
				}
				elsif ($line =~ /^\t\t\t:compound \(\)/) {
					$isUser='false';
				}
				elsif ($line =~ /^\t\t\t:compound \(/) {
					$isUser='true';
				}

				if (($line =~ /^\t\t\t\t?:\s/) && ($isUser eq 'true')){
					($dummy,$wert) = split(/:\s+\(*/,$line,2) ;
					$wert=~s/^\(//;		#--- remove ( at the beginning of user-rules
					$wert=~s/^"|"$//g;		#--- remove \" from user-rules
					if ($wert eq "Any)"){$wert="Any";}
					if ( "$wert" ne "ReferenceObject") {
						$wert =~ s/^(.*)@.*$/$1/;
						if ( "$access_from_users[$access_number]" eq '') {
							$access_from_users[$access_number] = "$wert";
						} else {
							$access_from_users[$access_number] = "$access_from_users[$access_number]§$wert";
						}
						# split 'user@location' into 'user' and 'location' then add 'location' only to $wert
						#$wert =~ s/^.*@(.*)$/$1/;
						$allObjs .= "$wert§";
					}

				}
				elsif(($isUser eq 'true') && ($line =~ /^\t\t\t?:\s\)/)){
					$isUser='false';
				}
			}
			elsif ("$mode" eq 'dst') {
				if ($line =~ /^\t\t\t\t?: /) {
					###--- not overly clean: optional TAB is good for
					###--- normal and compound objects
					($dummy,$wert) = split(/:\s+\(*/,$line,2) ;
					if ($wert eq "Any)"){$wert="Any";}
					if ( "$wert" ne "ReferenceObject") {
						if ( "$access_to[$access_number]" eq '') {
							$access_to[$access_number] = "$wert";
						} else {
							$access_to[$access_number] = "$access_to[$access_number]§$wert";
						}
						$allObjs .= "$wert§";
					}
				} elsif ($line =~ /^\t\t\t:op \(\"not in\"\)/) {
					$access_to_negated[$access_number] = 1;
				}
				elsif ($line =~ /^\t\t\t:op \(not in\)/) {
					$access_to_negated[$access_number] = 1;
				}
			}
			elsif ("$mode" eq 'services') {
				($dummy,$wert) = split(/\(/,$line,2) ;   #--- just for security servers
				if ( $line =~ /^\t\t\t\t?: \(smtp-\>.*/ ) {
					if ( "$access_services[$access_number]" eq '') {
						$access_services[$access_number] = "$wert";
					} else {
						$access_services[$access_number] = "$access_services[$access_number]§$wert";
					}
				} elsif ( $line =~ /^\t\t\t\t?: \(http-\>.*/ ) {
					if ( "$access_services[$access_number]" eq '') {
						$access_services[$access_number] = "$wert";
					} else {
						$access_services[$access_number] = "$access_services[$access_number]§$wert";
					}
				} elsif ( $line =~ /^\t\t\t\t?: \(https-\>.*/ ) {
					if ( "$access_services[$access_number]" eq '') {
						$access_services[$access_number] = "$wert";
					} else {
						$access_services[$access_number] = "$access_services[$access_number]§$wert";
					}
				} elsif ( $line =~ /^\t\t\t\t?: \(ftp-\>.*/ ) {
					if ( "$access_services[$access_number]" eq '') {
						$access_services[$access_number] = "$wert";
					} else {
						$access_services[$access_number] = "$access_services[$access_number]§$wert";
					}
				} elsif ($line =~ /^\t\t\t:\s+/) {		# PS	(any trouble
					($dummy,$wert) = split(/:\s+\(*/,$line,2) ;	# PS	(any trouble

					if ( "$access_services[$access_number]" eq '') {
						if ($wert eq "Any)"){$wert="Any";}
						$access_services[$access_number] = "$wert";
					} else {
						if ($wert eq "Any)"){$wert="Any";}
						$access_services[$access_number] = "$access_services[$access_number]§$wert";
					}
					$allSvc .= "$wert§";
				} elsif ($line =~ /^\t\t\t:op \(\"not in\"\)/) {
					$access_services_negated[$access_number] = 1;
				}
				elsif ($line =~ /^\t\t\t:op \(not in\)/) {
					$access_services_negated[$access_number] = 1;
				}
			}
			elsif ("$mode" eq 'action') {
				$wert =~ s/[\s\"]//g;		# PS
				$wert = lc ($wert);		# PS
				if  ( $line =~ /^\t\t\t:\s+\([a-z]*/ ) {	# PS
					($dummy,$wert) = split(/:\s+\(/,$line,2);	# PS
					$wert =~ s/[\s\"]//g;		# PS
					$wert = lc ($wert);		# PS
					$access_action[$access_number] = $wert;
				}
				# read client auth properties
				while($line = <INFILE>){
					fromdos($line);
					if($line =~ /^\t\t\t\t:clauth_to_hours \(([0-9]+)\)/){
						$access_clauth_to_hours[$access_number] = $1;
					}elsif($line =~ /^\t\t\t\t:clauth_to_minutes \(([0-9]+)\)/){
						$access_clauth_to_minutes[$access_number] = $1;
					}elsif($line =~ /^\t\t\t\t:clauth_to_infinite \((false|true)\)/){
						$access_clauth_to_infinite[$access_number] = $1;
					}elsif($line =~ /^\t\t\t\t:sessions \(([0-9]+)\)/){
						$access_sessions[$access_number] = $1;
					}elsif($line =~ /^\t\t\t\t:sessions_infinite \((false|true)\)/){
						$access_sessions_infinite[$access_number] = $1;
					}elsif(fromdos("$line") eq "\t\t)"){
						# set $access_clauth_to
						$access_clauth_to[$access_number] =
								$access_clauth_to_infinite[$access_number] eq "false" ?
							$access_clauth_to_hours[$access_number] * 60 + $access_clauth_to_minutes[$access_number] :
							"infinite";

						# set $access_sessions_value
						$access_sessions_value[$access_number] =
								$access_sessions_infinite[$access_number] eq "false" ?
							$access_sessions[$access_number] :
							"infinite";
						$mode = 'none';
						last;
					}
				}
			}
			elsif ("$mode" eq 'track') {
				if  ( $line =~ /^\t\t\t: \"?[A-Z]([a-z]*)\"?/ ) {
					($dummy,$wert) = split(/: /,$line,2) ;
					$access_track[$access_number] = "$wert";
				}
			}
			elsif ("$mode" eq 'install') {
				if  ( $line =~ /^\t\t\t: / ) {
					($dummy,$wert) = split(/:\s+\(*/,$line,2) ;		# PS left parenthesis
					$wert =~ s/\(//; # Handle Gateway object
					$allObjs .= "$wert§";
					if ( "$wert" ne "ReferenceObject") {
						if ( "$access_install_on[$access_number]" eq '') {
							$access_install_on[$access_number] = "$wert";
						} else {
							$access_install_on[$access_number] = "$access_install_on[$access_number]§$wert";
						}
					}
				}
			}
			elsif ("$mode" eq 'time') {
				if  ( $line =~ /^\t\t\t: .*/ ) {
					($dummy,$wert) = split(/:\s+\(*/,$line,2) ;
					if ($wert eq "Any)"){$wert="Any";}
					if ( "$access_time[$access_number]" eq '') {
						$access_time[$access_number] = "$wert";
					} else {
						$access_time[$access_number] = "$access_time[$access_number] $wert";
					}
				}
			}
		} #--- inner while, i.e. one rule

		$allObjs = '';
		$allSvc = '';
		$fileEOF = ($line = <INFILE>);
		$line = &fromdos($line);
		&DebugLog("Access.READ1b: $line");
		# Below added for R65 features 2008-02-12 By Jacob
		if (defined $access_name[$access_number]){
			$access_comment[$access_number]="Name:$access_name[$access_number], Comment: $access_comment[$access_number]";
		}
	} #--- outer while
	return &fromdos("$line");
}



##########################################################################
##########################################################################
###   Print FWdoc config files
##########################################################################
##########################################################################


##########################################################################
# print or Nothing
#	file handle
#	parameter string (may NOT be null)
#	object string - maybe null, in which case nothing is printed
#	final string - comma, colon, bracket, whatever - maybe null

sub PrintOrNothing {
	my ($FILE)         = $_[0];
	my ($param)        = $_[1];
	my ($object)       = $_[2];
	my ($final)        = $_[3];

	if ( "$object" ne '') {
		print $FILE "\"$param\": \"$object\"$final\n";
	}
}

##########################################################################
# print implicit rules
#	location id ( first / "before last" / last
sub subImplicit_Output {
	my ($locstr)       = $_[0];

	if ( $FLAG_implicitrules ) {
		if ( ("$prop_setting{'fw1enable'}" eq 'true') &&
			(lc("$prop_setting{'fw1enable_p'}") eq "$locstr") ) {
			# FW1_mgmt
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"FW1 Host"} ], "to": [ "FW1 Management" ], "services": [ {"layer3":"FW1_mgmt"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print "\n";
			# FW1_ela
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"FloodGate1- Host"} ], "to": [ "FW1 Management" ], "services": [ {"layer3":"FW1_ela"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print "\n";
			# RDP
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"Any"} ], "to": [ "Any" ], "services": [ {"layer3":"RDP"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print "\n";
			# FW1_cvp
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [{"object": "FW1 Host" ]}, "to": [ "CVP-Servers" ], "services": [ {"layer3":"FW1_cvp"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print "\n";
			# FW1_ufp
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": {"object":[ "FW1 Host" ]}, "to": [ "UFP-Servers" ], "services": [ {"layer3":"FW1_ufp"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print "\n";
			# RADIUS
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"FW1 Host"} ], "to": [ "Radius-Servers" ], "services": [ {"layer3":"RADIUS"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print "\n";
			# TACACS
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"FW1 Host"} ], "to": [ "TACACS-Servers" ], "services": [ {"layer3":"TACACS"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print "\n";
			# ldap
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"FW1 Host"} ], "to": [ "LDAP-Servers" ], "services": [ {"layer3":"ldap"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print '"action": "accept", "log": "none", "time": "Any",';
			print "\n";
			# load_agent
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"FW1 Host"} ], "to": [ "Logical-Servers" ], "services": [ {"layer3":"load_agent"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print '"action": "accept", "log": "none", "time": "Any",';
			print "\n";
			# ike
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"FW1 Host"} ], "to": [ "Any" ], "services": [ {"layer3":"IKE"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print '"action": "accept", "log": "none", "time": "Any",';
			print "\n";
			# FW1_topo
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"Any"} ], "to": [ "FW1 Host" ], "services": [ {"layer3":"FW1_topo"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print '"action": "accept", "log": "none", "time": "Any",';
			print "\n";
			# FW1_key
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"Any"} ], "to": [ "FW1 Host" ], "services": [ {"layer3":"FW1_key"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print '"action": "accept", "log": "none", "time": "Any",';
			print "\n";
			# IKE
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"Any"} ], "to": [ "FW1 Host" ], "services": [ {"layer3":"IKE"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print '"action": "accept", "log": "none", "time": "Any",';
			print "\n";
			# FW1
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"FW1 Host"} ], "to": [ "FW1 Host" ], "services": [ {"layer3":"FW1"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] }, ';
			print "\n";
			# FW1_log
			print '{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"FW1 Host"} ], "to": [ "FW1 Host" ], "services": [ {"layer3":"FW1_log"} ], "comment": "Implicit rule:  Enable FW1",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] } ';
			print "\n";
		}
		# outgoing
		if ( ("$prop_setting{'outgoing'}" eq 'true') &&
			(lc("$prop_setting{'outgoing_p'}") eq "$locstr") ) {
			print ',{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"FW1 Host"} ], "to": [ "Any" ], "services": [ {"layer3":"Any"} ], "comment": "Implicit rule: Outgoing Connections",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] } ';
			print "\n";
		}
		# RIP
		if ( ("$prop_setting{'rip'}" eq 'true') &&
			(lc("$prop_setting{'rip_p'}") eq "$locstr") ) {
			print ',{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"Any"} ], "to": [ "Any" ], "services": [ {"layer3":"rip"} ], "comment": "Implicit rule:  Enable RIP",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] } ';
			print "\n";
		}

		# ICMP
		if ( ("$prop_setting{'icmpenable'}" eq 'true') &&
			(lc("$prop_setting{'icmpenable_p'}") eq "$locstr") ) {
			print ',{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"Any"} ], "to": [ "Any" ], "services": [ {"layer3":"icmp"} ], "comment": "Implicit rule:  Enable ICMP",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] } ';
			print "\n";
		}
		# domain TCP
		if ( ("$prop_setting{'domain_tcp'}" eq 'true') &&
			(lc("$prop_setting{'domain_tcp_p'}") eq "$locstr") ) {
			print ',{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"Any"} ], "to": [ "Any" ], "services": [ {"layer3":"dns-tcp"} ], "comment": "Implicit rule:  Enable Domain-TCP",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] } ';
			print "\n";
		}
		# domain UDP
		if ( ("$prop_setting{'domain_udp'}" eq 'true') &&
			(lc("$prop_setting{'domain_udp_p'}") eq "$locstr") ) {
			print ',{ "enabled": "yes", "from_inverted": "no", "to_inverted": "no", "services_inverted": "no", ';
			print '"from": [ {"object":"Any"} ], "to": [ "Any" ], "services": [ {"layer3":"dns-upd"} ], "comment": "Implicit rule:  Enable Domain-UPD",';
			print '"action": "accept", "log": "none", "time": "Any",';
			print '"install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] } ';
			print "\n";
		}
	}
}

##########################################################################
# print configuration into FWdoc file
#	filename for the resulting file

sub Output_FWdoc {
	my ($name)         = '';
	my ($linkto)       = '';
	my ($printcomment) = '';
	my ($comma)        = '';
	my (@loctime)      = localtime();

	print "{\n  \"firewall\": { \n";
	print "        \"brand\": \"CheckPoint\",\n";
	print "        \"type\": \"FireWall-1 / VPN-1\",\n";
	print "        \"version\": \"3.0 - 4.1 - NG R65\",\n";
	print '        "date": "';
	print $loctime[5]+1900 . "-$loctime[4]-$loctime[3]";
	print "\",\n";
	print '        "identifier": "';
	print $FW1rules;
	print "\",\n";
	print '        "filter": [],';
	print '        "comment": "Generated: by ';
	print "$SCRIPT_INFORMATION\"\n";
	print "  \},\n";
	#----------------------------- Access rules -----------------------------
	print "  \"accessrules\": \[ \n";
	for ( $i = 0; $i<=$access_number; $i++ ) {
		if ( $i == 0 ){
			subImplicit_Output ('first');
		} elsif ( $i == $access_number ){
			subImplicit_Output ('before last');
		}
		print "    $comma\{\n";
		$comma=',';
		$number = $i + 1;
		print "        \"number\": \"$number\",\n";
		if ( $access_header[$i] ) {
			print '        "header": "';
			print $access_header[$i];
			print '",';
			print "\n";
		} else {
			print '        "header": "';
			print '",';
			print "\n";
		}
		if ( $access_disabled[$i] ) {
			print '        "enabled": "no",';
		} else {
			print '        "enabled": "yes",';
		}
		print "\n";

		print '        "from": [';
		print "\n";
		$scomma='';
		@obj_array = split (/§/, $access_from[$i]);
		foreach $name (@obj_array){
			($nusr,$nnam) = split (/\@/, $name, 2);
			if ( length($nnam) == 0 ) {
				print "            $scomma\{\"object\": \"$name\" \}\n";
			} else {
				print "            $scomma\{\"object\": \"$nnam\", \"user\": \"$nusr\" \}\n";
				RegisterUser($nusr);
			}
			$scomma=',';
		}
		print "        \],\n";



		if ( $access_from_negated[$i] ) {
			print '        "from_inverted": "yes",';
		} else {
			print '        "from_inverted": "no",';
		}
		print "\n";

		#
		print '        "users": [';
		print "\n";
		$scomma='';
		@obj_array = split (/§/, $access_from_users[$i]);
		foreach $name (@obj_array){
			print "            $scomma\"$name\"\n";
			$scomma=',';
		}
		print "        \],\n";
		print "\n";
		#

		print '        "to": [';
		print "\n";
		$scomma='';
		@obj_array = split (/§/, $access_to[$i]);
		foreach $name (@obj_array){
			print "            $scomma\"$name\"\n";
			$scomma=',';
		}
		print "        \],\n";
		if ( $access_to_negated[$i] ) {
			print '        "to_inverted": "yes",';
		} else {
			print '        "to_inverted": "no",';
		}
		print "\n";

		print '        "services": [';
		print "\n";
		$scomma='';
		@obj_array = split (/§/, $access_services[$i]);
		foreach $name (@obj_array){
			($nsvc,$nl7) = split (/->/, $name, 2);
			if ( length($nl7) == 0 ) {
				print "            $scomma\{\"layer3\": \"$name\" \}\n";
			} else {
				print "            $scomma\{\"layer3\": \"$nsvc\", \"layer7\": \"L7" . $nsvc . "_$nl7\" \}\n";
				RegisterL7("L7" . $nsvc . "_$nl7", "$nsvc", "", "", "", "", "", "", "$nsvc-Filter $nl7");
			}
			$scomma=',';
		}
		print "        \],\n";
		if ( $access_services_negated[$i] ) {
			print '        "services_inverted": "yes",';
		} else {
			print '        "services_inverted": "no",';
		}
		print "\n";

		print '        "action": "';
		print $access_action[$i];
		print "\",\n";
		print '        "action_qualifier": "';
		# print out client auth properties in 'action' column
		if($access_action[$i] eq "clientauth"){
			print "t : $access_clauth_to[$i] min, s : $access_sessions_value[$i]\",\n";
		} else {
			print "\",\n";
		}

		print '        "log": "';
		print $access_track[$i];
		print "\",\n";



		#----- unclean, but we don't have TIME objects handled yet.
		#----- so we do the type handling manually here.
		print '        "time": "';
		if ( lc("$access_time[$i]") eq 'any' ) {
			print "Any";
		} else{
			print $access_time[$i];
		}
		print "\",\n";

		print '        "install_on": [';
		print "\n";
		$scomma='';
		@obj_array = split (/§/, $access_install_on[$i]);
		foreach $name (@obj_array){
			print "            $scomma\{\n";
			$scomma=',';
			print '                "firewall": "';
			print "$name\",\n";
			print '                "interface": [ "Any" ],';
			print "\n";
			print '                "method": "fw1"';
			print "\n";
			print "            \}\n";
		}
		print "        \],\n";

		print '        "comment": "';
		$access_comment[$i] = encode_utf8($access_comment[$i]);
		print $access_comment[$i];
		print "\",\n";

		print '        "location": "';
		print $access_location[$i];
		print "\"\n";

		print "    \}\n";
	}
	subImplicit_Output ('last');



	print "  \],\n";
	$comma='';

	#----------------------------- NAT rules -----------------------------
	$natrulesfinal = '';
	if ( $nat_number > 0 ) {
		print "  \"natrules\": \[ \n";
		# commented by Albert Estevez
		#$natrulesindent = ',';
		$natrulesindent = '';

		$natrulesfinal = "  \],\n";
	} else {
		#$natrulesindent = "  \"natrules\": \[ \n";
		print "  \"natrules\": \[ \n";
		$natrulesfinal = "  \],\n";
	}
	#Added by Albert Estevez
	$number="0";
	#--- now the implicit NAT rules ---
	foreach $name (@obj_name){
		if ( "$obj_NATadr{$name}" ne '' ) {
			$number=$number+1;
			$natrulesfinal = "  \],\n";
			#--- forward rule
			print "    $natrulesindent\{\n";
			$natrulesindent = ',';
			print '        "enabled": "yes",';
			print "\n";

			print '        "orig_from": [ "';
			print "$name\" ],\n";

			print '        "orig_to": [ "Any" ]';
			print ",\n";

			print '        "orig_service": [ "Any" ]';
			print ",\n";

			print '        "nat_type": "';
			if ( $obj_NATtype{$name} ) {
				print 'static';
			} else {
				print 'masq';
			}
			print "\",\n";

			print '        "nat_from": "';
			print "$obj_NATadr{$name}\",\n";

			print '        "nat_to": "ORIGINAL"';
			print ",\n";

			print '        "nat_service": "ORIGINAL"';
			print ",\n";

			print '	       "install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] ';
			print ",\n";

			print '        "comment": "(implicit)"';
			print "\n";
			print "    \},\n";
			#--- backward rule
			print "    \{\n";
			print '        "enabled": "yes",';
			print "\n";

			print '        "orig_from": [ "Any" ]';
			print ",\n";

			print '        "orig_to": [ "';
			print "$name\" ],\n";

			print '        "orig_service": [ "Any" ]';
			print ",\n";

			print '        "nat_type": "';
			if ( $obj_NATtype{$name} ) {
				print 'static-ip';
			} else {
				print 'masq-ip';
			}
			print "\",\n";

			print '        "nat_from": "';
			print "$obj_NATadr{$name}\",\n";

			print '        "nat_to": "ORIGINAL"';
			print ",\n";

			print '        "nat_service": "ORIGINAL"';
			print ",\n";

			print '        "install_on": [ { "firewall": "Gateways", "interface": [ "Any" ], "method": "FW1" } ] ';
			print ",\n";

			print '        "comment": "(implicit rule set in object definition)"';
			print "\n";
			print "    \}\n";
		}
	}



	#Added by Albert Estevez
	if ($number > 0){
		print ",";
	}

	#--- first the explicit ones ---
	for ( $i = 0; $i<=$nat_number; $i++ ) {
		print "    $comma\{\n";
		$comma=',';
		$number = $i + 1;
		print "        \"number\": \"$number\",\n";

		if ( $nat_header[$i] ) {
			print '        "header": "';
			print $nat_header[$i];
			print '",';
			print "\n";
		} else {
			print '        "header": "';
			print '",';
			print "\n";
		}

		if ( $nat_disabled[$i] ) {
			print '        "enabled": "no",';
		} else {
			print '        "enabled": "yes",';
		}
		print "\n";

		print '        "orig_from": ["';
		print "$nat_orig_from[$i]\" ],\n";

		print '        "orig_to": [ "';
		print "$nat_orig_to[$i]\" ],\n";

		print '        "orig_service": [ "';
		print "$nat_orig_svc[$i]\" ],\n";

		print '        "nat_type": "';
		if ( $nat_transl_from_methd[$i] ) {
			print 'static';
		} else {
			print 'masq';
		}
		print "\",\n";

		print '        "nat_from": "';
		print "$nat_transl_from[$i]\",\n";

		print '        "nat_to": "';
		print "$nat_transl_to[$i]\",\n";

		print '        "nat_service": "';
		print "$nat_transl_svc[$i]\",\n";

		print '        "install_on": [';
		print "\n";
		$scomma='';
		@obj_array = split (/§/, $nat_install_on[$i]);
		foreach $name (@obj_array){
			print "            $scomma\{\n";
			$scomma=',';
			print '                "firewall": "';
			print "$name\",\n";
			print '                "interface": [ "Any" ],';
			print "\n";
			print '                "method": "fw1"';
			print "\n";
			print "            \}\n";
		}
		print "        \],\n";


		print '        "comment": "';
		$nat_comment[$i] = encode_utf8($nat_comment[$i]);
		print $nat_comment[$i];
		print "\"\n";
		print "    \}\n";
	}


	print $natrulesfinal;


	#----------------------------- objects -----------------------------
	print "  \"objects\": \{ \n";

	$comma='';
	$objnr = 0;
	foreach $name (@obj_name){
		print "\t$comma\"$name\": \{\n";
		$comma=',';
		print "\t    \"name\": \"$name\",\n";

		if ( $obj_shared{$name} ) {
			print "\t    \"shared\": \"$obj_shared{$name}\",\n";
		}

		print "\t    \"type\": \"$obj_type{$name}\",\n";
		print "\t    \"on-interface\": ";
		if ( $obj_location{$name} ) {
			print '[ "external" ]';
		} else {
			print '[ "internal" ]';
		}
		print "\n";
#$obj_shared
		if ( "$obj_ipaddr{$name}" ne '' ) {
			$netmask = $obj_netmask{$name};
			print "\t    ,\"ipaddr\": ";
			if ($FLAG_anonymize) {
				print "\"A.N.O.N/YM\"\n";
			} else {
				if ( $netmask ne '' ) { $netmask = "/$netmask"; }
				print "\"$obj_ipaddr{$name}$netmask\"\n";
			}
		}
		if ( "$obj_nataddr{$name}" ne '' ) {
			print "\t    ,\"nataddr\": \"$obj_natadr{$name}\",\n";
			print "\t    \"nattype\": ";
			if ( $obj_NATtype{$name} ) {
				print '"static"';
			} else {
				print '"masq"';
			}
			print "\n";
		}

		#Added by Albert to support groups with exclusion
		if ( "$obj_members_base{$name}" ne '' ) {
			print "\t    ,\"groupmembers_base\": [";
			$scomma='';
			@obj_array = split (/§/, $obj_members_base{$name});
			$name1=$obj_members_base{$name};
			print " $scomma\"$name1\"";
			print "  \]\n";
		}

		if ( "$obj_members_exception{$name}" ne '' ) {
			print "\t    ,\"groupmembers_exception\": [";
			$scomma='';
			$name2=$obj_members_exception{$name};
			print " $scomma\"$name2\"";
			print " \]\n";
		}
		#End Albert
		#Albert Add interfaces
		if ( "$obj_interfaces{$name}" ne '' ) {
			print "\t    ,\"interfaces\": [\n";
			$scomma='';
			@obj_array = split (/§/, $obj_interfaces{$name});
			foreach $name (@obj_array){
				print "\t\t    $scomma\"$name\"\n";
				$scomma=',';
			}
			print "            \]\n";
		}


		#
		if ( "$obj_members{$name}" ne '' ) {
			print "\t    ,\"groupmembers\": [\n";
			$scomma='';
			@obj_array = split (/§/, $obj_members{$name});
			foreach $name (@obj_array){
				print "\t\t    $scomma\"$name\"\n";
				$scomma=',';
			}
			print "            \]\n";
		}
		if ( $obj_is_fw1{$name} ) {
			print "\t    ,\"gateway_brand\": \"Checkpoint\"\n";
		}
		if ( "$obj_comment{$name}" ne '' ) {
			$obj_comment{$name} = encode_utf8($obj_comment{$name});
			print "\t    ,\"comment\": \"$obj_comment{$name}\"\n";
		}
		print "\t\}\n";
	}
	print '    , "FW1 Host": { "name": "implicit-FW1 Host", "type": "gateway_fw", "comment": "CheckPoint implicit object: the firewall and its interfaces" }';
	print '    , "Gateways": { "name": "implicit-Gateways", "type": "gateways", "comment": "CheckPoint implicit object: all Gateways and their interfaces" }';
	print "\n  \},\n";

	#----------------------------- services -----------------------------
	$comma='';
	print "  \"services\": \{ \n";
	$dcerpc='';
	$sunrpc='';
	foreach $name (@svc_name){
		print "\t$comma\"$name\": \{\n";
		$comma=',';
		print "\t    \"name\": \"$name\",\n";
		if ( $svc_shared{$name} ) {
			print "\t    \"shared\": \"$svc_shared{$name}\",\n";
		}
		$tmpmatch = ""; $tmpprolog = ""; $tmpcomment = "";
		if (defined($svc_match{$name})) {$tmpmatch = $svc_match{$name}; }
		if (defined($svc_prolog{$name})) {$tmpprolog = $svc_prolog{$name}; }
		if (defined($svc_comment{$name})) {$tmpcomment = $svc_comment{$name}; }
		if ( $svc_type{$name} eq 'rpc' ) {
			$svc_type{$name} = 'tcp';
			$rcpnumber = $svc_dst_port{$name};
			$svc_dst_port{$name} = '111';
			$svc_layer7filter{$name} = "SunRPC_$name";
			RegisterL7 ("SunRPC_$name", "SunRPC", "", "", "", "$rpcnumber", "$tmpmatch", "$tmpprolog", "$tmpcomment");
			$sunrpc=', "SunRPC": { "name":"SunRPC", "type":"tcp", "destinationport":"111","comment":"Sun-RPC, used e.g. for NFS" }';
		} elsif ( $svc_type{$name} eq 'dcerpc' ) {
			$svc_type{$name} = 'tcp';
			$rcpnumber = $svc_dst_port{$name};
			$svc_dst_port{$name} = '135';
			$svc_layer7filter{$name} = "DCERPC_$name";
			RegisterL7 ("DCERPC_$name", "DCERPC", "", "", "", "$rpcnumber", "$tmpmatch", "$tmpprolog", "$tmpcomment");
			$dcerpc=', "DCERPC": { "name":"DCERPC", "type":"tcp", "destinationport":"135","comment":"Microsoft-RPC (DCERPC/MS-RPC), used e.g. for MS-Exchange" }';
		}
		print "\t    \"type\": \"$svc_type{$name}\"\n";
		if ( $svc_dst_port{$name} ne '' ) {
			print "\t    ,\"destinationport\": \"$svc_dst_port{$name}\"\n";
		}
		if ( $svc_src_low{$name} ne '' ) {
			print "\t    ,\"sourceport\": \"$svc_src_low{$name}";
			if (( $svc_src_high{$name} ne '' ) && ($svc_src_high{$name} ne $svc_src_low{$name})) {
				print "-$svc_src_high{$name}\"\n";
			}
			else {
				print "\"\n";
			}
		}
		if ( $svc_layer7filter{$name} ne '' ) {
			print "\t    ,\"layer7filter\": \"$svc_layer7filter{$name}\"\n";
		}
		if ( "$svc_members{$name}" ne '' ) {
			print "\n\t    ,\"groupmembers\": [\n";
			$scomma='';
			@obj_array = split (/§/, $svc_members{$name});
			foreach $name (@obj_array){
				print "\t\t    $scomma\"$name\"\n";
				$scomma=',';
			}
			print "        \]\n";
		}
		if ( $svc_comment{$name} ne '' ) {
			$svc_comment{$name} = encode_utf8($svc_comment{$name});
			print "\t    ,\"comment\": \"$svc_comment{$name}\"\n";
		}
		print "\t\}\n";
	}
	print "$sunrpc\n $dcerpc\n";
	print "  \}\n";
	#----------------------------- layer7 -----------------------------
	$comma='';
	if ( $l7_number > 0 ) {
		print "  ,\"layer7filter\": \{ \n";
		foreach $name (@l7_name){
			print "\t$comma\"$name\": \{\n";
			$comma=',';
			print "\t    \"name\": \"$name\",\n";
			print "\t    \"protocol\": \"$l7_service{$name}\"\n";
			if ( length($l7_maxsize{$name}) > 0 ) {
				print "\t    ,\"maxsize\": \"$l7_maxsize{$name}\"\n";
			}
			if ( length($l7_fwd_to{$name}) > 0 ) {
				print "\t    ,\"forward_to_server\": \"$l7_fwd_to{$name}\"\n";
			}
			if ( length($l7_fwd_with{$name}) > 0 ) {
				print "\t    ,\"forward_protocol\": \"$l7_fwd_with{$name}\"\n";
			}
			if ( length($l7_rpc{$name}) > 0 ) {
				print "\t    ,\"rpcnumber\": \"$l7_rpc{$name}\"\n";
			}
			if ( length($l7_match{$name}) > 0 ) {
				print "\t    ,\"match\": \"$l7_match{$name}\"\n";
			}
			if ( length($l7_matchprolog{$name}) > 0 ) {
				print "\t    ,\"match_prolog\": \"$l7_matchprolog{$name}\"\n";
			}
			if ( length($l7_comment{$name}) > 0 ) {
				$l7_comment{$name} = encode_utf8($l7_comment{$name});
				print "\t    ,\"comment\": \"$l7_comment{$name}\"\n";
			}
			print "\t\}\n";
		}
		print "  \}\n";
	}
	#----------------------------- users -----------------------------
	$comma='';
	if ( $user_number > 0 ) {
		print "  ,\"users\": \{ \n";
		foreach $name (@user_name){
			print "\t$comma\"$name\": \{\n";
			$comma=',';
			print "\t    \"name\": \"$name\",\n";
			print "\t    \"type\": \"user\",\n";
			print "\t    \"password\": \"(unknown)\",\n";
			print "\t    \"comment\": \"(placeholder generated, real user unknown)\"\n";
			print "\t\}\n";
		}
		print "  \}\n";
	}
	print "}\n";
}



##########################################################################
##########################################################################
###   MAIN
##########################################################################
##########################################################################

# Parse and process options
if (!GetOptions(\%optctl,
	'objects=s', 'rules=s',
	'merge_SP3=s', 'merge_AI=s',
	'with_implicit_rules',
	'verbose', 'debug', 'version', 'anonymize'
)
	|| keys(%optctl) == 0 || $optctl{help} == 1 || $optctl{version} == 1 )
{
	if ($optctl{version} == 1)
	{
		print STDERR "Parsing ...\n";
	} else {
		&Usage();
	}
	exit;
}


#--------------------------------------------------
# filename options
if (defined($optctl{'objects'})) { $FW1objects = $optctl{'objects'}; }
if (defined($optctl{'rules'})) { $FW1rules = $optctl{'rules'};}
if (defined($optctl{'merge_SP3'})) { $FWSrules = $optctl{'merge_SP3'};}							# GT
if (defined($optctl{'merge_AI'})) { $FWSrules = $optctl{'merge_AI'};}							# GT


#--------------------------------------------------
# switches / flags
$FLAG_implicitrules = (defined($optctl{'with_implicit_rules'}));
$FLAG_verbose = (defined($optctl{'verbose'}));
$FLAG_debug = (defined($optctl{'debug'}));
$FLAG_anonymizeALL = (defined($optctl{'anonymizeObjects'}));
$FLAG_anonymize = ( (defined($optctl{'anonymizeIP'})) || $FLAG_anonymizeALL );


if (! $FLAG_verbose) {
	print STDERR "Parsing ...\n\n";
}

#--------------------------------------------------
# check on parameter inconsistencies

if (defined($optctl{'merge_AI'}) &&
	defined($optctl{'merge_SP3'}) ) {
	die "Use only one of the --merge_ options  -  Aborting.";
}


#----------------------------------------------------------------

if ($FLAG_verbose) { open (LOGFILE,">$LogFile") or die "ERROR: Can't create logfile\n"; }
if ($FLAG_debug) { open (DEBUGFILE,">$DebugFile") or die "ERROR: Can't create debugfile\n"; }

&PrintLog("Parsing ...\n\n");

#------ first the objects ------

open (INFILE,"$FW1objects")
	or die "Cannot open the object file $FW1objects!\n\n";

&PrintLog("skipping...");
while ($line = <INFILE>) {
	$line = &fromdos($line);
	&DebugLog("READ Objects.C = $line");
	#--------------------------------------------
	if ( ( $line =~ /^\t\:netobj \(netobj/ ) ||			# V4.1 style
		( $line =~ /^\t\:network_objects \(network_objects/ )||	# NG style
		($line =~/^\t:network_objects \(/)                     # R65 style Added 2008-02-12 by Jacob
	) {
		&PrintLog("\n\nReading network objects...");
		&ReadNetworkObjects;
		&PrintLog("\n\nskipping...");
	}
	#--------------------------------------------
	if (( $line =~ /^\t\:servers \(servers/ )||      # V4.1 = NG style
		($line =~ /^\t\:servers \(/)                 # R65 style Added 2008-02-12 by Jacob
	) {
		&PrintLog("\n\nReading servers objects...");
		if ($line !~ /^\t\:servers \(servers\)/ ) {
			&ReadServers;
		}
		&PrintLog("\n\nskipping...");
	}
	#--------------------------------------------
	if ( ( $line =~ /^\t\:servobj \(servobj/ ) ||	# V4.1 style
		( $line =~ /^\t\:services \(services/ ) ||	# NG style
		( $line =~ /^\t\:services \(/ )            # R65 style Added 2008-02-12 by Jacob
	) {
		&PrintLog("\n\nReading services...");
		&ReadServices;
		&PrintLog("\n\nskipping...");
	}
	#--------------------------------------------
	if ( ( $line =~ /^\t\:resourcesobj \(resourcesobj/ ) ||	# V4.1 style
		( $line =~ /^\t\:resources_types \(resources_types/ ) 	# NG style
	) {
		&PrintLog("\n\nReading resources...");
		&ReadResources;
		&PrintLog("\n\nskipping...");
	}
	#--------------------------------------------
	if ( ( $line =~ /^\t\:props \(/ ) ||	# V4.1 style
		( $line =~ /^\t\:properties \(/ ) 	# NG style
	) {
		&PrintLog("\n\nReading properties...");
		&ReadProperties;
		&PrintLog("\n\nskipping...");
	}
	#--------------------------------------------
	if ( ( $line =~ /^\t\:netobjadtr \(/ )	# V4.1 style
	) {
		&PrintLog("\n\nReading netobjadtr...");
		&ReadNetobjadtr;
		&PrintLog("\n\nskipping...");
	}
	#Albert Estevez Adding Communities Support
	#--------------------------------------------
	if ( ( $line =~ /^\t\:communities \(/ ) ||	# NG style
		( $line =~ /^\t\:communitie \(/ ) 	# NG style
	) {
		&PrintLog("\n\nReading Communities...");
		&ReadCommunities;
		&PrintLog("\n\nskipping...");
	}
	#--------------------------------------------
	else {
		&PrintLog('.');
	}
}

&PrintLog(".\n");
close (INFILE);

#------ GT, 2003-02-06: Begin --------
if ( "$FWSrules" ne "" )
{
	$wXfws_out = $FW1rules . "_FWS";

	open (INW, "$FW1rules") or die "ERROR: Can't open $FW1rules\n";
	#binmode INW;
	open (INFWS, "$FWSrules") or die "ERROR: Can't open $FWSrules\n";
	#binmode INFWS;
	open (OUT, "> $wXfws_out") or die "ERROR: Can't create $wXfws_out\n";
	#binmode OUT;

	# print "GT, 2003-02-06: merge $FW1rules with comments of $FWSrules into $wXfws_out\n";

	while (<INFWS>)
	{
		if (/:chkpf_uid \(\"\{(.+?)\}/)
		{
			$uid = $1;
			$com{$uid} = "";
		}
		if (/:comments \((.*)\)/)
		{
			s/^"|"$//;
			s/\t//;
			$comment = $_;
			$com{$ruleuid} = $comment;
		}
		if (/:header_text \((.*)\)/)
		{
			s/"//;
			s/\t//;
			$hdrtext = $_;
		}
		if (/:rule \(/)
		{
			$ruleuid="";
		}
		if (/^\t\)/ || /:rule_adtr \(/)
		{
			if ($hdrtext)
			{
				$TAILHEADER{$secuid}=$hdrtext;
			}
			$hdrtext="";
		}
		if (/:ClassName \(security_/ || /:ClassName \(address_/)
		{
			$ruleuid=$uid;
		}
		if (/:ClassName \(security_rule\)/)
		{
			$secuid=$uid;
			if ($hdrtext)
			{
				$hdr{$ruleuid} = $hdrtext;
				$hdrtext="";
			}
		}
	}

	while (<INW>)
	{
		if (/:chkpf_uid \(\"\{(.+?)\}/)
		{
			$uid = $1;
		}
		if (/:ClassName \(security_rule\)/ || /:ClassName \(address_/)
		{
			$ruleuid=$uid;
		}
		if (/^\)/ || /:rule_adtr /)
		{
			if ($TAILHEADER{$ruleuid})
			{
				print OUT "\t:rule (\n";
				print OUT "\t	:AdminInfo (\n";
				print OUT "\t		:chkpf_uid (\"00000000-0000-0000-0000-000000000001\")\n";
				print OUT "\t		:ClassName (security_header_rule)\n";
				print OUT "\t	)\n";
				print OUT "\t	:disabled (true)\n";
				print OUT $TAILHEADER{$ruleuid};
				print OUT "\t)\n";
			}
		}
		if (/:dst \(/ || /:dst_adtr_translated \(/)
		{
			print OUT $com{$ruleuid};
			print OUT $hdr{$ruleuid} if ($hdr{$ruleuid});
		}
		print OUT;
	}

	close INW;
	close INFWS;
	close OUT;

	$FW1rules = $wXfws_out;				# now change --rules to created file
}
#------ GT, 2003-02-06: End   --------

#------ now the rulebase ------

if ( ! $FLAG_norules ) {

	$nat_number = -1;
	open (INFILE,"$FW1rules")
		or die "Cannot open the rules file $FW1rules!\n\n";

	&PrintLog("\n\nskipping...");
	while ( $line = <INFILE> ) {
		$line = &fromdos("$line");
		&DebugLog("Skipping Rules: $line \n");
		if ( $line =~ /^\t\:rule \(/ ) {
			&PrintLog("\n\nReading access rules...");
			$line = &ReadAccessRules($line);
			&DebugLog("\n\nreturned $line");
			&PrintLog("\n\nskipping...");
		}
		if ( $line =~ /^\t\:rule_adtr \(/ ) {
			&PrintLog("\n\nReading NAT rules...");
			&ReadNATrules($line);
			&PrintLog("\n\nskipping...");
		} else {
			&PrintLog('.');
		}
	}

	close (INFILE);
}


&PrintLog("\n\nReading Done.\n\n");

#--------------------------------------------------
# convert ruleset
&PrintLog("Printing ruleset to FWdoc into STDOUT.\n");
&Output_FWdoc ();
&PrintLog("\nDone.\n\n");


if ($FLAG_verbose) { close (LOGFILE); }
if ($FLAG_debug) { close (DEBUGFILE); }

#############################################################################

