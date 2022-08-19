package Service::LDAP;

use 5.00010;
use strict;
use Carp qw(croak);
use Net::LDAP;
use Net::LDAPS;
use Unicode::String qw(utf8 utf16le);
use Digest::MD5 qw(md5_hex);
use Data::Dumper;
use vars qw($VERSION);
use Affinity::Validate;
use String::MkPasswd qw(mkpasswd);
use Redis::Client;
use URI::Escape::XS;
use LWP::Simple qw(get);
use JSON::XS;
use UUID qw(uuid);
use JSON::XS;
use DateTime;
use DBI;
use Unicode::Map8;
use Unicode::String qw(utf16);

$VERSION = '2.02';
#test123\

sub new
{
        my $class = shift;
        my $param = shift;

        croak("Service::LDAP Failed to initialise. No Bind Account [bind_account] Specified") unless $param->{bind_account};
        croak("Service::LDAP Failed to initialise. No Bind Password [bind_password] Specified") unless $param->{bind_password};
        croak("Service::LDAP Failed to initialise. No Base DN / RootDSE [base_dn] Specified") unless $param->{base_dn};
        croak("Service::LDAP Failed to initialise. No Host [host] Specified") unless $param->{host};
	
	
		my $redis = $param->{redis};
		my $dbh   = $param->{dbh},
	

        #my $ldap = Net::LDAP->new($param->{host}) || die $@;
        my $ldap = Net::LDAPS->new($param->{host}, port => 636) || die $@;
		my $msg = $ldap->bind($param->{bind_account}, password => $param->{bind_password});
        if($msg->error  ne "Success"){
                croak "LDAP Bind  Failed. Could not bind to service. ".$msg->error;
        };

		#my $core = Service::LDAP::Core->new({ldap=>$ldap, base=>$param->{base_dn} });
        my $self = {
		host => $param->{host},	
		ldap => $ldap, 
		base => $param->{base_dn }, 
		ou_users => $param->{ou_users},
		ou_groups => $param->{ou_groups},
		redis => $redis, 
		dbh => $dbh, 
		coder => JSON::XS->new->utf8->allow_nonref->allow_blessed->convert_blessed};
        
	
		bless $self,$class;
        return $self;


}

sub _sorted
{
	my $hashref = shift;
	my @sorted;
	foreach my $key(sort keys %{$hashref}){
		push(@sorted,$hashref->{$key});
	}	
       
	return \@sorted;
}

sub list_companies
{
        my $self = shift;
        my $param = shift;
        my $base = $self->{ou_users};
		print STDERR __LINE__;;
		print STDERR "==============";
		return &_sorted(&_ou($self,$base));
}

sub list_departments
{
        my $self = shift;
        my $param = shift;

		croak("Service::LDAP::list_departments Failed. No Company supplied for search") unless $param->{company};
	
		my $company = "OU=".$param->{company};
        my $base = $company.",".$self->{ou_users};
		my $Data = &_sorted(&_ou($self,$base));

   		return &_sorted(&_ou($self,$base));
}

sub list_groups
{
        my $self = shift;
        my $param = shift;
        my $base = $self->{ou_groups};
		my $filter = 'CN=*';

		my $Data = &_cn($self,$base,$filter);
		return $Data;

}

sub get_groups
{
		my $self = shift;
        my $param = shift;
		my $group = "OU=".$param->{group};
        print STDERR "group is $group\n";
		my $base = $group.",".$self->{ou_groups};
        my $filter = "CN=".$param->{filter};

        croak("Service::LDAP::list_groups Failed. No Group supplied for search") unless $group;
		croak("Service::LDAP::list_groups Failed. No Filter supplied for search") unless $filter;

		my $Data = &_cn($self,$base,$filter);
        return $Data;
}

sub group_members
{
		my $self = shift;
		my $param = shift;
		my $group = $param->{group};
        my $base = "OU=$group".",".$self->{ou_groups};
		print STDERR "$base\n\n";
		my $filter = "CN=".$param->{filter};

		print STDERR $base;
		#croak("Service::LDAP::group_members Failed. No Group supplied for search") unless $group;
		croak("Service::LDAP::list_groups Failed. No Filter supplied for search") unless $filter;


		my $search = $self->{ldap}->search( base => $base, filter => $filter, scope => "subtree");
        my $DN;

		my @members;
        foreach my $entry ($search->entries) {
                my $dn          = $entry->dn();
                $dn             = uc($dn);
                my $cat         = $entry->get_value("objectcategory");
                (undef,$cat)    = split("=",$cat);
                my $ldap_class = lc($cat);
                $ldap_class =~ s/\,cn$//g;
                $ldap_class = "ldap_".$ldap_class;

                $DN->{$dn}->{ldap_category} = $cat;
                $DN->{$dn}->{ldap_class} = $ldap_class;

                @members = $entry->get_value("member");
	}
	
	my $Data;
	foreach my $dn(@members){
			my $filter = "distinguishedName=".$dn;
		
			my $search = $self->{ldap}->search( base => $self->{base}, filter => $filter, scope => "subtree");
			foreach my $entry (sort $search->entries) {
					my $Val;
					foreach my $attr( $entry->attributes){
                			if($attr eq "objectSid"){
			       	       			eval { $Val->{sid} = &_sid($entry->get_value("objectSid")); };
                        	}elsif($attr eq "objectGUID"){
                                	eval { $Val->{gid} = &_sid($entry->get_value("objectGUID")); };
                        	}else{
                               		$Val->{$attr} = $entry->get_value($attr);
                        	}
                	}
            $Data->{$Val->{sid}} = $Val;
        	}
	}

	return $Data;
	
}

sub user_get
{
	my $self = shift;
	my $param = shift;
	my $base = $self->{ou_users};
	my $clue = $param->{filter};

	croak("Service::LDAP::list_groups Failed. No Filter supplied for search") unless $clue;
	
	my $filter;
	if($clue =~ /^CN=/i){ 
		$filter = "distinguishedName=".$clue;
	}elsif($clue =~ /^S\-/i){
        	$filter = "objectSid=".$clue;
	}else{
		$filter = "sAMAccountName=".$clue;
	}
	my $search = $self->{ldap}->search( base => $self->{base}, filter => $filter, scope => "subtree");
	my $Data;
        foreach my $entry ($search->entries) {
        	my $Val;
               	foreach my $attr( $entry->attributes){
                	if($attr eq "objectSid"){
                        		eval { $Val->{sid} = &_sid($entry->get_value("objectSid")); };
                         }elsif($attr eq "objectGUID"){
                                 eval { $Val->{gid} = &_sid($entry->get_value("objectGUID")); };
                         }else{
                                $Val->{$attr} = $entry->get_value($attr);
                        }
                        
                        $Data->{$Val->{sid}} = $Val;
                }
        }
        return $Data;
	
}

sub user_create
{
	my $self = shift;
	my $param = shift;
	my $base = $self->{ou_users};
	my $validate = Affinity::Validate->new();
	my $fname = uc($validate->sanitise($param->{fname}));
	my $lname = uc($validate->sanitise($param->{lname}));
	my $fullname = $fname." ".$lname;
	my $zaid = $param->{zaid};
	my $cell = $validate->phone_number($param->{cell});
	my $mail = $param->{mail};
	my $memof = $param->{group};
	if ($mail){
		$mail = uc($validate->email($mail));
	}else{
		$mail = 0;
	}
	my $dep =  uc($param->{dep});
	my $comp = uc($param->{comp});
	my $dn;
	if($dep eq "NULL"){
	$dn = "CN=$fullname,OU=$comp,$base";
	}else{
	$dn = "CN=$fullname,OU=$dep,OU=$comp,$base";
	};
	my $sam = "$fname$lname";
	my $up = $sam."@"."Affinity.Local";
	my $manager = $param->{manager};
	my $dn_manager = "CN=$manager,OU=$dep,OU=$comp,$base";
	my $charmap = Unicode::Map8->new('latin1')  or  die;
	my $pass = mkpasswd(-length => 12, -minnum => 3, -minlower => 4, -minupper => 4, -minspecial => 1 ,-noambiguous => 0);
	my $newUniPW = $charmap->tou(qq/"$pass"/)->byteswap()->utf16();
	croak("Service::LDAP::user_create Failed to initialise. Invalid First Name") unless $fname;
    croak("Service::LDAP::user_create Failed to initialise. Invalid Last Name") unless $lname;
    croak("Service::LDAP::user_create Failed to initialise. Invalid Cellphone Number") unless $cell;
    croak("Service::LDAP::user_create Failed to initialise. Invalid Department") unless $dep;
	croak("Service::LDAP::user_create Failed to initialise. Invalid Company") unless $comp;

	#croak("Not a valid South African ID Number") unless $zaid->{valid};
    #my $idnumber = $zaid->{zaid};

	my $add = $self->{ldap}->add(
            $dn,
            attr => [
                'cn'          => $fullname,
                'sn'          => $lname,
				'employeeID'  => $zaid,
				'mobile'      => $cell,
				'mail'        => $mail,
				'company'     => $comp,
				'department'  => $dep,
        		'displayName' => $fullname,
        		'givenName'   => $fname,
				'sAMAccountName' => $sam,
				'unicodePwd' => $newUniPW,
				'manager'	=> $manager,
				'userPrincipalName' => $up,
				'userAccountControl' => 66080,
                'objectclass' =>
                  [ "top", "person", "organizationalPerson", "user" ]
            ]
        );

	#$add->code  and  warn "failed to add entry: ", $add->error;
	#return $add;
	if($add->error  ne "Success"){
                croak "Failed to add entry. ".$add->error;
        }else{

				my $grp_add = $self->{ldap}->modify($memof,
                        changes => [add => [member => $dn ] ]
        		);
                if($grp_add->error  ne "Success"){
                        croak("Service::LDAP::user_create Failed to add user to $memof");
                }else{

                }

 				return({
				cn          => $fullname,
                sn          => $lname,
                employeeID  => $zaid,
                mobile      => $cell,
                mail        => $mail,
                company    => $comp,
                department  => $dep,
                displayName => $fullname,
                givenName   => $fname,
                sAMAccountName => $sam,
                unicodePwd => $pass,
                manager       => $manager,
				parameters_sent => $param,
				});
        }


}

sub user_update
{
	my $self = shift;
        my $param = shift;
	
	my $dn = $param->{dn};
	my $field = $param->{field};
	my $value = $param->{value};

        croak("Service::LDAP::user_update Failed. No DN supplied for update") unless $dn;
	croak("Service::LDAP::user_update Failed. Invalid Field") unless $field;
	croak("Service::LDAP::user_update Failed. Invalid Value") unless $value;

	my $msg = $self->{ldap}->modify($dn, replace => { $field => $value } );
	
	if($msg->error  ne "Success"){
                croak "Update Failed. ".$msg->error;
        }else{
		return $param;
	}

}

sub search
{
	my $self = shift;
        my $param = shift;
        my $base = $self->{ou_users};
        my $client = $self->{redis};
        $client->select(0);

        croak("Service::LDAP::search Failed. No Cellphone Number provided.") unless $param->{cell};
        croak("Service::LDAP::search Failed. No ID Number provided.") unless $param->{zaid};

	my $cell = "mobile=".$param->{cell};
        my $zaid = "employeeID=".$param->{zaid};
        my $Data;
        my $random = int( rand(1000)) + 9999;
        my $dn;
        my $zaidr = &_cn($self,$base,$zaid);
        my $cellr = &_cn($self,$base,$cell);
	my $ad_zaid;
        my $ad_cell;

        foreach my $key(keys %{$zaidr}){
                        $ad_zaid = $zaidr->{$key}->{employeeID};
        }
        foreach my $key(keys %{$cellr}){
                        $ad_cell = $cellr->{$key}->{mobile};
        }

        $zaid =~ s/^employeeID=//;
        $cell =~ s/^mobile=//;
  
    	if($zaid != $ad_zaid || $cell != $ad_cell){
                croak("Account Error. Please contact IT.");
        }else{
                $Data = $cellr;
                foreach my $key(keys %{$Data}){
                        my $name = $Data->{$key}->{name};
                        my $msg = qq{Dear $name, your OTP is: $random};
                        $dn = $key;
                        $cell = $Data->{$key}->{mobile};
                        $cell =~ s/^0/27/;
                        $client->set("$dn-OTP" => "$random");
                        #seconds to minutes
						$client->expire("$dn-OTP","300");
                        my $url = "http://sms.connet-systems.com/submit/single?";
                        my %sms;
						#$sms{username} = 'affdev.intranet';
                        #$sms{account} = 'Affinity/Development_Intranet';
                        #$sms{password} = 'afr204fit';
                        $sms{username} = 'affinity.funer';
                        $sms{account} = 'affinity.funer';
                        $sms{password} = 'wkh4289';
						$sms{da} = $cell;
                        $sms{ud} = $msg;
                        #print STDERR Dumper (\%sms);
                               foreach my $key(keys %sms){
                                        my $value = encodeURIComponent($sms{$key});
                                        $url = $url."\&".$key."=".$value;
                                        my $response = get($url);
                                        #print STDERR $response;
                               }
		}
	}
	return $Data;
}

sub forgot_pass
{
	my $self = shift;
	my $param = shift;
	my $base = $self->{ou_users};
	my $client = $self->{redis};
	$client->select(0);
	croak("Service::LDAP::forgot_pass Failed. No DN provided.") unless $param->{dn};
	my $dn = $param->{dn};
	my $compare = $client->get($dn."-OTP");
    croak("Invalid OTP") unless $compare;
	my $otp	= $param->{otp};
	my $cell = $param->{cell};
	my $uname = $param->{username};
	$cell =~ s/^0/27/;
    croak("Service::LDAP::forgot_pass Failed. No OTP supplied") unless $otp;
	croak("Service::LDAP::forgot_pass Failed. No cellphone number") unless $cell;
	croak("Service::LDAP::forgot_pass Failed. No Username provided") unless $uname;
	if($otp == $compare){
			my $charmap = Unicode::Map8->new('latin1')  or  die;
			my $pass = mkpasswd(-length => 12, -minnum => 3, -minlower => 4, -minupper => 4, -minspecial => 1, -noambiguous => 1);
      		my $newUniPW = $charmap->tou(qq/"$pass"/)->byteswap()->utf16();
            my $msg = $self->{ldap}->modify($dn, replace => {'unicodePwd' => $newUniPW } );
            if($msg->error  ne "Success"){
            		croak ("Service::LDAP::forgot_pass Failed. ".$msg->error);
            }else{
						my $url = "http://sms.connet-systems.com/submit/single?";
                       	my %sms;
						#$sms{username} = 'affdev.intranet';
                        #$sms{account} = 'Affinity/Development_Intranet';
                        #$sms{password} = 'afr204fit';
                       	$sms{username} = 'affinity.funer';
                       	$sms{account} = 'affinity.funer';
                       	$sms{password} = 'wkh4289';
                       	$sms{da} = $cell;
                       	$sms{ud} = qq{Password updated. Username: $uname Password: $pass};
                       	print STDERR Dumper (\%sms);
                        foreach my $key(keys %sms){
                        		my $value = encodeURIComponent($sms{$key});
                                $url = $url."\&".$key."=".$value;
                                my $response = get($url);
                                print STDERR $response;
                        }
		}	
              return $param;
	}else{
				croak("Service::LDAP::forgot_pass failed. OTP does not match.");
	}
						
	

}

sub address_book
{
		my $self = shift;
        my $param = shift;
        my $base = $self->{ou_users};
		my $clue = $param->{filter};
        my $filter;
		print STDERR "clue is: $clue\n"; 	
		if($clue =~ /^givenName=/i){
		(undef,$clue) = split("=",$clue);
		$filter = "givenName=".$clue;
        }elsif($clue =~ /^sn=/i){
		(undef,$clue) = split("=",$clue);
                $filter = "sn=".$clue;
        }elsif($clue =~ /^department=/i){
		(undef,$clue) = split("=",$clue);
                $filter = "department=".$clue;
        }elsif($clue =~ /^title=/i){
		(undef,$clue) = split("=",$clue);
		$filter = "title=".$clue;
		}elsif($clue =~ /^employeeID=/i){
		print STDERR "*************************************".$clue."***************************************";
                (undef,$clue) = split("=",$clue);
                $filter = "employeeID=".$clue;
		}elsif($clue =~ /^mobile=/i){
		print STDERR "*************************************".$clue."***************************************";
                (undef,$clue) = split("=",$clue);
                $filter = "mobile=".$clue;
        }elsif($clue =~ /^sid=/i){
                print STDERR "*************************************".$clue."***************************************";
                (undef,$clue) = split("=",$clue);
                $filter = "objectSid=".$clue;
        }elsif($clue =~ /^mail=/i){
                print STDERR "*************************************".$clue."***************************************";
                (undef,$clue) = split("=",$clue);
                $filter = "mail=".$clue;
        }else{
		croak("Invalid search entry");
		}
        croak("Service::LDAP::address_book Failed. No Base supplied for search") unless $base;
        croak("Service::LDAP::address_book Failed. No Filter supplied for search") unless $filter;
        print STDERR "filter is: $filter\n";
        my $search = $self->{ldap}->search( base => $self->{base}, filter => $filter, scope => "subtree");
        my $Data;
        foreach my $entry ($search->entries) {
                my $dn = $entry->dn();
		my $Val;
                foreach my $attr( $entry->attributes){
                       	if($attr eq "objectSid"){
                                eval { $Val->{sid} = &_sid($entry->get_value("objectSid")); };
                        }elsif($attr eq "objectGUID"){
                                 eval { $Val->{gid} = &_sid($entry->get_value("objectGUID")); };
                        }else{
                                #$Val->{$attr} = $entry->get_value($attr);
				my @values = $entry->get_value($attr);
                                if($values[1]){
                                        $Val->{$attr} = \@values;
                                }else{
                                        $Val->{$attr} = $values[0];
                                }
                        }

			$Data->{$dn} = $Val;
			#$Data->{$Val->{sid}} = $Val;
                }
        }
		if(!defined($Data)){
               	croak("No Account Found.");
        }else{
        	return $Data;
		}
}

sub _ou
{
        my $self = shift;
        my $base = shift;
        my $filter = 'OU=*';

        my $OU;

        my $search = $self->{ldap}->search( base => $base, filter => $filter, scope => "one");
        foreach my $entry ($search->entries) {
                my $dn = $entry->dn();
                my $Data;
                foreach my $attr( $entry->attributes){
                        if($attr eq "objectSid"){
                                eval { $Data->{sid} = &_sid($entry->get_value("objectSid")); };
                        }elsif($attr eq "objectGUID"){
                                eval { $Data->{gid} = &_sid($entry->get_value("objectGUID")); };
                        }else{
                                $Data->{$attr} = $entry->get_value($attr);
                        }
                }
                $OU->{$dn} = $Data;
        }
	#if(!defined($OU)){
	#	croak("Nothing Found.");
	#}else{
        	return $OU;
	#}
}

sub _cn
{
        my $self = shift;
        my $base = shift;
        my $filter = shift;

        my $CN;
	
		my $search = $self->{ldap}->search(
                                                base => $base,
                                                filter => $filter,
                                                scope => "subtree");

        foreach my $entry ($search->entries) {
                my $dn = $entry->dn();
		my $Data;
                foreach my $attr( $entry->attributes){
                        if($attr eq "objectSid"){
                                eval { $Data->{sid} = &_sid($entry->get_value("objectSid")); };
                        }elsif($attr eq "objectGUID"){
                                eval { $Data->{gid} = &_sid($entry->get_value("objectGUID")); };
                        }else{
								#Might need to do the arfray thing because memerof is an array in AD
                                $Data->{$attr} = $entry->get_value($attr);
                        }
                }
			$CN->{$dn} = $Data;
        }
	#if(!defined($CN)){
         #       croak("Nothing Found.");
        #}else{
         #       return $CN;
        #}
		return $CN;
}

sub _sid
{
	my ($sid) = @_;
	my ($revision_level, $authority, $sub_authority_count,  @sub_authorities) = unpack 'C Vxx C V*', $sid;
	return join '-', 'S', $revision_level, $authority,@sub_authorities;
}

sub session_create
{
	my $self = shift;
	my $param = shift;
	my $username = $param->{username};
	my $pass = $param->{password};
	my $ip = $param->{ip};
	my $base = $self->{base};
        my $redis = $self->{redis};

	print STDERR "password is $pass\n";
	croak("Service::LDAP::session_create Failed. No username supplied") unless $username;
    croak("Service::LDAP::session_create Failed. No password supplied") unless $pass;

	my $string = uuid();
        		

	$redis->select(1);

	my $user = "sAMAccountName=".$username;
	my $user_base = $self->{ou_users};
	my $search = $self->{ldap}->search( base => $user_base, filter => $user, scope => "subtree");

	my $Val;
	my $dn;
	foreach my $entry ($search->entries) {
		$dn = $entry->dn();	
		foreach my $attr( $entry->attributes){
   			next if($attr =~ /;binary$/); 
			if($attr eq "objectSid"){
                        	eval { $Val->{sid} = &_sid($entry->get_value("objectSid")); };
               	         }elsif($attr eq "objectGUID"){
                         	eval { $Val->{gid} = &_sid($entry->get_value("objectGUID")); };
                         }else{
				my @values = $entry->get_value($attr);
                         	if($values[1]){
                                	$Val->{$attr} = \@values;
                         	}else{
                                 	$Val->{$attr} = $values[0];
                         	}
                               	#$Val->{$attr} = $entry->get_value($attr);
                        }
		}
	}

	if($dn){
		my $bind = $self->{ldap}->bind($username, password => $pass, dn => $dn);

		if($bind->error eq "Success"){
				my $session = md5_hex($string);
				$Val->{session_key} = $session;
				$Val->{ip_address} = $ip;
				#my $json = $self->{coder}->encode($Val);
				&_session_log($self,$Val,$session,$ip);
				# Get the extra data for the user
				my $sql = qq {SELECT APPS.`name`, APP_Data.`Field`, APP_Data.`Value`
				FROM APPS, APP_Data
				WHERE APP_Data.`Active` = "1"
				AND APP_Data.`App_ID` = APPS.`id`
				AND APP_Data.`sid` = "$Val->{sid}"};
				my $rep = $self->{dbh}->prepare($sql);
        		$rep->execute || croak("Could not get APP info");
       			while(my $ref = $rep->fetchrow_hashref){
						$Val->{app_data}->{$ref->{name}}->{$ref->{Field}} = $ref->{Value};
				}
				$rep->finish;
				my $json = $self->{coder}->encode($Val);
				$redis->set("$session" => "$json");
				#seconds to minutes
				$redis->expire($session,"700");	
				#$redis->persist($session);
				return $Val;
		}else{
				croak("Incorrect Password");
		}
	}else{
		croak("Account not found");
	}
		
}

sub session_get
{
        my $self = shift;
		my $param = shift;
        my $key = $param->{session_key};

        croak("Service::LDAP::session_create Failed. No Session Key [session_key] Provided") unless $key;
        $self->{redis}->select(1);
        my $json = $self->{redis}->get($key);
		#seconds to minutes
		$self->{redis}->expire($key,"700");
        croak("Service::LDAP::session_create Failed. The provided session key was not found") unless $json;

        return $self->{coder}->decode($json);
}

sub session_delete
{
        my $self = shift;
		my $param = shift;
        my $key = $param->{session_key};

        croak("Service::LDAP::session_delete Failed. No Session Key [session_key] Provided") unless $key;
        $self->{redis}->select(1);
        my $json = $self->{redis}->del($key);

			return $param;
}

sub _session_log
{
	my $self	= shift;
	my $Val 	= shift;
	my $session 	= shift;
	my $ip		= shift;
	my $param	= shift;

	my $name = $Val->{distinguishedName};
	my $sid = $Val->{sid};
	my $date = DateTime->now->strftime('%Y-%m-%d');   
	my $sql = qq{insert into ad_sessions (session_key, DN, sid, date,IP_address) values("$session", "$name", "$sid", "$date","$ip")};
	my $rep = $self->{dbh}->prepare($sql);
	$rep->execute || croak("Could not log session");
	$rep->finish;
}

sub session_store_set
{
	my $self = shift;
	my $param = shift;
	my $redis = $self->{redis};
	my $session = $param->{session_key};
	my $field = $param->{field};
	my $value = $param->{value};

	croak("Service::LDAP::session_store_set Failed. No session supplied") unless $session;
	croak("Service::LDAP::session_store_set Failed. No field supplied") unless $field;
	croak("Service::LDAP::session_store_set Failed. No value supplied") unless $value;
	
	$redis->select(1);
	my $json_session_data = $redis->get($session);

	if($json_session_data){
		my $session_data = $self->{coder}->decode($json_session_data);
		$session_data->{store}->{$field} = $value;
		my $json = $self->{coder}->encode($session_data);
		$redis->set($session,$json);
		$redis->persist($session);
		return $session_data;
	}else{
		croak("Service::LDAP::session_store_set Failed. Session does not exist");
	};
}

sub session_store_get
{
		my $self = shift;
		my $param = shift;
		my $redis = $self->{redis};
		my $session = $param->{session_key};
        my $field = $param->{field};

        croak("Service::LDAP::session_store_get Failed. No session supplied") unless $session;
        croak("Service::LDAP::session_store_get Failed. No field supplied") unless $field;

	$redis->select(1);
	my $json_session_data = $redis->get($session);
        if($json_session_data){
        	my $session_data = $self->{coder}->decode($json_session_data);
		my $store = $session_data->{store}->{$field};
		return $store;
        }else{
        	croak("Service::LDAP::session_store_get Failed. Session does not exist");
        };
}

sub dump
{
	my $self = shift;
	my $param = shift;
	my $type = $param->{type};
	$type = "DN" unless $type;

	my $filter = $type."=*";
	my $ldap = $self->{ldap};
	my $base = $self->{base};
	my $mesg = $ldap->search( # perform a search
                base   => $base,
                filter => "DN=*"
        );

        my $E;
	my @entries = $mesg->entries;
	foreach my $entry(@entries){
		my $dn = $entry->dn;
		foreach my $attr($entry->attributes){
			next if($attr =~ /;binary$/); # Skip binary data
			my @values = $entry->get_value($attr);
			if($values[1]){	
				$E->{$dn}->{$attr} = \@values;
			}else{
				$E->{$dn}->{$attr} = $values[0];
			}
      		}
	}	
	return $E;
}

1;
__END__
# Below is stub documentation for your module. You'd better edit it!

=head1 NAME

Service::LDAP - Perl API for Active Directory

=head1 SYNOPSIS

  use Service::LDAP;

  # Login and Bind
  my $ldap = Service::LDAP->new({bind_account => $bindaccount, bind_password => $password, base_dn => $base, host => $host});

  # Get companies
  my $companies = $ldap->list_companies();
  
  # Get the departments
  my $Dept = $ldap->list_departments({company => $company});

  # List USER GROUPS
  my $Grp = $ldap->list_groups();

  # Get group
  my $group_get = $ldap->get_groups({group => $group, filter => $filter});

  # Get Group Members
  my $mems = $ldap->group_members({group => "APPLICATIONS", filter => "MANAGEMENT" })

  # Get User by DN / Sid / sAMAccountName
  my $user = $ldap->user_get({filter => $sAMAccountName });

  # Create new user
  my $add = $ldap->user_create({
                                        fname => $first_name,
                                        lname => $last_name,
                                        zaid => $zaid,
                                        cell => $cell,
                                        mail => $mail,
                                        dep => $department,
                                        manager => $manager,
                                        comp => $company,
                                        });

  # Update User
  my $update = $ldap->({dn => $dn, field => $field, value => $value });

  # Forgot Password
  my $pass = $ldap->forgot_pass({mail => $mail, otp => $otp, newpass => $newpassword, confirmpass => $confirmpass});

  # Address Book / Search (givenName, sn, department, title)
  my $add = $ldap->address_book({filter => "title=perl developer"});

  # Create Session
  my $sess = $ldap->session_create({username => $username,password => $password});

  #Get Session Details
  my $sess_get = $ldap->session_get({session_key => $key});    

  #Store Value
  my $sess = $ldap->session_store_set({session_key => "f8542c0522489bed9843ce7adf51dd88", field => "Role", value => "100"});

  #Get Value
  my $get = $ldap->session_store_get({session_key => "f8542c0522489bed9843ce7adf51dd88", field => "Role"});


=head1 DESCRIPTION

Affinity Perl API to communicate with Active Directory.
This module does common related task to search, update and remove Active Directory data.

=head2 EXPORT

None by default. Object Orientated Programming.



=head1 SEE ALSO

Carp qw(croak);
Net::LDAP;
Net::LDAPS;
Unicode::String qw(utf8 utf16le);
Digest::MD5 qw(md5_hex);
Data::Dumper;
Affinity::Validate;
String::MkPasswd qw(mkpasswd);
Redis::Client;
URI::Escape::XS;
LWP::Simple qw(get);
JSON::XS;
#Service::LDAP::Core;
UUID qw(uuid);
JSON::XS;
DateTime;
DBI;
Unicode::Map8;
Unicode::String qw(utf16);

voip@affinityhealth.co.za

=head1 AUTHOR

Affinity Health, E<lt>Affinity Health@E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2021 by Affinity Health

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.26.1 or,
at your option, any later version of Perl 5 you may have available.


=cut
