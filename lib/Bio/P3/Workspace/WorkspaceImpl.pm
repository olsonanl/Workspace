package Bio::P3::Workspace::WorkspaceImpl;
use strict;
# Use Semantic Versioning (2.0.0-rc.1)
# http://semver.org 
our $VERSION = "0.1.0";

=head1 NAME

Workspace

=head1 DESCRIPTION



=cut

#BEGIN_HEADER
use base 'RPC::Any::Package::JSONRPC';
use POSIX qw(:time_h :sys_wait_h);
use File::Path;
use File::Copy ("cp","mv");
use File::stat;
use File::Which qw(which);
use Fcntl ':mode';
use Data::UUID;
use Data::UUID::MT;
use REST::Client;
use LWP::UserAgent;
use JSON::XS;
use Data::Dumper;
use HTTP::Request::Common;
use Log::Log4perl qw(:easy);
use MongoDB::Connection;
use URI::Escape;
use AnyEvent;
use AnyEvent::HTTP;
use AnyEvent::Run;
use Config::Simple;
use Plack::Request;
use Plack::Response;
use Fcntl ':seek';
use DateTime;
use DateTime::Format::ISO8601;
use P3AuthLogin;
use P3AuthToken;
use P3TokenValidator;
use IO::File;
use Time::HiRes 'gettimeofday';
use Digest::HMAC_SHA1 qw(hmac_sha1 hmac_sha1_hex);
use Scalar::Util qw (blessed);
use Bio::P3::Workspace::Service;
use MIME::Types;

our $mime_types = MIME::Types->new;
{
    my $faType = MIME::Type->new(extensions => [".fa", ".fasta", ".fna", ".faa"],
				 type => "text/plain");
    $mime_types->addType($faType);
}
our %mime_overrides = (pdb => "text/plain",
		       sdf => "text/plain",
		       gb => "text/plain",
		       sh => "text/plain",
		      );


our $date_parser = DateTime::Format::ISO8601->new();

Log::Log4perl->easy_init($DEBUG);

#
# Alias our context variable.
#
*Bio::P3::Workspace::WorkspaceImpl::CallContext = *Bio::P3::Workspace::Service::CallContext;
our $CallContext;

sub _format_datetime
{
    my($dt) = @_;
    $dt = $dt->clone();
    $dt->set_time_zone('UTC');
    return $dt->iso8601() . "Z";
}

#Returns the authentication token supplied to the service in the context object
sub _authentication {
	my($self) = @_;
	return $CallContext->token;
}

#Returns the username supplied to the service in the context object
sub _getUsername {
	my ($self) = @_;
	return $CallContext->user_id;
}

sub _getEscapedUsername {
	my ($self) = @_;
	return $self->_escape_username_for_mongo($CallContext->user_id);
}

sub _get_newobject_owner {
	my ($self) = @_;
	if (defined($CallContext->{_setowner}) && $self->_adminmode()) {
		return $CallContext->{_setowner};
	}
	return $self->_getUsername();
}

#Returns the method supplied to the service in the context object
sub _current_method {
	my ($self) = @_;
	if (!defined($CallContext)) {
		return undef;
	}
	return $CallContext->method;
}

sub _validateargs {
	my ($self,$args,$mandatoryArguments,$optionalArguments,$substitutions) = @_;
	$CallContext->{_adminmode} = 0;
	if (!defined($args)) {
	    $args = {};
	}
	if (ref($args) ne "HASH") {
		$self->_error("Arguments not hash");
	}
	if (defined($args->{adminmode}) && $args->{adminmode} == 1) {
		if ($self->_user_is_admin() == 0) {
			$self->_error("Cannot run functions in admin mode. User is not an admin!");
		}
		$CallContext->{_adminmode} = 1;
	}
	if (defined($substitutions) && ref($substitutions) eq "HASH") {
		foreach my $original (keys(%{$substitutions})) {
			$args->{$original} = $args->{$substitutions->{$original}};
		}
	}
	if (defined($mandatoryArguments)) {
		for (my $i=0; $i < @{$mandatoryArguments}; $i++) {
			if (!defined($args->{$mandatoryArguments->[$i]})) {
				push(@{$args->{_error}},$mandatoryArguments->[$i]);
			}
		}
	}
	if (defined($args->{_error})) {
		$self->_error("Mandatory arguments ".join("; ",@{$args->{_error}})." missing.");
	}
	if (defined($optionalArguments)) {
		foreach my $argument (keys(%{$optionalArguments})) {
			if (!defined($args->{$argument})) {
				$args->{$argument} = $optionalArguments->{$argument};	
			}
		}
	}
	return $args;
}

sub _shockurl {
	my $self = shift;
	return $self->{_params}->{"shock-url"};
}

sub _wsauth {
	my $self = shift;
	if (!defined($self->{_wsauth})) {
	    #
	    # Currently our token comes from a RAST-authenticated login. This should
	    # get factored out / improved if we change that assumption.
	    #
	    my $token = P3AuthLogin::login_rast($self->{_params}->{wsuser}, $self->{_params}->{wspassword});
	    $token or die "Failure logging in service user\n";
	    $self->{_wsauth} = $token;
	}
	return $self->{_wsauth};
}

sub _url {
	my $self = shift;
	return $self->{_params}->{"url"};
}

sub _error {
	my($self,$msg) = @_;
	$msg = "_ERROR_".$msg."_ERROR_";
	die $msg;
}

sub _db_path {
	my($self) = @_;
	return $self->{_params}->{"db-path"};
}

sub _mongodb {
	my ($self) = @_;
	return $self->{_mongodb};
}

sub _adminmode {
	my ($self) = @_;
	if (!defined($CallContext->{_adminmode})) {
		$CallContext->{_adminmode} = 0;
	}
	return $CallContext->{_adminmode};
}

sub _user_is_admin {
	my ($self) = @_;
	if (defined($self->{_admins}->{$self->_getUsername()})) {
		return 1;
	}
	return 0;
}

sub _updateDB {
	my ($self,$name,$query,$update) = @_;
	$self->_mongodb()->get_collection($name)->update($query,$update);
	return 1;
}

#Retrieving workspace object from mongodb**
sub _get_db_ws {
	my ($self,$query,$throwerror) = @_;
	if (defined($query->{raw_id})) {
		my $id = $query->{raw_id};
		delete $query->{raw_id};
		if ($id =~ m/^\/([^\/]+)\/([^\/]+)\/*$/) {
			$query->{owner} = $1;
			$query->{name} = $2;
		} elsif ($id =~ m/^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$/) {
			$query->{uuid} = $id;
		} elsif ($id =~ m/([^\/]+)\/*$/) {
			$query->{owner} = $self->_getUsername();
			$query->{name} = $1;
		}
	}
	my $cursor = $self->_mongodb()->get_collection('workspaces')->find($query);
	my $object = $cursor->next;
	if (!defined($object) && defined($throwerror) && $throwerror == 1) {
		$self->_error("Workspace not found!");
	}
	#
	# We must walk the permissions field and unescape the username keys.
	#
	if (ref($object) eq 'HASH')
	{
	    my $old_perms = $object->{permissions};
	    if (ref($old_perms) eq 'HASH')
	    {
		my $new_perms = {};
		while (my($user, $perm) = each %$old_perms)
		{
		    $new_perms->{$self->_unescape_username_for_mongo($user)} = $perm;
		}
		$object->{permissions} = $new_perms;
	    }
	}
	     
	return $object;
}

#Retrive object from mongodb based on input query**
sub _get_db_object {
	my ($self,$query,$throwerror) = @_;
	my $objects = $self->_query_database($query,0);
	if (!defined($objects->[0]) && $throwerror == 1) {
		$self->_error("Object not found!");
	}
	return $objects->[0];
}

#Returns metadata tuple for input object or workspace**
sub _generate_object_meta {
	my ($self,$obj) = @_;
	my $creation_dt = $date_parser->parse_datetime($obj->{creation_date});
	my $creation_date = _format_datetime($creation_dt);	
	if (defined($obj->{workspace_uuid})) {
		my $path = "/".$obj->{wsobj}->{owner}."/".$obj->{wsobj}->{name}."/".$obj->{path}."/";
		if (length($obj->{path}) == 0) {
			$path = "/".$obj->{wsobj}->{owner}."/".$obj->{wsobj}->{name}."/";
		}
		my $shock = "";
		if (defined($obj->{shocknode})) {
			$shock = $obj->{shocknode};
		}
		$obj->{autometadata}->{is_folder} = $self->is_folder($obj->{type});
		return [$obj->{name},
			$obj->{type},
			$path,
			$creation_date,
			$obj->{uuid},
			$obj->{owner},
			$obj->{size},
			$obj->{metadata},
			$obj->{autometadata},
			$self->_get_ws_permission($obj->{wsobj}),
			$obj->{wsobj}->{global_permission},
			$shock];
	} else {
		return [$obj->{name},
			"folder",
			"/".$obj->{owner}."/",
			$creation_date,
			$obj->{uuid},
			$obj->{owner},
			0,
			$obj->{metadata},
		        {},
			$self->_get_ws_permission($obj),
			$obj->{global_permission},
			""];
	}
}

#
# Retrieving object data from filesystem or giving permission to download shock node**
#
# This routine is only invoked after verifying the current user has permissions on the file.
# Thus we can check for the Shock permissions to allow the current user permission
# if that user is different from the owner of the file.
#
sub _retrieve_object_data {
	my ($self,$obj,$wsobj) = @_;
	if ($obj->{folder} == 1) {
		return "";
	}
	my $ws = $obj->{wsobj};
	my $data;
	if (!defined($obj->{shock}) || $obj->{shock} == 0) {
		my $filename = $self->_db_path()."/".$ws->{owner}."/".$ws->{name}."/".$obj->{path}."/".$obj->{name};
		open (my $fh,"<",$filename);
		while (my $line = <$fh>) {
			$data .= $line;	
		}
		close($fh);
	} else {
		if ($wsobj->{global_permission} ne "n") {
			$self->_make_shock_node_public($obj->{shocknode});
		}
		else
		{
			my $ua = LWP::UserAgent->new();
			my $res = $ua->put($obj->{shocknode}."/acl/all?users=".$self->_getUsername(),Authorization => "OAuth ".$self->_wsauth());
		}
		$data = $obj->{shocknode};
	}
	if (!defined($data)) {
		$data = "";
	}
	return $data;
}

#Validating that the input permissions have a recognizable value**
sub _validate_workspace_permission {
	my ($self,$input) = @_;
	if ($input !~ m/^[awronp]$/) {
		$self->_error("Input permissions ".$input." invalid!");
	}
	return $input;
}

#Validating that the input workspace name does not contain bad characters**
sub _validate_workspace_name {
	my ($self,$input) = @_;
	if (!defined($input)) {
		$self->_error("Workspace name is undefined!");
	}
	if (length($input) == 0) {
		$self->_error("Workspace name is empty!");
	}
	if ($input =~ m/[:\/]/) {
		$self->_error("Workspace ".$input." contains forbidden characters!");
	}
	return $input;
}
#Validating that the input workspace name does not contain bad characters**
sub _validate_object_name {
	my ($self,$input) = @_;
	if (!defined($input)) {
		$self->_error("Object name is undefined!");
	}
	if (length($input) == 0) {
		$self->_error("Object name is empty!");
	}
	if ($input =~ m/[:\/]/) {
		$self->_error("Object name ".$input." contains forbidden characters!");
	}
	return $input;
}

#Validating object type**
sub _validate_object_type {
	my ($self,$type) = @_;
	$type = lc($type);
	if ($type eq "directory") {
		$type = "folder";
	}
	if (!defined($self->{_types}->{$type})) {
		$self->_error("Invalid type submitted!");
	}
	return $type;
}


sub _get_ws_permission {
	my ($self,$wsobj) = @_;
	if ($wsobj->{global_permission} eq "p") {
		return "p";
	}
	my $curruser = $self->_getUsername();
	if ($wsobj->{owner} eq $curruser) {
		return "o";
	}
	my $values = {
		n => 0,
		p => 1,
		r => 1,
		w => 2,
		a => 3,
		o => 4
	};
	if (defined($wsobj->{permissions}->{$curruser})) {
		if ($values->{$wsobj->{permissions}->{$curruser}} > $values->{$wsobj->{global_permission}}) {
			return $wsobj->{permissions}->{$curruser};
		}
	}
	return $wsobj->{global_permission};
}

#Checking whether user has sufficient permissions to undertake action**
sub _check_ws_permissions {
	my ($self,$wsobj,$minperm,$throwerror) = @_;
	if ($self->_adminmode() == 1) {
		return 1;
	}
	my $perm = $self->_get_ws_permission($wsobj);
	my $values = {
		n => 0,
		p => 1,
		r => 1,
		w => 2,
		a => 3,
		o => 4
	};
	if ($values->{$perm} < $values->{$minperm}) {
		if ($throwerror == 1) {
			$self->_error("User lacks permission to ".$wsobj->{owner}."/".$wsobj->{name}." for requested action!");
		}
		return 0;
	}
	return 1;
}

sub _escape_username_for_mongo
{
    my($self, $name) = @_;

    return uri_escape($name, '.\$');
}

sub _unescape_username_for_mongo
{
    my($self, $name) = @_;

    return uri_unescape($name);
}

#Parses input full paths to user, workspace, path, and object**
sub _parse_ws_path {
	my ($self,$input) = @_;
	#Three classes of paths are accepted:
	#/<username>/<workspace>/
	#/_uuid/<ws uuid>/
	#<obj uuid>
	
	#<obj uuid>
	$input =~ s/\/+/\//g;
	
	if ($input =~ m/^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$/) {
		my $obj = $self->_query_database({uuid => $input});
		return ($obj->[0]->{wsobj}->{owner},$obj->[0]->{wsobj}->{name},$obj->[0]->{path},$obj->[0]->{name});
	}
	
	#/_uuid/<ws uuid>/
	if ($input =~ m/^\/_uuid\/([A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12})\/*$/) {
		my $wsobj = $self->_wscache("_uuid",$1);
		return ($wsobj->{owner},$wsobj->{name},"","");
	}
	if ($input =~ m/^\/_uuid\/([A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12})\/([^\/]+)\/*$/) {
		my $wsobj = $self->_wscache("_uuid",$1);
		return ($wsobj->{owner},$wsobj->{name},"",$2);
	}
	if ($input =~ m/^\/_uuid\/([A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12})\/(.+)\/([^\/]+)\/*$/) {
		my $wsobj = $self->_wscache("_uuid",$1);
		return ($wsobj->{owner},$wsobj->{name},$2,$3);
	}
	#/<username>/<workspace>
	$input =~ s/\/+/\//g;
	if ($input =~ m/^\/([^\/]+)\/([^\/]+)\/*$/) {
		return ($1,$2,"","");
	}
	if ($input =~ m/^\/([^\/]+)\/([^\/]+)\/([^\/]+)\/*$/) {
		return ($1,$2,"",$3);
	}
	if ($input =~ m/^\/([^\/]+)\/([^\/]+)\/(.+)\/([^\/]+)\/*$/) {
		return ($1,$2,$3,$4);
	}
}

sub _count_directory_contents {
	my ($self,$obj,$recursive) = @_;
	if ($recursive == 1) {
		my $path = "^".$obj->{path}."/".$obj->{name};
		$path =~ s/[()]/\\$&/g; #RDO 2020-1201
		return $self->_query_database({
			workspace_uuid => $obj->{workspace_uuid},
			path => qr/$path/
		},1);
	}
	return $self->_query_database({
		workspace_uuid => $obj->{workspace_uuid},
		path => $obj->{path}."/".$obj->{name}
	},1);
}

#Get all subobjects contained within directory**
sub _get_directory_contents {
	my ($self,$obj,$recursive) = @_;
	my $query = {};
#pathfix
	my $esc_path = quotemeta($obj->{path});
	my $esc_name = quotemeta($obj->{name});
	if ($recursive == 1) {
		my $path = "^".$esc_path."/".$esc_name;
		if (length($obj->{path}) == 0) {
			$path = "^".$esc_name;
		}
		$query = {
			workspace_uuid => $obj->{workspace_uuid},
			path => qr/$path/
		};
	} else {
		my $path = $esc_path."/".$esc_name;
		if (length($obj->{path}) == 0) {
			$path = $esc_name;
		}
		$query = {
			workspace_uuid => $obj->{workspace_uuid},
			path => $path
		};
	}
	my $objects = $self->_query_database($query,0);
	return $objects;
}

#Retrive objects from mongodb based on input query**
sub _query_database {
	my ($self,$query,$count,$update_shock, $hint) = @_;
	if (defined($query->{path})) {
		$query->{path} =~ s/^\///;
		$query->{path} =~ s/\/$//;
	}
	if ($count == 1) {
		return $self->_mongodb()->get_collection('objects')->count($query);
	}
	my $output = [];
	# print "RUN QUERY " . Dumper($query);
	my $cursor = $self->_mongodb()->get_collection('objects')->find($query);
	if ($hint)
	{
	    # print STDERR "USE HINT $hint\n";
	    $cursor = $cursor->hint($hint);
	    # print Dumper($cursor);
	}
	my $hash;
	while (my $object = $cursor->next) {
		$object->{wsobj} = $self->_wscache("_uuid",$object->{workspace_uuid});
		if ($object->{shock} == 1 && $object->{size} == 0) {			
			$self->_update_shock_node($object,$update_shock);
		}
		if (defined($hash->{$object->{workspace_uuid}}->{$object->{path}}->{$object->{name}})) {
			for (my $i=0; $i < @{$output}; $i++) {
				if ($output->[$i] == $hash->{$object->{workspace_uuid}}->{$object->{path}}->{$object->{name}}) {
					$self->_mongodb()->get_collection('objects')->remove({
						uuid => $output->[$i]->{uuid},
						workspace_uuid => $output->[$i]->{workspace_uuid},
						path => $output->[$i]->{path},
						name => $output->[$i]->{name}
					});
					$output->[$i] = $object;
				}
			}
		} else {
			push(@{$output},$object);
		}
		$hash->{$object->{workspace_uuid}}->{$object->{path}}->{$object->{name}} = $object;
	}
	return $output;
}

#Copy of move a set of objects in the database**
sub _copy_or_move_objects
{
    my ($self,$objects, $overwrite, $recursive,$move) = @_;
    my $output = [];
    my $wshash = {};
    my $destinations;
    my $objdest;
    my $delhash = {};
    my $saveobjs = [];
    for (my $i=0; $i < @{$objects}; $i++) {
    	my ($user,$ws,$path,$name) = $self->_parse_ws_path($objects->[$i]->[0]);
    	my $wsobj = $self->_wscache($user,$ws);
    	if ($move == 0) {
	    $self->_check_ws_permissions($wsobj,"r",1);
    	} else {
	    $self->_check_ws_permissions($wsobj,"w",1);
    	}
    	#Checking if a workspace is being copied
    	if (length($path)+length($name) == 0) {
	    if ($move == 1) {
		$self->_check_ws_permissions($wsobj,"o",1);
	    }
	    #Adding original to del hash
	    if ($move == 1) {
		$delhash->{$user}->{$ws}->{$path}->{$name} = $wsobj;
	    }
	    #Adding object to save array
	    push(@{$saveobjs},[$objects->[$i]->[1],"folder",$wsobj->{metadata},$wsobj,undef,1,$move]);
	    if ($recursive == 1) {
		my $subobjs = $self->_query_database({workspace_uuid => $wsobj->{uuid}},0);
		for (my $j=0; $j < @{$subobjs}; $j++) {
    				#Computing destination path
		    my $dpath = $objects->[$i]->[1]."/".$subobjs->[$j]->{path}."/".$subobjs->[$j]->{name};
		    $dpath =~ s/\/+/\//g;
    				#Adding subobject to save array
		    push(@{$saveobjs},[$dpath,$subobjs->[$j]->{type},$subobjs->[$j]->{metadata},$subobjs->[$j],undef,1,$move]);
		}
	    }
    	} else {
	    #An object is being copied
	    my $obj = $self->_get_db_object({
		workspace_uuid => $wsobj->{uuid},
		path => $path,
		name => $name
		},1);
	    #Adding original to del hash
	    if ($move == 1) {
		$delhash->{$user}->{$ws}->{$path}->{$name} = $obj;
	    }
	    #Adding object to save array
	    push(@{$saveobjs},[$objects->[$i]->[1],$obj->{type},$obj->{metadata},$obj,undef,1,$move]);
	    #Checking if object being copied is a directory
	    if	($obj->{folder} == 1 && $recursive == 1) {
		my $subobjs = $self->_get_directory_contents($obj,1);
		for (my $j=0; $j < @{$subobjs}; $j++) {
	    			#Computing destination path
		    my $subpath = $obj->{path}."/".$obj->{name};
		    if (length($obj->{path}) == 0) {
			$subpath = $obj->{name};
		    }
		    my $partialpath = substr($subobjs->[$j]->{path},length($subpath));
		    my $dpath = $objects->[$i]->[1]."/".$partialpath."/".$subobjs->[$j]->{name};
		    $dpath =~ s/\/+/\//g;
    				#Adding subobject to save array
		    push(@{$saveobjs},[$dpath,$subobjs->[$j]->{type},$subobjs->[$j]->{metadata},$subobjs->[$j],undef,1,$move]);
		}
	    }
    	}
    }
    #Validating the save list
    my $voutput = $self->_validate_save_objects_before_saving($saveobjs,$overwrite);
    #Running deletions
    $self->_delete_validated_object_set($voutput->{del});
    #Creating objects
    $self->_write_log("begin copy create");
    my $output = $self->_create_validated_object_set($voutput->{create},0,0,"n");
    $self->_write_log("end copy create");
    #Running deletions
    if (keys(%{$delhash}) > 0) {
	$self->_write_log("begin copy delete");
	$self->_delete_validated_object_set($delhash);
	$self->_write_log("end copy delete");
    }
    return $output;
}

#This function creates an empty shock node, gives the logged user ACLs, and returns the node ID**
sub _create_shock_node {
	my ($self) = @_;
	my $ua = LWP::UserAgent->new();
	my $res = $ua->post($self->_shockurl()."/node",Authorization => "OAuth ".$self->_wsauth());
	my $json = JSON::XS->new;
	my $data = $json->decode($res->content);
	my $res = $ua->put($self->_shockurl()."/node/".$data->{data}->{id}."/acl/all?users=".$self->_getUsername(),Authorization => "OAuth ".$self->_wsauth());
	return $data->{data}->{id};
}

sub _make_shock_node_public {
	my ($self,$url) = @_;
	my $ua = LWP::UserAgent->new();
	my $res = $ua->get($url."/acl/",Authorization => "OAuth ".$self->_wsauth());
	my $json = JSON::XS->new;
	my $data = $json->decode($res->content);

	#
	# This is wrong:
	# $res = $ua->delete($url."/acl/read?users=".join(",",@{$data->{data}->{read}}),Authorization => "OAuth ".$self->_wsauth());
	#
	# The current shock in PATRIC is old and does not support the public acl. So here we will
	# add the user to the acl list.
	#
	$ua->put("$url/acl/read?users=".$self->_getUsername(),Authorization => "OAuth ".$self->_wsauth());
}

sub _update_shock_node {
    my ($self,$object,$force) = @_;
    if ($force == 1 ||
	!defined($self->{_shockupdate}->{$object->{uuid}}) ||
	(time() - $self->{_shockupdate}->{$object->{uuid}}) > $self->{_params}->{"update-interval"}) {

	#
	# Need to ensure the shock node is valid (we have had bugs in the past that resulted
	# in the node string ending in / which results in an attempted dump of all nodes in shock)
	#
	if ($object->{shocknode} =~ m,/$,)
	{
	    warn "Invalid shock node $object->{shocknode} in " . Dumper($object);
	    return;
	}
	my $ua = LWP::UserAgent->new();
	my $res = $ua->get($object->{shocknode},Authorization => "OAuth ".$self->_wsauth());
		my $json = JSON::XS->new;
		my $data = $json->decode($res->content);
		if (length($data->{data}->{file}->{name}) == 0) {
			$self->{_shockupdate}->{$object->{uuid}} = time();
		} else {
			my $timestamp = _format_datetime(DateTime->now());
			delete $self->{_shockupdate}->{$object->{uuid}};
			$object->{size} = $data->{data}->{file}->{size};
			$object->{autometadata}->{inspection_started} = $timestamp;
			$self->_updateDB("objects",{uuid => $object->{uuid}},{'$set' => {size => $data->{data}->{file}->{size},"autometadata.inspection_started" => $timestamp}});
			$self->_compute_autometadata([$object]);
		}
	}
}

#This function clears away any exiting objects before saving new objects. Returns a hash of all objects involved**
sub _validate_save_objects_before_saving {
	my ($self,$objects,$overwrite) = @_;
    my $output = {};
    for (my $i=0; $i < @{$objects}; $i++) {
    	#Parsing path
    	my ($user,$ws,$path,$name) = $self->_parse_ws_path($objects->[$i]->[0]);
    	if (!defined($output->{create}->{$user}->{$ws}->{$path}->{$name})) {
	    	#Checking metadata
	    	if (!defined($objects->[$i]->[2])) {
	    		$objects->[$i]->[2] = {};
	    	} elsif (ref($objects->[$i]->[2]) ne 'HASH') {
	    		$self->_error("Meta data for ".$objects->[$i]->[0]." is not a valid type!");	
	    	}
	    	#Checking object type
	    	$objects->[$i]->[1] = $self->_validate_object_type($objects->[$i]->[1],$objects->[$i]->[0]);
	    	#Checking if any workspace is listed
	    	if (length($ws) == 0) {
	    		$self->_error($objects->[$i]->[0]." is not a valid object path!");	
	    	}
	    	#Attempting to retrieve workspace object
	    	my $wsobj = $self->_wscache($user,$ws);
	    	if ((length($path)+length($name)) == 0) {
	    		my $nocreate = 0;
	    		#We are creating a workspace
	    		if (defined($wsobj)) {
		    		if ($self->is_folder($objects->[$i]->[1]) == 1) {
		    			#We ignore creation of folders that already exist
		    			$nocreate = 1;	
		    		} else {
		    			#Cannot overwrite a workspace on creation
		    			$self->_error("Cannot overwrite existing top level folder:".$objects->[$i]->[0]);
		    		}
		    	} elsif ($user ne $self->_getUsername() && $self->_adminmode() == 0) {
		    		#Users can only create their own workspaces
		    		$self->_error("Insufficient permissions to create ".$objects->[$i]->[0]);
		    	} elsif ($self->is_folder($objects->[$i]->[1]) == 0) {
		    		#Workspace must be a folder
		    		$self->_error("Cannot create ".$objects->[$i]->[0]." because top level objects must be folders!");
		    	}
		    	#Checking workspace name
		    	$ws = $self->_validate_workspace_name($ws);
		    	#Adding workspace to creation list
			print Dumper(O => $objects->[$i], $output, $nocreate);
		    	if ($nocreate == 0) {
		    		$output->{create}->{$user}->{$ws}->{$path}->{$name} = $objects->[$i];
		    	}
	    	} elsif (!defined($wsobj)) {
	    		#Saving to nonexistent workspace - adding workspace to creation list
	    		$output->{create}->{$user}->{$ws}->{""}->{""} = [$user."/".$ws,"folder",{},undef];
	    	} else {
	    		#Saving to existing workspace - checking permissions
	    		$self->_check_ws_permissions($wsobj,"w",1);
	    		#Checking object name
		    	$name = $self->_validate_object_name($name);
	    		#Checking for potential overwritten objects
	    		my $obj = $self->_get_db_object({
			    	workspace_uuid => $wsobj->{uuid},
			    	path => $path,
			    	name => $name
			    },0);
			    my $nocreate = 0;
			    if (defined($obj)) {
		    		if ($obj->{folder} == 1) {
		    			if ($self->is_folder($objects->[$i]->[1]) == 1) {
		    				#We ignore creation of folders that already exist
		    				$nocreate = 1;	
		    			} else {
		    				$self->_error("Cannot overwrite directory ".$objects->[$i]->[0]." on save!");
		    			}
		    		} elsif ($overwrite == 0) {
		    			$self->_error("Overwriting object ".$objects->[$i]->[0]." and overwrite flag is not set!");
		    		}
		    		if ($nocreate == 0) {
		    			$output->{del}->{$user}->{$ws}->{$path}->{$name} = $obj;
		    		}
		    	} else {
		    		#Checking that all subdirectories exist, and if they don't, adding them
		    		my $array = [split(/\//,$path)];
		    		my $currpath = "";
		    		for (my $i=0; $i < @{$array}; $i++) {
		    			my $subdir = $self->_get_db_object({
					    	workspace_uuid => $wsobj->{uuid},
					    	path => $currpath,
					    	name => $array->[$i]
					    },0);
					    if (!defined($subdir)) {
					    	$output->{create}->{$user}->{$ws}->{$currpath}->{$array->[$i]} = [$user."/".$ws."/".$currpath."/".$array->[$i],"folder",{},undef];
					    }
					    if (length($currpath) > 0) {
					    	$currpath .= "/";
					    }
					    $currpath .= $array->[$i];
		    		}
		    	}
		    	if ($nocreate == 0) {
		    		$output->{create}->{$user}->{$ws}->{$path}->{$name} = $objects->[$i];
		    	}
	    	}
    	}
    }
    return $output;
}
#Only call this function if the entire deletion list has been validated for existance and permissions** 
sub _delete_validated_object_set {
    my ($self,$delhash,$nodeletefiles) = @_;
    foreach my $user (keys(%{$delhash})) {
    	foreach my $workspace (keys(%{$delhash->{$user}})) {
	    my $paths = [reverse(sort(keys(%{$delhash->{$user}->{$workspace}})))];
	    foreach my $path (@{$paths}) {
		foreach my $object (keys(%{$delhash->{$user}->{$workspace}->{$path}})) {
		    if ((length($path)+length($object)) == 0) {
			$self->_delete_workspace($delhash->{$user}->{$workspace}->{$path}->{$object});
		    } else {
			$self->_delete_object($delhash->{$user}->{$workspace}->{$path}->{$object},$nodeletefiles);
		    }
		}
	    }
    	}
    }
}
#Delete the specified workspace and all the objects it contains**
sub _delete_workspace {
	my ($self,$wsobj) = @_;
    if (!defined($wsobj->{owner}) || length($wsobj->{owner}) == 0) {$self->_error("Owner not specified in deletion!");}
    if (!defined($wsobj->{name}) || length($wsobj->{name}) == 0) {$self->_error("Top directory not specified in deletion!");}
    rmtree($self->_db_path()."/".$wsobj->{owner}."/".$wsobj->{name});
	$self->_mongodb()->get_collection('workspaces')->remove({uuid => $wsobj->{uuid}});
	$self->_mongodb()->get_collection('objects')->remove({workspace_uuid => $wsobj->{uuid}});
}
#Delete the specified object**
sub _delete_object {
    my ($self,$obj,$nodeletefiles) = @_;
    #Ensuring all parts of object path have nonzero length
    if (!defined($obj->{wsobj}->{owner}) || length($obj->{wsobj}->{owner}) == 0)
    {
	$self->_error("Owner not specified in deletion!");
    }
    if (!defined($obj->{wsobj}->{name}) || length($obj->{wsobj}->{name}) == 0)
    {
	$self->_error("Top directory not specified in deletion!");
    }
    if (!defined($obj->{name}) || length($obj->{name}) == 0)
    {
	$self->_error("Name not specified in deletion!");
    }
    if ($obj->{folder} == 1) {
	my $objs = $self->_get_directory_contents($obj,0);
	for (my $i=0; $i < @{$objs}; $i++) {
	    $self->_delete_object($objs->[$i]);
	}
	if (!defined($nodeletefiles)) {
	    rmtree($self->_db_path()."/".$obj->{wsobj}->{owner}."/".$obj->{wsobj}->{name}."/".$obj->{path}."/".$obj->{name});
	}
	$self->_write_log("begin_delete_folder", $obj->{uuid}, $obj->{workspace_uuid},
			  $obj->{path}, $obj->{name}, $obj->{shocknode});
	$self->_mongodb()->get_collection('objects')->remove({
	    uuid => $obj->{uuid},
	    workspace_uuid => $obj->{workspace_uuid},
	    path => $obj->{path},
	    name => $obj->{name}
	});
	$self->_write_log("end_delete_folder", $obj->{uuid}, $obj->{workspace_uuid}, $obj->{path}, $obj->{name}, $obj->{shocknode});
    } else {
	$self->_write_log("begin_delete_object", $obj->{uuid}, $obj->{workspace_uuid}, $obj->{path}, $obj->{name}, $obj->{shocknode});
	$self->_mongodb()->get_collection('objects')->remove({
	    uuid => $obj->{uuid},
	    workspace_uuid => $obj->{workspace_uuid},
	    path => $obj->{path},
	    name => $obj->{name}
	});
	$self->_write_log("end_delete_object", $obj->{uuid}, $obj->{workspace_uuid}, $obj->{path}, $obj->{name}, $obj->{shocknode});
	if (!defined($nodeletefiles)) {
	    unlink($self->_db_path()."/".$obj->{wsobj}->{owner}."/".$obj->{wsobj}->{name}."/".$obj->{path}."/".$obj->{name});
	}
    }
}

#Only call this function to create a set of prevalidated object**
sub _create_validated_object_set {
    my ($self,$createhash,$createUploadNodes,$downloadFromLinks,$permission) = @_;
    #Only call this function if the entire creation list has been validated for subdirectories, overwrites, and permissions
    my $output = [];
    foreach my $user (keys(%{$createhash})) {
    	foreach my $workspace (keys(%{$createhash->{$user}})) {
	    my $paths = [(sort(keys(%{$createhash->{$user}->{$workspace}})))];
	    foreach my $path (@{$paths}) {
		foreach my $object (keys(%{$createhash->{$user}->{$workspace}->{$path}})) {
		    my $objspec = $createhash->{$user}->{$workspace}->{$path}->{$object};
		    my $createinput = {
			user => $user,
			workspace => $workspace,
			path => $path,
			name => $object,
			permission => $permission,
			type => $objspec->[1],
			data => $objspec->[3],
			metadata => $objspec->[2],
			createUploadNodes => $createUploadNodes,
			downloadFromLinks => $downloadFromLinks,
		    };
		    if (defined($objspec->[4])) {
			if ($self->_getUsername() ne $self->{_params}->{wsuser} && $self->_adminmode() eq 0) {
			    $self->_error("Only the workspace or admin can set creation date!");	
			}
			if ($objspec->[4] =~ m/^\d+$/) {
			    $objspec->[4] = _format_datetime(DateTime->from_epoch( epoch => $objspec->[4] ));
			}
			$createinput->{creation_date} = $objspec->[4];
		    }
		    if (defined($objspec->[5])) {
			$createinput->{copy} = $objspec->[5];
			$createinput->{move} = $objspec->[6];
		    }
		    my $obj = $self->_create($createinput);
		    push(@{$output},$obj);
		}
	    }
    	}
    }
    $self->_compute_autometadata($output);
    return $output;
}

#This function creates objects and workspaces**
sub _create {
    my ($self,$specs) = @_;
    if (length($specs->{path}) == 0 && length($specs->{name}) == 0) {
		return $self->_create_workspace($specs);
	}
	return $self->_create_object($specs);
}
#This function creates workspaces**
sub _create_workspace {
	my ($self,$specs) = @_;
    if (!defined($specs->{user}) || length($specs->{user}) == 0) {$self->_error("Owner not specified in creation!");}
    if (!defined($specs->{workspace}) || length($specs->{workspace}) == 0) {$self->_error("Top directory not specified in creation!");}
    if ($specs->{user} ne $self->_getUsername() && $self->_adminmode() == 0) {
    	$self->_error("User does not have permission to create workspace!");
    }
    
    #Creating workspace directory on disk
    File::Path::mkpath ($self->_db_path()."/".$specs->{user}."/".$specs->{workspace});
    #Creating workspace object in mongodb
    my $uuid = Data::UUID->new()->create_str();
    if (defined($specs->{move}) && $specs->{move} == 1) {
    	$uuid = $specs->{data}->{uuid};
    }
    if (!defined($specs->{creation_date})) {
    	$specs->{creation_date} = _format_datetime(DateTime->now());
    }
    $self->_mongodb()->get_collection('workspaces')->insert({
		creation_date => $specs->{creation_date},
		uuid => $uuid,
		name => $specs->{workspace},
		owner => $specs->{user},
		global_permission => $specs->{permission},
		metadata => $specs->{metadata},
		permissions => {}
	});
	return $self->_get_db_ws({
		name => $specs->{workspace},
		owner => $specs->{user}
	});
}
#This function creates objects**
sub _create_object {
    my ($self,$specs) = @_;
    $specs->{path} =~ s/^\/+//;
    $specs->{path} =~ s/\/+$//;
    
    my $uuid = Data::UUID->new()->create_str();
    if (defined($specs->{move}) && $specs->{move} == 1) {
    	$uuid = $specs->{data}->{uuid};
    }
    if (!defined($specs->{creation_date})) {
    	$specs->{creation_date} = _format_datetime(DateTime->now());
    }
    my $wsobj = $self->_wscache($specs->{user},$specs->{workspace});
    $self->_check_ws_permissions($wsobj,"w",1);
    my $object = {
	wsobj => $wsobj,
	size => 0,
	folder => 0,
	type => $specs->{type},
	path => $specs->{path},
	name => $specs->{name},
	workspace_uuid => $wsobj->{uuid},
	uuid => $uuid,
	creation_date => $specs->{creation_date},
	owner => $self->_get_newobject_owner(),
	autometadata => { inspection_started => _format_datetime(DateTime->now()) },
	shock => 0,
	metadata => $specs->{metadata}
    };
    if (!-e $self->{_params}->{"script-path"}."/ws-autometa-".$specs->{type}.".pl") {
	$object->{autometadata} = {};
    }
    if (!defined($object->{wsobj}->{owner}) || length($object->{wsobj}->{owner}) == 0) {$self->_error("Owner not specified in creation!");}
    if (!defined($object->{wsobj}->{name}) || length($object->{wsobj}->{name}) == 0) {$self->_error("Top directory not specified in creation!");}
    if (!defined($object->{name}) || length($object->{name}) == 0) {$self->_error("Name not specified in creation!");}
    if ($self->is_folder($specs->{type}) == 1) {
	#Creating folder on file system
	$object->{autometadata} = {};
	$object->{folder} = 1;
	File::Path::mkpath ($self->_db_path()."/".$specs->{user}."/".$specs->{workspace}."/".$specs->{path}."/".$specs->{name});
    } elsif (defined($specs->{copy}) && $specs->{copy} == 1) {
	$object->{shock} = $specs->{data}->{shock};
	$object->{size} = $specs->{data}->{size};
	$object->{autometadata} = $specs->{data}->{autometadata};
	if (defined($specs->{data}->{shocknode})) {
	    $object->{shocknode} = $specs->{data}->{shocknode};
	}
	if (defined($specs->{data}->{downloadLink})) {
	    $object->{downloadLink} = $specs->{data}->{downloadLink};
	}
	if (defined($specs->{data}->{downloaded})) {
	    $object->{downloaded} = $specs->{data}->{downloaded};
	}
	if ($object->{shock} == 0) {
	    if ($specs->{move} == 1) {
		mv($self->_db_path()."/".$specs->{data}->{wsobj}->{owner}."/".$specs->{data}->{wsobj}->{name}."/".$specs->{data}->{path}."/".$specs->{data}->{name},$self->_db_path()."/".$specs->{user}."/".$specs->{workspace}."/".$specs->{path}."/".$specs->{name});
	    } else {
		cp($self->_db_path()."/".$specs->{data}->{wsobj}->{owner}."/".$specs->{data}->{wsobj}->{name}."/".$specs->{data}->{path}."/".$specs->{data}->{name},$self->_db_path()."/".$specs->{user}."/".$specs->{workspace}."/".$specs->{path}."/".$specs->{name});
	    }
	}
    } elsif ($specs->{createUploadNodes} == 1) {
	#Creating upload node if requested
	$object->{shock} = 1;
	$object->{shocknode} = $self->_shockurl()."/node/".$self->_create_shock_node();
    } elsif ($specs->{downloadFromLinks} == 1) {
	#Creating upload node and setting download link, which will be processed asynchronously
	$object->{shock} = 1;
	$object->{shocknode} = $self->_shockurl()."/node/".$self->_create_shock_node();
	$object->{downloadLink} = $specs->{data};
	$object->{downloaded} == 0;
    } else {
	#Writing data to file system directly and setting file size
	my $data = $specs->{data};
	if (!-d $self->_db_path()."/".$specs->{user}."/".$specs->{workspace}."/".$specs->{path}) {
	    File::Path::mkpath ($self->_db_path()."/".$specs->{user}."/".$specs->{workspace}."/".$specs->{path});
	}
	open (my $fh,">",$self->_db_path()."/".$specs->{user}."/".$specs->{workspace}."/".$specs->{path}."/".$specs->{name});
	if (ref($data) eq 'ARRAY' || ref($data) eq 'HASH') {
	    my $JSON = JSON::XS->new->utf8(1);
	    $data = $JSON->encode($data);	
	}
	print $fh $data;
	close($fh);
	my $fstat = stat($self->_db_path()."/".$specs->{user}."/".$specs->{workspace}."/".$specs->{path}."/".$specs->{name});
	$object->{size} = $fstat->size();
    }
    # Creating object in mongodb
    # We need to remove wsobj from the object so it doesn't land in the database.
    #
    my $wsobj_del = delete $object->{wsobj};
    $self->_mongodb()->get_collection('objects')->insert($object);
    
    $self->_write_log("create_object", $object->{uuid}, $object->{workspace_uuid},
		      $object->{path}, $object->{name}, $object->{shocknode});
    $object->{wsobj} = $wsobj_del;
    return $object;
}
#Retreive a workspace from the database either by uuid or by name/user**
sub _wscache {
	my ($self,$user,$ws,$throwerror) = @_;
	if (!defined($CallContext->{_wscache}->{$user}->{$ws})) {
		if ($user eq "_uuid") {
			my $obj = $self->_get_db_ws({
				uuid => $ws
			});
			$CallContext->{_wscache}->{$user}->{$ws} = $obj;
			$CallContext->{_wscache}->{$obj->{owner}}->{$obj->{name}} = $obj;
		} else {
			my $obj = $self->_get_db_ws({
				owner => $user,
				name => $ws
			});
			$CallContext->{_wscache}->{$user}->{$ws} = $obj;
			$CallContext->{_wscache}->{_uuid}->{$obj->{uuid}} = $obj;
		}
	}
	if (!defined($CallContext->{_wscache}->{$user}->{$ws})) {
		#delete $CallContext->{_wscache}->{$user}->{$ws};
		if ($throwerror == 1) {
			$self->_error("Workspace ".$user."/".$ws." does not exist!");
		}
	}
	return $CallContext->{_wscache}->{$user}->{$ws};
}

#List all workspaces matching input query**
sub _list_workspaces {
    my ($self,$user,$query) = @_;
    if (defined($user)) {
	$query->{owner} = $user;
    }
    if ($self->_adminmode() != 1)
    {
	my $user_perm_check = { join(".", "permissions", $self->_getEscapedUsername()) => { '$exists' => 1 }};
	if (defined($query->{'$or'}))
	{
	    my $oldarray = $query->{'$or'};
	    $query->{'$or'} = [];

	    for my $old_elt (@{$oldarray})
	    {
		my $included = 0;
		if (!defined($old_elt->{owner}))
		{
		    my $hash = {};
		    foreach my $key (keys(%{$old_elt}))
		    {
			$hash->{$key} = $old_elt->{$key};
		    }
		    $hash->{owner} = $self->_getUsername();
		    push(@{$query->{'$or'}},$hash);
		}
		elsif ($old_elt->{owner} eq $self->_getUsername())
		{
		    $included = 1;
		    my $hash = {};
		    foreach my $key (keys(%{$old_elt})) {
			$hash->{$key} = $old_elt->{$key};
		    }
		    push(@{$query->{'$or'}},$hash);
		}
		if (!defined($old_elt->{global_permission}))
		{
		    my $hash = {};
		    foreach my $key (keys(%{$old_elt})) {
			$hash->{$key} = $old_elt->{$key};
		    }
		    $hash->{global_permission} = {'$ne' => "n"};
		    push(@{$query->{'$or'}},$hash);
		}
		elsif ($old_elt->{global_permission} ne "n" && $included == 0)
		{
		    $included = 1;
		    my $hash = {};
		    foreach my $key (keys(%{$old_elt})) {
			$hash->{$key} = $old_elt->{$key};
		    }
		    push(@{$query->{'$or'}},$hash);
		}
		if (!defined($old_elt->{"permissions.".$self->_getUsername()}))
		{
		    my $hash = {};
		    foreach my $key (keys(%{$old_elt})) {
			$hash->{$key} = $old_elt->{$key};
		    }
		    $hash->{"permissions.".$self->_getUsername()} = {'$exists' => 1 };
		    push(@{$query->{'$or'}},$hash);
		}
		elsif ($included == 0)
		{
		    my $hash = {};
		    foreach my $key (keys(%{$old_elt})) {
			$hash->{$key} = $old_elt->{$key};
		    }
		    push(@{$query->{'$or'}},$hash);
		}
	    }
	}
	else
	{
	    $query->{'$or'} = [
			   { owner => $self->_getUsername() },
			   { global_permission =>  {'$ne' => "n"} },
			   $user_perm_check,
		];
	}
    }
    my $objs = [];
    my $cursor = $self->_mongodb()->get_collection('workspaces')->find($query);
	while (my $object = $cursor->next) {
		push(@{$objs},$object);
	}
	return $objs;
}

#
# Given a path string, return the regex suitable for
# a mongo search to return all objects below that path.
#
sub _compute_mongo_regex_for_path
{
    my($self, $path) = @_;
    if (length($path) > 0) {
	my $term = '(/|$)';
	
	# print STDERR "Before $path\n";
	#$path =~ s/[.()]/\\$&/g;
	$path = quotemeta($path);
	# print STDERR "After $path\n";
	
	my $rc = qr/^$path$term/;
	# print STDERR "RE $rc\n";
	return $rc;
    }
    else
    {
	return "";
    }
}

#List all objects matching input query**
sub _list_objects {
	my ($self,$fullpath,$query,$excludeDirectories,$excludeObjects,$recursive) = @_;
	my $hint;
	my ($user,$ws,$path,$name) = $self->_parse_ws_path($fullpath);
	if (length($name) > 0) {
		if (length($path) > 0) {
			$path .= "/";
		}
		$path .= $name;
	}
	my $wsobj = $self->_wscache($user,$ws);
	$self->_check_ws_permissions($wsobj,"r",1);
	if ($excludeDirectories == 1 && $excludeObjects == 1) {
		return [];
	}
	if (!defined($query)) {
		$query = {};
	}
	$query->{workspace_uuid} = $wsobj->{uuid};
	if ($excludeDirectories == 1) {
		$query->{folder} = 0;
	} elsif ($excludeObjects == 1) {
		$query->{folder} = 1;
	    }
	#
	# HACK: Force query hint for huge workspace.
	#
	my %bad_ws = ('942D0C20-D8CF-11EA-A092-E9C4682E0674' => 1,
		      '7E50286E-C07E-11EB-954E-D6FC682E0674' => 1);

	if ($recursive == 1 && !$bad_ws{$wsobj->{uuid}})
	{

	    if (length($path) > 0) {
		# print STDERR "INVOKE $path\n";
		$query->{path} = $self->_compute_mongo_regex_for_path($path);

		# print STDERR "GOT $path $query->{path}\n";
		#$path = "^".quotemeta($path);
		#$query->{path} = qr/$path/;

		if ($bad_ws{$wsobj->{uuid}})
		{
		    $hint = "path_1_workspace_uuid_1";
		}
	    }
	} else {
		$query->{path} = $path;
	}
	return $self->_query_database($query,0, 1, $hint);
}

#Formating queries to support direct mongo queries - this will need to get far more sophisticated**
sub _formatQuery {
	my ($self,$inquery,$workspaces) = @_;
	#Query fields:
	#owner => <string> (ws & obj)
	#metadata.key => <string> (ws & obj)
	#name => <string> (ws & obj)
	#type => <string> (obj)
	#uuid => <string> (ws & obj)
	#creation_date => <string> (ws & obj)
	#path => <string> (obj)
	#size => <num> (obj)
	if (defined($workspaces) && $workspaces == 1) {
		if (defined($inquery->{type})) {
			delete $inquery->{type};
		}
		if (defined($inquery->{size})) {
			delete $inquery->{size};
		}
		if (defined($inquery->{path})) {
			delete $inquery->{path};
		}
	}
	foreach my $term (keys(%{$inquery})) {
		if (ref($inquery->{$term}) eq "ARRAY" && $term ne '$or') {
			$inquery->{$term} = {'$in' => $inquery->{$term}};
		}
	}
	return $inquery;
}

#
# Here begins the implementation of the download handler.
#
# This code is executed in the context of an asynchronous IO web service, so
# we cannot allow the download request to block.
#

#
# Start the download service. This will create a timer to garbage-collect
# download records from the mongodb.
#


sub _download_service_start
{
    my($self) = @_;

    my $timer;
    $timer = AnyEvent->timer(after => 0,
			     interval => 120,
			     cb => sub { $self->_download_cleanup($self->{_mongodb}); });
    $self->{_download_timer} = $timer;
	
}

#
# This should be an async mongo lookup. Later.
#
sub _download_cleanup
{
    my($self, $db) = @_;
    for my $coll_name (qw(downloads auth_cookie))
    {
	my $coll = $db->get_collection($coll_name);
	my $now = time;
	$coll->remove({expiration_time => {'$lt', $now}});
	my $res = $db->last_error();
	if ($res->{ok})
	{
	    if ($res->{n} > 0)
	    {
		print STDERR "Removed $res->{n} expired records from $coll_name\n";
	    }
	}
	else
	{
	    print STDERR "Error expiring records from $coll_name: " . Dumper($res);
	}
    }
}

#
# Handle the request to create a session token in a cookie
# that is bound to the user's auth token
#

sub _set_auth_request
{
    my($self, $env) = @_;
    my $req = Plack::Request->new($env);
    my $path = $req->path_info;

    my $token = $req->header("Authorization");
    if (!$token)
    {
	return [401, [], ["Authentication required"]];
    }

    my $auth_token = P3AuthToken->new(token => $token, ignore_authrc => 1);
    my($valid, $validate_err) = P3TokenValidator->new->validate($auth_token);

    if (!$valid)
    {
        warn "Token validation error $validate_err\n";
	return [403, [], "Authentication failed"];
    }


    my $coll = $self->_mongodb()->get_collection('auth_cookie');

    my $download_lifetime = $self->{_params}->{'download-lifetime'};
    if (!$download_lifetime)
    {
	$download_lifetime = 60 * 60;
	warn "default dl lifetime to $download_lifetime\n";
    }
    my $expires = time + $download_lifetime;

    my $gen = Data::UUID->new;
    my $session_token = $gen->create_b64();
    $session_token =~ s/=*$//;
    $session_token =~ s/\+/-/g;
    $session_token =~ s,/,_,g;

    my $doc = {
	session_token => $session_token,
	expiration_time => $expires,
	auth_token => $token,
    };
    $coll->insert($doc);
    my $res = Plack::Response->new(200);
#    $res->header('Set-Cookie' => "session=$session_token; HttpOnly; SameSite=Lax; Path=/; Max-Age=$download_lifetime");
    $res->header('Set-Cookie' => "bvbrc_ws_view_session=$session_token; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=$download_lifetime");
    $res->body("Cookie set\n");
    return $res->finalize;
}

sub _download_request
{
    my($self, $env) = @_;
    my $req = Plack::Request->new($env);
    my $path = $req->path_info;

    if ($path =~ m,^/archive/([a-z0-9]{40})$,)
    {
	my $key = $1;
	$self->_handle_archive_request($req, $key);
    }
    else
    {
	my($dlid, $name) = $path =~ m,^/([^/]+)/([^/]+)$,;
	if (!($name && $dlid))
	{
	    return [404, ['Content-Type' => 'text/plain' ], ["Invalid path\n"]];
	}
	$self->_handle_dl_file_request($req, $name, $dlid);
    }
}

#
# This handler is mounted at / and should only be hit when
# /download or /view not included.
#
sub _download_request_orig
{
    my($self, $env) = @_;
    my $req = Plack::Request->new($env);
    my $path = $req->path_info;

    if ($path =~ m,^/archive/([a-z0-9]{40})$,)
    {
	my $key = $1;
	$self->_handle_archive_request($req, $key);
    }
    else
    {
	my($dlid, $name) = $path =~ m,^/([^/]+)/([^/]+)$,;
	if (!($name && $dlid))
	{
	    return [404, ['Content-Type' => 'text/plain' ], ["Invalid path\n"]];
	}
	$self->_handle_dl_file_request($req, $name, $dlid);
    }
}

sub _view_request
{
    my($self, $env) = @_;
    my $req = Plack::Request->new($env);
    my $path = $req->path_info;

    my $session = $req->cookies->{bvbrc_ws_view_session};
    if (!$session)
    {
	return [503, ['Content-Type' => 'text/plain' ], ["Invalid session\n"]];
    }

    my $coll = $self->_mongodb()->get_collection('auth_cookie');

    my $res = $coll->find_one({session_token => $session});
    if (!$res)
    {
	warn "No session found for $session\n";
	return [503, ['Content-Type' => 'text/plain' ], ["Invalid session\n"]];
    }
    # print STDERR Dumper($res);
    if ($res->{expiration_time} < time)
    {
	warn "Session token has expired\n";
	return [503, ['Content-Type' => 'text/plain' ], ["Invalid session\n"]];
    }
    my $token = $res->{auth_token};
    my $auth_token = P3AuthToken->new(token => $token, ignore_authrc => 1);

    #
    # We're coming in thru the REST API so we don't have a standard service context set up
    #

    my $doc = eval {
	local $CallContext = new Bio::P3::Workspace::ServiceContext;
	$CallContext->authenticated(1);
	$CallContext->token($token);
	$CallContext->user_id($auth_token->user_id);

	$self->_lookup_ws_file_details($path, $token);
    };
    if ($@)
    {
	warn "Cannot find file details for $path\n";
	return [404, ['Content-Type' => 'text/plain' ], ["Invalid path\n"]];
    }

    $self->_send_ws_file($req, $doc, $token, 1);
}

sub _handle_archive_request
{
    my($self, $req, $key) = @_;

    #
    # Query mongo for the request details.
    #

    my $coll = $self->_mongodb()->get_collection('downloads');

    my $res = $coll->find_one({ download_signature => $key });

    if (!$res)
    {
	return [404, ['Content-Type' => 'text/plain' ], ["Invalid path\n"]];
    }

    my $objs = $res->{objects};
    
    if (ref($objs) ne 'ARRAY' || @$objs == 0)
    {
	return [404, ['Content-Type' => 'text/plain' ], ["Not found\n"]];
    }
    
    #
    # Valid request.
    #
    # Return handler closure that will run the zip archive program.
    #
    return sub {
	my($responder) = @_;

	my $fn;
	if ($res->{archive_name})
	{
	    $fn = qq(; filename="$res->{archive_name}");
	}
	my $writer = $responder->([200,
				   ['Content-type' => 'application/zip',
				    'Content-Disposition' => "attachment$fn"]]);
	my $handle;
	my $stderr = File::Temp->new();
	close($stderr);
	$handle = AnyEvent::Run->new(cmd => ["p3x-create-archive",
					     "--auth-token", $res->{user_token},
					     # "--uncompressed",
					     "--log-stderr", "$stderr", @$objs],
				     on_read => sub {
					 my $rh = shift;
					 # print STDERR "GOT " . length($rh->{rbuf}) . "\n";
					 eval {
					     $writer->write($rh->{rbuf});
					 };
					 if ($@)
					 {
					     print STDERR "CAUGHT ERROR $@\n";
					     print STDERR "Propagated error data:\n";
					     if (open(my $fh, "<", $stderr))
					     {
						 while (<$fh>)
						 {
						     print STDERR $_;
						 }
						 close($fh);
					     }
					     print STDERR "End error data\n";
					     undef $handle;
					     return;
					 }
					 $rh->{rbuf} = '';
				     },
				     on_error => sub {
					 my($rh, $fatal, $message) = @_;
					 print STDERR "Error on zip: $message\n";
					 if (open(my $fh, "<", $stderr))
					 {
					     while (<$fh>)
					     {
						 print STDERR $_;
					     }
					     close($fh);
					 }
					 if ($fatal)
					 {
					     undef $handle;
					 }
				     },
				     on_eof => sub {
					 my $res = waitpid($self->{child_pid}, WNOHANG);
					 my $stat = $?;
					 print STDERR "exitcode $self->{child_pid} $res $stat\n";
					 if ($stat != 0)
					 {
					     my $rc = $stat << 8;
					     print STDERR "Child died with status $stat. Propagated error data:\n";
					     if (open(my $fh, "<", $stderr))
					     {
						 while (<$fh>)
						 {
						     print STDERR $_;
						 }
						 close($fh);
					     }
					     print STDERR "End error data\n";
					 }
					 undef $handle;
				     });
	$handle->{read_size} = 32768;
    }
}

#
# Dies on errors, use with eval.
#
sub _lookup_ws_file_details
{
    my($self, $ws_path, $token) = @_;

    my $auth_token = P3AuthToken->new(token => $token, ignore_authrc => 1);

    my ($user,$ws,$path,$name) = $self->_parse_ws_path($ws_path);
    
    if (!defined($ws) || length($ws) == 0) {
	die("Path $ws_path does not include at least a top level directory!");
    }

    my $wsobj = $self->_wscache($user,$ws);
    $self->_check_ws_permissions($wsobj,"r",1);

    my $obj = $self->_get_db_object({
	workspace_uuid => $wsobj->{uuid},
	path => $path,
	name => $name
	});

    if ($obj->{folder} == 1) {
	die "Object is folder not a file";
    }
    elsif (!$obj->{wsobj})
    {
	die "No wsobj found";
    }

    my $doc = {
	workspace_path => $ws_path,
	name => $obj->{name},
	size => $obj->{size},
    };

    if (!defined($obj->{shock}) || $obj->{shock} == 0) {
	my $filename = $self->_db_path()."/".$obj->{wsobj}->{owner}."/".$obj->{wsobj}->{name}."/".$obj->{path}."/".$obj->{name};
	$doc->{file_path} = $filename;
    } else {
	my $ua = LWP::UserAgent->new();

	my $user = $auth_token->user_id;
	#
	# ACL change requires using the workspace owner token
	#
	my $res = $ua->put($obj->{shocknode}."/acl/read?users=$user", Authorization => "OAuth " . $self->_wsauth());
	
	$doc->{shock_node} = $obj->{shocknode};
    }
    return $doc;
}

sub _handle_dl_file_request
{
    my($self, $req, $name, $dlid) = @_;

    my $coll = $self->_mongodb()->get_collection('downloads');
	
    my $res = $coll->find_one({ download_key => $dlid });
	
    if (!$res)
    {
	return [404, ['Content-Type' => 'text/plain' ], ["Invalid path\n"]];
    }

    $self->_send_ws_file($req, $res, $res->{user_token}, 0);
}

sub _send_ws_file
{
    my($self, $req, $ws_obj, $token, $inline) = @_;

    my @resp_headers;
    if ($inline)
    {
	my($ext) = $ws_obj->{name} =~ /\.([^.]+)$/;
	my $mime_type;
	if (my $ov = $mime_overrides{$ext})
	{
	    $mime_type = $ov;
	}
	else
	{
	    $mime_type = $mime_types->mimeTypeOf($ws_obj->{name}) // "text/plain";
	}
	
	@resp_headers = ('Content-Disposition' => "inline",
		    'Content-Type' => $mime_type,
		   );
    }
    else
    {
	@resp_headers = ('Content-Disposition' => "attachment; filename=\"$ws_obj->{name}\"",
			'Content-type' => 'application/octet-stream',
			);

    }
    #
    # Determine if we are being asked for a byte range.
    # Right now we will just support a single range.
    #
    my $hdrs = $req->headers;
    my $range = $hdrs->header("Range");
    
    my($range_beg, $range_end) = $range =~ /bytes=(\d+)-(\d*)\s*$/;
    
    my $file_size = $ws_obj->{size};

    my $have_range;
    if (defined($range_beg))
    {
	$have_range = 1;
	if ($range_end eq '' || $range_end >= $file_size)
	{
	    $range_end = $file_size - 1;
	}
    }
    
    my $range_len = $range_end - $range_beg + 1;

    # print STDERR Dumper($range, $hdrs, $file_size, $range_beg, $range_end, $range_len);

    if ($ws_obj->{shock_node})
    {
	#
	# For shock, construct http request for file.
	#
	# Note that with the formulation below we might have an uncaught
	# error on the HTTP connect to shock. By using the responder/writer
	# interface we can't reasonably deal with it. However, see the
	# sample code in http://cpansearch.perl.org/src/MIYAGAWA/Twiggy-0.1025/eg/chat-websocket/chat.psgi
	# that uses the underlying socket to do this right. 
	#
	
	return sub {
	    my($responder) = @_;

	    my $writer;
	    my $url;
	    if ($have_range)
	    {
		$writer = $responder->([206,
					[@resp_headers,
					 'Content-Range' => "bytes $range_beg-$range_end/$file_size",
					 'Content-Length' => $range_len,
					 ]]);
		
		$url = $ws_obj->{shock_node} . "?download&seek=$range_beg&length=$range_len";
	    }
	    else
	    {
		$writer = $responder->([200, \@resp_headers]);
		$url = $ws_obj->{shock_node} . "?download";
	    }
	    
	    my @headers;
	    if ($token)
	    {
		@headers = (headers => {Authorization => "OAuth $token" });
	    }
	    # print STDERR "retrieve $url\n" . Dumper(@headers);
	    http_request(GET => $url,
			 @headers,
			 # handle_params => { max_read_size => 32768 },
			 on_header => sub { print STDERR Dumper(@_); },
			 on_body => sub {
			     my($data, $hdr) = @_;
			     # print STDERR Dumper($hdr);
			     if ($data)
			     {
				 $writer->write($data);
				 my $len = length($data);
				 return 1;
			     }
			     else
			     {
				 $writer->close();
				 return 0;
			     }
			 },
			 sub {});
	};
		     
    }
    else
    {
	my $fh;
	if (!open($fh, "<", $ws_obj->{file_path}))
	{
	    warn "Could not open $ws_obj->{file_path}: $!";
	    return [404, ['Content-Type' => 'text/plain' ], ["Invalid path\n"]];
	}
	my $stat = stat($fh);
	if (S_ISDIR($stat->mode))
	{
	    return [404, ['Content-Type' => 'text/plain' ], ["Not a file\n"]];
	}

	if ($have_range)
	{
	    seek($fh, $range_beg, SEEK_SET);
	}

	print STDERR "Opened $ws_obj->{file_path} fh=$fh\n";

	return sub {
	    my($responder) = @_;

	    my $writer;

	    if ($have_range)
	    {
		$writer = $responder->([206,
					[@resp_headers,
					 'Content-Range' => "bytes $range_beg-$range_end/$file_size",
					 'Content-Length' => $range_len,
					 ]]);
	    }
	    else
	    {
		$writer = $responder->([200, \@resp_headers]);
	    }

	    print STDERR "retrieve $ws_obj->{file_path}\n";
	    my $ah;
	    $ah = new AnyEvent::Handle(fh => $fh,
				       on_error => sub { print STDERR "Error\n"; },
				       on_eof => sub {
					   $writer->close();
					   undef $ah;
				       },
				       on_read => sub {
					   my($h) = @_;

					   if ($h->{rbuf})
					   {
					       my $len = length($h->{rbuf});

					       if ($have_range && ($len > $range_len))
					       {
						   $writer->write(substr($h->{rbuf}, 0, $range_len));
						   $h->rbuf = '';
						   $writer->close();
						   undef $ah;
					       }
					       else
					       {
						   $range_len -= $len if $have_range;
						   $writer->write($h->{rbuf});
						   $h->rbuf = '';
					       }
					   }
					   else
					   {
					       $writer->close();
					       undef $ah;
					   }
				       });
	};
    }

    [200, ['Content-Type' => 'text/plain'], []];
}

sub _autometadata_script_path_for_type
{
    my($self, $type) = @_;

    my $script = "ws-autometa-$type";
    my $path = which($script);
    return $path;
}
    
sub _compute_autometadata {
    my($self, $objs) = @_;

    my $path = $self->{_params}->{"job-directory"};
    if (!-d $path) {
	File::Path::mkpath ($path);
    }
    my $fulldir = File::Temp::tempdir(DIR => $path);
    if (!-d $fulldir) {
	File::Path::mkpath ($fulldir);
    }
    my $objs_to_process = [];
    for my $obj (@$objs)
    {
	if ($obj->{folder} == 0 && defined($obj->{autometadata}->{inspection_started}))
	{
	    my $script = $self->_autometadata_script_path_for_type($obj->{type});
	    
	    if ($script)
	    {
		delete $obj->{_id};
		delete $obj->{wsobj}->{_id};
		push(@{$objs_to_process}, [$obj, $script]);
	    }
	    else
	    {
		#
		# If we have no update script, set the autometadata as empty
		#
		print STDERR "No script found for type $obj->{type}\n";
		$self->_updateDB("objects",{uuid => $obj->{uuid}},{'$set' => {"autometadata" => {}}});
	    }
	}
    }
    if (@$objs_to_process)
    {
	open (my $fh, ">", "$fulldir/objects.json") or die "Error writing $fulldir/objects.json: $!";
	my $JSON = JSON::XS->new->utf8(1);
	print $fh $JSON->encode($objs_to_process);
	close($fh);
	$ENV{WS_AUTH_TOKEN} = $self->_wsauth();
	my $rc = system("ws-update-metadata", $fulldir, "impl");
	if ($rc != 0)
	{
	    warn "Error $rc processing metadata for $fulldir\n";
	}
    }
    else
    {
	File::Path::rmtree($fulldir);
    }
};

sub is_folder {
	my($self, $type) = @_;
	if (defined($self->{_foldertypes}->{lc($type)})) {
		return 1;
	}
	return 0;
}

sub _write_log
{
    my($self, @fields) = @_;
    if (my $fh = $self->{_log_fh})
    {
	my($sec, $usec) = gettimeofday;
	my $ts = sprintf(strftime("%Y-%m-%d %H:%M:%S.%%06d", gmtime $sec), $usec);
	print $fh join("\t", $ts, $self->_getUsername, @fields), "\n";
    }
}

#END_HEADER

sub new
{
    my($class, @args) = @_;
    my $self = {
    };
    bless $self, $class;
    #BEGIN_CONSTRUCTOR

    my $params = $args[0];
    my $paramlist = [qw(
    	update-interval
    	job-directory
    	script-path
    	shock-url
    	db-path
    	mongodb-database
    	mongodb-host
    	mongodb-user
    	mongodb-pwd
    	url
    	wsuser
    	wspassword
    	adminlist
        download-lifetime
        download-url-base
        types-file
	log-path
    )];
    if ((my $e = $ENV{KB_DEPLOYMENT_CONFIG}) && -e $ENV{KB_DEPLOYMENT_CONFIG}) {
		my $service = $ENV{KB_SERVICE_NAME};
		if (!defined($service)) {
			$service = "Workspace";
		}
		if (defined($service)) {
			my $c = Config::Simple->new();
			$c->read($e);
			for my $p (@{$paramlist}) {
			  	my $v = $c->param("$service.$p");
			  	if ($v && !defined($params->{$p})) {
					$params->{$p} = $v;
					if ($v eq "null") {
						$params->{$p} = undef;
					}
			    }
			}
		}
    }
	$params = $self->_validateargs($params,["db-path","wsuser","wspassword","types-file"],{
		"script-path" => "/kb/deployment/plbin/",
		"job-directory" => "/tmp/wsjobs/",
		"update-interval" => 1800,
		"mongodb-host" => "localhost",
		"mongodb-database" => "P3Workspace",
		"mongodb-user" => undef,
		"mongodb-pwd" => undef,
		url => "http://kbase.us/services/P3workspace"
	});
	$params->{"db-path"} .= "/P3WSDB/";
	open (my $fh,"<",$params->{"types-file"});
	while (my $line = <$fh>) {
		chomp($line);
		$self->{_types}->{$line} = 1;
	}
        close($fh);
        my $timeout = 120_000;
	my $config = {
		host => $params->{"mongodb-host"},
		db_name => $params->{"mongodb-database"},
		auto_connect => 1,
		auto_reconnect => 1,
	        timeout => $timeout,
		query_timeout => $timeout
	};
	if (defined($params->{adminlist})) {
		my $array = [split(/;/,$params->{adminlist})];
		for (my $i=0; $i < @{$array}; $i++) {
			$self->{_admins}->{$array->[$i]} = 1;
		}
		$self->{_admins}->{$params->{wsuser}} = 1;	
	}
	if(defined $params->{"mongodb-user"} && defined $params->{"mongodb-pwd"}) {
		$config->{username} = $params->{"mongodb-user"};
		$config->{password} = $params->{"mongodb-pwd"};
	}
	my $conn = MongoDB::Connection->new(%$config);
        $self->{_mongodb_config} = $config;
	if (!defined($conn)) {
		$self->_error("Unable to connect to mongodb database!");
	}
	$self->{_mongodb} = $conn->get_database($params->{"mongodb-database"});
	$self->{_params} = $params;
	$self->{_params}->{"db-path"} =~ s/\/\//\//g;
	$self->{_params}->{"db-path"} =~ s/\/$//g;
	$self->{_foldertypes} = {
		folder => 1,
		modelfolder => 1
	};

    if ($params->{'log-path'})
    {
	my $log_file = sprintf("%s/log-%06d.txt", $params->{'log-path'}, $$);
	my $log_fh;
	if (open($log_fh, ">>", $log_file))
	{
	    print STDERR "Begin logging to $log_file\n";
	    $self->{_log_fh} = $log_fh;
	    $log_fh->autoflush(1);
	}
	else
	{
	    warn "Cannot log to $log_file: $!";
	}
	    
    }

    #END_CONSTRUCTOR

    if ($self->can('_init_instance'))
    {
	$self->_init_instance();
    }
    return $self;
}
=head1 METHODS
=head2 create

  $output = $obj->create($input)

=over 4


=item Parameter and return types

=begin html

<pre>
$input is a create_params
$output is a reference to a list where each element is an ObjectMeta
create_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a reference to a list containing 5 items:
	0: a FullObjectPath
	1: an ObjectType
	2: an UserMetadata
	3: an ObjectData
	4: (creation_time) a Timestamp

	permission has a value which is a WorkspacePerm
	createUploadNodes has a value which is a bool
	downloadLinks has a value which is a bool
	overwrite has a value which is a bool
	adminmode has a value which is a bool
	setowner has a value which is a string
FullObjectPath is a string
ObjectType is a string
UserMetadata is a reference to a hash where the key is a string and the value is a string
ObjectData is a string
Timestamp is a string
WorkspacePerm is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectID is a string
Username is a string
ObjectSize is an int
AutoMetadata is a reference to a hash where the key is a string and the value is a string
</pre>

=end html

=begin text

$input is a create_params
$output is a reference to a list where each element is an ObjectMeta
create_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a reference to a list containing 5 items:
	0: a FullObjectPath
	1: an ObjectType
	2: an UserMetadata
	3: an ObjectData
	4: (creation_time) a Timestamp

	permission has a value which is a WorkspacePerm
	createUploadNodes has a value which is a bool
	downloadLinks has a value which is a bool
	overwrite has a value which is a bool
	adminmode has a value which is a bool
	setowner has a value which is a string
FullObjectPath is a string
ObjectType is a string
UserMetadata is a reference to a hash where the key is a string and the value is a string
ObjectData is a string
Timestamp is a string
WorkspacePerm is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectID is a string
Username is a string
ObjectSize is an int
AutoMetadata is a reference to a hash where the key is a string and the value is a string

=end text



=item Description


=back

=cut

sub create
{
    my $self = shift;
    my($input) = @_;

    my @_bad_arguments;
    (ref($input) eq 'HASH') or push(@_bad_arguments, "Invalid type for argument \"input\" (value was \"$input\")");
    if (@_bad_arguments) {
	my $msg = "Invalid arguments passed to create:\n" . join("", map { "\t$_\n" } @_bad_arguments);
	die $msg;
    }

    my $ctx = $Bio::P3::Workspace::Service::CallContext;
    my($output);
    #BEGIN create

#die "The workspace is currently in readonly mode\n";
    $output = [];
    $input = $self->_validateargs($input,["objects"],{
		createUploadNodes => 0,
		downloadFromLinks => 0,
		overwrite => 0,
		permission => "n",
		setowner => undef
	});
	
	if (defined($input->{setowner})) {
		if ($self->_adminmode() == 0) {
			$self->_error("Cannot set owner unless adminmode is active!");
		}
		$CallContext->{_setowner} = $input->{setowner};
	}
    #Validating permissions
    $input->{permission} = $self->_validate_workspace_permission($input->{permission});
	#Validating input objects
    my $voutput = $self->_validate_save_objects_before_saving($input->{objects},$input->{overwrite});
	#Deleting overwritten objects
    $self->_delete_validated_object_set($voutput->{del});
	#Creating validated objects
    my $objects = $self->_create_validated_object_set($voutput->{create},$input->{createUploadNodes},$input->{downloadFromLinks},$input->{permission});
    for (my $i=0; $i < @{$objects}; $i++) {
    	push(@{$output},$self->_generate_object_meta($objects->[$i]));	
    }
    #END create
    my @_bad_returns;
    (ref($output) eq 'ARRAY') or push(@_bad_returns, "Invalid type for return variable \"output\" (value was \"$output\")");
    if (@_bad_returns) {
	my $msg = "Invalid returns passed to create:\n" . join("", map { "\t$_\n" } @_bad_returns);
	die $msg;
    }
    return($output);
}


=head2 update_metadata

  $output = $obj->update_metadata($input)

=over 4


=item Parameter and return types

=begin html

<pre>
$input is an update_metadata_params
$output is a reference to a list where each element is an ObjectMeta
update_metadata_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a reference to a list containing 4 items:
	0: a FullObjectPath
	1: an UserMetadata
	2: an ObjectType
	3: (creation_time) a Timestamp

	autometadata has a value which is a bool
	append has a value which is a bool
	adminmode has a value which is a bool
FullObjectPath is a string
UserMetadata is a reference to a hash where the key is a string and the value is a string
ObjectType is a string
Timestamp is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectID is a string
Username is a string
ObjectSize is an int
AutoMetadata is a reference to a hash where the key is a string and the value is a string
WorkspacePerm is a string
</pre>

=end html

=begin text

$input is an update_metadata_params
$output is a reference to a list where each element is an ObjectMeta
update_metadata_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a reference to a list containing 4 items:
	0: a FullObjectPath
	1: an UserMetadata
	2: an ObjectType
	3: (creation_time) a Timestamp

	autometadata has a value which is a bool
	append has a value which is a bool
	adminmode has a value which is a bool
FullObjectPath is a string
UserMetadata is a reference to a hash where the key is a string and the value is a string
ObjectType is a string
Timestamp is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectID is a string
Username is a string
ObjectSize is an int
AutoMetadata is a reference to a hash where the key is a string and the value is a string
WorkspacePerm is a string

=end text



=item Description


=back

=cut

sub update_metadata
{
    my $self = shift;
    my($input) = @_;

    my @_bad_arguments;
    (ref($input) eq 'HASH') or push(@_bad_arguments, "Invalid type for argument \"input\" (value was \"$input\")");
    if (@_bad_arguments) {
	my $msg = "Invalid arguments passed to update_metadata:\n" . join("", map { "\t$_\n" } @_bad_arguments);
	die $msg;
    }

    my $ctx = $Bio::P3::Workspace::Service::CallContext;
    my($output);
    #BEGIN update_metadata
    $input = $self->_validateargs($input,["objects"],{autometadata => 0,append => 0});
    if ($input->{autometadata} == 1) {
    	if ($self->_getUsername() ne $self->{_params}->{wsuser} && $self->_adminmode() eq 0) {
    		$self->_error("Only the workspace or admin can set autometadata!");	
    	}
    }
    for (my $i=0; $i < @{$input->{objects}}; $i++) {
    	my ($user,$ws,$path,$name) = $self->_parse_ws_path($input->{objects}->[$i]->[0]);
    	if (!defined($ws) || length($ws) == 0) {
    		$self->_error("Path ".$input->{objects}->[$i]." does not include at least a top level directory!");
    	}
    	my $wsobj = $self->_wscache($user,$ws);
    	$self->_check_ws_permissions($wsobj,"w",1);
    	my $type = "objects";
    	my $obj;
    	if (length($path) == 0 && length($name) == 0) {
    		$type = "workspaces";
    		$obj = $wsobj;
    	} else {
	    	$obj = $self->_get_db_object({
	    		workspace_uuid => $wsobj->{uuid},
	    		path => $path,
	    		name => $name
	    	});
    	}
    	if (defined($input->{objects}->[$i]->[1])) {
	    	my $key = "metadata";
	    	if ($input->{autometadata} == 1) {
	    		$key = "autometadata";
	    	}
	    	if ($input->{append} == 1) {
	    		foreach my $item (keys(%{$input->{objects}->[$i]->[1]})) {
	    			$obj->{$key}->{$item} = $input->{objects}->[$i]->[1]->{$item};
	    		}
	    	} else {
	    		$obj->{$key} = $input->{objects}->[$i]->[1];
	    	}
	    	$self->_updateDB($type,{uuid => $obj->{uuid}},{'$set' => {$key => $obj->{$key}}});
    	}
    	if (defined($input->{objects}->[$i]->[2])) {
    		$obj->{type} = $input->{objects}->[$i]->[2];
    		$self->_updateDB($type,{uuid => $obj->{uuid}},{'$set' => {type => $input->{objects}->[$i]->[2]}});
    	}
    	if (defined($input->{objects}->[$i]->[3])) {
    		if ($self->_getUsername() ne $self->{_params}->{wsuser} && $self->_adminmode() eq 0) {
    			$self->_error("Only the workspace or admin can set creation date!");	
    		}
    		if ($input->{objects}->[$i]->[3] =~ m/^\d+$/) {
    			$input->{objects}->[$i]->[3] = _format_datetime(DateTime->from_epoch( epoch => $input->{objects}->[$i]->[3] ));
    		}
    		$obj->{creation_date} = $input->{objects}->[$i]->[3];
    		$self->_updateDB($type,{uuid => $obj->{uuid}},{'$set' => {creation_date => $input->{objects}->[$i]->[3]}});
    	}
	    push(@{$output},$self->_generate_object_meta($obj));
    }
    #END update_metadata
    my @_bad_returns;
    (ref($output) eq 'ARRAY') or push(@_bad_returns, "Invalid type for return variable \"output\" (value was \"$output\")");
    if (@_bad_returns) {
	my $msg = "Invalid returns passed to update_metadata:\n" . join("", map { "\t$_\n" } @_bad_returns);
	die $msg;
    }
    return($output);
}


=head2 get

  $output = $obj->get($input)

=over 4


=item Parameter and return types

=begin html

<pre>
$input is a get_params
$output is a reference to a list where each element is a reference to a list containing 2 items:
	0: an ObjectMeta
	1: an ObjectData
get_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a FullObjectPath
	metadata_only has a value which is a bool
	adminmode has a value which is a bool
FullObjectPath is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectType is a string
Timestamp is a string
ObjectID is a string
Username is a string
ObjectSize is an int
UserMetadata is a reference to a hash where the key is a string and the value is a string
AutoMetadata is a reference to a hash where the key is a string and the value is a string
WorkspacePerm is a string
ObjectData is a string
</pre>

=end html

=begin text

$input is a get_params
$output is a reference to a list where each element is a reference to a list containing 2 items:
	0: an ObjectMeta
	1: an ObjectData
get_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a FullObjectPath
	metadata_only has a value which is a bool
	adminmode has a value which is a bool
FullObjectPath is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectType is a string
Timestamp is a string
ObjectID is a string
Username is a string
ObjectSize is an int
UserMetadata is a reference to a hash where the key is a string and the value is a string
AutoMetadata is a reference to a hash where the key is a string and the value is a string
WorkspacePerm is a string
ObjectData is a string

=end text



=item Description


=back

=cut

sub get
{
    my $self = shift;
    my($input) = @_;

    my @_bad_arguments;
    (ref($input) eq 'HASH') or push(@_bad_arguments, "Invalid type for argument \"input\" (value was \"$input\")");
    if (@_bad_arguments) {
	my $msg = "Invalid arguments passed to get:\n" . join("", map { "\t$_\n" } @_bad_arguments);
	die $msg;
    }

    my $ctx = $Bio::P3::Workspace::Service::CallContext;
    my($output);
    #BEGIN get
    $input = $self->_validateargs($input,["objects"],{metadata_only => 0});
    for (my $i=0; $i < @{$input->{objects}}; $i++) {
    	my ($user,$ws,$path,$name) = $self->_parse_ws_path($input->{objects}->[$i]);
    	if (!defined($ws) || length($ws) == 0) {
    		$self->_error("Path ".$input->{objects}->[$i]." does not include at least a top level directory!");
    	}
    	my $wsobj = $self->_wscache($user,$ws);
    	$self->_check_ws_permissions($wsobj,"r",1);
    	if (length($path) == 0 && length($name) == 0) {
    		if ($input->{metadata_only} == 1) {
		    	push(@{$output},[$self->_generate_object_meta($wsobj)]); 
	    	} else {
	    		push(@{$output},[$self->_generate_object_meta($wsobj),""]);
	    	}
    	} else {
	    	my $obj = $self->_get_db_object({
	    		workspace_uuid => $wsobj->{uuid},
	    		path => $path,
	    		name => $name
	    	},1);
	    	if ($input->{metadata_only} == 1) {
		    	push(@{$output},[$self->_generate_object_meta($obj)]); 
	    	} else {
	    		push(@{$output},[
		    		$self->_generate_object_meta($obj),
	    			$self->_retrieve_object_data($obj,$wsobj)
		    	]);
	    	}
    	}
    }
    #END get
    my @_bad_returns;
    (ref($output) eq 'ARRAY') or push(@_bad_returns, "Invalid type for return variable \"output\" (value was \"$output\")");
    if (@_bad_returns) {
	my $msg = "Invalid returns passed to get:\n" . join("", map { "\t$_\n" } @_bad_returns);
	die $msg;
    }
    return($output);
}


=head2 update_auto_meta

  $output = $obj->update_auto_meta($input)

=over 4


=item Parameter and return types

=begin html

<pre>
$input is an update_auto_meta_params
$output is a reference to a list where each element is an ObjectMeta
update_auto_meta_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a FullObjectPath
	adminmode has a value which is a bool
FullObjectPath is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectType is a string
Timestamp is a string
ObjectID is a string
Username is a string
ObjectSize is an int
UserMetadata is a reference to a hash where the key is a string and the value is a string
AutoMetadata is a reference to a hash where the key is a string and the value is a string
WorkspacePerm is a string
</pre>

=end html

=begin text

$input is an update_auto_meta_params
$output is a reference to a list where each element is an ObjectMeta
update_auto_meta_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a FullObjectPath
	adminmode has a value which is a bool
FullObjectPath is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectType is a string
Timestamp is a string
ObjectID is a string
Username is a string
ObjectSize is an int
UserMetadata is a reference to a hash where the key is a string and the value is a string
AutoMetadata is a reference to a hash where the key is a string and the value is a string
WorkspacePerm is a string

=end text



=item Description


=back

=cut

sub update_auto_meta
{
    my $self = shift;
    my($input) = @_;

    my @_bad_arguments;
    (ref($input) eq 'HASH') or push(@_bad_arguments, "Invalid type for argument \"input\" (value was \"$input\")");
    if (@_bad_arguments) {
	my $msg = "Invalid arguments passed to update_auto_meta:\n" . join("", map { "\t$_\n" } @_bad_arguments);
	die $msg;
    }

    my $ctx = $Bio::P3::Workspace::Service::CallContext;
    my($output);
    #BEGIN update_auto_meta
    $input = $self->_validateargs($input,["objects"],{});
    for (my $i=0; $i < @{$input->{objects}}; $i++) {
    	my ($user,$ws,$path,$name) = $self->_parse_ws_path($input->{objects}->[$i]);
    	if (!defined($ws) || length($ws) == 0) {
    		$self->_error("Path ".$input->{objects}->[$i]." does not include at least a top level directory!");
    	}
    	my $wsobj = $self->_wscache($user,$ws);
    	$self->_check_ws_permissions($wsobj,"r",1);
    	if (length($path) == 0 && length($name) == 0) {
    		$self->_error("Path does not point to an object!");
    	} else {
	    	my $obj = $self->_get_db_object({
	    		workspace_uuid => $wsobj->{uuid},
	    		path => $path,
	    		name => $name
	    	});
	    	if ($obj->{shock} == 0) {
	    		$obj->{autometadata}->{inspection_started} = _format_datetime(DateTime->now());
		    	$self->_compute_autometadata($obj,1);
	    		push(@{$output},$self->_generate_object_meta($obj)); 
	    	} else {
	    		$self->_update_shock_node($obj,1);
	    		push(@{$output},$self->_generate_object_meta($obj)); 
	    	}
    	}
    }
    #END update_auto_meta
    my @_bad_returns;
    (ref($output) eq 'ARRAY') or push(@_bad_returns, "Invalid type for return variable \"output\" (value was \"$output\")");
    if (@_bad_returns) {
	my $msg = "Invalid returns passed to update_auto_meta:\n" . join("", map { "\t$_\n" } @_bad_returns);
	die $msg;
    }
    return($output);
}


=head2 get_download_url

  $urls = $obj->get_download_url($input)

=over 4


=item Parameter and return types

=begin html

<pre>
$input is a get_download_url_params
$urls is a reference to a list where each element is a string
get_download_url_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a FullObjectPath
FullObjectPath is a string
</pre>

=end html

=begin text

$input is a get_download_url_params
$urls is a reference to a list where each element is a string
get_download_url_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a FullObjectPath
FullObjectPath is a string

=end text



=item Description


=back

=cut

sub get_download_url
{
    my $self = shift;
    my($input) = @_;

    my @_bad_arguments;
    (ref($input) eq 'HASH') or push(@_bad_arguments, "Invalid type for argument \"input\" (value was \"$input\")");
    if (@_bad_arguments) {
	my $msg = "Invalid arguments passed to get_download_url:\n" . join("", map { "\t$_\n" } @_bad_arguments);
	die $msg;
    }

    my $ctx = $Bio::P3::Workspace::Service::CallContext;
    my($urls);
    #BEGIN get_download_url

    $input = $self->_validateargs($input,["objects"],{});
    my @objs;
    for my $ws_path (@{$input->{objects}})
    {
    	my ($user,$ws,$path,$name) = $self->_parse_ws_path($ws_path);

    	if (!defined($ws) || length($ws) == 0) {
    		$self->_error("Path $ws_path does not include at least a top level directory!");
    	}

    	my $wsobj = $self->_wscache($user,$ws);
    	$self->_check_ws_permissions($wsobj,"r",1);

	my $obj = $self->_get_db_object({
	    workspace_uuid => $wsobj->{uuid},
	    path => $path,
	    name => $name
	    });
	
	if ($obj->{folder} == 1) {
	    push(@objs, []);
	    next;
	}
	elsif (!$obj->{wsobj})
	{
	    push(@objs, []);
	    next;
	}

	my $doc = {
	    workspace_path => $ws_path,
	};

	if (!defined($obj->{shock}) || $obj->{shock} == 0) {
	    my $filename = $self->_db_path()."/".$obj->{wsobj}->{owner}."/".$obj->{wsobj}->{name}."/".$obj->{path}."/".$obj->{name};
	    $doc->{file_path} = $filename;
	} else {
	    my $ua = LWP::UserAgent->new();
	    my($user, $token);
	    if (_authentication())
	    {
		$user = $self->_getUsername();
		$token = _authentication();
	    }
	    else
	    {
		$user = $self->{_params}->{wsuser};
		$token = $self->_wsauth();
	    }
	    
	    #
	    # ACL change requires using the workspace owner token
	    #
	    my $res = $ua->put($obj->{shocknode}."/acl/read?users=$user", Authorization => "OAuth " . $self->_wsauth());

	    $doc->{shock_node} = $obj->{shocknode};
	    $doc->{user_token} = $token;
	}

	push(@objs, [$ws_path, $name, $doc, $obj->{size}]);
    }

    #
    # Permissions checked out, generate download records.
    #

    my $coll = $self->_mongodb()->get_collection('downloads');

    my $download_lifetime = $self->{_params}->{'download-lifetime'};
    if (!$download_lifetime)
    {
	$download_lifetime = 60 * 60;
	warn "default dl lifetime to $download_lifetime\n";
    }
    my $expires = time + $download_lifetime;

    my $gen = Data::UUID->new;

    $urls = [];
    
    for my $ent (@objs)
    {
	my($obj, $name, $doc, $size) = @$ent;
	my $url;
	if ($obj)
	{
	    my $dlid = $gen->create_b64();
	    $dlid =~ s/=*$//;
	    $dlid =~ s/\+/-/g;
	    $dlid =~ s,/,_,g;
	    $doc->{download_key} = $dlid;
	    $doc->{expiration_time} = $expires;
	    $doc->{name} = $name;
	    $doc->{size} = $size;
	    $coll->insert($doc);
	    $url = $self->{_params}->{'download-url-base'} . "/download/$dlid/" . uri_escape($name);
	}
	push(@$urls, $url);
    }    

    
    #END get_download_url
    my @_bad_returns;
    (ref($urls) eq 'ARRAY') or push(@_bad_returns, "Invalid type for return variable \"urls\" (value was \"$urls\")");
    if (@_bad_returns) {
	my $msg = "Invalid returns passed to get_download_url:\n" . join("", map { "\t$_\n" } @_bad_returns);
	die $msg;
    }
    return($urls);
}


=head2 get_archive_url

  $url, $file_count, $total_size = $obj->get_archive_url($input)

=over 4


=item Parameter and return types

=begin html

<pre>
$input is a get_archive_url_params
$url is a string
$file_count is an int
$total_size is an int
get_archive_url_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a FullObjectPath
	recursive has a value which is a bool
	archive_name has a value which is a string
	archive_type has a value which is a string
FullObjectPath is a string
bool is an int
</pre>

=end html

=begin text

$input is a get_archive_url_params
$url is a string
$file_count is an int
$total_size is an int
get_archive_url_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a FullObjectPath
	recursive has a value which is a bool
	archive_name has a value which is a string
	archive_type has a value which is a string
FullObjectPath is a string
bool is an int

=end text



=item Description


=back

=cut

sub get_archive_url
{
    my $self = shift;
    my($input) = @_;

    my @_bad_arguments;
    (ref($input) eq 'HASH') or push(@_bad_arguments, "Invalid type for argument \"input\" (value was \"$input\")");
    if (@_bad_arguments) {
	my $msg = "Invalid arguments passed to get_archive_url:\n" . join("", map { "\t$_\n" } @_bad_arguments);
	die $msg;
    }

    my $ctx = $Bio::P3::Workspace::Service::CallContext;
    my($url, $file_count, $total_size);
    #BEGIN get_archive_url

    $input = $self->_validateargs($input,["objects"],{
	recursive => 0,
	archive_name => undef,
	archive_type => 'zip',
    });

    #
    # Scan our input objects and if we are not recursive, remove
    # any folders.
    #
    # We also compute a the download size estimate. If we are
    # performing a recursive archive, we perform an aggregate
    # query to mongo to get the size of the child objects.
    #
    
    my @objs;
    $total_size = 0;
    $file_count = 0;
    my $col = $self->_mongodb()->get_collection('objects');

    for my $ws_path (@{$input->{objects}})
    {
    	my ($user,$ws,$path,$name) = $self->_parse_ws_path($ws_path);

    	if (!defined($ws) || length($ws) == 0) {
    		$self->_error("Path $ws_path does not include at least a top level directory!");
    	}

    	my $wsobj = $self->_wscache($user,$ws);
    	$self->_check_ws_permissions($wsobj,"r",1);

	my $obj = $self->_get_db_object({
	    workspace_uuid => $wsobj->{uuid},
	    path => $path,
	    name => $name
	    });

	print "$wsobj->{uuid} obj $obj->{path} $obj->{name} $obj->{folder}\n";
	print Dumper($obj);

	#
	# Check recursive if a folder or an entire workspace.
	#
	if ($obj->{folder} || ($path eq '' && $name eq ''))
	{
	    if (!$input->{recursive})
	    {
		warn "Skipping folder $ws_path because recursive not set\n";
		next;
	    }

	    my @path_q;
	    if ($path ne '' || $name ne '')
	    {
		my $subpath = ($path eq '' && $name eq '') ? "" : ($path ? "$path/$name" : $name);
		@path_q = (path => $self->_compute_mongo_regex_for_path($subpath));
	    }
	    my $path_spec = {
		@path_q,
		workspace_uuid => $wsobj->{uuid},
		folder => 0,
	    };

	    my $res = $col->aggregate([
				   { '$match' => $path_spec },
				   { '$group' => {
				       _id => 0,
				       total_size => { '$sum' => '$size' },
				       file_count => { '$sum' => 1 },
				   } },
				       ]);

	    print Dumper($path_spec, $res);
	    $total_size += $res->[0]->{total_size};
	    $file_count += $res->[0]->{file_count};

	    if (0)
	    {
		# Debug - print matches.
		my $res = $col->find($path_spec);
		my $n = 0;
		while (my $r = $res->next)
		{
		    print "$r->{name} $r->{path} $r->{folder} $r->{size}\n";
		    last if $n++ > 100;
		}
	    }

	}
	elsif (!$obj->{wsobj})
	{
	    next;
	}
	else
	{
	    print "add $obj->{size}\n";
	    $total_size += $obj->{size};
	    $file_count++;
	}

	#
	# In the download-url code, we tweak shock. We do not need to do this
	# here since the zip-archiving code itself uses the Workspace::get method.
	# It adds some inefficiency but keeps the code clean. 
	#
	
	push(@objs, $ws_path);
    }

    my $download_lifetime = $self->{_params}->{'download-lifetime'};
    if (!$download_lifetime)
    {
	$download_lifetime = 60 * 60;
	warn "default dl lifetime to $download_lifetime\n";
    }
    my $expires = time + $download_lifetime;

    my $gen = Data::UUID::MT->new;
    my $key = $gen->create_hex();
    $key =~ s/^0x//;

    my $user = $self->_getUsername();
    my $token = Bio::P3::Workspace::WorkspaceImpl::_authentication();

    #
    # The visible path that we provide the user
    # is a HMAC hash created by signing the random
    # download key with the signature from the user's token.
    #

    my $token_obj = P3AuthToken->new(token => $token);
    my $dl_sig = hmac_sha1_hex($key, $token_obj->signature);

    # return value
    $url = $self->{_params}->{'download-url-base'} . "/archive/$dl_sig";

    my $archive = $input->{archive_name};
    if (!$archive)
    {
	$archive = strftime("ws-archive-%Y-%m-%d-%H-%M.zip", gmtime);
    }

    my $doc = {
	user_token => $token,
	user => $user,
	archive_type => $input->{archive_type},
	archive_name => $archive,
	objects => \@objs,
	download_key => $key,
	download_signature => $dl_sig,
	expiration_time => $expires,
	total_size => $total_size,
	file_count => $file_count,
    };
    print STDERR Dumper($doc);

    my $coll = $self->_mongodb()->get_collection('downloads');

    $coll->insert($doc);

    #END get_archive_url
    my @_bad_returns;
    (!ref($url)) or push(@_bad_returns, "Invalid type for return variable \"url\" (value was \"$url\")");
    (!ref($file_count)) or push(@_bad_returns, "Invalid type for return variable \"file_count\" (value was \"$file_count\")");
    (!ref($total_size)) or push(@_bad_returns, "Invalid type for return variable \"total_size\" (value was \"$total_size\")");
    if (@_bad_returns) {
	my $msg = "Invalid returns passed to get_archive_url:\n" . join("", map { "\t$_\n" } @_bad_returns);
	die $msg;
    }
    return($url, $file_count, $total_size);
}


=head2 ls

  $output = $obj->ls($input)

=over 4


=item Parameter and return types

=begin html

<pre>
$input is a list_params
$output is a reference to a hash where the key is a FullObjectPath and the value is a reference to a list where each element is an ObjectMeta
list_params is a reference to a hash where the following keys are defined:
	paths has a value which is a reference to a list where each element is a FullObjectPath
	excludeDirectories has a value which is a bool
	excludeObjects has a value which is a bool
	recursive has a value which is a bool
	fullHierachicalOutput has a value which is a bool
	query has a value which is a reference to a hash where the key is a string and the value is a reference to a list where each element is a string
	adminmode has a value which is a bool
FullObjectPath is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectType is a string
Timestamp is a string
ObjectID is a string
Username is a string
ObjectSize is an int
UserMetadata is a reference to a hash where the key is a string and the value is a string
AutoMetadata is a reference to a hash where the key is a string and the value is a string
WorkspacePerm is a string
</pre>

=end html

=begin text

$input is a list_params
$output is a reference to a hash where the key is a FullObjectPath and the value is a reference to a list where each element is an ObjectMeta
list_params is a reference to a hash where the following keys are defined:
	paths has a value which is a reference to a list where each element is a FullObjectPath
	excludeDirectories has a value which is a bool
	excludeObjects has a value which is a bool
	recursive has a value which is a bool
	fullHierachicalOutput has a value which is a bool
	query has a value which is a reference to a hash where the key is a string and the value is a reference to a list where each element is a string
	adminmode has a value which is a bool
FullObjectPath is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectType is a string
Timestamp is a string
ObjectID is a string
Username is a string
ObjectSize is an int
UserMetadata is a reference to a hash where the key is a string and the value is a string
AutoMetadata is a reference to a hash where the key is a string and the value is a string
WorkspacePerm is a string

=end text



=item Description


=back

=cut

sub ls
{
    my $self = shift;
    my($input) = @_;

    my @_bad_arguments;
    (ref($input) eq 'HASH') or push(@_bad_arguments, "Invalid type for argument \"input\" (value was \"$input\")");
    if (@_bad_arguments) {
	my $msg = "Invalid arguments passed to ls:\n" . join("", map { "\t$_\n" } @_bad_arguments);
	die $msg;
    }

    my $ctx = $Bio::P3::Workspace::Service::CallContext;
    my($output);
    #BEGIN ls

    $output = {};
    $input = $self->_validateargs($input,["paths"],{
    	excludeDirectories => 0,
		excludeObjects => 0,
		recursive => 0,
		fullHierachicalOutput => 0,
		query => {}
    });
    foreach my $fullpath (@{$input->{paths}}) {
    	my $objs = [];
    	if ($fullpath eq "" || $fullpath eq "/") {
    		$objs = $self->_list_workspaces(undef,$self->_formatQuery($input->{query},1));
    	} elsif ($fullpath =~ m/^\/([^\/]+)\/*$/) {
    		$objs = $self->_list_workspaces($1,$self->_formatQuery($input->{query},1));
    	} else {
    		$objs = $self->_list_objects($fullpath,$self->_formatQuery($input->{query},0),$input->{excludeDirectories},$input->{excludeObjects},$input->{recursive});
    	}
    	for (my $i=0; $i < @{$objs}; $i++) {
    		my $meta = $self->_generate_object_meta($objs->[$i]);
    		if ($input->{fullHierachicalOutput} == 1) {
    			$meta->[2] =~ s/\/$//;
    			push(@{$output->{$meta->[2]}},$meta);
    		} else {
    			push(@{$output->{$fullpath}},$meta);
    		}
    		
    	}
    }
    #END ls
    my @_bad_returns;
    (ref($output) eq 'HASH') or push(@_bad_returns, "Invalid type for return variable \"output\" (value was \"$output\")");
    if (@_bad_returns) {
	my $msg = "Invalid returns passed to ls:\n" . join("", map { "\t$_\n" } @_bad_returns);
	die $msg;
    }
    return($output);
}


=head2 copy

  $output = $obj->copy($input)

=over 4


=item Parameter and return types

=begin html

<pre>
$input is a copy_params
$output is a reference to a list where each element is an ObjectMeta
copy_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a reference to a list containing 2 items:
	0: (source) a FullObjectPath
	1: (destination) a FullObjectPath

	overwrite has a value which is a bool
	recursive has a value which is a bool
	move has a value which is a bool
	adminmode has a value which is a bool
FullObjectPath is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectType is a string
Timestamp is a string
ObjectID is a string
Username is a string
ObjectSize is an int
UserMetadata is a reference to a hash where the key is a string and the value is a string
AutoMetadata is a reference to a hash where the key is a string and the value is a string
WorkspacePerm is a string
</pre>

=end html

=begin text

$input is a copy_params
$output is a reference to a list where each element is an ObjectMeta
copy_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a reference to a list containing 2 items:
	0: (source) a FullObjectPath
	1: (destination) a FullObjectPath

	overwrite has a value which is a bool
	recursive has a value which is a bool
	move has a value which is a bool
	adminmode has a value which is a bool
FullObjectPath is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectType is a string
Timestamp is a string
ObjectID is a string
Username is a string
ObjectSize is an int
UserMetadata is a reference to a hash where the key is a string and the value is a string
AutoMetadata is a reference to a hash where the key is a string and the value is a string
WorkspacePerm is a string

=end text



=item Description


=back

=cut

sub copy
{
    my $self = shift;
    my($input) = @_;

    my @_bad_arguments;
    (ref($input) eq 'HASH') or push(@_bad_arguments, "Invalid type for argument \"input\" (value was \"$input\")");
    if (@_bad_arguments) {
	my $msg = "Invalid arguments passed to copy:\n" . join("", map { "\t$_\n" } @_bad_arguments);
	die $msg;
    }

    my $ctx = $Bio::P3::Workspace::Service::CallContext;
    my($output);
    #BEGIN copy
    $input = $self->_validateargs($input,["objects"],{
    	overwrite => 0,
    	recursive => 0,
    	move => 0
    });
    my $n = @{$input->{objects}};
    $self->_write_log("begin copy_or_move n_objects=$n overwrite=$input->{overwrite} recursive=$input->{recursive} move=$input->{move}");
    for (my $i = 0; $i < $n; $i++)
    {
	my $obj = $input->{objects}->[$i];
	$self->_write_log("object $i", $obj->[0], $obj->[1]);
    }
    $output = $self->_copy_or_move_objects($input->{objects},$input->{overwrite},$input->{recursive},$input->{move});
    $self->_write_log("end copy_or_move n_objects=$n overwrite=$input->{overwrite} recursive=$input->{recursive} move=$input->{move}");
    for (my $i=0; $i < @{$output}; $i++) {
    	$output->[$i] = $self->_generate_object_meta($output->[$i]);
    }
    #END copy
    my @_bad_returns;
    (ref($output) eq 'ARRAY') or push(@_bad_returns, "Invalid type for return variable \"output\" (value was \"$output\")");
    if (@_bad_returns) {
	my $msg = "Invalid returns passed to copy:\n" . join("", map { "\t$_\n" } @_bad_returns);
	die $msg;
    }
    return($output);
}


=head2 delete

  $output = $obj->delete($input)

=over 4


=item Parameter and return types

=begin html

<pre>
$input is a delete_params
$output is a reference to a list where each element is an ObjectMeta
delete_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a FullObjectPath
	deleteDirectories has a value which is a bool
	force has a value which is a bool
	adminmode has a value which is a bool
FullObjectPath is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectType is a string
Timestamp is a string
ObjectID is a string
Username is a string
ObjectSize is an int
UserMetadata is a reference to a hash where the key is a string and the value is a string
AutoMetadata is a reference to a hash where the key is a string and the value is a string
WorkspacePerm is a string
</pre>

=end html

=begin text

$input is a delete_params
$output is a reference to a list where each element is an ObjectMeta
delete_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a FullObjectPath
	deleteDirectories has a value which is a bool
	force has a value which is a bool
	adminmode has a value which is a bool
FullObjectPath is a string
bool is an int
ObjectMeta is a reference to a list containing 13 items:
	0: an ObjectName
	1: an ObjectType
	2: a FullObjectPath
	3: (creation_time) a Timestamp
	4: an ObjectID
	5: (object_owner) an Username
	6: an ObjectSize
	7: an UserMetadata
	8: an AutoMetadata
	9: (user_permission) a WorkspacePerm
	10: (global_permission) a WorkspacePerm
	11: (shockurl) a string
	12: (error) a string
ObjectName is a string
ObjectType is a string
Timestamp is a string
ObjectID is a string
Username is a string
ObjectSize is an int
UserMetadata is a reference to a hash where the key is a string and the value is a string
AutoMetadata is a reference to a hash where the key is a string and the value is a string
WorkspacePerm is a string

=end text



=item Description


=back

=cut

sub delete
{
    my $self = shift;
    my($input) = @_;

    my @_bad_arguments;
    (ref($input) eq 'HASH') or push(@_bad_arguments, "Invalid type for argument \"input\" (value was \"$input\")");
    if (@_bad_arguments) {
	my $msg = "Invalid arguments passed to delete:\n" . join("", map { "\t$_\n" } @_bad_arguments);
	die $msg;
    }

    my $ctx = $Bio::P3::Workspace::Service::CallContext;
    my($output);
    #BEGIN delete
    $input = $self->_validateargs($input,["objects"],{
    	deleteDirectories => 0,
    	force => 0
    });
    my $delhash = {};
    $output = [];
    for (my $i=0; $i < @{$input->{objects}}; $i++) {
    	my ($user,$ws,$path,$name) = $self->_parse_ws_path($input->{objects}->[$i]);
    	if (length($ws) == 0) {
    		$self->_error("Path does not point to folder or object:".$input->{objects}->[$i]);
    	} elsif ((length($path)+length($name)) == 0) {
    		my $wsobj = $self->_wscache($user,$ws,1);
    		$self->_check_ws_permissions($wsobj,"o",1);
    		push(@{$output},$self->_generate_object_meta($wsobj));
    		$delhash->{$user}->{$ws}->{""}->{""} = $wsobj;
       	} else {
    		my $wsobj = $self->_wscache($user,$ws,1);
    		$self->_check_ws_permissions($wsobj,"w",1);
    		my $obj = $self->_get_db_object({
	    		workspace_uuid => $wsobj->{uuid},
	    		path => $path,
	    		name => $name
	    	});
       		if ($obj->{folder} == 1) {
       			if ($input->{deleteDirectories} == 0) {
       				$self->_error("Object list includes directory ".$input->{objects}->[$i].", and deleteDirectories flag was not set!");
       			} elsif ($input->{force} == 0 && $self->_count_directory_contents($obj,0) > 0) {
	    			$self->_error("Deleting non-empty directory ".$input->{objects}->[$i].", and force flag was not set!");
	    		}
       		}
       		push(@{$output},$self->_generate_object_meta($obj));
       		$delhash->{$user}->{$ws}->{$path}->{$name} = $obj;
       	}
    }
    $self->_delete_validated_object_set($delhash);
    #END delete
    my @_bad_returns;
    (ref($output) eq 'ARRAY') or push(@_bad_returns, "Invalid type for return variable \"output\" (value was \"$output\")");
    if (@_bad_returns) {
	my $msg = "Invalid returns passed to delete:\n" . join("", map { "\t$_\n" } @_bad_returns);
	die $msg;
    }
    return($output);
}


=head2 set_permissions

  $output = $obj->set_permissions($input)

=over 4


=item Parameter and return types

=begin html

<pre>
$input is a set_permissions_params
$output is a reference to a list where each element is a reference to a list containing 2 items:
	0: an Username
	1: a WorkspacePerm
set_permissions_params is a reference to a hash where the following keys are defined:
	path has a value which is a FullObjectPath
	permissions has a value which is a reference to a list where each element is a reference to a list containing 2 items:
	0: an Username
	1: a WorkspacePerm

	new_global_permission has a value which is a WorkspacePerm
	adminmode has a value which is a bool
FullObjectPath is a string
Username is a string
WorkspacePerm is a string
bool is an int
</pre>

=end html

=begin text

$input is a set_permissions_params
$output is a reference to a list where each element is a reference to a list containing 2 items:
	0: an Username
	1: a WorkspacePerm
set_permissions_params is a reference to a hash where the following keys are defined:
	path has a value which is a FullObjectPath
	permissions has a value which is a reference to a list where each element is a reference to a list containing 2 items:
	0: an Username
	1: a WorkspacePerm

	new_global_permission has a value which is a WorkspacePerm
	adminmode has a value which is a bool
FullObjectPath is a string
Username is a string
WorkspacePerm is a string
bool is an int

=end text



=item Description


=back

=cut

sub set_permissions
{
    my $self = shift;
    my($input) = @_;

    my @_bad_arguments;
    (ref($input) eq 'HASH') or push(@_bad_arguments, "Invalid type for argument \"input\" (value was \"$input\")");
    if (@_bad_arguments) {
	my $msg = "Invalid arguments passed to set_permissions:\n" . join("", map { "\t$_\n" } @_bad_arguments);
	die $msg;
    }

    my $ctx = $Bio::P3::Workspace::Service::CallContext;
    my($output);
    #BEGIN set_permissions
    $input = $self->_validateargs($input,["path"],{
    	permissions => [],
    	new_global_permission => undef
	});
    my ($user,$ws,$path,$name) = $self->_parse_ws_path($input->{path});
    #Checking that workspace exists and a top lever directory is being adjusted
    my $wsobj = $self->_wscache($user,$ws,1);
    if (length($path) + length($name) > 0) {
    	$self->_error("Can only set permissions on top-level folders!");
    }
    #Checking that user has permissions to change permissions
    if ($wsobj->{global_permission} eq "p") {
    	if ($wsobj->{owner} ne $self->_getUsername() && $self->_adminmode() == 0) {
	    $self->_error("Only owner and administrators can change permissions on a published workspace!");
    	}
    } else {
    	$self->_check_ws_permissions($wsobj,"a",1);
    }
    #Checking that none of the user-permissions are "p"
    for (my $i=0; $i < @{$input->{permissions}}; $i++) {
    	if ($input->{permissions}->[$i]->[1] eq "p") {
	    $self->_error("Cannot set user-specific permissions to publish!");
    	}
    }
    if (defined($input->{new_global_permission})) {
    	#Only workspace owner or administrator can set global permissions to "p"
    	if ($input->{new_global_permission} eq "p") {
	    $self->_check_ws_permissions($wsobj,"o",1);
    	}
    	$input->{new_global_permission} = $self->_validate_workspace_permission($input->{new_global_permission});
    	$self->_updateDB("workspaces",
		     { uuid => $wsobj->{uuid} },
		     {'$set' => { global_permission => $input->{new_global_permission}}});
    	$wsobj->{global_permission} = $input->{new_global_permission};
    }
    for my $perm (@{$input->{permissions}})
    {
    	$perm->[1] = $self->_validate_workspace_permission($perm->[1]);
    	if ($perm->[1] eq "n" && defined($wsobj->{permissions}->{$perm->[0]})) {
	    $self->_updateDB("workspaces",
			 { uuid => $wsobj->{uuid} },
			 {'$unset' =>
			  { 'permissions.'. $self->_escape_username_for_mongo($perm->[0]) =>
				$wsobj->{permissions}->{$perm->[0]}}});
	    delete $wsobj->{permissions}->{$perm->[0]};
    	} else {
	    my($user, $perm) = @{$perm};
	    my $esc_user = $self->_escape_username_for_mongo($user);
	    
	    $self->_updateDB("workspaces",
			 {uuid => $wsobj->{uuid}},
			 { '$set' => { "permissions." . $esc_user => $perm } });
	    # {'$set' => {'permissions.'.$perm->[0] => $perm->[1]}});
	    $wsobj->{permissions}->{$user} = $perm;
    	}
    }
    $output = [];
    foreach my $puser (keys(%{$wsobj->{permissions}})) {
    	push(@{$output},[$puser,$wsobj->{permissions}->{$puser}]);
    }
    push(@{$output},["global_permission",$wsobj->{global_permission}]);
    
    #END set_permissions
    my @_bad_returns;
    (ref($output) eq 'ARRAY') or push(@_bad_returns, "Invalid type for return variable \"output\" (value was \"$output\")");
    if (@_bad_returns) {
	my $msg = "Invalid returns passed to set_permissions:\n" . join("", map { "\t$_\n" } @_bad_returns);
	die $msg;
    }
    return($output);
}


=head2 list_permissions

  $output = $obj->list_permissions($input)

=over 4


=item Parameter and return types

=begin html

<pre>
$input is a list_permissions_params
$output is a reference to a hash where the key is a string and the value is a reference to a list where each element is a reference to a list containing 2 items:
	0: an Username
	1: a WorkspacePerm
list_permissions_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a FullObjectPath
	adminmode has a value which is a bool
FullObjectPath is a string
bool is an int
Username is a string
WorkspacePerm is a string
</pre>

=end html

=begin text

$input is a list_permissions_params
$output is a reference to a hash where the key is a string and the value is a reference to a list where each element is a reference to a list containing 2 items:
	0: an Username
	1: a WorkspacePerm
list_permissions_params is a reference to a hash where the following keys are defined:
	objects has a value which is a reference to a list where each element is a FullObjectPath
	adminmode has a value which is a bool
FullObjectPath is a string
bool is an int
Username is a string
WorkspacePerm is a string

=end text



=item Description


=back

=cut

sub list_permissions
{
    my $self = shift;
    my($input) = @_;

    my @_bad_arguments;
    (ref($input) eq 'HASH') or push(@_bad_arguments, "Invalid type for argument \"input\" (value was \"$input\")");
    if (@_bad_arguments) {
	my $msg = "Invalid arguments passed to list_permissions:\n" . join("", map { "\t$_\n" } @_bad_arguments);
	die $msg;
    }

    my $ctx = $Bio::P3::Workspace::Service::CallContext;
    my($output);
    #BEGIN list_permissions
    $input = $self->_validateargs($input,["objects"],{});
    $output = {};
    for my $obj (@{$input->{objects}})
    {
    	my ($user,$ws,$path,$name) = $self->_parse_ws_path($obj);
	my $wsobj = $self->_wscache($user,$ws,1);
	$self->_check_ws_permissions($wsobj,"r",1);
	foreach my $puser (keys(%{$wsobj->{permissions}}))
	{
	    push(@{$output->{$obj}},[$puser,$wsobj->{permissions}->{$puser}]);
	}
	push(@{$output->{$obj}},["global_permission",$wsobj->{global_permission}]);
    }
    #END list_permissions
    my @_bad_returns;
    (ref($output) eq 'HASH') or push(@_bad_returns, "Invalid type for return variable \"output\" (value was \"$output\")");
    if (@_bad_returns) {
	my $msg = "Invalid returns passed to list_permissions:\n" . join("", map { "\t$_\n" } @_bad_returns);
	die $msg;
    }
    return($output);
}





=head2 version 

  $return = $obj->version()

=over 4

=item Parameter and return types

=begin html

<pre>
$return is a string
</pre>

=end html

=begin text

$return is a string

=end text

=item Description

Return the module version. This is a Semantic Versioning number.

=back

=cut

sub version {
    return $VERSION;
}



=head1 TYPES



=head2 WorkspacePerm

=over 4


=item Description

User permission in worksace (e.g. w - write, r - read, a - admin, n - none)

=item Definition

=begin html

<pre>
a string
</pre>

=end html

=begin text

a string

=end text

=back



=head2 Username

=over 4


=item Description

Login name for user

=item Definition

=begin html

<pre>
a string
</pre>

=end html

=begin text

a string

=end text

=back



=head2 bool

=over 4


=item Definition

=begin html

<pre>
an int
</pre>

=end html

=begin text

an int

=end text

=back



=head2 Timestamp

=over 4


=item Description

Indication of a system time

=item Definition

=begin html

<pre>
a string
</pre>

=end html

=begin text

a string

=end text

=back



=head2 ObjectName

=over 4


=item Description

Name assigned to an object saved to a workspace

=item Definition

=begin html

<pre>
a string
</pre>

=end html

=begin text

a string

=end text

=back



=head2 ObjectID

=over 4


=item Description

Unique UUID assigned to every object in a workspace on save - IDs never reused

=item Definition

=begin html

<pre>
a string
</pre>

=end html

=begin text

a string

=end text

=back



=head2 ObjectType

=over 4


=item Description

Specified type of an object (e.g. Genome)

=item Definition

=begin html

<pre>
a string
</pre>

=end html

=begin text

a string

=end text

=back



=head2 ObjectSize

=over 4


=item Description

Size of the object

=item Definition

=begin html

<pre>
an int
</pre>

=end html

=begin text

an int

=end text

=back



=head2 ObjectData

=over 4


=item Description

Generic type containing object data

=item Definition

=begin html

<pre>
a string
</pre>

=end html

=begin text

a string

=end text

=back



=head2 FullObjectPath

=over 4


=item Description

Path to any object in workspace database

=item Definition

=begin html

<pre>
a string
</pre>

=end html

=begin text

a string

=end text

=back



=head2 UserMetadata

=over 4


=item Description

This is a key value hash of user-specified metadata

=item Definition

=begin html

<pre>
a reference to a hash where the key is a string and the value is a string
</pre>

=end html

=begin text

a reference to a hash where the key is a string and the value is a string

=end text

=back



=head2 AutoMetadata

=over 4


=item Description

This is a key value hash of automated metadata populated based on object type

=item Definition

=begin html

<pre>
a reference to a hash where the key is a string and the value is a string
</pre>

=end html

=begin text

a reference to a hash where the key is a string and the value is a string

=end text

=back



=head2 ObjectMeta

=over 4


=item Description

ObjectMeta: tuple containing information about an object in the workspace 

       ObjectName - name selected for object in workspace
       ObjectType - type of the object in the workspace
       FullObjectPath - full path to object in workspace, including object name
       Timestamp creation_time - time when the object was created
       ObjectID - a globally unique UUID assigned to every object that will never change even if the object is moved
       Username object_owner - name of object owner
       ObjectSize - size of the object in bytes or if object is directory, the number of objects in directory
       UserMetadata - arbitrary user metadata associated with object
       AutoMetadata - automatically populated metadata generated from object data in automated way
       WorkspacePerm user_permission - permissions for the authenticated user of this workspace.
       WorkspacePerm global_permission - whether this workspace is globally readable.
       string shockurl - shockurl included if object is a reference to a shock node
       string error - set if there was an error on the operation on this object.

=item Definition

=begin html

<pre>
a reference to a list containing 13 items:
0: an ObjectName
1: an ObjectType
2: a FullObjectPath
3: (creation_time) a Timestamp
4: an ObjectID
5: (object_owner) an Username
6: an ObjectSize
7: an UserMetadata
8: an AutoMetadata
9: (user_permission) a WorkspacePerm
10: (global_permission) a WorkspacePerm
11: (shockurl) a string
12: (error) a string

</pre>

=end html

=begin text

a reference to a list containing 13 items:
0: an ObjectName
1: an ObjectType
2: a FullObjectPath
3: (creation_time) a Timestamp
4: an ObjectID
5: (object_owner) an Username
6: an ObjectSize
7: an UserMetadata
8: an AutoMetadata
9: (user_permission) a WorkspacePerm
10: (global_permission) a WorkspacePerm
11: (shockurl) a string
12: (error) a string


=end text

=back



=head2 create_params

=over 4


=item Description

********* DATA LOAD FUNCTIONS *******************

=item Definition

=begin html

<pre>
a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a reference to a list containing 5 items:
0: a FullObjectPath
1: an ObjectType
2: an UserMetadata
3: an ObjectData
4: (creation_time) a Timestamp

permission has a value which is a WorkspacePerm
createUploadNodes has a value which is a bool
downloadLinks has a value which is a bool
overwrite has a value which is a bool
adminmode has a value which is a bool
setowner has a value which is a string

</pre>

=end html

=begin text

a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a reference to a list containing 5 items:
0: a FullObjectPath
1: an ObjectType
2: an UserMetadata
3: an ObjectData
4: (creation_time) a Timestamp

permission has a value which is a WorkspacePerm
createUploadNodes has a value which is a bool
downloadLinks has a value which is a bool
overwrite has a value which is a bool
adminmode has a value which is a bool
setowner has a value which is a string


=end text

=back



=head2 update_metadata_params

=over 4


=item Description

"update_metadata" command
        Description: 
        This function permits the alteration of metadata associated with an object
        
        Parameters:
        list<tuple<FullObjectPath,UserMetadata>> objects - list of object paths and new metadatas
        bool autometadata - this flag can only be used by the workspace itself
        bool adminmode - run this command as an admin, meaning you can set permissions on anything anywhere

=item Definition

=begin html

<pre>
a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a reference to a list containing 4 items:
0: a FullObjectPath
1: an UserMetadata
2: an ObjectType
3: (creation_time) a Timestamp

autometadata has a value which is a bool
append has a value which is a bool
adminmode has a value which is a bool

</pre>

=end html

=begin text

a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a reference to a list containing 4 items:
0: a FullObjectPath
1: an UserMetadata
2: an ObjectType
3: (creation_time) a Timestamp

autometadata has a value which is a bool
append has a value which is a bool
adminmode has a value which is a bool


=end text

=back



=head2 get_params

=over 4


=item Description

********* DATA RETRIEVAL FUNCTIONS *******************

=item Definition

=begin html

<pre>
a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a FullObjectPath
metadata_only has a value which is a bool
adminmode has a value which is a bool

</pre>

=end html

=begin text

a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a FullObjectPath
metadata_only has a value which is a bool
adminmode has a value which is a bool


=end text

=back



=head2 update_auto_meta_params

=over 4


=item Description

"update_shock_meta" command
        Description:
        Call this function to trigger an immediate update of workspace metadata for an object,
        which should typically take place once the upload of a file into shock has completed

        Parameters:
        list<FullObjectPath> objects - list of full paths to objects for which shock nodes should be updated

=item Definition

=begin html

<pre>
a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a FullObjectPath
adminmode has a value which is a bool

</pre>

=end html

=begin text

a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a FullObjectPath
adminmode has a value which is a bool


=end text

=back



=head2 get_download_url_params

=over 4


=item Description

"get_download_url" command
        Description:
        This function returns a URL from which an object may be downloaded
        without any other authentication required. The download URL will only be
        valid for a limited amount of time. 

        Parameters:
        list<FullObjectPath> objects - list of full paths to objects for which URLs are to be constructed

=item Definition

=begin html

<pre>
a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a FullObjectPath

</pre>

=end html

=begin text

a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a FullObjectPath


=end text

=back



=head2 get_archive_url_params

=over 4


=item Description

"get_archive_url" command
        Description:
        This function returns a URL from which an archive of the given 
        objects may be downloaded. The download URL will only be valid for a limited
        amount of time.

        Parameters:
        list<FullObjectPath> objects - list of full paths to objects to be archived
        bool recursive - if true, recurse into folders
        string archive_name - name to be given to the archive file
        string archive_type - type of archive, one of "zip", "tar.gz", "tar.bz2"

=item Definition

=begin html

<pre>
a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a FullObjectPath
recursive has a value which is a bool
archive_name has a value which is a string
archive_type has a value which is a string

</pre>

=end html

=begin text

a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a FullObjectPath
recursive has a value which is a bool
archive_name has a value which is a string
archive_type has a value which is a string


=end text

=back



=head2 list_params

=over 4


=item Description

"list" command
        Description: 
        This function retrieves a list of all objects and directories below the specified paths with optional ability to filter by search
        
        Parameters:
        list<FullObjectPath> paths - list of full paths for which subobjects should be listed
        bool excludeDirectories - don't return directories with output (optional; default = "0")
        bool excludeObjects - don't return objects with output (optional; default = "0")
        bool recursive - recursively list contents of all subdirectories; will not work above top level directory (optional; default "0")
        bool fullHierachicalOutput - return a hash of all directories with contents of each; only useful with "recursive" (optional; default = "0")
        mapping<string,string> query - filter output object lists by specified key/value query (optional; default = {})
        bool adminmode - run this command as an admin, meaning you can see anything anywhere

=item Definition

=begin html

<pre>
a reference to a hash where the following keys are defined:
paths has a value which is a reference to a list where each element is a FullObjectPath
excludeDirectories has a value which is a bool
excludeObjects has a value which is a bool
recursive has a value which is a bool
fullHierachicalOutput has a value which is a bool
query has a value which is a reference to a hash where the key is a string and the value is a reference to a list where each element is a string
adminmode has a value which is a bool

</pre>

=end html

=begin text

a reference to a hash where the following keys are defined:
paths has a value which is a reference to a list where each element is a FullObjectPath
excludeDirectories has a value which is a bool
excludeObjects has a value which is a bool
recursive has a value which is a bool
fullHierachicalOutput has a value which is a bool
query has a value which is a reference to a hash where the key is a string and the value is a reference to a list where each element is a string
adminmode has a value which is a bool


=end text

=back



=head2 copy_params

=over 4


=item Description

********* REORGANIZATION FUNCTIONS ******************

=item Definition

=begin html

<pre>
a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a reference to a list containing 2 items:
0: (source) a FullObjectPath
1: (destination) a FullObjectPath

overwrite has a value which is a bool
recursive has a value which is a bool
move has a value which is a bool
adminmode has a value which is a bool

</pre>

=end html

=begin text

a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a reference to a list containing 2 items:
0: (source) a FullObjectPath
1: (destination) a FullObjectPath

overwrite has a value which is a bool
recursive has a value which is a bool
move has a value which is a bool
adminmode has a value which is a bool


=end text

=back



=head2 delete_params

=over 4


=item Description

********* DELETION FUNCTIONS ******************

=item Definition

=begin html

<pre>
a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a FullObjectPath
deleteDirectories has a value which is a bool
force has a value which is a bool
adminmode has a value which is a bool

</pre>

=end html

=begin text

a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a FullObjectPath
deleteDirectories has a value which is a bool
force has a value which is a bool
adminmode has a value which is a bool


=end text

=back



=head2 set_permissions_params

=over 4


=item Description

********* FUNCTIONS RELATED TO SHARING *******************

=item Definition

=begin html

<pre>
a reference to a hash where the following keys are defined:
path has a value which is a FullObjectPath
permissions has a value which is a reference to a list where each element is a reference to a list containing 2 items:
0: an Username
1: a WorkspacePerm

new_global_permission has a value which is a WorkspacePerm
adminmode has a value which is a bool

</pre>

=end html

=begin text

a reference to a hash where the following keys are defined:
path has a value which is a FullObjectPath
permissions has a value which is a reference to a list where each element is a reference to a list containing 2 items:
0: an Username
1: a WorkspacePerm

new_global_permission has a value which is a WorkspacePerm
adminmode has a value which is a bool


=end text

=back



=head2 list_permissions_params

=over 4


=item Description

"list_permissions" command
        Description: 
        This function lists permissions for the specified objects
        
        Parameters:
        list<FullObjectPath> objects - path to objects for which permissions are to be listed
        bool adminmode - run this command as an admin, meaning you can list permissions on anything anywhere

=item Definition

=begin html

<pre>
a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a FullObjectPath
adminmode has a value which is a bool

</pre>

=end html

=begin text

a reference to a hash where the following keys are defined:
objects has a value which is a reference to a list where each element is a FullObjectPath
adminmode has a value which is a bool


=end text

=back


=cut

1;
