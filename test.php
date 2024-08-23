<?php

include 'UnixPermissions.php';
include 'runcmd.php';

var_dump(getGroups('rob')); 

/**
 * Get an array of groups that the given user belongs to by asking the operating system directly.
 * @param string $username
 * @throws \Exception
 * @return bool|string[]
 */
function getGroups($username){
	$descriptorspec = array(
		0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
		1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
		2 => array("pipe", "w")   // stderr is a pipe that the child will write to
	);

	$process = proc_open("groups $username", $descriptorspec, $pipes);
	
	$stderr = '';
	$stdout = '';
	$status = 0;
	
	if (is_resource($process)) {
		fclose($pipes[0]);

		$stdout = stream_get_contents($pipes[1]);
		fclose($pipes[1]);

		$stderr = stream_get_contents($pipes[2]);
		fclose($pipes[2]);

		$status = proc_close($process);
	}else{
		$stderr = 'Unable to run command.';
		$status = 1;
	}
	
	if(!empty($stderr)){
		throw new Exception($stderr);
	}

	if($status != 0) return false;

	return explode(" ", trim($stdout));
}




echo "<pre>\n\n";

$base_path = realpath(dirname(__FILE__));

$username = posix_getpwuid(posix_geteuid())['name'];
echo "Current user: $username\n";

echo "\n\n";
printFileInfo("$base_path/mydir", $username);

echo "\n\n";
printFileInfo("$base_path/mydir/myfile.txt", $username);

function isUserInGroup($user, $groupname){
	$groups = @explode(" ", trim(runcmd("groups $user")->stdout));
	return is_array($groups) && is_array($groups) && in_array($groupname, $groups);
}

function printFileInfo($path, $user){
	echo "Path: $path\n";
	$exists = file_exists("$path")?"Yes":"No";
	echo "Exists: $exists\n";
	
	$perms = getPerms("$path");
	echo "Permissions: $perms\n";
	
	$owner = @posix_getpwuid(fileowner("$path"))['name'];
	echo "Owner: $owner\n";
	
	$group = @posix_getgrgid(filegroup("$path"))['name'];
	echo "Group: $group\n";
	
	$readable = is_readable("$path")?"Yes":"No";
	echo "Readable: $readable\n";
	
	$writable = is_writable("$path")?"Yes":"No";
	echo "writable: $writable\n";

	$is_owner = $user === $owner ? "Yes" : "No";
	echo "Current user is owner: $is_owner\n";

	$in_group = isUserInGroup($user, $group) ? "Yes" : "No";
	echo "Current use is in group: $in_group\n";
}



function getPerms($path){
	$perms = @fileperms($path);

	$info = " ".substr(sprintf('%o', $perms), -4);
	
	// Owner
	$info .= "\n  owner:  ";
	$info .= (($perms & 0x0100) ? 'r' : '-');
	$info .= (($perms & 0x0080) ? 'w' : '-');
	$info .= (($perms & 0x0040) ?
				(($perms & 0x0800) ? 's' : 'x' ) :
				(($perms & 0x0800) ? 'S' : '-'));
	
	// Group
	$info .= "\n  group:  ";
	$info .= (($perms & 0x0020) ? 'r' : '-');
	$info .= (($perms & 0x0010) ? 'w' : '-');
	$info .= (($perms & 0x0008) ?
				(($perms & 0x0400) ? 's' : 'x' ) :
				(($perms & 0x0400) ? 'S' : '-'));
	
	// World
	$info .= "\n  public: ";
	$info .= (($perms & 0x0004) ? 'r' : '-');
	$info .= (($perms & 0x0002) ? 'w' : '-');
	$info .= (($perms & 0x0001) ?
				(($perms & 0x0200) ? 't' : 'x' ) :
				(($perms & 0x0200) ? 'T' : '-'));

	return $info;
}