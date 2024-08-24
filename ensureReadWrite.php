<?php
include 'UnixPermissions.php';
include 'runcmd.php';


/**
 * Given a file path:
 *     - if it's a file, ensure that the current process has read/write access to it
 *     - if it's a directory, ensure the current use has execute to it
 *     - ensure that the current user has execute permissions on every parent directory
 * @param mixed $path
 * @return string[][] - An array containing arrays of error and solution strings
 */
function ensureReadWrite($path){
	$results = [];
	$current_user = posix_getpwuid(posix_geteuid())['name'];
	$path_parts = explode("/", $path);
	while(count($path_parts)){
		$path = implode("/", $path_parts);
		if(empty($path)) $path = '/';
		if(file_exists($path)){
			$perms = UnixPermissions::fromNumeric(@substr(sprintf('%o', fileperms($path)), -4));
			$owner = @posix_getpwuid(fileowner("$path"))['name'];
			$group = @posix_getgrgid(filegroup("$path"))['name'];

			$groups = @explode(" ", trim(runcmd("groups $current_user")->stdout));
			$in_group = is_array($groups) && is_array($groups) && in_array($group, $groups);

			if(is_dir($path)){
				if($owner === $current_user){
					if(!$perms->can('owner', 'execute')){
						$results[] = [
							'error' => "Owner can't read directory contents: $path",
							'solution' => "sudo chmod ".$perms->set('owner', 'execute')->asNumeric()." $path"
						];
					}
				}else if($in_group){
					if(!$perms->can('group', 'execute')){
						$results[] = [
							'error' => "Group can't read directory contents: $path",
							'solution' => "sudo chmod ".$perms->set('group', 'execute')->asNumeric()." $path"
						];
					}
				}else{
					if(!$perms->can('public', 'execute')){
						$results[] = [
							'error' => "Public can't read directory contents: $path",
							'solution' => "sudo chmod ".$perms->set('public', 'execute')->asNumeric()." $path"
						];
					}
				}
			}else{
				$missing_perms = [];
				if($owner === $current_user){
					if(!$perms->can('owner', 'read')) $missing_perms[] = 'read';
					if(!$perms->can('owner', 'write')) $missing_perms[] = 'write';
					if(!empty($missing_perms)){
						foreach($missing_perms as $missing_perm){
							$perms->set('owner', $missing_perm);
						}
						$results[] = [
							'error' => "Owner can't ".implode(', ', $missing_perms)." file: $path",
							'solution' => "sudo chmod ".$perms->asNumeric()." $path"
						];
					}
				}else if($in_group){
					if(!$perms->can('group', 'read')) $missing_perms[] = 'read';
					if(!$perms->can('group', 'write')) $missing_perms[] = 'write';
					if(!empty($missing_perms)){
						foreach($missing_perms as $missing_perm){
							$perms->set('group', $missing_perm);
						}
						$results[] = [
							'error' => "Group can't ".implode(', ', $missing_perms)." file: $path",
							'solution' => "sudo chmod ".$perms->asNumeric()." $path"
						];
					}
				}else{
					if(!$perms->can('public', 'read')) $missing_perms[] = 'read';
					if(!$perms->can('public', 'write')) $missing_perms[] = 'write';
					if(!empty($missing_perms)){
						foreach($missing_perms as $missing_perm){
							$perms->set('public', $missing_perm);
						}
						$results[] = [
							'error' => "Public can't ".implode(', ', $missing_perms)." file: $path",
							'solution' => "sudo chmod ".$perms->asNumeric()." $path"
						];
					}
				}
			}
		}
		array_pop($path_parts);
	}
	return $results;
}
