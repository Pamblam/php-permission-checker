<?php

/**
 * Given a file path:
 *     - if it's a file, ensure that the current process has read/write access to it
 *     - if it's a directory, ensure the current use has execute to it
 *     - ensure that the current user has execute permissions on every parent directory
 * @param mixed $path
 * @return string[][] - An array containing arrays of error and solution strings
 */
function ensureReadWrite($path){

	// The results to be returned
	$results = [];

	// Bit map of the permissions owner, group, public / read, write, execute
	$bit_map = ['or', 'ow', 'oe', 'gr', 'gw', 'ge', 'pr', 'pw', 'pe'];

	// The user of the current process
	$current_user = posix_getpwuid(posix_geteuid())['name'];

	// Each dir/file in the path
	$path_parts = explode("/", $path);

	while(count($path_parts)){

		// The current path
		$path = implode("/", $path_parts);
		if(empty($path)) $path = '/';

		if(file_exists($path)){

			// Permissions in octal eg 777
			$perm_oct = @substr(sprintf('%o', fileperms($path)), -4);

			// 9-digit binary string of representing the permissions
			$perm_bin = str_pad(decbin(octdec($perm_oct)), 9, '0', STR_PAD_LEFT);

			// Array of permissions bits
			$perm_bits = str_split($perm_bin);

			// Get the owner and group of the current process
			$owner = @posix_getpwuid(fileowner("$path"))['name'];
			$group = @posix_getgrgid(filegroup("$path"))['name'];

			// Get an array of groups that the current user belongs to
			$groups = @explode(" ", trim(shell_exec("groups $current_user")));

			// Is the current user a member of the file's group
			$in_group = is_array($groups) && is_array($groups) && in_array($group, $groups);

			// If it's a directory we just need execute so we can look inside it
			if(is_dir($path)){

				// Determine if we need owner, group, or public permissions
				$bit = 'pe'; $user = "Public";
				if($owner === $current_user){
					$user = "Owner";
					$bit = 'oe';
				}else if($in_group){
					$user = "Group";
					$bit = 'ge';
				}

				// The index of the bit that we need to check
				$bit_index = array_search($bit, $bit_map);

				// If the current user does not have execute permissions
				if($perm_bits[$bit_index] !== '1'){

					// Set the appropriate permission
					$perm_bits[$bit_index] = '1';

					// Convert back to octal value
					$new_perms = str_pad(decoct(bindec(intval(implode('', $perm_bits)))), 3, '0', STR_PAD_LEFT);

					$results[] = [
						'error' => "$user can't read directory contents: $path",
						'solution' => "sudo chmod $new_perms $path"
					];
				}

			}else{

				// Determine if we need owner, group, or public permissions
				$read_bit = 'pr'; 
				$write_bit = 'pw'; 
				$user = "Public";
				if($owner === $current_user){
					$user = "Owner";
					$read_bit = 'or'; 
					$write_bit = 'ow'; 
				}else if($in_group){
					$user = "Group";
					$read_bit = 'gr'; 
					$write_bit = 'gw'; 
				}

				// Get the index of the bits we need to check
				$read_bit_index = array_search($read_bit, $bit_map);
				$write_bit_index = array_search($write_bit, $bit_map);

				// Array of permisions that are missing (read, write, or both)
				$missing_perms = [];
				
				// Check for read permissions
				if($perm_bits[$read_bit_index] !== '1'){
					$perm_bits[$read_bit_index] = '1';
					$missing_perms[] = 'read';
				}

				// Check for write permissions
				if($perm_bits[$write_bit_index] !== '1'){
					$perm_bits[$write_bit_index] = '1';
					$missing_perms[] = 'write';
				}

				if(!empty($missing_perms)){
					// Convert back to octal value
					$new_perms = str_pad(decoct(bindec(intval(implode('', $perm_bits)))), 3, '0', STR_PAD_LEFT);

					$results[] = [
						'error' => "$user can't ".implode("or", $missing_perms)." file: $path",
						'solution' => "sudo chmod $new_perms $path"
					];
				}

			}
		}
		array_pop($path_parts);
	}
	return $results;
}
