<?php

include 'ensureReadWrite.php';

echo "<pre>\n\n";

$username = posix_getpwuid(posix_geteuid())['name'];
echo "Currently running as user: $username\n";

$base_path = realpath(dirname(__FILE__));
$path = "$base_path/mydir/myfile.txt";

$results = ensureReadWrite($path);

if(empty($results)){
	echo "Current user has read/write permissions to $path!\n\n";
}else{
	foreach($results as $result){
		echo "Problem: \n\t{$result['error']}\n";
		echo "Solution: run this...\n\t{$result['solution']}\n\n";
	}
}


