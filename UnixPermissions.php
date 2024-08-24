<?php

/**
 * Class to manupilate and convert unix-style permissions
 * example: UnixPermissions::fromString('rw-rw-rw-')->asNumeric() // 666
 * example: UnixPermissions::fromNumeric(666)->unset('group', 'read')->asNumeric() // 626
 * example: UnixPermissions::fromNumeric(646)->set('group', 'write')->asString() // 'rw-rw-rw-'
 * example: UnixPermissions::fromString('rw-rw-rw-')->can('group', 'read') // true
 */
class UnixPermissions{
	private static $perms_map = [
		0 => '---',
		1 => '--x',
		2 => '-w-',
		3 => '-wx',
		4 => 'r--',
		5 => 'r-x',
		6 => 'rw-',
		7 => 'rwx'
	];
    
	private $numeric_perms;
    
	private function __construct($nums){
		$this->numeric_perms = intval($nums);
	}

	/**
	 * Construct from a string
	 * @param mixed $str
	 * @return UnixPermissions
	 */
	public static function fromString($str){
		return new UnixPermissions(self::strToNum($str));
	}

	/**
	 * Construct from a number
	 * @param mixed $nums
	 * @throws \Exception
	 * @return UnixPermissions
	 */
	public static function fromNumeric($nums){
		$parts = str_split(str_pad("$nums", 3, '0'));
		if(count($parts)!==3&&count($parts)!==4) throw new Exception("Invalid numeric permission.");
		if(count($parts)===4) array_shift($parts);
		foreach($parts as $part){
			if(!is_numeric($part) || intval($part) > 7) throw new Exception("Invalid numeric permission.");
		}
		return new UnixPermissions(intval(implode('', $parts)));
	}

	/**
	 * Return as number
	 * @return int
	 */
	public function asNumeric(){
		return str_pad("{$this->numeric_perms}", 3, '0');
	}

	/**
	 * Return as a string
	 * @return string
	 */
	public function asString(){
		return self::numToStr($this->numeric_perms);
	}

	/**
	 * Determine if the permission allows the owner/group/public to read/write/execute
	 * @param enum $userType 'owner' | 'group' | 'public'
	 * @param enum $permission 'read'| 'write' | 'execute'
	 * @throws \Exception
	 * @return bool
	 */
	public function can($userType, $permission){
		$parts = str_split(str_pad("{$this->numeric_perms}", 3, '0'));
		$type_idx = array_search($userType, ['owner', 'group', 'public']);
		if(false === $type_idx) throw new Exception('Invalid argument: $userType');
		$perms = ['read'=>'r','write'=>'w','execute'=>'x'];
		if(empty($perms[$permission])) throw new Exception('Invalid argument: $permission');
		$permstr = self::$perms_map[intval($parts[$type_idx])];
		return false !== strpos($permstr, $perms[$permission]);
	}

	/**
	 * Alter the permission to allow the given user type a specific permission
	 * @param enum $userType 'owner' | 'group' | 'public'
	 * @param enum $permission 'read'| 'write' | 'execute'
	 * @throws \Exception
	 * @return bool
	 */
	public function set($userType, $permission){
		// Split the number into individual numbers: 777 -> ['7', '7', '7']
		$parts = str_split(str_pad("{$this->numeric_perms}", 3, '0'));

		// Determine the number that we're operating on: // 0 for owner, 1 for group, etc
		$type_idx = array_search($userType, ['owner', 'group', 'public']);
		if(false === $type_idx) throw new Exception('Invalid argument: $userType');

		// Map to convert long form to short form permissions string, and permission index
		$perms = ['read'=>'r','write'=>'w','execute'=>'x'];
		if(empty($perms[$permission])) throw new Exception('Invalid argument: $permission');

		// Get the permissions string that corresponds with the permission that we're operating on, eg. '---' for 0
		$permstr = self::$perms_map[intval($parts[$type_idx])];

		// Split the permission string: ['-','-','-'] for '---'
		$str_parts = str_split($permstr);

		// Index of the permission string to change, eg. 0 for read, 1 for write, etc
		$perm_idx = array_search($perms[$permission], array_values($perms));

		// Set the appropriate index of the permissions string array to the appropriate permission letter: eg. ['-','-','-'] -> ['-','r','-']
		$str_parts[$perm_idx] = $perms[$permission];

		// Concat the permission string array into a single string: eg. ['r','-','-'] -> 'r--'
		$new_str = implode('', $str_parts);

		// Get the numeric value for the new permission string, eg 4 for 'r--', set it to the appropriate position in the numeric array
		$parts[$type_idx] = array_search($new_str, self::$perms_map);

		// Concat the numeric array, convert to a number and store it.
		$this->numeric_perms = intval(implode('', $parts));
		return $this;
	}

	/**
	 * Alter the permission to unset the given permission on the given user type
	 * @param enum $userType 'owner' | 'group' | 'public'
	 * @param enum $permission 'read'| 'write' | 'execute'
	 * @throws \Exception
	 * @return bool
	 */
	public function unset($userType, $permission){
		$parts = str_split(str_pad("{$this->numeric_perms}", 3, '0'));
		$type_idx = array_search($userType, ['owner', 'group', 'public']);
		if(false === $type_idx) throw new Exception('Invalid argument: $userType');
		$perms = ['read'=>'r','write'=>'w','execute'=>'x'];
		if(empty($perms[$permission])) throw new Exception('Invalid argument: $permission');
		$permstr = self::$perms_map[intval($parts[$type_idx])];
		$str_parts = str_split($permstr);
		$str_parts[array_search($perms[$permission], array_values($perms))] = '-';
		$new_str = implode('', $str_parts);
		$parts[$type_idx] = array_search($new_str, self::$perms_map);
		$this->numeric_perms = intval(implode('', $parts));
		return $this;
	}

	private static function numToStr($nums){
		$str = '';
		$parts = str_split(str_pad("$nums", 3, '0'));
		if(count($parts)!==3&&count($parts)!==4) throw new Exception("Invalid numeric permission.");
		if(count($parts)===4) array_shift($parts);
		foreach($parts as $part){
			if(!is_numeric($part) || intval($part) > 7) throw new Exception("Invalid numeric permission.");
			$str .= self::$perms_map[intval($part)];
		}
		return $str;
	}

	private static function strToNum($str){
		$chars=str_split($str);
		if(count($chars)===10) array_shift($chars);
		if(count($chars)!==9) throw new Exception("Invalid string permission.");
		$owner = substr($str, 0, 3);
		$group = substr($str, 3, 3);
		$public = substr($str, 6, 3);
		$owner_num = array_search($owner, self::$perms_map);
		if($owner_num === false) throw new Exception("Invalid string permission.");
		$group_num = array_search($group, self::$perms_map);
		if($group_num === false) throw new Exception("Invalid string permission.");
		$public_num = array_search($public, self::$perms_map);
		if($public_num === false) throw new Exception("Invalid string permission.");
		return intval("$owner_num$group_num$public_num");
	}
}