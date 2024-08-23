<?php

/**
 * Class to manupilate and convert unix-style permissions
 * example: UnixPermissions::fromString('rw-rw-rw-')->asNumeric() // 666
 * example: UnixPermissions::fromNumeric(666)->unset('group', 'read')->asNumeric() // 646
 * example: UnixPermissions::fromNumeric(646)->set('group', 'read')->asString() // 'rw-rw-rw-'
 * example: UnixPermissions::fromString('rw-rw-rw-')->can('group', 'read')->asString() // true
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
		$parts = str_split("$nums");
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
		return $this->numeric_perms;
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
		$parts = str_split("{$this->numeric_perms}");
		$type_idx = array_search($userType, ['owner', 'group', 'public']);
		if(false === $type_idx) throw new Exception('Invalid argument: $userType');
		$perms = ['write'=>'w','read'=>'r','execute'=>'x'];
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
		$parts = str_split("{$this->numeric_perms}");
		$type_idx = array_search($userType, ['owner', 'group', 'public']);
		if(false === $type_idx) throw new Exception('Invalid argument: $userType');
		$perms = ['write'=>'w','read'=>'r','execute'=>'x'];
		if(empty($perms[$permission])) throw new Exception('Invalid argument: $permission');
		$permstr = self::$perms_map[intval($parts[$type_idx])];
		$str_parts = str_split($permstr);
		$str_parts[array_search($perms[$permission], array_values($perms))] = $perms[$permission];
		$new_str = implode('', $str_parts);
		$parts[$type_idx] = array_search($new_str, self::$perms_map);
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
		$parts = str_split("{$this->numeric_perms}");
		$type_idx = array_search($userType, ['owner', 'group', 'public']);
		if(false === $type_idx) throw new Exception('Invalid argument: $userType');
		$perms = ['write'=>'w','read'=>'r','execute'=>'x'];
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
		$parts=str_split($nums);
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