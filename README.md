# Ensure php has read/write access

The goal of this is to give the user a list of commands to run to ensure that PHP has permissions to read/write a given file, by changing *only exactly what needs to be changed* based on the php processes current owner and group, rather than suggesting a user make broad sweeping permission changes to a file like `chmod` the file to 755 or 777. Will check that the process has read/write access to the file itself, if the file exists and PHP has exec access on all the parent folders, all the way to the root, regardless of cwd.

Since this is based on the current process, the required changes may differe between browser and cli.

Also, if the process doesn't have execute access to one of the parent folders it will not be able to check permissions on it's children until that access is granted, therefore this program may not be able to provide all the necessary solutions in one run, and may need to be run multiple times to completely solve an access problem.

# Testing

Clone the repo and make `mydir` or `mydir/myfile.txt` inaccessible by changing either it's owner, group, or permission. Run the `test.php` file from the browser or the cli. It will list each access problem and provide a `chmod` command to resolve it. Run the commands and rerun `test.php` until it says it has read write access.

# Known issues

This works fine, as is, as far as I know, but the `UnixPermissions` class could be made more efficient by using bitwise operators instead of string manipulation.

The `runcmd` is overkill for these purposes. I happened to have the function handy so I used it, but it could/should be replaced with a one-liner. This function is only used to get the groups that a given user belongs to because PHP's built in posix functions don't work as expected. See [this StackOverflow post](https://stackoverflow.com/questions/51737006/posix-getgrnam-returns-a-limited-number-of-members-from-members-array).