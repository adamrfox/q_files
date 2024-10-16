# q_files
A Project to manage open files on a Qumulo Cluster

While QumuoCore supports using the MMC to view and close open SMB files, there are times when this may want to be automated.  There are also some limits with repsect to the number of open files the MMC will display. 
It is possble to use the Qumulo CLI (qq) to view and close open file, but it is a multi-step process.  This project is an attempt to simpify the interface.

<pre>
Usage: q_files.py [-hD] [-t token] [-c creds] [-f token_file] command qumulo [file file ...]
-h | --help : Displays the Usage
-D | --DEBUG : Provides debug information
-c | --creds : Login credentials format user:password
-t | --token : Use an auth token
-f | --token-file : Use a token file generated from qq auth_create_token
command : list and close are currently supported
file file ... : A list of file names, ids, or locations. Space separated. [for close only]
</pre>

Authentication:
The API calls used by this script need to be authenticated.  The script provides multple ways to do this.

1. Specify the user and password on the command line via -c.  The format is user:password.
2. Specify an access token on the command line via -t.
3. Specify a file that congtains the token.  The format expected is the output from the Qumulo CLI command qq auth_create_access token.  If a file called .qfsd_creds exists (the default file from that command), the script wil use that.  This is useful for unattended runs (e.g. via cron)
4. If no other options are used, the script will prompt for a user and password.  The password is not echoed to the screen.

Specifiying Files to Close:
When open files are listed, the ID, location, and name are shown.  Any of these can be used to close a file.  If an ID or name is used, all locations to that file will be closed.  If a file has multiple instnaces and it is desired to only close of them, use the location as it is unqiue.

The script can, of course, be run as an admin user but that's not required.  Another user with limited RBAC user with the following privs can be used:
<PRE>
SMB_FILE_HANDLE_READ
SMB_FILE_HANDLE_WRITE
</PRE>
