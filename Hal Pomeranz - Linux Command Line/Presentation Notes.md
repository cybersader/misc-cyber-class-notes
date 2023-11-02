# Unix/Linux Files Layout
- /etc - like Windows registry 
- /var - log files, relatively temporary files
- /dev/shm - attackers often stage malware here, it's volatile RAM data so it deletes itself if someone unplugs
- /home - where the users live
- /root - root
# Moving Around 
- cd - takes you back home

- "/var/log" - absolute pathname
- "cd /folder_you_are_next_to" - relative pathname

- '.' files are hidden
	- usually startup files
	- config files

- "." - current directory, yourself
- ".." - one level up

-  We don't put current directory in our search path (unsafe to do so)
	- Use "./" to get to files in the current directory

- Traversal exploiting misconfiguration
	- You can use tons of "../" to get to the root, then use "/etc/passwd" to surely get to the root
		- There may be configured rules that only allow commands in the local directory and this gets around that

- "~/" - things under my home directory, current user

# Basic Unix/Linux Commands
- copy entire dir
	- cp -r (recursive)
		- -r option is common to go across entire directory
- mv - doesn't care about file vs dir
	- same as renaming technically
	- mv bashhis bash_his (renaming)

- rm FILE

- rm -r DIR

- ls has a LOT of flags
	- A - show hidden without . or ..
		- Hackers will make files like ".. " which will still show up here.  Linux ppl ignore front of directory sometimes
	- ls -l
		- get detailed files information
	- Show files, but no directories
	- ls -ld
		- show directory, but not the contents
	- Dates are last modified time for file
		- other flags can show different dates

- Sorting 
	- ls -lt
		- sort by modified time
	- ls -ltr reverse sorted
	- ls -lArt
		- sys admin butter
	- ls -lAShr | less

- less
	- hit b to go back up
	- g or G to go to front or back
	- keyword searching - 
		- "/keyword" - from front
		- "?keyword" - from back

- help
	- ls --help
- man
	- mansplaining
	- man -k KEYWORD_RELATED_TO_COMMAND
		- helpful for finding commands for things

- history
	- history of all commands that have been run
	- !number_that_matches_command

- cat
	- concatenate
	- use the jam files into one
	- cat FILES > output.txt

- Wildcards
	- cat filename* > output.txt
- echo
	- print
	- echo PATTERN*
		- prints files matching pattern
	- ? - matches single character
	- *  - matches sets of character
	- \[0-9\]

- Regex?
	- cp -r .\[A-Za-z0-9\]* * /Evidence
		- ignores ".."

- whoami or id #privesc 
	- shows user id 

- Other ways to figure out who you are
	- try less on the etc/shadow

- type "command_here"
	- tells you where command lives
	- compare this to where it should normally live

- file "filesname"
	- what the file really is

- sudo
	- run one command with root privs
	- IAM good for this, some commands are allowed per user #privesc

- su 
	- login as root

- sudo -s
	- not getting logged by sudo
	- -s : give me root shell but loses audit trail
	- bash history on disk: only written when shell exits
		- ways to keep shell from exiting or avoiding shell from getting written #antiforensics #DFIR

- Misc
	- change prompt with "export PS1='C:\\> '"
	- export HISTFILE=/dev/null
		- change where bash history goes?

# Building Blocks
#dataanalytics #data #forensics #DFIR

- etc/passwd
	- broken up into columns by colons

- cut -d: -f1,5 /etc/passwd
	- d - delimiter
	- f - fields (1,5 - 1 through 5)
	- cut by delimiter or even -c for character position
	- cut not good with whitespace delimited
		- use awk
- ps -ef
		- all the bash shells currently running

- df -h
	- look at directories and storage

- awk - breaks up lines on whitespace #search
	- awk '{print $1}' access_log*
	- print first columns from access log
	- awk –F: '{print $1, $5}' /etc/passwd
		- multiple columns with delimiter
	- ps -ef | awk

- grep #search
	- can do regex and all sorts of goodness
	- ps -ef | grep bash
	- grep on files
		- grep bash /etc/passwd
	- You can grep with a file of patterns
		- grep -f patterns.txt -r directory
	- -l : matching file names, but not matching lines

- Regex #search
	- grep and awk can both use them

- Sorting! #sort #sorting #search
	- you can sort on lines, but also on fields
	- bad guys may create new accounts in passwd files - user ID 0 has root, so they'll bury it in passwd file
	- sort -t: -n -k3,3
		- -t delimiter
	- Multiple -k to do nested sorting
	- sort -nr
		- 

- uniq
	- use -c to get counts too

- head
	- show first lines of output

- watch
	- 

- tail
	- watch end of log file
	- tail -n +2
		- skip 2 lines
		- does counting start at 1...yes
	- tail into grep
		- watch end of file with only matches to grep
	- watching log files #logmgmt #siem #detectionengineering 

- wc
	- word count
	- -l : count lines
	- grep -lr keyword directory | wc -l to show number of files

# Output Redirection
- Pipes "|" command to command
- ">" save to file

- What's really happening
	- STDIN (0 file descriptor)
		- < - technically
	- STDOUT (1 file descriptor)
		- Use >> to append or > to overwrite or write
	- STDERR (2 file descriptor)
		- you can use 2> file to direct errors to other places or files

- Shell options
	- set -o noclobber
		- keeps you from overwriting files

- .bash_rc
	- set options like no clobber here for default configurations

- 2>&1
	- send everything to both of the same places

- Reverse shells use redirection syntax
	- Run shell process, but send all the standard stuff into netcat and send them back to a listener

- Linux Reverse Shell
	- articles on SANS forensics

- tee
	- t joint that redirects stdout to something, then you can keep doing rest of command

- kill users in shells
	- kill $(ps -ef | grep bash | awk '/lab/ {print $2}')

- grep -f (cut -d: -f3 /etc/passwd | sort | uniq -d) -w /etc/passwd
	- cut -d: -f3 /etc/passwd | sort | uniq -d
	- cut by semicolon on passwords (third column - user ids) sort into uniq
- echo I roll a $(( $RANDOM % 6 + 1))
	- roll dice

- Always send to STDOU before STDIN or else you'll print to the terminal

## Unix: The Programming Environment
- The command shell is a programming language
	- It is an interpreted programming language

- Echo
	- print command for Unix shell
	- echo -n suppresses newline

- Loops
	- for file in \*.gz
	- while loops
		- commonly used for manipulating outputted fields from whitespace text files
			- cat /etc/passwd | while read username junk uid gid name home shell; do …
	- set IFS:= 
		- change the delimiter for the read command

- pv
	- progress bars 

## Conditionals
- if, then, else is clunky
- They tend to use shortcuts - 
	- short circuit evaluation - like ternary operator

- Use && for short circuits
	- if this then the next thing
	- ping >/dev/null && ssh
	- if ping works, then ssh

- || for negation
	- if .

- What qualifies as true or false - test operator or return value
	- STDERR?
	- Return value is what's being detected which is totally separate
	- all commands have RETURN values
		- You can use $? to get the value of the last command that got ran

- Custom functions
	- you can put custom functions into a bash rc file
	- you can make shell functions as templates

- Test operator
	- test operator
	- \[\[\]\]
```
[[-f /etc/passwd]] && cp /etc/passwd /tmp
```
# Other Iterators

- find
	- walk over directory and select files based on criteria
	- Weird CLI syntax
		- in chunks
		- 1. what are you looking through
		- 2. what are you looking for
		- 3 what to do about it
		- ![](IMG-20231102083655596.png)
		- exec rm -i for interactive automated deletion
	- Be careful doing exec on tons of files...really slow to open and close a bunch of processes
	- Examples:
		- Itrusion detection command:
			- `find / (entire fs) -xdev -type d -name .\*`
			- -xdev option
				- stay in the filesystem and don't cross mount boundaries - search one volume and nothing underneath it
			- some threat actors use directories that start with dot in places like `/tmp`
		- Find regular files under dev
			- /dev usually has special device files to communicate with the network and disk drives.  Attackers hide files here too
			- `find /dev -type f`
		- use parentheses and backlashes in places
			- `find .\( -name \*.jpg -o \*.jpeg \)  -ls`
		- -mtime or +mtime
			- `sudo find / -xdev -mtime -1`
			- `sudo find /var/log -type f -mtime +30 -exe gzip {} \;`
				- curly braces are matching filename you found
			- checking back months ago and looking at FS changes since then. Not a way with mtime to do this easily.  We can use touch though
				- `touch -t 202340215000 /tmp/myfile`
				- stats /tmp/myfile
				- Now we can use find 
				- `sudo find / -xdev -newer /tmp/myfile`
				- NEW SEARCH OPERATOR THOUGH HAHA...so you don't need the before steps at all
					- `sudo find / -xdev -newermt '2023-23-14 00:00:00'`
		- Collecting files to gzip
			- `sudo find /var/log -type f -mtime +30 | xargs gzip {}`
		- Running commands with xargs on lots of files
			- usually pipe to xargs instead
			- Filenames with space require - print0 arg and -0 for xargs
				- `find /tmp -type f -print 0 | xargs -0`
			- You can mass move files with mv -d with xargs
# REGEX! - regular expressions
- grep into regex
	- `ls folder | grep 'jp.\*g'`
	- use -E to tell grep you're using extended regex

# AWK, SED, TR
- awk
	- pattern match and output with print when delimited columns are involved
	- match on regular expressions with ~
- sed
	- modify things on the fly with regex
	- replace
		- sed 's/bash/zsh'
			- replace bash with zshell
	- -i 
		- modifies files in place and creates backups files while allowing you to change the file extension
- tr
	- great way to deal with null terminated files

```
tr \\000 \\n
```

# Processes
- use the ps command to see columns and use ww when commands are really long

- Netstat
	- stolen from Unix
	- Deprecated on Linux to the IP command but every other system still uses it, so it's more portable
	- netstat -nut (XD)
		- Active connections
	- netstat -lnut
		- Great for seeing what's listening on port
	- netstat -lpanut
		- see what processes are  listening
		- a - listening and active
		- e - adds a bit more info too

- kill and signals
	- must be sudo/root or process owner
	- sends signal to process which tells a process to terminate
	- some processes don't terminate with kill though
		- ps -ef | grep sshd
			- PID 825
			- sudo kill -HUP 825
				- HUP tells them to read config changes
	- User 1 signals
		- can be related to debugging
	- User 2
		- stop debugging
	- Kill is really just a way to communicate with processes
	- Abort
		- shut down process, but also do a core dump
	- sudo pkill -HUP sshd
		- this will terminate your user session
		- useful though when 
	- sudo kill -9 PID
		- shut down without cleaning up
			- This will frick up your stuff

- Changing process priority level
	- every process usually gets timesliced onto the CPU
	- If there's a coinminer, you can just make sure the process can't consume much
	- -20 max priority 
	- `renice` 
		- reconfigure priority for processes

- lsof
	- list open files
	- everything is a file in Linux
	- lsof -c /rsyslog/
		- in IR we look for processes executing or binaries executing from weird places
		- you shouldn't see mem libraries from places other than usr ...usually a bad sign
	- lsof -i :22
		- internetworking activity on port 22
		- use -n to avoid reverse DNS lookups
	- Mapping ports to process
		- lsof -c sshd -i -a
			- merge things in sshd and networking using "-a" for and
	- for quick unmounts
		- `kill $(lsof +d /home -t)`
	- show all processes that have files open anywhere under var/log
		- `lsof +D /var/log/`
	- show cwd for all processes on system
		- `lsof -d cwd | aws '{print $9}' | sort u`

- where do all these commands get process information
	- all from /proc directory

- about exe
	- you can delete binaries and have processes still running
		- you can't find the binary in the FS, but you can recover it via:
		- you can find it in proc with ls -l proc\/\*\/\exe 
		- cp /proc/PID/exe /tmp/recovered-binary

- You can use dd with maps to dump process memory

- STRATEGY:
	- use lsof at first, then use column to drill into /proc
# User, Groups, Perms
- script to make suspicious stuff
	- process under /dev/shm/.rk
	- lsof +L1
		- show all opened files that have link count less than 1 (opened but deleted files)

- Really useful when you can get hashes and look for known exploits, else you send it to a malware analyst

- Groups
	- nothing like AD groups.  Made at first to let devs share files
	- you can have your UID and default GID, but you can also have more groups in the /etc/group file
	- ways to figure out who you are:
		- tty
		- who 
		- who am i
		- whoami
	- Having the same user is bad because you'll be sharing files
	- the passwd file is used to associate a username with a user id

- Permissions
	- ls -ld /etc
		- 777
	- Permissions of owner, group, other
	- Other permission bits:
		- r, w, x
		- r,w,s - set ID: r,-,s - set GUID: r,-t - sticky bit
			- regular users need  to be able to change password, which means modifying data in etc/shadow
			- set ID allows for updates to password. Program with set ID executes as the owner of the executable.  Password command executes as root
			- attackers sometimes leave behind rogue set ID programs as backdoors
	- Permissions are stored as bits
		- 777 for all permissions - octal notation
		- 3 additional bits in an extra number
			- set UID
			- set GID
			- Sticky
	- Sticky - only owner can remove files
		- Made to stick into memory - doesn't really matter anymore in that way
		- Now it's an exclusion to something being writeable, but not deletable
	- RWX are different between files and directories
		- Dir is just a special file - file that lists filenames in dir
			- deleting a file from dir also requires permissions for dir
	- You can find with permissions
		- `find -xdev -perm /6000`
			- find all setUID and setGID files and directories
	- umask
		- what bits you don't want to be set when you create a new file
		- use 077 in a sensitive environment if you don't want people to be able to see this
		- Discretionary AC
			- explicit setting of permissions for other people

	- changing ownerships
		- only root can do it
		- 

# Shortcuts
- TAB to autocomplete paths, files
- DOUBLE TAB to show options when multiple matching files
- ALT or CTRL backspace to backspace words (goes over underscores)
- UP arrow of SCROLL to go back in command history
- To get to VERY LEFT of command - CTRL-A to beginning, CTRL-E to the end
- CTRL-C or CTRL-U to undo or stop command
- - CTRL-R: back up in history and keyword search
- CTRL-L - clears screen
- exit or CTRL-D to get out of root
- ALT ENTER or '\' to get to next line for multi line commands for readbilit
