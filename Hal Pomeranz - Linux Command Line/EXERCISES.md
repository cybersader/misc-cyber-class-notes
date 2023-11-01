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