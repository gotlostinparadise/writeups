# [HackTheBox Write-Up: Keeper] - [Easy]

## Introduction
In today's write-up, we'll be diving deep into the Keeper machine from HackTheBox. This machine teaches a very important lesson about the interconnectedness of vulnerabilities and how, at times, lateral thinking is just as important as technical know-how.

## Initial Reconnaissance
The journey began at the Keeper website http://keeper.htb, which pointed us to http://tickets.keeper.htb/, a login page for Request Tracker. It's always a good idea to start with the basics, and in this case, trying default credentials bore fruit: 'root:password' were the default credentials for the Request Tracker administrative interface.

## Digging Deeper
Inside, there was a single issue: someone had trouble with their KeePass. The user had dumped their KeePass file in their home directory for investigation. A quick look at the user's profile revealed a note containing user's initial password: Welcome2023!. This was my ticket in.
![](<../../../assets/htb/keeper/user_keepass_issue.png>)
![](<../../../assets/htb/keeper/user_profile_note_with_password.png>)

## Gaining Initial Access
Using the password, I SSHed into the machine and secured first flag: the user flag. But the journey was far from over.
In the user's home directory, there was a ZIP file containing two intriguing items: keystore.kdbx and keepass.dmp.

## Exploiting Known Vulnerabilities
After some research, a vulnerability (CVE-2023-32784) was found, that would allow to dump the master password from keepass.dmp. However, the dumped password, \*\*dgr\*d med fl\*de, was incomplete.

![](<../../../assets/htb/keeper/keepass_master_pass_dump_attempt.png>)

A crucial clue was found back in the user's profile on Request Tracker. Investigating user's name and city, it was clear the user was Danish. 
![](<../../../assets/htb/keeper/user_info.png>)

And for anyone familiar with the Danish language, \*\*dgr\*d med fl\*de can be decoded to rødgrød med fløde, a popular Danish dish translating to 'red porridge with cream'. The special character 'ø' was the reason initial exploit didn't dump the entire password.

## Cracking the KeePass Vault
Using the web-based KeePass client at https://app.keeweb.info/, I unlocked the .kdbx file with the password 'rødgrød med fløde'. Inside, I found the contents of a PuTTY PPK file for the root user:
![](<../../../assets/htb/keeper/keepass_contents.png>)

## Root Access
With puttygen, it's easy to convert the PPK to an id_rsa SSH private key, which allows to SSH into the machine as root. The journey concluded with the capture of the root flag:

*$ puttygen key.ppk -O private-openssh -o id_rsa*

*$ chmod 600 id_rsa*

*$ ssh -i id_rsa root@keeper.htb*

![](<../../../assets/htb/keeper/root.png>)



## Conclusion
The Keeper machine offered a wonderful blend of technical challenges and cultural nuances. It emphasized the importance of keen observation and the need to sometimes think outside the box — or in this case, outside the language. Whether it's a default password or a Danish dish, every piece of information can be the key to unlocking the next stage. Always keep your eyes open, and remember: hacking is as much an art as it is a science.