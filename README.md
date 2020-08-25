# TokenPlayer
Abusing and Manipulating Windows Access Tokens.

___TokenPlayer___ is just a small tool i made to learn win32 api programming and understand better the access token model of windows.

## Features:
- Stealing and Impersonating primary tokens.
- Impersonating Protected Processes.
- Bypassing UAC by using the Token-Duplication method.
- Making new tokens for network authentication by providing credentials (similar to runas /netonly) without the need for special rights or elevated context.
- Spoof the parent process ID and spawn a process with an alternative parent process.
- Execute any application with provided parameters under an impersonated context.
- Can be used from non-interactive contexts (e.g. reverse shell) by using pipes for parent-child process communication.

## Usage:
```
General options:
  --help                 Display help menu.

Impersonation Options:
  --impersonate          Impersonates the specified pid and spawns a new child
                         process under its context.
  --pid arg              Proccess ID to steal the token from.
  --spawn                Spawns a new command prompt under the context of the
                         stolen token.

Execution Options:
  --exec                 Execute an instance of a specified program under the
                         impersonated context.
  --pid arg              Proccess ID to steal the token from.
  --prog                 The full path to the program to be executed.
  --args                 Optional execution arguments for the specified
                         program.

Make Token Options:
  --maketoken            Create a new process under a set of creds for only
                         network authentication (Similar to runas /netonly).
  --username arg         Username
  --password arg         Password in plaintext format.
  --domain arg           The domain the user belongs, if domain isn't specified
                         the local machine will be used.

UAC Bypass Options:
  --pwnuac               Will try to bypass UAC using the token-duplication
                         method.
  --spawn                Spawns a new elevated prompt.
  --prog arg             The full path to the program to be executed.
  --args arg             Optional execution arguments for the specified
                         program.
```

## Usage 1: Token Impersonation
### Using same console:
![Token Impersonation](https://github.com/S1ckB0y1337/TokenPlayer/blob/master/Examples/impersonation.png)
### Spawning a new console:
![Token Impersonation In New Window](https://github.com/S1ckB0y1337/TokenPlayer/blob/master/Examples/impersonationInNewWindow.png)

## Usage 2: Executing an application (e.g. rev shell)
![Executing Reverse Shell](https://github.com/S1ckB0y1337/TokenPlayer/blob/master/Examples/revshellImpersonation.png)

## Usage 3: Make Token
![Make Token](https://github.com/S1ckB0y1337/TokenPlayer/blob/master/Examples/maketoken.png)

## Usage 4: UAC Bypass
![UAC Bypass](https://github.com/S1ckB0y1337/TokenPlayer/blob/master/Examples/uacpwned.png)

## Usage 5: PPID Spoofing
![PPID Spoofing](https://github.com/S1ckB0y1337/TokenPlayer/blob/master/Examples/ppidspoofing.png)

## Compile Instructions
To compile it yourself you will need to install the [boost](https://www.boost.org/) library, because it uses it for parsing and handling the command line arguments. Also you'll need to specify the external library's folder on the project's settings.

## References
- [Windows Access Tokens and Alternate Credentials](https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/)
- [Understanding and Defending Against Access Token Theft](https://posts.specterops.io/understanding-and-defending-against-access-token-theft-finding-alternatives-to-winlogon-exe-80696c8a73b)
- [T1134: Primary Access Token Manipulation](https://www.ired.team/offensive-security/privilege-escalation/t1134-access-token-manipulation)
- [Privilege escalation through Token Manipulation](https://hacknpentest.com/privilege-escalation-through-token-manipulation/)
- [Creating a Child Process with Redirected Input and Output](https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output?redirectedfrom=MSDN)
- [Reading Your Way Around UAC (Part 1)](https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-1.html)
- [Reading Your Way Around UAC (Part 2)](https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-2.html)
- [Reading Your Way Around UAC (Part 3)](https://www.tiraniddo.dev/2017/05/reading-your-way-around-uac-part-3.html)
- [UAC-TokenMagic.ps1](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/UAC-TokenMagic.ps1)
- [UAC-TokenDuplication](https://github.com/ThunderGunExpress/UAC-TokenDuplication)
- [RunasCs](https://github.com/antonioCoco/RunasCs)
- [Access Token Manipulation: Parent PID Spoofing](https://attack.mitre.org/techniques/T1134/004/)
- [Alternative methods of becoming SYSTEM](https://blog.xpnsec.com/becoming-system/)


