# TokenPlayer
Abusing and Manipulating Windows Access Tokens.

___TokenPlayer___ is just a small tool i made to learn win32 api programming and understand better the access token model of windows.

## Info:
The two main functions are stealing and impersonating a token from another process and creating tokens from scratch by providing valid credentials. It can impersonate even processes that have PPL (Protected Process Light) enabled by using the *PROCESS_QUERY_LIMITED_INFORMATION* flag on OpenProcess() function. This will let us open a handle to even protected processes. For making a new token it uses the CreateProcessWithLogonW() function, so no special privileges are required. Also it provides the option to be used from a non interactive context (e.g. a reverse shell) by using two pipes for parent-child process communication, but also provides the option to spawn a new window instance of command prompt with the impersonated context.

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
  --exec                 Execute an instance of a specified program.
  --pid arg              Proccess ID to steal the token from.
  --prog                 The full path to the program to be executed.
  --args                 Optional execution arguments for the specified
                         program.

Make Token Options:
  --make                 Create a new process under a set of creds for only
                         network authentication (Similar to runas /netonly).
  --username arg         Username
  --password arg         Password in plaintext format.
  --domain arg           The domain the user belongs, if domain isn't specified
                         the local machine will be used.
```

## Compile Instructions
To compile it yourself you will need to install the [boost](https://www.boost.org/) library, because it uses it for parsing and handling the command line arguments. Also you'll need to spcify the external library's folder on the project's settings.

## References
-[Windows Access Tokens and Alternate Credentials](https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/)
-[Understanding and Defending Against Access Token Theft](https://posts.specterops.io/understanding-and-defending-against-access-token-theft-finding-alternatives-to-winlogon-exe-80696c8a73b)
-[T1134: Primary Access Token Manipulation](https://www.ired.team/offensive-security/privilege-escalation/t1134-access-token-manipulation)
-[Privilege escalation through Token Manipulation](https://hacknpentest.com/privilege-escalation-through-token-manipulation/)
-[Creating a Child Process with Redirected Input and Output](https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output?redirectedfrom=MSDN)
-[Juicy Potato (abusing the golden privileges)](https://github.com/ohpe/juicy-potato)
-[RunasCs](https://github.com/antonioCoco/RunasCs)


