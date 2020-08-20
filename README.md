# TokenPlayer
Abusing and Manipulating Windows Access Tokens.

___TokenPlayer___ is just a small tool i made to learn win32 api programming and understand better the access token model of windows.

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
