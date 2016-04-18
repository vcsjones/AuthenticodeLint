# Authenticode Lint

Lints an Authenticode signed binary.

This tool aides in the checking of a binary to lint Authenticode signed executables.

Authenticode, or "digitally signing" a binary is the process of applying a digital signature to the file.
Authenticode Lint looks at various aspects of the signature that might be problematic for users or all
together incorrect usage.

The tool is run from the command line, and has fairly simple usage. The most simple usage is:

    authlint.exe -in "C:\path to some\executable.exe"

Which will print results something like this:

>Rule #10000 "Primary SHA1" passed.
>
>Rule #10001 "SHA2 Signed" passed.

Rules can be suppressed with the `-suppress` option:

    authlint.exe -in "C:\path to some\executable.exe" -suppress 10001,10000

More information and options are available using `-help`.

# Documentation

Documentation for usage and for each rule is documented [on the wiki](https://github.com/vcsjones/AuthenticodeLint/wiki).

# Goals

The purpose of this tool is not to validate that everything uses the strongest signature algorithms
and certificates possible. Rather, this tool aims to make sure that the signatures provide proper
security while maintaining compatibility with as many enviroments as possible. For example, this tool
validates that the binary is has [dual signatures](https://textslashplain.com/2016/01/10/authenticode-in-2016/)
for broader compatility than using SHA256 alone.
