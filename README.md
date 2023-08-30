[![CodeQL](https://github.com/mroi/unison-intercept/actions/workflows/codeql.yml/badge.svg)](https://github.com/mroi/unison-intercept/actions/workflows/codeql.yml)

Unison libSystem Intercept for macOS
====================================

I use the [Unison](https://github.com/bcpierce00/unison) file synchronization tool to keep 
files between multiple machines and servers up to date. However, I wanted to customize some 
aspects of Unison’s behavior. Because I did not want to make invasive changes to its 
codebase, I decided to amend Unison’s functionality from the outside by intercepting its use 
of the C-level `libSystem` (`libc` on Linux and other Unixes) APIs.

This project provides a `libintercept.dylib` library, which re-exports all of `libSystem` 
and can therefore replace it. Selected API calls are replaced or extended with my own 
functionality.

If you compile the project either in Xcode or using `xcodebuild`, make sure to point the 
`UNISON_PATH` build setting to your `Unison.app` bundle. By default, the build system is 
configured to my personal needs. A release build will place `libintercept.dylib` inside the 
Unison bundle and modify Unison with `install_name_tool` to link against 
`libintercept.dylib` instead of `libSystem`. The build will also attempt to sign the 
resulting executables.

For Linux and other Unixes, the enclosed `Makefile` builds and installs an equivalent 
`libintercept.so`, which can be activated by setting the `LD_PRELOAD` environment variable 
when launching Unison.

Intercept Functionality
-----------------------

Currently, five intercept layers are provided, which add the following features to Unison:

**nocache**  
Cause all writes performed by Unison to bypass the buffer cache. This has two advantages: It 
avoids polluting the cache if Unison handles large files and it improves data safety, as the 
subsequent read check done by Unison will read from the physical storage medium and not from 
the cache.

**config**  
As Unison reads its configuration files, this intercept layer parses them and extracts 
additional configuration options used by other intercepts. All additional options start with 
`#` and therefore look like comments to the normal Unison parser.

**encrypt**
Files are encrypted after local reads and decrypted before local writes. This ensures that 
Unison operates on encrypted data when transferring file content to servers. The encryption 
key can be configured using `#encrypt = Path PATH -> aes-256-gcm:SECRET` directives.

**prepost**  
Runs pre and post processing commands. Global pre and post commands, which execute once 
synchronization starts and completes, are configured as `#precmd = COMMAND` and
`#postcmd = COMMAND`. Lines of the form `#post = Path PATH -> COMMAND` cause a command to be 
executed whenever a specific file has been changed.

**symlink**  
Creates symlinks for a specified path name before they are traversed by Unison. The path and 
link content are configured using `#symlink = Path PATH -> TARGET`. Symlinks are only 
created within the first Unison root located below the current home directory.

**umask**  
Files created in the user’s home directory employ a `umask` of 0700. This restriction does 
not apply to subdirectories or explicit permission changes with `chmod`.

___
This work is licensed under the [GNU GPLv3](https://www.gnu.org/licenses/gpl-3.0.html).
