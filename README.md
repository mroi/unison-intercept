Unison libSystem Intercept for macOS
====================================

I use the [Unison](www.seas.upenn.edu/~bcpierce/unison/) file synchronization tool to keep 
files between multiple machines and servers up to date. However, I wanted to customize some 
aspects of Unison’s behavior. But I did not want to make invasive changes to its codebase, 
so I decided to amend Unison’s functionality from the outside by intercepting its use of the 
C-level `libSystem` APIs.

This project provides a `libintercept.dylib` library, which re-exports all of `libSystem` 
and can therefore replace it. Selected API calls however are replaced or extended with my 
own functionality.

If you compile the project in either Xcode or using `xcodebuild`, make sure to point the 
`UNISON_PATH` build setting to your `Unison.app` bundle. By default, the build system is 
configured to my personal needs. A release build will place `libintercept.dylib` inside the 
Unison bundle and modify Unison to link against it instead of `libSystem`. The build will 
also attempt to sign the resulting executables.

Currently, three intercept layers are provided, which add the following features to Unison:

**nocache**  
Cause all writes performed by Unison to bypass the buffer cache. This has two advantages: It 
avoids polluting the cache if Unison handles large files and it improves data safety, the 
subsequent read check done by Unison will read from the physical storage medium and not from 
the cache.

**config**  
As Unison reads its configuration files, this intercept layer parses them and extracts 
additional configuration options used by other intercepts. All additional options start with 
`#` and therefore look like comments to the internal Unison parser.

**post**  
Runs post processing commands whenever a specified file changes. This step is configured 
using lines of the form `#post = Path PATH -> COMMAND`.

This work is licensed under the [GNU GPL v3](https://www.gnu.org/licenses/gpl-3.0.html) or 
higher.
