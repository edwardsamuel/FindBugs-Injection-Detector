#Injection Detector Plug-In for FindBugs

Input Injections are considered as the most common and effective vulnerabilities to exploit in many software systems (esp. web apps). Input injection is caused by executing user inputs which have not been validated or sanitized, so that the purpose of execution is changed by malicious agents into their advantages. 

The input injection detector is done by extending an existing static analysis tool, namely **FindBugs** (currently we only support **FindBugs 2.0.3**). The detection uses dataflow analysis to monitor user-contaminated variables. To improve accuracy, reducing false positives and false negatives, dataflow analysis is used to monitor variables that have been validated or sanitized by developers.

## Vulnerabilities
This plug-in can detect following vulnerabilities:

 1. SQL injection
 2. Shell/command injection
 3. XPath injection
 4. LDAP injection
 5. Cross-site scripting (XSS) type-1
 6. Cross-site scripting (XSS) type-2
 7. Unvalidated redirects
 8. Unvalidated forwards
 9. HTTP response splitting
 10. Path traversal
 11. Remote file inclusion

## Build

 1. Clone this repository.
 2. Download **FindBugs 2.0.3** source code (You can download it from [SourceForge](http://sourceforge.net/projects/findbugs/files/findbugs/2.0.3/findbugs-2.0.3-source.zip/download)).
 3. Extract `findbugs-2.0.3-source.zip` to root directory of this repositories. In the root directory, you should have 3 (three) directories: `findbugs-2.0.3`, `findbugs-injection-detector`, and `vulnerable-sites`.
 4. Rename `findbugs-2.0.3` to `findbugs`.
 5. In terminal, change current directory to `findbugs`, and then run `ant build` to compile and build **FindBugs**.
 6. In terminal, change current directory to `findbugs-injection-detector`, and then run `ant install` to compile, build, and install the detector to **FindBugs** in `findbugs` directory.

You should have `injection-detector.jar` in `findbugs-injection-detector` after building the plug-in. This file is plug-in for **FindBugs**. To install to another copy of **FindBugs**, you could copy `injection-detector.jar` to `plugin` directory in **FindBugs**.