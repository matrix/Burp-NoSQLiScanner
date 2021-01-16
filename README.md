# Burp NoSQLi Scanner
Currently Burp doesn't have an engine that detects NoSQL Injection, so I created this plugin to add support
<br>
using my preferred language, Java (it's a joke, it's a trap) :D
<br>
Happy pentest :)

## Limitations

1 - Parallel scanning of multiple parameter at once is not supported for now.<br>
Consequently, at the moment the plugin does not detect derived problems, such as authentication bypass.<br>

2 - No tab in the Burp UI for now. <br>

I'm lazy, but sooner or later I will resolve all two :)<br>

3 - Exploiting is not supported, do it manually if needed.

## Building

Refer to [BUILD.md](BUILD.md) for instructions on how to build it from source.
