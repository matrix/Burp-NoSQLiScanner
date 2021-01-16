# Building Burp-NoSQLiScanner

Get a copy of **Burp-NoSQLiScanner** repository and jump inside
```sh
$ git clone https://github.com/matrix/Burp-NoSQLiScanner &>/dev/null
$ cd Burp-NoSQLiScanner

```
Run "gradle build fatJar"
```sh
$ gradle build fatJar

BUILD SUCCESSFUL in 888ms
3 actionable tasks: 3 executed
```
You can find the compiled jar in the following directory path

```sh
$ ls build/libs/
Burp-NoSQLiScanner-1.0.jar
Burp-NoSQLiScanner-all-1.0.jar
```

Use 'Burp-NoSQLiScanner-all-1.0.jar' when import with Burp UI.

;)
