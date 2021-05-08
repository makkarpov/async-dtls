async-dtls
==========

Asynchronous DTLS implementation for BouncyCastle, designed to be merged into it. Re-uses a lot of existing BouncyCastle code, and is placed in `org.bouncycastle.tls` packet to have access to it's private classes.

How to run
----------

1. Download [bctls-jdk15on-1.68.jar](https://repo1.maven.org/maven2/org/bouncycastle/bctls-jdk15on/1.68/bctls-jdk15on-1.68.jar) and place it in project root directory
2. Open it in the archiver and delete all signatures from `META-INF`, otherwise Java will complain