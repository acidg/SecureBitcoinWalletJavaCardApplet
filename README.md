# JavaCardApplet for the Secure Bitcoin Wallet

This project is the JavaCard applet for the [Secure Bitcoin Wallet App](https://github.com/sockeqwe/SecureBitcoinWallet).

## Requirements
We use Eclipse and [ant-javacard](https://github.com/martinpaljak/ant-javacard).

The JavaCard SDK 3.0.5 (JCDK) is needed, too. You can get it [here](http://www.oracle.com/technetwork/java/embedded/javacard/downloads/javacard-sdk-2043229.html). _ant-javacard_ has to be configured via the build.xml to find the JCDK.

For testing, [jCardSim](https://github.com/licel/jcardsim) is used. This project is a JavaCard simulator, which also includes an implementation of the Oracle JavaCard Development Kit 3.0.4. The library can be found in the [lib folder](lib). The javadoc can be found at the [GitHub page](https://github.com/licel/jcardsim) of jcardsim. Just clone the repository and link Eclipse to its doc and/or source folders.