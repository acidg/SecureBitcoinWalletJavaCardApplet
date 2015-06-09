# JavaCardApplet for the Secure Bitcoin Wallet

This project is the JavaCard applet for the Secure Bitcoin Wallet app.

## Requirements
We use Eclipse and the [EclipseJCDE](http://sourceforge.net/projects/eclipse-jcde/)
plugin. To install it, you have to extract all .jar files of the plugin folder
inside the zip file into the plugin directory of your eclipse installation root.

The JavaCard SDK 2.2.2 (JCDK) is needed, too. You can get it [here](http://www.oracle.com/technetwork/java/javasebusiness/downloads/java-archive-downloads-javame-419430.html#java_card_kit-2.2.2-oth-JPR). The EclipseJCDE has to be configured to find the JCDK package. The file you need is called _java_card_kit-2_2_2-rr-bin-linux-do.zip_ and can be found in a folder called _java_card_kit-2_2_2_ inside the zip file from Oracle. Extract its content to a suitable location, where you want the JCDK to be installed. After that, select the location in the configuration tool for the EclipseJCDE (Eclipse menu: Java Card -> Preferences -> Java Card Home).

For testing and simulation of the JavaCard, [jCardSim](https://github.com/licel/jcardsim) is used. This project is a JavaCard simulator, which also includes an implementation of the Oracle JavaCard Development Kit 2.2.2. and its sources. The library can be found in the [lib folder](lib).