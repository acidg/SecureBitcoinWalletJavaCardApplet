package de.tum.in.securebitcoinwallet.javacardapplet.test;

import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

import de.tum.in.securebitcoinwallet.javacardapplet.test.tests.KeyStoreTest;
import de.tum.in.securebitcoinwallet.javacardapplet.test.tests.PINTest;
import de.tum.in.securebitcoinwallet.javacardapplet.test.tests.UtilTest;

@RunWith(Suite.class)
@SuiteClasses({ KeyStoreTest.class, PINTest.class, UtilTest.class})
public class TestApplet {

}
