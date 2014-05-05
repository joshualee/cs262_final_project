#!/bin/bash
(java -cp "bin/;lib/*" org.junit.runner.JUnitCore edu.harvard.cs262.tests.ClientServerTests)
(java -cp "bin/;lib/*" org.junit.runner.JUnitCore edu.harvard.cs262.tests.CryptoCipherTests)
(java -cp "bin/;lib/*" org.junit.runner.JUnitCore edu.harvard.cs262.tests.EVoteTests)
(java -cp bin edu.harvard.cs262.tests.ConsoleTest)