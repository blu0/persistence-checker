# Persistence Checker

* This batch script is meant to be run from a Windows command prompt.
* The script will check registry keys commonly used by malware for persistent objects that may be missed by AntiVirus/AntiMalware programs.
* Some registry keys require admin rights to query.

Usage:
C:>persistcheck.bat

This will create persistcheck.txt in the same directory the script is run from, where you can evaluate for malicious entries/anomalies.
