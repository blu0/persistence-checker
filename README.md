# Registry Scraper

* This batch script is meant to be run from a Windows command prompt.
* The script will copy registry entries commonly used by malware into a text file for analysis. It is meant to be used as a way to simplify searching for persistent objects that may be missed by AntiVirus/AntiMalware programs.
* Some registry keys may require admin rights to query.

### Usage:
C:>regscrape.bat

* This will create regscrape.txt in the same directory the script is run from, where you can evaluate for malicious entries/anomalies.
* Note that not all queries will return results.
* This is just a tool to help scoping of incidents. It not meant as a replacement for AntiVirus/AntiMalware software or legitimate forensics investigations.
