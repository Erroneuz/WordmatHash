# WordmatHash
Powershell script that fetches hash values from Wordmat setup and word templates and present a one-click import csv for Defender XDR and a list of hash values for other EDR/XDR services.

Why?
For easy whitelistning of Wordmat https://www.wordmat.dk/en/ hashes in anti-virus services, eg. Defender XDR.
Wordmat uses Word templates and often EDR/XDR services triggers false positives.

Usage
1. Powershell terminal
2. Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
3. .\Get-WordMatHashes.ps1 or define path for outputs, eg.: .\Get-WordMatHashes.ps1 -OutputFolder C:\Temp\wm -CsvPath C:\Temp\hashes.csv -TxtPath C:\Temp\hashes.txt
4. ??
5. Profit
