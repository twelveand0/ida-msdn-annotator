# ida-msdn-annotators
Add MSDN annotations to IDA imported functions and structures

---------------------------------------------------------------------------------------------------------------------

This work is almost based on Moritz Raabe and William Ballenthin's work at Fireeye.

I strongly recommend you to refer the original <a href="https://github.com/fireeye/flare-ida"> flare-ida </a> project.

##The differences include:
1. Add a new plugin responsible for adding annotations to structure types and members.
2. Add a new script to parese windows sdk help-htmls to extract structures' annotations.
3. Add new regrex rules to parse the imported functions' name in IDA.

##Usage
Usage for script adding annotations to imported functions can be found at

1. https://github.com/fireeye/flare-ida (<b>MSDN Annotations Usage</b> section)
2. https://www.fireeye.com/blog/threat-research/2014/09/flare-ida-pro-script-series-msdn-annotations-ida-pro-for-malware-analysis.html

Usage for script adding annotations to structures is similar to the above

###NOTES about preparing sdk help files
After you install standalone Windows SDK into your local drive (By default, it is located at 'C:\Program Files\Microsoft SDKs\Windows \v7.0\Help\1033'), you can find the installed help files in folder 'C:\Program Files\Microsoft SDKs\Windows \v7.0\Help \1033'. However, these files (endwith '.hxs') are compiled files and not human readable. You have to do something before running msdn_crawer.py.

1. <b>Prepare *hxcomp.exe* for decompiling</b> Install Vistual Studio 2008 and VS 2008 SDK version 1.0 (MUST BE) or lower VS and VS SDK version. Or copy all the .hxs files to a machine where *hxcom.exe* has been installed.
2. <b>Demcopiling .hxs files</b> Run *hxcomp.exe* (default location is 'C:\Program Files\Common Files\microsoft shared\Help 2.0 Compiler\hxcomp.exe') to decompile help files endwith '.hxs'. You can do it with the following command:

        for /R %x in (*.hxs) do hxcomp -u "%x"

  By default, you can find the extracted .htm files in 'C:\Users\%username%\AppData\Local\VirtualStore\Program Files\Microsoft SDKs\Windows\v7.0\Help\1033' (In Windows 7)

3. Run msdn_crawer.py

        python msdn_crawler.py -t [function|structure] <path to extracted MSDN html documentation> <path to tilib.exe> <path to til files>
        

