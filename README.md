Andriller.py
============

# SUMMARY

Andriller is a multi-platform forensic tool, that performs read-only, forensically sound, non-destructive acquisition from Android devices. The executable is run from a terminal or by executing directly; it produces premilinary results in the terminal window, and a report in a HTML format.

# DISCLAIMER

Andriller comes with absolutely no warranty. Even though Andriller was written in a way to be a forensically sound read-only utility, I do not take any responsibility to any damage or harm caused to your computer systems or your Android devices, which may be believed to have been caused by executing Andriller. I also do not take any responsibility of any unsolicited, non-consensual or unlawful misuses of this software. It is the end user's responsibility to believe an appropriate consent or a lawful excuse was obtained if the utility is used with an other's Android devices, and they are aware what the software does.

# DESCRIPTION

Once andriller is executed, it will produce permilinary results in the terminal window; for rooted devices it will download and decode the content automatically. It will produce a new folder in the location where it was executed, where the main "REPORT.html" file can be opened in a web browser.


# USAGE INSTRUCTIONS

Do not delete any files from this directory, or change anything else, as this may prevent you from successfully executing the program. Connect an Android device via USB with the USB debugging (ADB) enabled. If Android version 4.2.2+, tick remember and accept RSA fingerprint on the screen. If Superuser is installed, give it root permissions when asked. 

++ Microsoft Windows ++
- (Easy way)Run the compiled executable 'Andriller.exe'. That's it.
- (Hard way)install Python 3.x ,download from http://www.python.org/download/
- once installed, run the Andriller.py from command prompt
- if your system doesn't execute Andriller.py as a Python program:
	C:\Python33\python.exe [path_to]\Andriller.py

++ Linux OS ++
- make sure python3 is installed on your system; it comes as standard for Ubuntu, but not for others, like Fedora.
- for i386/i586/i686 (32-bit) systems, an executable './adb' comes with Andriller
- it is highly advisable to install 'adb' before executing Andriller:
	for Ubuntu:		$ sudo apt-get install android-tools-adb
	for Fedora:		# yum install adb
	for openSUSE:	# yast -i android-tools
- run executable 'Andriller.py' in a terminal:
	$ ./Andriller.py

++ Mac OSX ++
- install Python 3.x ,download from http://www.python.org/download/
- for most Macs, the './adb_mac' version 1.0.31 is included; for higher versions, obtain the latest adb from Android SDK (if you do, remember to rename it to 'adb_mac', and replace it with the one Andriller came with)
- execute Andriller in a terminal:
	$ python ./Andriller.py

# COMPATABILITY AND SUPPORT

Andriller was tested on rooted Android devices running OS versions:
2.2.x, 2.3.x, 4.0.x, 4.1.x, 4.2.2, 4.3, 4.4.2

Andriller has support for the following features.

Non-root devices (Android versions 2.x):
- Android device make and model
- IMEI, build version, OS version
- Wifi mac address
- Time and date check
- SIM card details (for a some Galaxy Sx devices only)
- Synchronised accounts

Non-rooted devices (via backup method, Android versions 4.x and above)
- Wi-Fi passwords (WPA-PSK/WEP)
- Call logs (Samsung) register
- Android browser saved passwords
- Android browser browsing history
- Google Chrome saved passwords
- Google Chrome browsing history
- Facebook* chat messages
- Facebook* user viewed photographs
- Facebook* user notifications
- WhatsApp* contacts list
- WhatsApp* chat messages
- Kik Messenger* chat messages
- BBM* chat messages (Blackberry Messenger)

Rooted devices (via root adbd or 'su' binary, any Android versions):
- Security lockscreen pattern gesture extraction (decoding online)
- Security lockscreen PIN code cracking (up to 8 digits)
- Wi-Fi passwords (WPA-PSK/WEP)
- Synchronised accounts and profile picture
- Bluetooth mac address and name
- Phonebook contacts
- Call logs register
- Call logs (Samsung) register
- SMS messages
- Android browser saved passwords
- Android browser browsing history
- Google Chrome saved passwords
- Google Chrome browsing history
- Facebook* chat messages
- Facebook* user viewed photographs
- Facebook* user notifications
- WhatsApp* contacts list
- WhatsApp* chat messages
- Kik Messenger* chat messages
- BBM* chat messages (Blackberry Messenger)

\* = if an Application is installed

# CONTACTS

For contact, to submit bugs, or suggestions:

http://android.saz.lt

den (at) saz (dot) lt

