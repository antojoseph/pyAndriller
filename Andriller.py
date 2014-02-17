#!/usr/bin/env python3

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Andriller.py - Forensic acquisition tool for Android devices.
# Website, Usage and Disclaimer: http://android.saz.lt
# Copyright (C) 2012-2014  Denis Sazonov
#
# This program is free software: you can redistribute it and/or modify 
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or 
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU 
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 

import os
import re
import sys
import time
import tarfile
import sqlite3 as sq
from json import loads
from io import BytesIO
from struct import pack
from zlib import decompress
from hashlib import md5,sha1
from base64 import b64decode
from binascii import hexlify,unhexlify
from datetime import datetime
from datetime import timedelta
from subprocess import check_output as co
from subprocess import call
from webbrowser import open_new_tab

# Setting variables
__author__ = "Denis Sazonov"
__version__ = "alpha-1.3.1"
__build_date__ = "17-Feb-2014"
__website__ = "http://android.saz.lt"

# Intro info print
logo = b'ICAgX19fX18gICAgICAgICAgICAgIC5fX18gICAgICAuX18uX18gIC5fXyAgICAgICAgICAgICAgICA\
KICAvICBfICBcICAgX19fXyAgICBfX3wgXy9fX19fX198X198ICB8IHwgIHwgICBfX19fX19fX19fXyAKIC8gIC9\
fXCAgXCAvICAgIFwgIC8gX18gfFxfICBfXyBcICB8ICB8IHwgIHwgXy8gX18gXF8gIF9fIFwKLyAgICB8ICAgIFw\
gICB8ICBcLyAvXy8gfCB8ICB8IFwvICB8ICB8X3wgIHxfXCAgX19fL3wgIHwgXC8KXF9fX198X18gIC9fX198ICA\
vXF9fX18gfCB8X198ICB8X198X19fXy9fX19fL1xfX18gID5fX3wgICAKICAgICAgICBcLyAgICAgXC8gICAgICB\
cLyAgIFZlcnNpb246IHswfSAgXC8gICAgICAgCiAgICAgICAgICAgICAgICAgICAgICAgICBCdWlsZCBkYXRlOiB\
7MX0KICAgICAgICAgICAgICAgICAgICAgICAgICAgIFdlYnNpdGU6IHsyfQ=='
print(b64decode(logo).decode().format(__version__, __build_date__, __website__))

REPORT = []		# List to be populated for generating the REPORT.html file
ERRORS = []		# List to be populated with errors occured
extraction_started = time.time()

# Check OS and define adb
download_adb = ' ERROR! \n\'./adb\' file is not present!\n Download it from \
http://android.saz.lt/download/adb.zip\n Unzip, and place them into this \
directory;\n Run the program again.'
# Check OS, define adb executable and path SEParator
if 'linux' in sys.platform:
	SEP = '/'
	if call(['which', 'adb']) == 0:
		ADB = "adb"; print('', end='\r')
	else:
		ADB = './adb'
		if os.path.isfile(ADB) == True:
			os.chmod(ADB, '0755')
		else:
			input(download_adb + "\n Press 'Enter' to exit.")
			sys.exit()
elif 'win32' in sys.platform:
	ADB = "adb.exe"
	SEP = '\\'
	if os.path.isfile(ADB) == False:
		input(download_adb + "\n Press 'Enter' to exit.")
		sys.exit()
elif 'darwin' in sys.platform:
	ADB = "./adb_mac"
	SEP = '/'
	if os.path.isfile(ADB) == False:
		input(download_adb + "\n Press 'Enter' to exit.")
		sys.exit()
try:
	ADB; co([ADB, 'start-server'])
except NameError:
	input(" ERROR! Cannot determine OS!\n Press 'Enter' to exit.")
	sys.exit()

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Unrooted (shell) devices, to print device information, limited extractions 
#
#print('{0:\u00B0^60}'.format(' General Device Information '))
print('{0:\u00B0^60}'.format(' General Device Information '))

# Check for connected Android device
if 'unknown' in co([ADB, 'get-state']).decode('UTF-8'):
	input(" No Android device found!\n Press 'Enter' to exit."); sys.exit()
else:
	ADB_SER = co([ADB, 'get-serialno']).decode('UTF-8').replace('\n', '').replace('\r', '')
	print(" ADB serial: " + ADB_SER); REPORT.append(["ADB serial", ADB_SER])

# Check permissions
QPERM = co([ADB, 'shell', 'id']).decode('UTF-8')
if 'root' in QPERM:
	PERM = 'root'
else:
	QPERMSU = co([ADB, 'shell', 'su', '-c', 'id']).decode('UTF-8')
	if 'root' in QPERMSU:
		PERM = 'root(su)'
	else:
		PERM = 'shell'
try:
	print(" Shell permissions: " + PERM); REPORT.append(["Shell permissions", PERM])
except NameError:
	input("  Android permission cannot be established!\n Press 'Enter' to exit."); sys.exit()

# Make & Model
BUILDPROP = co([ADB, 'shell', 'cat', '/system/build.prop']).decode('UTF-8')
for manuf in BUILDPROP.split('\n'):
	if 'ro.product.manufacturer' in manuf:
		DEVICE_MANUF = manuf.strip().split('=')[1].upper()
for model in BUILDPROP.split('\n'):
	if 'ro.product.model' in model:
		DEVICE_MODEL = model.strip().split('=')[1]
try:
	print(" Device model: {0} {1}".format(DEVICE_MANUF, DEVICE_MODEL))
	REPORT.append(["Manufacturer", DEVICE_MANUF]); REPORT.append(["Model", DEVICE_MODEL])
except:
	pass; ERRORS.append('Cannot get make and model.')

# IMEI
for _ in co([ADB, 'shell', 'dumpsys', 'iphonesubinfo']).decode('UTF-8').split('\n'):
	if 'Device ID' in _:
		IMEI = _.split(' = ')[1]; break
try:
	print(" IMEI: " + IMEI); REPORT.append(["IMEI", IMEI])
except:
	pass; ERRORS.append('Cannot get IMEI or IMEI is not supported.')

# A version
for aver in BUILDPROP.split('\n'):
	if 'ro.build.version.release' in aver:
		ANDROID_VER = aver.strip().split('=')[1]
try:
	print(" Android version: " + ANDROID_VER); REPORT.append(["Android version", ANDROID_VER])
except:
	pass; ERRORS.append('Cannot get Android version.')

# Build ID
for buildid in BUILDPROP.split('\n'):
	if 'ro.build.display.id' in buildid:
		BUILD_ID = buildid.strip().split('=')[1]
try:
	print(" Build number: " + BUILD_ID); REPORT.append(["Build name", BUILD_ID])
except:
	pass; ERRORS.append('Cannot get Build ID.')

# Wifi
DUMPSYS_W = co([ADB, 'shell', 'dumpsys', 'wifi']).decode('UTF-8')
try:
	wifi_beg = DUMPSYS_W.index('MAC:')+5
	wifi_end = DUMPSYS_W[wifi_beg:].index(',')
	if wifi_end == 17:
		WIFI_MAC = DUMPSYS_W[wifi_beg:wifi_beg+wifi_end].lower()
		print(" Wi-fi MAC: " + WIFI_MAC); REPORT.append(["Wifi MAC", WIFI_MAC])
except:
	pass; ERRORS.append('Wifi is not enabled, or is not supported by the device.')

# Time and date
LOCAL_TIME = time.strftime('%Y-%m-%d %H:%M:%S %Z')
try:
	print(" Local time: " + LOCAL_TIME); REPORT.append(["Local time", LOCAL_TIME])
except:
	pass; ERRORS.append('Cannot get local (Computer) time.')
ANDROID_TIME = co([ADB, 'shell', 'date', '+%F %T %Z']).decode('UTF-8').replace('\r\n', '')
try:
	print(" Android time: " + ANDROID_TIME); REPORT.append(["Android time", ANDROID_TIME])
except:
	pass; ERRORS.append('Cannot get remote (Android) time.')

# SIM card extraction 
SIM_LOC = '/data/system/SimCard.dat'
if co([ADB, 'shell', '"ls', SIM_LOC+'"']).decode('UTF-8').replace('\r', '').replace('\n', '') == SIM_LOC:
	SIM_DATA = co([ADB, 'shell', '"cat', SIM_LOC+'"']).decode('UTF-8').replace('\r', '')
	for sim_d in SIM_DATA.split('\n'):
		if 'CurrentSimSerialNumber' in sim_d:
			SIM_ICCID = sim_d.split('=')[1]
			if SIM_ICCID != '' and SIM_ICCID != 'null':
				REPORT.append(['SIM ICCID', SIM_ICCID])
		if 'CurrentSimPhoneNumber' in sim_d:
			SIM_MSISDN = sim_d.split('=')[1]
			if SIM_MSISDN != '' and SIM_MSISDN != 'null':
				REPORT.append(['SIM MSISDN', SIM_MSISDN])
		if 'CurrentSimOperatorName' in sim_d:
			SIM_OP = sim_d.split('=')[1]
			if SIM_OP != '' and SIM_OP != 'null':
				REPORT.append(['SIM Operator', SIM_OP])
		if 'PreviousSimSerialNumber' in sim_d:
			PRV_SIM_ICCID = sim_d.split('=')[1]
			if PRV_SIM_ICCID != '' and PRV_SIM_ICCID != 'null':
				REPORT.append(['SIM ICCID (Previous)', PRV_SIM_ICCID])
		if 'PreviousSimPhoneNumber' in sim_d:
			PRV_SIM_MSISDN = sim_d.split('=')[1]
			if PRV_SIM_MSISDN != '' and PRV_SIM_MSISDN != 'null':
				REPORT.append(['SIM MSISDN (Previous)', PRV_SIM_MSISDN])
else:
	ERRORS.append('SIM details are not available.')

# Accounts
ALLACC = co([ADB, 'shell', 'dumpsys', 'account']).decode('UTF-8')
all_acc = re.compile('Account {name=', re.DOTALL).finditer(ALLACC)
ACCOUNTS = []
for acc in all_acc:
	hit_pos = acc.start()
	tacc = ALLACC[hit_pos+14:]
	end_pos = tacc.index('}')
	acc0 = tacc[:end_pos].replace(' type=', '').split(',')
	acc = acc0[1]+": "+acc0[0]
	ACCOUNTS.append(acc)
if ACCOUNTS != []:
	print('{0:\u00B0^60}'.format(' Synchronised Accounts '))
	for account in ACCOUNTS:
		print(str(account))
	REPORT.append(["Accounts", ACCOUNTS])
else:
	ERRORS.append('No synchronised accounts were detected.')

# Create output directory
OR_DATE = time.strftime('%Y-%m-%d')
OR_TIME = time.strftime('%H.%M.%S')
OUTPUT = re.sub(r'\s', '', DEVICE_MANUF)+"_"+re.sub(r'\s', '', DEVICE_MODEL)+"_"+OR_DATE+"_"+OR_TIME+SEP
try:
	os.mkdir(OUTPUT)
	os.mkdir(OUTPUT+'db')
except:
	input(" Insufficient permissions to create a folder in this directory!\n Press 'Enter' to exit.")
	sys.exit()

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# ROOT EXTRACTION
#
#if 'root' in PERM:
#	print('{0:\u00B0^60}'.format(' Downloading databases '))

#
# DATABASE EXTRACTION
#
# Database links

DBLS = [
'/data/data/com.android.email/databases/EmailProvider.db',
'/data/data/com.android.email/databases/EmailProviderBody.db',
'/data/data/com.google.android.email/databases/EmailProvider.db',
'/data/data/com.google.android.email/databases/EmailProviderBody.db',
'/data/data/com.android.providers.settings/databases/settings.db',
'/data/data/com.android.providers.contacts/databases/contacts2.db',
'/data/data/com.sec.android.provider.logsprovider/databases/logs.db',
'/data/data/com.android.providers.telephony/databases/mmssms.db',
'/data/data/com.facebook.katana/databases/fb.db',
'/data/data/com.facebook.katana/databases/contacts_db2',
'/data/data/com.facebook.katana/databases/threads_db2',
'/data/data/com.facebook.katana/databases/notifications.db',
'/data/data/com.facebook.katana/databases/notifications_db',
'/data/data/com.facebook.katana/databases/photos_db',
'/data/data/com.whatsapp/databases/wa.db',
'/data/data/com.whatsapp/databases/msgstore.db',
'/data/data/kik.android/databases/kikDatabase.db',
'/data/data/kik.android/shared_prefs/KikPreferences.xml',	# kik passwd in sha1
'/data/data/com.bbm/files/bbmcore/master.db',
'/data/data/com.android.phone/shared_prefs/com.android_preferences.xml',	# No decoder (SIM)
'/data/data/com.android.chrome/app_chrome/Default/Login Data',
'/data/data/com.android.chrome/app_chrome/Default/History',
'/data/data/com.android.chrome/app_chrome/Default/Archived History',
'/data/data/com.android.browser/databases/browser2.db',
'/data/data/com.android.browser/databases/webview.db',
'/data/system/packages.list',	# No decoder
'/data/system/sync/accounts.xml',	# No decoder
'/data/system/users/0/accounts.db',
'/data/system/users/0/photo.png',
'/data/system/gesture.key',
#'/data/system/cm_gesture.key',		# No decoder
'/data/system/locksettings.db',
'/data/system/password.key',
'/data/misc/wifi/wpa_supplicant.conf',
]

AB_DBLS = [
'apps/com.android.email/db/EmailProvider.db',
'apps/com.android.email/db/EmailProviderBody.db',
'apps/com.google.android.email/db/EmailProvider.db',	# Add support
'apps/com.google.android.email/db/EmailProviderBody.db',	# Add support
'apps/com.android.providers.contacts/db/contacts2.db',
'apps/com.android.providers.settings/f/flattened-data',
'apps/com.android.providers.telephony/db/mmssms.db',
'apps/com.sec.android.provider.logsprovider/db/logs.db',
'apps/com.android.chrome/r/app_chrome/Default/Login Data',
'apps/com.android.chrome/r/app_chrome/Default/History',
'apps/com.android.chrome/r/app_chrome/Default/Archived History',
'apps/com.android.chrome/r/app_chrome/Default/Login Data',
'apps/com.android.browser/db/browser2.db',
'apps/com.android.browser/db/webview.db',
'apps/com.facebook.katana/db/fb.db',
'apps/com.facebook.katana/db/contacts_db2',
'apps/com.facebook.katana/db/threads_db2',
'apps/com.facebook.katana/db/notifications.db',
'apps/com.facebook.katana/db/notifications_db',
'apps/com.facebook.katana/db/photos_db',
'apps/com.whatsapp/db/wa.db',
'apps/com.whatsapp/db/msgstore.db',
'apps/kik.android/db/kikDatabase.db',
'apps/com.bbm/f/bbmcore/master.db',
]

#
# DOWNLOADING DATABASES
SUC, QM, DLT = '', '', '/data/local/tmp/'
if 'su' in PERM:	SUC, QM = 'su -c', '"'
#
DLLS = []	# downloaded databases empty list
def download_database(DB_PATH):
	DB_NAME, DB_PATHa = DB_PATH.split('/')[-1], DB_PATH
	if DB_NAME not in DLLS:
		if ' ' in DB_NAME:	DB_PATHa = DB_PATH.replace(DB_NAME, repr(DB_NAME))
		if co([ADB, 'shell', SUC, QM+'ls', repr(DB_PATHa)+QM]).decode('UTF-8').replace('\r', '').replace('\n', '') == DB_PATH:
			if 'su' in PERM:
				co([ADB, 'shell', SUC, QM+'dd', 'if='+repr(DB_PATHa), 'of='+repr(DLT+repr(DB_NAME))+QM])
				co([ADB, 'shell', SUC, QM+'chmod', '777', repr(DLT+repr(DB_NAME))+QM])
				co([ADB, 'pull', DLT+str(DB_NAME), OUTPUT+'db'+SEP+str(DB_NAME)])
				co([ADB, 'shell', SUC, QM+'rm', repr(DLT+repr(DB_NAME))+QM])
			else:
				co([ADB, 'pull', DB_PATH, OUTPUT+'db'+SEP+str(DB_NAME)])
			if os.path.isfile(OUTPUT+'db'+SEP+str(DB_NAME)) == True:
				DB_MD5 = md5(open(OUTPUT+'db'+SEP+str(DB_NAME), 'rb').read()).hexdigest()
				DLLS.append(DB_NAME)
				with open(OUTPUT+'db'+SEP+'checksums.md5', 'a') as md5file:
					md5file.write(DB_MD5+'\t'+str(DB_NAME)+'\n')
			else:
				ERRORS.append('Failed pulling {0} file from the device.'.fformat(DB_NAME))
		else:
			ERRORS.append('Remote file {0} is not present on the device.'.format(DB_NAME))

# Extract databases from AB
def android_backup_extractor():
	AB_raw = open(OUTPUT+'backup.ab', 'rb')
	AB_tar = tarfile.open(fileobj=BytesIO(decompress(AB_raw.read()[24:])))
	for ab_item in AB_DBLS:
		try:
			ab_obj = AB_tar.getmember(ab_item)
			DB_NAME = ab_item.split('/')[-1]
			if DB_NAME not in DLLS:
				with open(OUTPUT+'db'+SEP+str(DB_NAME), 'wb') as file_h:
					file_h.write(AB_tar.extractfile(ab_obj).read())
				if os.path.isfile(OUTPUT+'db'+SEP+str(DB_NAME)) == True:
					DB_MD5 = md5(open(OUTPUT+'db'+SEP+str(DB_NAME), 'rb').read()).hexdigest()
					DLLS.append(DB_NAME)
					with open(OUTPUT+'db'+SEP+'checksums.md5', 'a') as md5file:
						md5file.write(DB_MD5+'\t'+str(DB_NAME)+'\n')		
		except:
			pass
	del AB_raw,AB_tar

# Trigger download databases / android_backup
if 'root' in PERM:
	print('{0:\u00B0^60}'.format(' Data Extraction via Root '))
	for db in DBLS:
		download_database(db)
else:
	if int(ANDROID_VER[0]) >= 4:
		print('{0:\u00B0^60}'.format(' Data Extraction via Android Backup '))
		print('>>> Extraction via Android Backup method <<<\n>>> Unlock the screen and tap on "Back up my data" <<<')
		try:
			co([ADB, 'backup', '-all', '-f', OUTPUT+'backup.ab'])
		except:
			pass
		if os.path.isfile(OUTPUT+'backup.ab'):
			android_backup_extractor()
			print(' Success! {0} databases extracted from backup.'.format(len(DLLS)))

# Unix timestamp to date converter  # # # # # # # # # # # # # #
def unix_to_utc(unix_stamp):
	return datetime.utcfromtimestamp(int(str(unix_stamp)[:10])).strftime('%Y-%m-%d %H:%M:%S UTC')

def webkit_to_utc(webkit_stamp):
	wtu0 = (datetime(1601,1,1) + timedelta(microseconds=int(webkit_stamp))).timetuple()
	try:
		return unix_to_utc(int(time.mktime(wtu0)))
	except:
		return None

def format_html(data):
	if data != None:	return data.replace('<', '&lt;').replace('>', '&gt;')

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# DECODING DEFINITIONS FOR DATABASES
# 
REP_HEADER = '<!DOCTYPE html><html><head><meta charset="UTF-8">\n<title>{{_title}} Andriller Report for {_imei}</title>\n<style>body,td,tr {{{{font-family: Vernada, Arial, sans-serif; font-size: 12px;}}}}</style></head>\n<body>\n<a href="REPORT.html">[Back]</a>\n<p align="center"><i># This report was generated using Andriller on {_time} #</i></p>\n<h3 align="center">[{{_title}}] {_imei}</h3>\n'.format(_imei=IMEI, _time=LOCAL_TIME)	# REP_HEADER.format(_title=rep_title)
REP_FOOTER = '</table>\n<p align="center"><i># <a href="http://android.saz.lt" target="_blank">http://android.saz.lt</a> #</i></p>\n</body></html>'

# Decode gesture.key  # # # # # # # # # # # # # # # # # # # # #
def decode_gesturekey(file_to_decode):
	with open(OUTPUT+'db'+SEP+file_to_decode, 'rb') as fileh:
		ges_data = fileh.read()
	if len(ges_data) == 20:
		GKEY = hexlify(ges_data).decode('UTF-8')
		REPORT.append(['Security (Lockscreen Pattern)', '<a href="http://android.saz.lt/cgi-bin/online_pattern.py?encoded={0}" target="_blank">{0}</a>'.format(GKEY)])
# # # # #

# Brute force 8-digit password  # # # # # # # # # # # # # # # #
def decode_pwkey(pwkey, pwsalt):
	if pwsalt >= 0:
		salt = '{:x}'.format(pwsalt)
	else:
		salt = hexlify(pack(">q", pwsalt)).decode()
	print(' Cracking PIN, please wait...', end='\r')
	if len(pwkey) == 40:
		pwkey = unhexlify(pwkey)
		for pin in map('{0:04}'.format,range(10**4)):
			h0 = hashlib.sha1(('0'+pin+salt).encode()).digest()
			for it in map(str,range(1,1024)):
				h0 = hashlib.sha1(h0+(it+pin+salt).encode()).digest()
			if h0 == pwkey:
				print(' PIN cracked: {0}'.format(pin)+' '*12)
				return pin
				break
		else:
			ERRORS.append('PIN cracking was attempted, not successful.')
	elif len(pwkey) == 72:
		for pin in range(10**8):
			pin = str(pin).zfill(4)
			h = sha1((str(pin)+str(salt)).encode()).hexdigest()
			if h.upper() == pwkey[:40]:
				print(' PIN cracked: {0}'.format(pin)+' '*12)
				return pin
				break
		else:
			ERRORS.append('PIN cracking was attempted, not successful.')
	else:
		ERRORS.append('The \'password.key\' file is odd length, PIN cracking failed.')
# # # # #

# Decode accounts.db  # # # # # # # # # # # # # # # # # # # # #
def decode_accountsdb(file_to_decode):
	rep_title = 'Synchronised Accounts'
	with sq.connect(OUTPUT+'db'+SEP+file_to_decode) as c:
		acc_data = c.execute("SELECT name,type,password FROM accounts").fetchall()
	if acc_data != None:
		with open(OUTPUT+'accounts.html', 'w', encoding='UTF-8') as fileh:
			fileh.write(REP_HEADER.format(_title=rep_title))
			if 'photo.png' in DLLS:
				fileh.write('<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th nowrap>Main Account Photograph</th></tr>\n<tr><td><a href="db/photo.png" target="_blank"><img src="db/photo.png" height="50%" width="50%"></a></td></tr></table><p/>\n')
			fileh.write('<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th nowrap>Account type</th><th nowrap>Username</th><th nowrap>Password</th></tr>\n')
			for acc_item in acc_data:
				acc_type = acc_item[1]
				acc_user = acc_item[0]
				if acc_item[2] != None:
					acc_pass = acc_item[2]
				else:
					acc_pass = ''
				fileh.write('<tr><td>{_type}</td><td>{_user}</td><td>{_pass}</td></tr>\n'.format(_type=acc_type, _user=acc_user, _pass=acc_pass))
			fileh.write(REP_FOOTER)
		REPORT.append(['System', '<a href="accounts.html">{0} ({1:,})</a>'.format(rep_title, len(acc_data))])
# # # # #

# Decode 'Login Data'  # # # # # # # # # # # # # # # # # # # # #
def decode_logindata(file_to_decode):
	rep_title = 'Google Chrome: Passwords'
	with sq.connect(OUTPUT+'db'+SEP+file_to_decode) as c:
		cpw_data = c.execute("SELECT origin_url,username_value,password_value,date_created FROM logins ORDER BY date_created DESC").fetchall()
	if cpw_data != None:
		with open(OUTPUT+'chrome_passwords.html', 'w', encoding='UTF-8') as fileh:
			fileh.write(REP_HEADER.format(_title=rep_title)+'<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th nowrap>URL</th><th nowrap>Username</th><th nowrap bgcolor="#FF6666">Password</th><th nowrap>Date added</th></tr>\n')
			for cpw_item in cpw_data:
				cpw_url = cpw_item[0]
				cpw_user = cpw_item[1]
				cpw_pass = cpw_item[2].decode('UTF-8')
				cpw_date = unix_to_utc(cpw_item[3])
				fileh.write('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>\n'.format(cpw_url,cpw_user,cpw_pass,cpw_date))
			fileh.write(REP_FOOTER)
		REPORT.append(['Web browser', '<a href="chrome_passwords.html">{0} ({1:,})</a>'.format(rep_title, len(cpw_data))])

# Decode settings.db  # # # # # # # # # # # # # # # # # # # # #
def decode_settingsdb(file_to_decode):
	with sq.connect(OUTPUT+'db'+SEP+file_to_decode) as c:
		try:
			BT_MAC = c.execute("SELECT value FROM secure WHERE name = 'bluetooth_address'").fetchone()[0].lower()
			BT_NAME = c.execute("SELECT value FROM secure WHERE name = 'bluetooth_name'").fetchone()[0]
			for findlt in REPORT:
				if 'Local time' in findlt:
					LotLoc = REPORT.index(findlt)
					REPORT.insert(LotLoc, ["Bluetooth MAC", BT_MAC])
					REPORT.insert(LotLoc+1, ["Bluetooth name", BT_NAME])
					break
			else:
				REPORT.append(["Bluetooth MAC", BT_MAC])
				REPORT.append(["Bluetooth name", BT_NAME])
		except:
			pass; ERRORS.append('Bluetooth is not enabled, or is not supported by the device.')
		try:
			AN_ID = c.execute("SELECT value FROM secure WHERE name = 'android_id'").fetchone()[0].lower()
			REPORT.insert(1, ["Android ID", AN_ID])
		except:
			pass
		try:
			PW_SALT = c.execute("SELECT value FROM secure WHERE name = 'lockscreen.password_salt'").fetchone()[0]
			if 'password.key' in DLLS:
				with open(OUTPUT+'db'+SEP+'password.key', 'r') as fileh:
					PW_KEY = fileh.read()
				if len(PW_KEY) == 72:
					PW_PIN = decode_pwkey(PW_KEY, int(PW_SALT))
					if PW_PIN != None or PW_PIN != '':
						REPORT.append(["Security (Lockscreen PIN)", PW_PIN])
				else:
					ERRORS.append('The password.key file is odd length of {0} bytes.'.format(len(PW_KEY)))
		except:
			pass

# # # # # 

# Decode contacts2.db (Pbook) # # # # # # # # # # # # # # # # #
def decode_contacts2db(file_to_decode):
	rep_title = 'Contacts'
	con = sq.connect(OUTPUT+'db'+SEP+file_to_decode)
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='data'")
	if c.fetchone() != None:
		c.execute("SELECT raw_contact_id, mimetypes.mimetype, data1 FROM data JOIN mimetypes ON (data.mimetype_id=mimetypes._id) ORDER BY raw_contact_id")
		#c.execute("SELECT raw_contact_id, mimetypes.mimetype, data1 FROM data JOIN mimetypes ON (data.mimetype_id=mimetypes._id) JOIN visible_contacts ON (data.raw_contact_id=visible_contacts._id) ORDER BY raw_contact_id")	# alternative
		c2_data = c.fetchall()
		con.close()
		if c2_data != '':
			fileh = open(OUTPUT+'contacts.html', 'w', encoding='UTF-8')
			fileh.write(REP_HEADER.format(_title=rep_title)+'<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th nowrap>#</th><th nowrap>Name</th><th nowrap>Number</th><th nowrap>Email</th><th>Other</th></tr>\n')
			pbook = []; tD = {}
			for c2_item in c2_data:
				c2key = str(c2_item[0])
				c2typ = c2_item[1].split('/')[1]
				c2dat = c2_item[2]
				if c2dat != None and c2dat != '':
					if tD.get('index_key') == c2key:
						if c2typ in tD:
							tD[c2typ] = tD[c2typ]+'<br/>'+c2dat
						else:
							tD[c2typ] = c2dat
					else:
						if len(tD) > 0:
							pbook.append(tD); tD = {}
							tD['index_key'] = c2key
							tD[c2typ] = c2dat
						else:
							tD['index_key'] = c2key
							tD[c2typ] = c2dat
			pbook.append(tD); del tD
			for pb in pbook:
				pb_index = pb.pop('index_key')
				try:
					pb_name = pb.pop('name')
				except KeyError:
					pb_name = ''
				try:
					pb_number = re.sub(r'(?<=\d)\s(?=\d)', '', pb.pop('phone_v2'))
				except KeyError:
					pb_number = ''
				try:
					pb_email = pb.pop('email_v2')
				except KeyError:
					pb_email = ''
				try:
					pb_other = ''.join([(x+': '+pb[x]+'<br/>\n') for x in pb])
				except:
					pb_other = ''
				fileh.write('<tr><td nowrap>{0}</td><td nowrap>{1}</td><td nowrap>{2}</td><td nowrap>{3}</td><td>{4}</td></tr>\n'.format(pb_index, pb_name, pb_number, pb_email, pb_other))
			fileh.write(REP_FOOTER)
			fileh.close()
			REPORT.append(['Communications data', '<a href="contacts.html">{0} ({1:,})</a>'.format(rep_title, len(pbook))])
# # # # #

# Decode contacts2.db (Calls) # # # # # # # # # # # # # # # # #
def decode_calls_contacts2db(file_to_decode):
	rep_title = 'Call logs'
	con = sq.connect(OUTPUT+'db'+SEP+file_to_decode)
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='calls'")
	if c.fetchone() != None:
		c.execute("SELECT _id,type,number,name,date,duration FROM calls ORDER by date DESC")
		c2_data = c.fetchall()
		con.close()
		if c2_data != []:
			fileh = open(OUTPUT+'call_logs.html', 'w', encoding='UTF-8')
			fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>#</th><th>Type</th><th>Number</th><th>Name</th><th>Time</th><th>Duration</th></tr>\n')
			for c2_item in c2_data:
				c2_id = str(c2_item[0])
				c2_type_raw = c2_item[1]
				if c2_type_raw == 1:
					c2_type = 'Received'
				elif c2_type_raw == 2:
					c2_type = 'Dialled'
				elif c2_type_raw == 3:
					c2_type = 'Missed'
				elif c2_type_raw == 5:
					c2_type = 'Rejected'
				else:
					c2_type = 'Type({0})'.format(c2_type_raw)
				c2_number = re.sub(r'(?<=\d)\s(?=\d)', '', str(c2_item[2]))
				try:
					if int(sec_number) <= 0:
						c2_number = 'UNKNOWN'
				except:
					pass
				c2_name = c2_item[3]
				if c2_name == None:
					c2_name = ''
				c2_date = unix_to_utc(c2_item[4])
				c2_dur = str(timedelta(seconds=c2_item[5]))
				fileh.write('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>\n'.format(c2_id, c2_type, c2_number, c2_name, c2_date, c2_dur))
			fileh.write(REP_FOOTER)
			fileh.close()
			REPORT.append(['Communications data', '<a href="call_logs.html">{0} ({1:,})</a>'.format(rep_title, len(c2_data))])
# # # # #

# Decode logs.db (Samsung Calls(SEC)) # # # # # # # # # # # # # # # # #
def decode_logsdb(file_to_decode):
	rep_title = 'Samsung Call logs'
	con = sq.connect(OUTPUT+'db'+SEP+file_to_decode)
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
	if c.fetchone() != None:
		c.execute("SELECT _id,type,number,name,date,duration FROM logs WHERE logtype='100' ORDER by date DESC")
		sec_data = c.fetchall()
		con.close()
		fileh = open(OUTPUT+'sec_call_logs.html', 'w', encoding='UTF-8')
		fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>#</th><th>Type</th><th>Number</th><th>Name</th><th>Time</th><th>Duration</th></tr>')
		for sec_item in sec_data:
			sec_id = str(sec_item[0])
			sec_type_raw = sec_item[1]
			if sec_type_raw == 1:
				sec_type = 'Received'
			elif sec_type_raw == 2:
				sec_type = 'Dialled'
			elif sec_type_raw == 3:
				sec_type = 'Missed'
			elif sec_type_raw == 5:
				sec_type = 'Rejected'
			else:
				sec_type = 'Type({0})'.format(sec_type_raw)
			sec_number = re.sub(r'(?<=\d)\s(?=\d)', '', str(sec_item[2]))
			try:
				if int(sec_number) <= 0:
					sec_number = 'UNKNOWN'
			except:
				pass
			sec_name = sec_item[3]
			if sec_name == None:
				sec_name = ''
			sec_date = unix_to_utc(sec_item[4])
			sec_dur = str(timedelta(seconds=sec_item[5]))
			fileh.write('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>\n'.format(sec_id, sec_type, sec_number, sec_name, sec_date, sec_dur))
		fileh.write(REP_FOOTER)
		fileh.close()
		REPORT.append(['Communications data', '<a href="sec_call_logs.html">{0} ({1:,})</a>'.format(rep_title, len(sec_data))])
# # # # #

# Decode mmssms.db  # # # # # # # # # # # # # # # # # # # # # #
def decode_mmssmsdb(file_to_decode):
	rep_title = 'SMS Messages'
	con = sq.connect(OUTPUT+'db'+SEP+file_to_decode)
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sms'")
	if c.fetchone() != None:
		c.execute("SELECT address,body,date,type,_id FROM sms ORDER by sms.date DESC")
		sms_data = c.fetchall()
		con.close()
		fileh = open(OUTPUT+'mmssms.html', 'w', encoding='UTF-8')
		fileh.write(REP_HEADER.format(_title=rep_title) + '<table border=1 cellpadding=2 cellspacing=0 align=center>\n<tr bgcolor=#72A0C1><th>#</th><th>Number</th><th width="500">Message</th><th>Type</th><th nowrap>Time</th></tr>\n')
		for sms_item in sms_data:
			sms_number = re.sub(r'(?<=\d)\s(?=\d)', '', str(sms_item[0]))
			sms_text = str(sms_item[1])
			sms_time = unix_to_utc(sms_item[2])
			if sms_item[3] == 1:
				sms_typ = "Inbox"
			elif sms_item[3] == 2:
				sms_typ = "Sent"
			elif sms_item[3] == 3:
				sms_typ = "Draft"
			elif sms_item[3] == 5:
				sms_typ = "Sending failed"
			elif sms_item[3] == 6:
				sms_typ = "Sent"
			else:
				sms_typ = "Type"+"("+str(sms_item[3])+")"
			sms_index = sms_item[4]
			fileh.write('<tr><td>{0}</td><td>{1}</td><td width="500">{2}</td><td>{3}</td><td nowrap>{4}</td></tr>\n'.format(sms_index,sms_number,sms_text,sms_typ,sms_time))
		fileh.write(REP_FOOTER)
		fileh.close()
		REPORT.append(['Communications data', '<a href="mmssms.html">{0} ({1:,})</a>'.format(rep_title, len(sms_data))])
# # # # # 

# Decode threads_db2 # # # # # # # # # # # # # # # # # # #
def decode_threads_db2(file_to_decode):
	rep_title = 'Facebook: Messages'
	with sq.connect(OUTPUT+'db'+SEP+file_to_decode) as c:
		fbt_data = c.execute("SELECT sender,threads.participants,text,messages.timestamp_ms FROM messages JOIN threads ON (messages.thread_id=threads.thread_id) WHERE NOT messages.timestamp_ms='0' ORDER BY messages.timestamp_ms DESC").fetchall()
		try:
			fbt_users = c.execute("SELECT user_key,name,profile_pic_square FROM thread_users").fetchall()
		except sq.OperationalError:
			fbt_users = c.execute("SELECT user_key,name,pic_square FROM thread_users").fetchall()
		except:
			pass; fbt_users = []
	if fbt_data != '':
		fileh = open(OUTPUT+'fb_messages.html', 'w', encoding='UTF-8')
		fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th nowrap>Sender</th><th nowrap>Image</th><th width="500">Message</th><th nowrap>Recipient(s)</th><th>Time</th></tr>')
		for fbt_item in fbt_data:
			if fbt_item[0] != None:
				fbt_sender_nm = loads(fbt_item[0]).get('name')
				fbt_sender_id = loads(fbt_item[0]).get('user_key')
			else:
				fbt_sender_nm = ''
				fbt_sender_id = ''
			for fbimgs in fbt_users:
				if fbimgs[0] == fbt_sender_id:
					try:
						fbt_img = loads(fbimgs[2])[0].get('url')
					except:
						fbt_img = fbimgs[2]
			fbt_text = fbt_item[2]
			fbt_time = unix_to_utc(fbt_item[3])
			fbt_part = []
			for fbtdic in loads(fbt_item[1]):
				fbt_part.append(fbtdic.get('name')+' (ID:'+fbtdic.get('user_key').split(':')[1]+')')
			try:
				fbt_part.remove(fbt_sender_nm+' (ID:'+fbt_sender_id.split(':')[1]+')')
			except:
				pass
			fbt_parti = '<br/>'.join(fbt_part)
			fileh.write('<tr><td nowrap><a href="http://www.facebook.com/profile.php?id={0}">{1}</a></td><td><img src="{2}"></td><td width="500">{3}</td><td nowrap>{4}</td><td nowrap>{5}</td></tr>\n'.format(fbt_sender_id.split(':')[1], fbt_sender_nm, fbt_img, fbt_text, fbt_parti,fbt_time))
		fileh.write(REP_FOOTER)
		fileh.close()
		REPORT.append(['Applications data', '<a href="fb_messages.html">{0} ({1:,})</a>'.format(rep_title, len(fbt_data))])
# # # # #

# Decode photos_db # # # # # # # # # # # # # # # # # # # # # # #
def decode_photos_db(file_to_decode):
	rep_title = 'Facebook: Viewed Photos'
	con = sq.connect(OUTPUT+'db'+SEP+file_to_decode)
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='photos'")
	if c.fetchone() != None:
		c.execute("SELECT _id,owner,src_small,src_big,caption,created FROM photos ORDER BY _id DESC")
		fbp_data = c.fetchall()
		if len(fbp_data) > 0:
			fileh = open(OUTPUT+'fb_photos2.html', 'w', encoding='UTF-8')
			fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>#</th><th>Picture</th><th>Owner</th><th width="500">Caption</th><th nowrap>Date (uploaded)</th></tr>')
			for fbp_item in fbp_data:
				fbp_id = fbp_item[0]
				fbp_owner = str(fbp_item[1])
				fbp_thm = fbp_item[2]
				fbp_img = fbp_item[3]
				if fbp_item[4] == None:
					fbp_cap = ''
				else:
					fbp_cap = str(fbp_item[4])
				fbp_date = unix_to_utc(fbp_item[5])
				fileh.write('<tr><td>{0}</td><td><a href="{1}" target="_blank"><img src="{2}"></a></td><td><a href="http://www.facebook.com/profile.php?id={3}" target="_blank">{4}</a></td><td width="500">{5}</td><td nowrap>{6}</td></tr>\n'.format(fbp_id, fbp_img, fbp_thm, fbp_owner, fbp_owner, fbp_cap, fbp_date))
			fileh.write(REP_FOOTER)
			fileh.close()
			REPORT.append(['Applications data', '<a href="fb_photos2.html">{0} ({1:,})</a>'.format(rep_title, len(fbp_data))])

# # # # #

# Decode notifications.db # # # # # # # # # # # # # # # # # #
def decode_notificationsdb(file_to_decode):
	rep_title = 'Facebook: Notifications'
	con = sq.connect(OUTPUT+'db'+SEP+file_to_decode)
	c = con.cursor()
	noti_data = c.execute("SELECT gql_payload FROM gql_notifications ORDER BY updated DESC").fetchall()
	con.close()
	fileh = open(OUTPUT+'fb_notifications.html', 'w', encoding='UTF-8')
	fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th nowrap>Notifying Users</th><th width="200">Notification Title</th><th width="300">Post Text</th><th width="100">Attachments</th><th nowrap>Time/Location</th></tr>\n')
	for noti_item in noti_data:
		noti_d = loads(noti_item[0].decode('UTF-8'))
		ntf_name = noti_d.get('actors')[0].get('name')
		ntf_names = [str('<a href="http://www.facebook.com/profile.php?id=')+x.get('id')+str('" target="_blank">')+x.get('name')+str('</a>') for x in noti_d.get('actors')]
		if len(ntf_names) > 1:
			ntf_names = str('<br/>')+str(ntf_names[0])+str('<hr>')+'<br/>'.join(ntf_names[1:])
		else:
			ntf_names = str('<br/>')+str(ntf_names[0])
		ntf_title = noti_d.get('title').get('text')
		ntf_prof = noti_d.get('title').get('ranges')[0].get('entity').get('url')
		ntf_name_img = noti_d.get('actors')[0].get('profile_picture').get('uri')
		ntf_sum = noti_d.get('summary').get('text')
		ntf_url = noti_d.get('url')
		ntf_time = unix_to_utc(noti_d.get('creation_time'))
		try:	# Message, if any.!
			ntf_msg = noti_d.get('message').get('text')
		except:
			ntf_msg = ''
		try:	# Location, if any!
			ntf_loc_name = noti_d.get('implicit_place').get('name')
			ntf_loc_lat = str(noti_d.get('implicit_place').get('location').get('latitude'))
			ntf_loc_lon = str(noti_d.get('implicit_place').get('location').get('longitude'))
		except:
			ntf_loc_name = ntf_loc_lat = ntf_loc_lon = ''
		try:	# Attachments, if any!
			ntf_att_title = noti_d.get('attachments')[0].get('title')
			ntf_att_img = noti_d.get('attachments')[0].get('media').get('image').get('uri')
			ntf_att_thm = noti_d.get('attachments')[0].get('media').get('image_preview').get('uri')
			ntf_att_desc = noti_d.get('attachments')[0].get('description').get('text').replace('\n', '<br/>')
		except:
			ntf_att_title = ntf_att_img = ntf_att_thm =ntf_att_desc = ''
		try:	# Attached Story, if any!
			ntf_atts_msg = noti_d.get('attached_story').get('message').get('text').replace('\r', '<br/>').replace('\n', '<br/>')
			ntf_atts_img = noti_d.get('attached_story').get('attachments')[0].get('media').get('image').get('uri')
			ntf_atts_thm = noti_d.get('attached_story').get('attachments')[0].get('media').get('image_preview').get('uri')
		except:
			ntf_atts_msg = ntf_atts_thm = ntf_atts_img = ''
		fileh.write('<tr>\
	<td nowrap><a href="{0}" target="_blank"><img src="{1}" title="{2}"></a>{16}</td>\
	<td width="200"><a href="{3}" target="_blank">{4}</a></td>\
	<td width="300">{17}</td>\
	<td width="100"><a href="{6}"><img src="{7}"></a><br/>\
	{5}<a href="{10}"><img src="{11}"></a><br/>{9}</td>\
	<td nowrap>{12}<br/><a href="http://maps.google.com/maps?q={14},{15}" target="_blank">{13}</a></td>\
	</tr>\n'.format(
	ntf_prof, 			#0
	ntf_name_img, 		#1
	ntf_name, 			#2
	ntf_url, 			#3
	ntf_sum, 			#4
	ntf_att_title,		#5
	ntf_att_img,		#6
	ntf_att_thm,		#7
	ntf_att_desc,		#8
	ntf_atts_msg, 		#9
	ntf_atts_img, 		#10
	ntf_atts_thm, 		#11
	ntf_time,			#12
	ntf_loc_name,		#13
	ntf_loc_lat,		#14
	ntf_loc_lon,		#15
	ntf_names,			#16
	ntf_msg,			#17
	))
	fileh.write(REP_FOOTER)
	fileh.close()
	REPORT.append(['Applications data', '<a href="fb_notifications.html">{0} ({1:,})</a>'.format(rep_title, len(noti_data))])
# # # # #

# Decode fb.db  # # # # # # # # # # # # # # # # # # # # # # # #
def decode_fbdb(file_to_decode):
	rep_title = 'Facebook: Viewed Photos'
	con = sq.connect(OUTPUT+'db'+SEP+file_to_decode)
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='photos'")
	if c.fetchone() != None:
		c.execute("SELECT _id,owner,src_small,src_big,caption,created,thumbnail FROM photos ORDER BY _id DESC")
		fbp_data = c.fetchall()
		if len(fbp_data) > 0:
			os.mkdir(OUTPUT+'fb_media'); os.mkdir(OUTPUT+'fb_media'+SEP+'Thumbs')
			fileh = open(OUTPUT+'fb_photos.html', 'w', encoding='UTF-8')
			fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>#</th><th>Picture</th><th>Owner</th><th width="500">Caption</th><th nowrap>Date (uploaded)</th></tr>\n')
			for fbp_item in fbp_data:
				fbp_id = fbp_item[0]
				fbp_owner = str(fbp_item[1])
				fbp_thm = fbp_item[2]
				fbp_img = fbp_item[3]
				if fbp_item[4] == None:
					fbp_cap = ''
				else:
					fbp_cap = str(fbp_item[4])
				fbp_date = unix_to_utc(fbp_item[5])
				if fbp_item[6] != None:
					filewa = open(OUTPUT+'fb_media'+SEP+'Thumbs'+SEP+str(fbp_id)+'.jpg', 'wb')
					filewa.write(fbp_item[6]); filewa.close()					
					fbp_thumb = 'fb_media'+SEP+'Thumbs'+SEP+str(fbp_id)+'.jpg'
				else:
					fbp_thumb = fbp_item[2]
				fileh.write('<tr><td>{0}</td><td><a href="{1}" target="_blank"><img src="{2}"></a></td><td><a href="http://www.facebook.com/profile.php?id={3}" target="_blank">{4}</a></td><td width="500">{5}</td><td nowrap>{6}</td></tr>\n'.format(fbp_id, fbp_img, fbp_thm, fbp_owner, fbp_owner, fbp_cap, fbp_date))
			fileh.write(REP_FOOTER)
			fileh.close()
			REPORT.append(['Applications data', '<a href="fb_photos.html">{0} ({1:,})</a>'.format(rep_title, len(fbp_data))])

# # # # # 

# Decode wa.db  # # # # # # # # # # # # # # # # # # # # # # # #
def decode_wadb(file_to_decode):
	rep_title = 'WhatsApp Contacts'
	con = sq.connect(OUTPUT+'db'+SEP+file_to_decode)
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='wa_contacts'")
	if c.fetchone() != None:
		c.execute("select display_name,number,status from wa_contacts where is_whatsapp_user='1'")
		wa_data = c.fetchall()
		con.close()
		fileh = open(OUTPUT+'wa_contacts.html', 'w', encoding='UTF-8')
		fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>Name</th><th>Number</th><th>Status</th></tr>\n')
		for wa_item in wa_data:
			wa_name = wa_item[0]
			wa_number = re.sub(r'(?<=\d)\s(?=\d)', '', str(wa_item[1]))
			wa_status = wa_item[2]
			if wa_status == None:
				wa_status = ''
			fileh.write('<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>\n'.format(wa_name,wa_number,wa_status))
		fileh.write(REP_FOOTER)
		fileh.close()
		REPORT.append(['Applications data', '<a href="wa_contacts.html">{0} ({1:,})</a>'.format(rep_title, len(wa_data))])
# # # # # 

# Decode msgstore.db  # # # # # # # # # # # # # # # # # # # # #
def decode_msgstoredb(file_to_decode):
	rep_title = 'WhatsApp Messages'
	con = sq.connect(OUTPUT+'db'+SEP+file_to_decode)
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
	if c.fetchone() != None:
		os.mkdir(OUTPUT+'wa_media'); os.mkdir(OUTPUT+'wa_media'+SEP+'Thumbs')
		c.execute("SELECT _id, key_remote_jid, data, timestamp, key_from_me, media_size, media_mime_type, media_name, raw_data, latitude, longitude FROM messages WHERE NOT status='-1' ORDER BY timestamp DESC")
		wam_data = c.fetchall()
		con.close()
		fileh = open(OUTPUT+'wa_messages.html', 'w', encoding='UTF-8')
		fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>#</th><th>Number</th><th width="500">Message</th><th nowrap>Time</th><th>Type</th></tr>\n')
		for wam_item in wam_data:
			wam_id = wam_item[0]
			wam_number = wam_item[1].split('@')[0]
			if wam_number[0] != 0:	wam_number = '+' + wam_number.split('-')[0]
			wam_text = wam_item[2]		# data
			wam_date = unix_to_utc(wam_item[3])
			if wam_item[4] == 1:		# key_from_me
				wam_dir = 'Sent'
			else:
				wam_dir = 'Inbox'
			if wam_item[8] != None:			# raw_data
				if wam_item[7] != None:		# media_name
					wam_fname = wam_item[7].replace('\n', '')
				elif wam_item[6] != None:
					wam_fname = str(wam_item[0])+'.'+wam_item[6].split('/')[1]	# media_mime_type
				else:
					wam_fname = str(wam_item[0])+'.jpg'
				with open(OUTPUT+'wa_media'+SEP+'Thumbs'+SEP+wam_fname, 'wb') as filewa:
					filewa.write(wam_item[8])	# raw_data, writes file
				wam_text = '<img src="'+'wa_media'+SEP+'Thumbs'+SEP+wam_fname+'">'
				if wam_item[6] != None:
					wam_text = 'Type: '+str(wam_item[6])+'<br/>'+wam_text
				if wam_item[7] != None:
					wam_text = 'Filename: '+str(wam_item[7])+'<br/>'+wam_text
				if wam_item[9] != 0 and wam_item[10] != 0:		# latitude, longtitude
					wam_text = '<a href="http://maps.google.com/maps?q='+str(wam_item[9])+','+str(wam_item[10])+'" target="_blank">Map Location: '+str(wam_item[9])+','+str(wam_item[10])+'<br/>'+wam_text+'</a>'
			fileh.write('<tr><td>{0}</td><td>{1}</td><td width="500">{2}</td><td nowrap>{3}</td><td>{4}</td></tr>\n'.format(wam_id, wam_number, wam_text, wam_date, wam_dir))
		fileh.write(REP_FOOTER)
		fileh.close()
		REPORT.append(['Applications data', '<a href="wa_messages.html">{0} ({1:,})</a>'.format(rep_title, len(wam_data))])
# # # # # 

# Decode Kik Messenger kikDatabase.db # # # # # # # # # # # # #
def decode_kikDatabasedb(file_to_decode):
	rep_title = 'Kik Messages'
	con = sq.connect(OUTPUT+'db'+SEP+file_to_decode)
	c = con.cursor()
	kik_data = c.execute("SELECT messagesTable._id,body,user_name,was_me,timestamp,length,content_id FROM messagesTable JOIN KIKcontactsTable ON (messagesTable.partner_jid=KIKcontactsTable.jid) ORDER BY timestamp DESC").fetchall()
	con.close()
	fileh = open(OUTPUT+'kik_messages.html', 'w', encoding='UTF-8')
	fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>#</th><th>Username</th><th width="300">Message</th><th>Type</th><th nowrap>Time</th></tr>\n')
	for kik_item in kik_data:
		kik_id = kik_item[0]
		kik_num = kik_item[2]
		if kik_item[5] != 0:
			kik_msg = str(kik_item[1])
		else:
			kik_msg = 'Media Content ID: '+kik_item[6]
		if kik_item[3] == 1:
			kik_typ = 'Sent'
		elif kik_item[3] == 0:
			kik_typ = 'Inbox'
		else:
			kik_typ = 'Unknown'
		kik_time = unix_to_utc(kik_item[4])
		fileh.write('<tr><td>{0}</td><td>{1}</td><td width="300">{2}</td><td>{3}</td><td nowrap>{4}</td></tr>\n'.format(kik_id, kik_num, kik_msg, kik_typ, kik_time))
	fileh.write(REP_FOOTER)
	fileh.close()
	REPORT.append(['Applications data', '<a href="kik_messages.html">{0} ({1:,})</a>'.format(rep_title, len(kik_data))])
# # # # # 

# Decode BBM master.db  # # # # # # # # # # # # # # # # # # # #
def decode_masterdb(file_to_decode):
	rep_title = 'Blackberry Messenger'
	con = sq.connect(OUTPUT+'db'+SEP+file_to_decode)
	c = con.cursor()
	bbm_data = c.execute("SELECT TextMessageId, UserPins.Pin, IsInbound, TextMessages.Timestamp, Content, PictureTransferId, Users.DisplayName, Type, TextMessages.ConversationId FROM TextMessages JOIN Participants ON (TextMessages.ParticipantId=Participants.ParticipantId) JOIN UserPins ON (Participants.UserId=UserPins.UserId) JOIN Users ON (Participants.UserId=Users.UserId) ORDER BY TextMessages.Timestamp DESC").fetchall()
	bbm_convs = c.execute("SELECT UserPins.Pin,ConversationId FROM Participants JOIN UserPins ON (Participants.UserId=UserPins.UserId)").fetchall()
	fileh = open(OUTPUT+'bbm_messenger.html', 'w', encoding='UTF-8')
	fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1">\n\
    <th>#</th>\
	<th>Sender Name</th>\
    <th nowrap>Sender PIN</th>\
	<th>Recipient PIN</th>\
	<th width="300">Message</th>\
	<th nowrap>Type</th>\
	<th nowrap>Time</th>\
	</tr>\n')
	for bbm_item in bbm_data:
		bbm_msgid = str(bbm_item[0])
		bbm_msgpin = str(bbm_item[1])
		if bbm_item[2] == 1:
			bbm_msgtype = 'Inbox'
		else:
			bbm_msgtype = 'Sent'
		bbm_msgtime = unix_to_utc(bbm_item[3])
		bbm_msgtxt = str(bbm_item[4])
		if bbm_item[5] != None:
			bbm_msgimg = str('<i>Image #')+str(bbm_item[5])+str('</i>')
		else:
			bbm_msgimg = ''
		bbm_namepin = bbm_item[6]
		if bbm_item[7] == 1:
			bbm_mtype = 'PING!'
		else:
			bbm_mtype = ''
		bbm_parts = []
		for bbm_conv in bbm_convs:
			if bbm_conv[1] == bbm_item[8]:
				bbm_parts.append(bbm_conv[0])
		bbm_parts.remove(bbm_msgpin)
		bbm_parts = '<br/>'.join(bbm_parts)
		fileh.write('<tr>\
	<td>{0}</td>\
	<td nowrap>{5}</td>\
	<td>{1}</td>\
	<td>{8}</td>\
	<td width="300">{2}{6}{7}</td>\
	<td nowrap>{3}</td>\
	<td nowrap>{4}</td>\
	</tr>\n'.format(
	bbm_msgid,		#0
	bbm_msgpin,		#1
	bbm_msgtxt,		#2
	bbm_msgtype,	#3
	bbm_msgtime,	#4
	bbm_namepin,	#5
	bbm_msgimg,		#6
	bbm_mtype,		#7
	bbm_parts,		#8
	))
	fileh.write(REP_FOOTER)
	fileh.close()
	REPORT.append(['Applications data', '<a href="bbm_messenger.html">{0} ({1:,})</a>'.format(rep_title, len(bbm_data))])
# # # # #

# Decode 'wpa_supplicant.conf'or 'flattened-data' # # # # # # #
def decode_wifipw(file_to_decode):
	rep_title = 'Wi-Fi Passwords'
	wpa_raw = open(OUTPUT+'db'+SEP+file_to_decode, 'rb').read()
	with open(OUTPUT+'wifi_passwords.html', 'w', encoding='UTF-8') as fileh:
		fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th nowrap>SSID</th><th nowrap bgcolor="#FF6666">Password</th><th nowrap>Management</th></tr>\n')
		wpa_data = re.findall(b'\{\n\t(.*?)\n\}', wpa_raw, re.DOTALL)
		wpa_data = [_.decode() for _ in wpa_data]
		for wpa_rawitem in wpa_data:
			wpa_item = wpa_rawitem.split('\n\t')
			wpa_d = dict(zip([_.split('=')[0] for _ in wpa_item],[_.split('=')[1] for _ in wpa_item]))
			wpa = (wpa_d.get('ssid', '').strip('"'), wpa_d.get('psk', '').strip('"'), wpa_d.get('wep_key0', '').strip('"'), wpa_d.get('key_mgmt', ''))
			fileh.write('<tr><td>{0}</td><td>{1}{2}</td><td>{3}</td></tr>\n'.format(*wpa))
		fileh.write(REP_FOOTER)
	REPORT.append(['System', '<a href="wifi_passwords.html">{0} ({1:,})</a>'.format(rep_title, len(wpa_data))])
# # # # #

# Decode 'webview.db' # # # # # # # # # # # # # # # # # # # # #
def decode_webview(file_to_decode):
	rep_title = 'Android Web Browser: Passwords'
	with sq.connect(OUTPUT+'db'+SEP+file_to_decode) as c:
		wv_data = c.execute("SELECT _id,host,username,password FROM password").fetchall()
	with open(OUTPUT+'browser_passwords.html', 'w', encoding='UTF-8') as fileh:
		fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th nowrap>#</th><th nowrap>Host</th><th nowrap>Username</th><th nowrap bgcolor="#FF6666">Password</th></tr>\n')
		for wv_item in wv_data:
			fileh.write('<tr><td>{0}</td><td><a href="{1}" target="_blank">{1}</a></td><td>{2}</td><td>{3}</td></tr>\n'.format(*wv_item))
		fileh.write(REP_FOOTER)
	REPORT.append(['Web browser', '<a href="browser_passwords.html">{0} ({1:,})</a>'.format(rep_title, len(wv_data))])
# # # # #

# Decode 'browser2.db' history  # # # # # # # # # # # # # # # #
def decode_browser2(file_to_decode):
	rep_title = 'Android Web Browser: History'
	with sq.connect(OUTPUT+'db'+SEP+file_to_decode) as c:
		wbh_data = c.execute("SELECT title,url,date,visits FROM history ORDER BY date DESC").fetchall()
	with open(OUTPUT+'browser_history.html', 'w', encoding='UTF-8') as fileh:
		fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>Page title</th><th>URL</th><th>Time</th><th>Frequency</th></tr>\n')
		for wbh_item in wbh_data:
			wbh_s_title = wbh_item[0]
			if len(wbh_item[0]) > 60:	wbh_s_title = wbh_s_title[:55]+'.....' 
			wbh_s_url = wbh_item[1]
			if len(wbh_item[1]) > 60:	wbh_s_url = wbh_s_url[:45]+'.....'+wbh_s_url[-10:]
			wbh = (
	wbh_item[0],	#0 full title
	wbh_s_title,	#1 short title
	wbh_item[1],	#2 full url
	wbh_s_url,		#3 short url
	unix_to_utc(wbh_item[2]),	#4 time
	wbh_item[3],	#5 freq
	)
			fileh.write('<tr>\
	<td><a title="{0}">{1}</a></td>\
	<td><a href="{2}" title="{2}">{3}</a></td>\
	<td nowrap>{4}</td>\
	<td>{5}</td>\
	</tr>\n'.format(*wbh))
		fileh.write(REP_FOOTER)
	REPORT.append(['Web browser', '<a href="browser_history.html">{0} ({1:,})</a>'.format(rep_title, len(wbh_data))])
# # # # #

# Decode 'History' Chrome # # # # # # # # # # # # # # # # # # #
def decode_gchistory(file_to_decode):
	rep_title = 'Google Chrome: History'
	with sq.connect(OUTPUT+'db'+SEP+file_to_decode) as c:
		gch_data = c.execute("SELECT title,url,last_visit_time,visit_count FROM urls ORDER BY last_visit_time DESC").fetchall()
	with open(OUTPUT+'chrome_history.html', 'w', encoding='UTF-8') as fileh:
		fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>Page title</th><th>URL</th><th>Time</th><th>Frequency</th></tr>\n')
		for gch_item in gch_data:
			gch_s_title = gch_item[0]
			if len(gch_item[0]) > 60:	gch_s_title = gch_s_title[:55]+'.....' 
			gch_s_url = gch_item[1]
			if len(gch_item[1]) > 60:	gch_s_url = gch_s_url[:45]+'.....'+gch_s_url[-10:]
			gch = (
	gch_item[0],	#0 full title
	gch_s_title,	#1 short title
	gch_item[1],	#2 full url
	gch_s_url,		#3 short url
	webkit_to_utc(gch_item[2]),	#4 time
	gch_item[3],	#5 freq
	)
			fileh.write('<tr>\
	<td><a title="{0}">{1}</a></td>\
	<td><a href="{2}" title="{2}">{3}</a></td>\
	<td nowrap>{4}</td>\
	<td>{5}</td>\
	</tr>\n'.format(*gch))
		fileh.write(REP_FOOTER)
	REPORT.append(['Web browser', '<a href="chrome_history.html">{0} ({1:,})</a>'.format(rep_title, len(gch_data))])
# # # # #

# Decode 'Archived History' Chrome  # # # # # # # # # # # # # #
def decode_gcahistory(file_to_decode):
	rep_title = 'Google Chrome: Archived History'
	with sq.connect(OUTPUT+'db'+SEP+file_to_decode) as c:
		gcah_data = c.execute("SELECT title,url,last_visit_time,visit_count FROM urls ORDER BY last_visit_time DESC").fetchall()
	with open(OUTPUT+'chrome_archived_history.html', 'w', encoding='UTF-8') as fileh:
		fileh.write(REP_HEADER.format(_title=rep_title) + '<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>Page title</th><th>URL</th><th>Time</th><th>Frequency</th></tr>\n')
		for gcah_item in gcah_data:
			gcah_s_title = gcah_item[0]
			if len(gcah_item[0]) > 60:	gcah_s_title = gcah_s_title[:55]+'.....' 
			gcah_s_url = gcah_item[1]
			if len(gcah_item[1]) > 60:	gcah_s_url = gcah_s_url[:45]+'.....'+gcah_s_url[-10:]
			gcah = (
	gcah_item[0],	#0 full title
	gcah_s_title,	#1 short title
	gcah_item[1],	#2 full url
	gcah_s_url,		#3 short url
	webkit_to_utc(gcah_item[2]),	#4 time
	gcah_item[3],	#5 freq
	)
			fileh.write('<tr>\
	<td><a title="{0}">{1}</a></td>\
	<td><a href="{2}" title="{2}">{3}</a></td>\
	<td nowrap>{4}</td>\
	<td>{5}</td>\
	</tr>\n'.format(*gcah))
		fileh.write(REP_FOOTER)
	REPORT.append(['Web browser', '<a href="chrome_archived_history.html">{0} ({1:,})</a>'.format(rep_title, len(gcah_data))])
# # # # #

# Decode 'EmailProvider.db' # # # # # # # # # # # # # # # # # #
def decode_emailprov(file_to_decode):
	rep_title = 'E-mails'
	EMP_PATH = 'email_body'+SEP
	os.mkdir(OUTPUT+EMP_PATH)
	with sq.connect(OUTPUT+'db'+SEP+file_to_decode) as c:
		emp_auth = c.execute("SELECT protocol,address,port,login,password FROM HostAuth").fetchall()
		emp_data = c.execute("SELECT _id,fromList,toList,subject,snippet,flagAttachment,timeStamp FROM Message ORDER BY timeStamp DESC").fetchall()
		emp_body = sq.connect(OUTPUT+'db'+SEP+'EmailProviderBody.db').execute("SELECT messageKey,htmlContent,textContent FROM Body").fetchall()
		with open(OUTPUT+'email-provider.html', 'w', encoding='UTF-8') as fh:
			fh.write(REP_HEADER.format(_title=rep_title))
			if len(emp_auth) != 0:
				fh.write('<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>Protocol</th><th>Address</th><th>Port</th><th>Login</th><th nowrap bgcolor="#FF6666">Password</th></tr>\n')
				for _ in emp_auth:
					fh.write('<tr>\
	<td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>\n'.format(*_))
				fh.write('</table>\n<p/>')
			if len(emp_data) != 0:
				fh.write('<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1">\n<th>#</th><th>From</th><th>To</th><th>Subject</th><th width="300">Content (snippet)</th><th>Attachment</th><th nowrap>Time</th></tr>\n')
				for _ in emp_data:
					for _b in emp_body:
						if _b[0] == _[0]:
							ebody = _b[1]
							if ebody == None:
								ebody = _b[2]
								open(OUTPUT+EMP_PATH+str(_b[0]), 'w', encoding='UTF-8').write(ebody)
								_link = str(_b[0])
							else:
								open(OUTPUT+EMP_PATH+str(_b[0])+'.html', 'w', encoding='UTF-8').write(ebody)
								_link = str(_b[0])+'.html'
					else:
						try:
							ebody
						except:
							_link = ''
					_ = list(_)
					_[1] = format_html(_[1])
					_[2] = format_html(_[2])
					_[3] = format_html(_[3])
					if _[4] != None:	_[4] = '<a href="{0}">{1}</a>'.format(str(EMP_PATH+_link),format_html(_[4]))
					_[6] = unix_to_utc(_[6])
					fh.write('<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td width="300">{4}</td><td>{5}</td><td nowrap>{6}</td></tr>\n'.format(*_))
			fh.write(REP_FOOTER)
	REPORT.append(['Android E-mail', '<a href="email-provider.html">{0} ({1:,})</a>'.format(rep_title, len(emp_data))])
# # # # #

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# DECODING DOWNLOADED DATABASES
#
decoders = [
(decode_gesturekey, 'gesture.key'),
(decode_settingsdb, 'settings.db'),
(decode_accountsdb, 'accounts.db'),
(decode_wifipw, 'wpa_supplicant.conf'),
(decode_wifipw, 'flattened-data'),
(decode_webview, 'webview.db'),
(decode_browser2, 'browser2.db'),
(decode_logindata, 'Login Data'),
(decode_gchistory, 'History'),
(decode_gcahistory, 'Archived History'),
(decode_emailprov, 'EmailProvider.db'),
(decode_contacts2db, 'contacts2.db'),
(decode_calls_contacts2db, 'contacts2.db'),
(decode_logsdb, 'logs.db'),
(decode_mmssmsdb, 'mmssms.db'),
(decode_threads_db2, 'threads_db2'),
(decode_photos_db, 'photos_db'),
(decode_notificationsdb, 'notifications.db'),
(decode_notificationsdb, 'notifications_db'),
(decode_fbdb, 'fb.db'),
(decode_wadb, 'wa.db'),
(decode_msgstoredb, 'msgstore.db'),
(decode_kikDatabasedb, 'kikDatabase.db'),
(decode_masterdb, 'master.db'),
]

# Loop for decoding all DB's
def decode_databases(DLLS):
	decoding_start = time.time()
	for dec in decoders:
		if dec[1] in DLLS:
			try:
				dec[0](dec[1])
				print(' Decoding \'{0}\': OK'.format(dec[1]))
			except:
				print(' Decoding \'{0}\': failed'.format(dec[1]))
				pass; ERRORS.append('Unexpected error decoding \'{0}\'!'.format(dec[1]))
	print(' Data decoded in {:.3f} seconds'.format(time.time()-decoding_start))

if DLLS != []:
	print('{0:\u00B0^60}'.format(' Decoding data '))
	decode_databases(DLLS)

# Error log file
if ERRORS != []:
	for err in ERRORS:
		with open(OUTPUT+'log-errors.log', 'a', encoding='UTF-8') as fileh:
			fileh.write('#{0}\t{1}\r\n'.format(ERRORS.index(err)+1, err))

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# REPORTING
#
print('{0:\u00B0^60}'.format(' Generating report '))

with open(OUTPUT+'REPORT.html', 'w', encoding='UTF-8') as file_handle:
	file_handle.write('<!DOCTYPE html><html><head><meta charset="UTF-8">\n<title>Andriller Report for {_imei}</title>\n<style>body,td,tr {{font-family: Vernada, Arial, sans-serif; font-size: 12px;}}</style></head><body>\n<p align="center"><i># This report was generated using Andriller version {_av} on {_time} #</i></p><h3 align="center">[Andriller Report] {_dma} {_dmo} | {_imei}</h3>\n<table border="1" cellpadding=2 cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>Type</th><th>Data</th></tr>\n'.format(_imei=IMEI, _av=__version__, _time=LOCAL_TIME, _dma=DEVICE_MANUF, _dmo=DEVICE_MODEL))
	for torep in REPORT:
		file_handle.write('<tr><td>{0}:</td><td>'.format(torep[0]))
		if type(torep[1]) is list:
			for tore in torep[1]:
				file_handle.write('{0}<br/>'.format(tore))
			file_handle.write('</td></tr>\n')
		else:
			file_handle.write('{0}</td></tr>\n'.format(torep[1]))
	file_handle.write(REP_FOOTER)

# Print generated report path & open browser:
print(" Completed in {:.0f} seconds!".format(time.time()-extraction_started))
try:
	open_new_tab(os.getcwd()+SEP+OUTPUT+'REPORT.html')
except:	
	print(' Report saved: ' + os.getcwd()+SEP+OUTPUT+'REPORT.html')
	input(" Press 'Enter' to exit.")
