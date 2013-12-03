#!/usr/bin/env python3

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Andriller.py - Forensic acquisition tool for Android devices.
# Website, Usage and Disclaimer: http://android.saz.lt
# Copyright (C) 2012-2013  Denis Sazonov
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

import sys
import os
import time
import re
import hashlib
import sqlite3 as sq
from json import loads
from binascii import hexlify
from datetime import datetime
from datetime import timedelta
from subprocess import check_output as co
from subprocess import call

# Setting variables
ANDRILLER_VERSION = "alpha-1.1.1"
A_BUILD_DATE = "03/12/2013"

# Intro info
print(">>>>>>>>>> Andriller version: %s" % ANDRILLER_VERSION)
print(">>>>>>>>>> Build date: %s" % A_BUILD_DATE)
print(">>>>>>>>>> http://android.saz.lt")

REPORT = []		# List to be populated for generating the REPORT.html file

# Check OS and define adb
download_adb = ' ERROR! \n\'./adb\' file is not present!\n Download it from http://android.saz.lt/download/adb.zip; \n Unzip, and place them into this directory;\n Run the program again.'
OS_CHECK = sys.platform
if OS_CHECK == 'linux' or OS_CHECK == 'linux2':
	if call(['which', 'adb']) == 0:
		ADB = "adb"
		SEP = '/'
	else:
		ADB = './adb'
		SEP = '/'
		if os.path.isfile(ADB) == True:
			os.chmod(ADB, '0755')
		else:
			input(download_adb + "\n Press 'Enter' to exit.")
			sys.exit()
elif OS_CHECK == 'win32':
	ADB = "adb.exe"
	SEP = '\\'
	if os.path.isfile(ADB) == False:
		input(download_adb + "\n Press 'Enter' to exit.")
		sys.exit()
elif OS_CHECK == 'darwin':
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
print(">>>>>>>>>> General Device Information.")

# Check for connected Android device
if 'unknown' in co([ADB, 'get-state']).decode('UTF-8'):
	input(" No Android device found!\n Press 'Enter' to exit.")
	sys.exit()
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
	input("  Android permission cannot be established!\n Press 'Enter' to exit.")
	sys.exit()

BUILDPROP = co([ADB, 'shell', 'cat', '/system/build.prop']).decode('UTF-8')

# Make & Model
for manuf in BUILDPROP.split('\n'):
	if 'ro.product.manufacturer' in manuf:
		DEVICE_MANUF = manuf.strip().split('=')[1]
for model in BUILDPROP.split('\n'):
	if 'ro.product.model' in model:
		DEVICE_MODEL = model.strip().split('=')[1]
try:
	print(" Device model: %s %s" % (DEVICE_MANUF, DEVICE_MODEL)); REPORT.append(["Manufacturer", DEVICE_MANUF]); REPORT.append(["Model", DEVICE_MODEL])
except:
	pass

# IMEI
IMEI = co([ADB, 'shell', 'dumpsys', 'iphonesubinfo']).decode('UTF-8').split()[-1]
try:
	print(" IMEI: " + IMEI); REPORT.append(["IMEI", IMEI])
except:
	pass

# A version
for aver in BUILDPROP.split('\n'):
	if 'ro.build.version.release' in aver:
		ANDROID_VER = aver.strip().split('=')[1]
try:
	print(" Android version: " + ANDROID_VER); REPORT.append(["Android version", ANDROID_VER])
except:
	pass

# Build ID
for buildid in BUILDPROP.split('\n'):
	if 'ro.build.display.id' in buildid:
		BUILD_ID = buildid.strip().split('=')[1]
try:
	print(" Build number: " + BUILD_ID); REPORT.append(["Build name", BUILD_ID])
except:
	pass

# Wifi
DUMPSYS_W = co([ADB, 'shell', 'dumpsys', 'wifi']).decode('UTF-8')
try:
	wifi_beg = DUMPSYS_W.index('MAC:')+5
	wifi_end = DUMPSYS_W[wifi_beg:].index(',')
	if wifi_end == 17:
		WIFI_MAC = DUMPSYS_W[wifi_beg:wifi_beg+wifi_end].lower()
		try:
			print(" Wi-fi MAC: " + WIFI_MAC); REPORT.append(["Wifi MAC", WIFI_MAC])
		except:
			pass
except:
	pass

# Time and date
LOCAL_TIME = time.strftime('%Y-%m-%d %H:%M:%S %Z')
try:
	print(" Local time: " + LOCAL_TIME); REPORT.append(["Local time", LOCAL_TIME])
except:
	pass
ANDROID_TIME = co([ADB, 'shell', 'date', '+%F %T %Z']).decode('UTF-8').replace('\r\n', '')
try:
	print(" Android time: " + ANDROID_TIME); REPORT.append(["Android time", ANDROID_TIME])
except:
	pass

# SIM card extraction 
SIM_LOC = '/data/system/SimCard.dat'
if co([ADB, 'shell', 'ls', SIM_LOC]).decode('UTF-8').replace('\r', '').replace('\n', '') == SIM_LOC:
	SIM_DATA = co([ADB, 'shell', 'cat', SIM_LOC]).decode('UTF-8').replace('\r', '')
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

#
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
if ACCOUNTS != '':
	print(">>>>>>>>>> Sync'ed Accounts.")
	for account in ACCOUNTS:
		print(' ' + str(account))
	REPORT.append(["Accounts", ACCOUNTS])

# Create output directory
OR_DATE = time.strftime('%Y-%m-%d')
OR_TIME = time.strftime('%H.%M.%S')
OUTPUT = DEVICE_MANUF+"_"+DEVICE_MODEL+"_"+OR_DATE+"_"+OR_TIME+SEP
try:
	os.mkdir(OUTPUT)
	os.mkdir(OUTPUT+SEP+'db')
except:
	input(" Insufficient permissions to create a folder in this directory!\n Press 'Enter' to exit.")
	sys.exit()

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# ROOT EXTRACTION
#
if 'root' in PERM:
	print(">>>>>>>>>> Downloading databases...")

#
# DATABASE EXTRACTION
#
# Database links

DBLS = [
'/data/data/com.android.providers.settings/databases/settings.db',
'/data/data/com.android.providers.contacts/databases/contacts2.db',
'/data/data/com.sec.android.provider.logsprovider/databases/logs.db',
'/data/data/com.android.providers.telephony/databases/mmssms.db',
'/data/data/com.facebook.katana/databases/fb.db',
'/data/data/com.facebook.katana/databases/contacts_db2',
'/data/data/com.facebook.katana/databases/threads_db2',
'/data/data/com.facebook.katana/databases/notifications.db',
'/data/data/com.facebook.katana/databases/photos_db',
'/data/data/com.whatsapp/databases/wa.db',
'/data/data/com.whatsapp/databases/msgstore.db',
'/data/data/kik.android/databases/kikDatabase.db',
'/data/data/com.bbm/files/bbmcore/master.db',
'/data/system/gesture.key',
'/data/system/cm_gesture.key',
'/data/system/locksettings.db',
'/data/system/password.key'
]

#
# DOWNLOADING DATABASES

DLLS = []	# downloaded databases empty list
def download_database(DB_PATH):
	DB_NAME = DB_PATH.split('/')[-1]
	if co([ADB, 'shell', 'su', '-c', 'ls', DB_PATH]).decode('UTF-8').replace('\r', '').replace('\n', '') == DB_PATH:
		if 'su' in PERM:
			co([ADB, 'shell', 'su', '-c', 'dd', 'if='+DB_PATH, 'of=/data/local/tmp/'+DB_NAME])
			co([ADB, 'shell', 'su', '-c', 'chmod', '777', '/data/local/tmp/'+DB_NAME])
			co([ADB, 'pull', '/data/local/tmp/'+DB_NAME, OUTPUT+SEP+'db'+SEP+DB_NAME])
			co([ADB, 'shell', 'su', '-c', 'rm', '/data/local/tmp/'+DB_NAME])
		else:
			co([ADB, 'pull', DB_PATH, OUTPUT+SEP+'db'+SEP+DB_NAME])
		if os.path.isfile(OUTPUT+SEP+'db'+SEP+DB_NAME) == True:
			fileh = open(OUTPUT+SEP+'db'+SEP+'md5sums', 'a')
			DB_MD5 = hashlib.md5(open(OUTPUT+SEP+'db'+SEP+DB_NAME, 'rb').read()).hexdigest()
			DLLS.append(DB_NAME) #; DLLS.append(DB_MD5)
			fileh.write(DB_MD5+'\t'+DB_NAME+'\n')
			fileh.close()

if 'root' in PERM:
	for db in DBLS:
		download_database(db)

# Download content of a path  # # # # # # # # # # # # # # # # #
def download_folder(R_PATH,L_PATH):
	os.mkdir(OUTPUT+SEP+L_PATH)
	if 'su' in PERM:
		for ipull in co([ADB, 'shell', 'su', '-c', 'ls', str(R_PATH)]):
			co([ADB, 'shell', 'su', '-c', 'dd', 'if='+R_PATH+ipull, 'of=/data/local/tmp/'+ipull])
			co([ADB, 'shell', 'su', '-c', 'chmod', '777', '/data/local/tmp/'+ipull])
			co([ADB, 'pull', '/data/local/tmp/'+ipull, OUTPUT+SEP+L_PATH+SEP+ipull])
			co([ADB, 'shell', 'su', '-c', 'rm', '/data/local/tmp/'+ipull])
	else:
		for ipull in co([ADB, 'shell', 'ls', str(R_PATH)]):
			co([ADB, 'pull', R_PATH, OUTPUT+SEP+L_PATH+SEP+ipull])

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# DECODING DEFINITIONS FOR DATABASES
# 

# Decode gesture.key  # # # # # # # # # # # # # # # # # # # # #
def decode_gesturekey():
	fileh = open(OUTPUT+SEP+'db'+SEP+'gesture.key', 'rb')
	ges_data = fileh.read()
	if len(ges_data) == 20:
		GKEY = hexlify(ges_data).decode('UTF-8')
		REPORT.append(['Gesture pattern', '<a href="http://android.saz.lt/cgi-bin/online_pattern.py?encoded=%s" target="_blank">%s</a>' % (GKEY, GKEY)])
# # # # #

REP_FOOTER = '</table>\n<p align="center"><i># <a href="http://android.saz.lt" target="_blank">http://android.saz.lt</a> #</i></p>\n</body></html>'

# Brute force 4-digit password  # # # # # # # # # # # # # # # #
def decode_pwkey(pwkey, pwsalt):
	for pin in range(0,10000):
		pin = str(pin).zfill(4)
		salt = '%x' % pwsalt
		h = hashlib.sha1((str(pin)+str(salt)).encode('ascii')).hexdigest()
		if h.upper() == pwkey[:40]:
			return pin
# # # # #

# Decode settings.db  # # # # # # # # # # # # # # # # # # # # #
def decode_settingsdb():
	con = sq.connect(OUTPUT+SEP+'db'+SEP+'settings.db')
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='secure'")
	if c.fetchone() != None:
		c.execute("SELECT value FROM secure WHERE name = 'bluetooth_address'")
		BT_MAC = c.fetchone()
		c.execute("SELECT value FROM secure WHERE name = 'bluetooth_name'")
		BT_NAME = c.fetchone()
		c.execute("SELECT value FROM secure WHERE name = 'android_id'")
		AN_ID = c.fetchone(); REPORT.insert(1, ["Android ID", AN_ID])
		c.execute("SELECT value FROM secure WHERE name = 'lockscreen.password_salt'")
		try:
			PW_SALT = int(c.fetchone()[0])
		except:
			PW_SALT = None
		con.close()
		if BT_MAC != None:
			for findlt in REPORT:
				if 'Local time' in findlt:
					LotLoc = REPORT.index(findlt)
					REPORT.insert(LotLoc, ["Bluetooth MAC", BT_MAC])
					REPORT.insert(LotLoc+1, ["Bluetooth name", BT_NAME])
					break
		if PW_SALT != None:
			if 'password.key' in DLLS:
				fileh = open(OUTPUT+SEP+'db'+SEP+'password.key', 'r')
				PW_KEY = fileh.read(); fileh.close()
				if len(PW_KEY) == 72:
					PW_PIN = decode_pwkey(PW_KEY, PW_SALT)
					if PW_PIN != None or PW_PIN != '':
						REPORT.append(["Lockscreen PIN", PW_PIN])

# # # # # 

# Decode contacts2.db (Pbook) # # # # # # # # # # # # # # # # #
def decode_contacts2db():
	rep_title = 'Contacts'
	con = sq.connect(OUTPUT+SEP+'db'+SEP+'contacts2.db')
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='data'")
	if c.fetchone() != None:
		c.execute("SELECT raw_contact_id, mimetypes.mimetype, data1 FROM data JOIN mimetypes ON (data.mimetype_id=mimetypes._id) ORDER BY raw_contact_id")
		#c.execute("SELECT raw_contact_id, mimetypes.mimetype, data1 FROM data JOIN mimetypes ON (data.mimetype_id=mimetypes._id) JOIN visible_contacts ON (data.raw_contact_id=visible_contacts._id) ORDER BY raw_contact_id")
		c2_data = c.fetchall()
		con.close()
		if c2_data != '':
			fileh = open(OUTPUT+'contacts.html', 'w', encoding='UTF-8')
			fileh.write('<!DOCTYPE html><html><head>\n<title>%s Andriller Report for %s</title>\n<style>body,td,tr {font-family: Vernada, Arial, sans-serif; font-size: 12px;}</style></head>\n<body>\n<a href="REPORT.html">[Back]</a>\n<p align="center"><i># This report was generated using Andriller on %s #</i></p>\n<h3 align="center">[%s] %s</h3>\n<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th nowrap>#</th><th nowrap>Name</th><th nowrap>Number</th><th nowrap>Email</th><th>Other</th></tr>' % (str(rep_title), str(IMEI), str(LOCAL_TIME), str(rep_title), str(IMEI)))
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
					pb_number = pb.pop('phone_v2')
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
				fileh.write('<tr><td nowrap>%s</td><td nowrap>%s</td><td nowrap>%s</td><td nowrap>%s</td><td>%s</td></tr>\n' % (pb_index, pb_name, pb_number, pb_email, pb_other))
			fileh.write(REP_FOOTER)
			fileh.close()
			REPORT.append(['Communications data', '<a href="contacts.html">%s (%d)</a>' % (rep_title, len(pbook))])
# # # # #

# Decode contacts2.db (Calls) # # # # # # # # # # # # # # # # #
def decode_calls_contacts2db():
	rep_title = 'Call logs'
	con = sq.connect(OUTPUT+'db'+SEP+'contacts2.db')
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='calls'")
	if c.fetchone() != None:	# check if table exists
		c.execute("SELECT _id,type,number,name,date,duration FROM calls ORDER by date DESC")
		c2_data = c.fetchall()
		con.close()
		if c2_data != []:
			fileh = open(OUTPUT+'call_logs.html', 'w', encoding='UTF-8')
			fileh.write('<!DOCTYPE html><html><head>\n<title>%s Andriller Report for %s</title>\n<style>body,td,tr {font-family: Vernada, Arial, sans-serif; font-size: 12px;}</style></head>\n<body>\n<a href="REPORT.html">[Back]</a>\n<p align="center"><i># This report was generated using Andriller on %s #</i></p>\n<h3 align="center">[%s] %s</h3>\n<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>#</th><th>Type</th><th>Number</th><th>Name</th><th>Time</th><th>Duration</th></tr>' % (str(rep_title), str(IMEI), str(LOCAL_TIME), str(rep_title), str(IMEI)))
			for c2_item in c2_data:
				c2_id = str(c2_item[0])		# id
				c2_type_raw = c2_item[1]	# type
				if c2_type_raw == 1:
					c2_type = 'Received'
				elif c2_type_raw == 2:
					c2_type = 'Dialled'
				elif c2_type_raw == 3:
					c2_type = 'Missed'
				elif c2_type_raw == 5:
					c2_type = 'Rejected'
				else:
					c2_type = 'Type('+str(c2_type_raw)+')'
				c2_number = str(c2_item[2])		# number
				if int(c2_number) <= 0:
					c2_number = 'UNKNOWN'
				c2_name = c2_item[3]		# name
				if c2_name == None:
					c2_name = ''
				c2_date = datetime.utcfromtimestamp(int(str(c2_item[4])[:10])).strftime('%Y-%m-%d %H:%M:%S UTC')
				c2_dur = str(timedelta(seconds=c2_item[5]))		# duration
				fileh.write('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' % (str(c2_id), str(c2_type), str(c2_number), str(c2_name), str(c2_date), str(c2_dur), ))
			fileh.write(REP_FOOTER)
			fileh.close()
			REPORT.append(['Communications data', '<a href="call_logs.html">%s (%d)</a>' % (rep_title, len(c2_data))])
# # # # #

# Decode logs.db (Samsung Calls(SEC)) # # # # # # # # # # # # # # # # #
def decode_logsdb():
	rep_title = 'Samsung Call logs'
	con = sq.connect(OUTPUT+'db'+SEP+'logs.db')
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
	if c.fetchone() != None:
		c.execute("SELECT _id,type,number,name,date,duration FROM logs WHERE logtype='100' ORDER by date DESC")
		sec_data = c.fetchall()
		con.close()
		fileh = open(OUTPUT+'sec_call_logs.html', 'w', encoding='UTF-8')
		fileh.write('<!DOCTYPE html><html><head>\n<title>%s Andriller Report for %s</title>\n<style>body,td,tr {font-family: Vernada, Arial, sans-serif; font-size: 12px;}</style></head>\n<body>\n<a href="REPORT.html">[Back]</a>\n<p align="center"><i># This report was generated using Andriller on %s #</i></p>\n<h3 align="center">[%s] %s</h3>\n<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>#</th><th>Type</th><th>Number</th><th>Name</th><th>Time</th><th>Duration</th></tr>' % (str(rep_title), str(IMEI), str(LOCAL_TIME), str(rep_title), str(IMEI)))
		for sec_item in sec_data:
			sec_id = str(sec_item[0])		# id
			sec_type_raw = sec_item[1]	# type
			if sec_type_raw == 1:
				sec_type = 'Received'
			elif sec_type_raw == 2:
				sec_type = 'Dialled'
			elif sec_type_raw == 3:
				sec_type = 'Missed'
			elif sec_type_raw == 5:
				sec_type = 'Rejected'
			else:
				sec_type = 'Type('+str(sec_type_raw)+')'
			sec_number = str(sec_item[2])		# number
			if int(sec_number) <= 0:
				sec_number = 'UNKNOWN'
			sec_name = sec_item[3]		# name
			if sec_name == None:
				sec_name = ''
			sec_date = datetime.utcfromtimestamp(int(str(sec_item[4])[:10])).strftime('%Y-%m-%d %H:%M:%S UTC')
			sec_dur = str(timedelta(seconds=sec_item[5]))		# duration
			fileh.write('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' % (str(sec_id), str(sec_type), str(sec_number), str(sec_name), str(sec_date), str(sec_dur), ))
		fileh.write(REP_FOOTER)
		fileh.close()
		REPORT.append(['Communications data', '<a href="sec_call_logs.html">%s (%d)</a>' % (rep_title, len(sec_data))])
# # # # #

# Decode mmssms.db  # # # # # # # # # # # # # # # # # # # # # #
def decode_mmssmsdb():
	rep_title = 'SMS Messages'
	con = sq.connect(OUTPUT+'db'+SEP+'mmssms.db')
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sms'")
	if c.fetchone() != None:
		c.execute("SELECT address,body,date,type,_id FROM sms ORDER by sms.date DESC")
		sms_data = c.fetchall()
		con.close()
		fileh = open(OUTPUT+'mmssms.html', 'w', encoding='UTF-8')
		fileh.write('<!DOCTYPE html><html><head>\n<title>%s Andriller Report for %s</title>\n<style>body,td,tr {font-family: Vernada, Arial, sans-serif; font-size: 12px;}</style></head>\n<body>\n<a href="REPORT.html">[Back]</a>\n<p align="center"><i># This report was generated using Andriller on %s #</i></p>\n<h3 align="center">[%s] %s</h3>\n<table border=1 cellpadding=2 cellspacing=0 align=center>\n<tr bgcolor=#72A0C1><th>#</th><th>Number</th><th width="500">Message</th><th>Type</th><th nowrap>Time</th></tr>\n' % (str(rep_title), str(IMEI), str(LOCAL_TIME), str(rep_title), str(IMEI)))
		for sms_item in sms_data:
			sms_number = str(sms_item[0])
			sms_text = str(sms_item[1])
			sms_time = datetime.utcfromtimestamp(int(str(sms_item[2])[:10])).strftime('%Y-%m-%d %H:%M:%S UTC')
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
			fileh.write('<tr><td>%s</td><td>%s</td><td width="500">%s</td><td>%s</td><td nowrap>%s</td></tr>\n' % (str(sms_index),sms_number,sms_text,sms_typ,sms_time))
		fileh.write(REP_FOOTER)
		fileh.close()
		REPORT.append(['Communications data', '<a href="mmssms.html">%s (%d)</a>' % (rep_title, len(sms_data))])
# # # # # 

# Decode threads_db2 # # # # # # # # # # # # # # # # # # #
def decode_threads_db2():
	rep_title = 'Facebook: Messages'
	con = sq.connect(OUTPUT+SEP+'db'+SEP+'threads_db2')
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
	if c.fetchone() != None:
		c.execute("SELECT sender,threads.participants,text,messages.timestamp_ms FROM messages JOIN threads ON (messages.thread_id=threads.thread_id) WHERE NOT messages.timestamp_ms='0' ORDER BY messages.timestamp_ms DESC")
		fbt_data = c.fetchall()
		c.execute("SELECT user_key,name,profile_pic_square FROM thread_users")
		fbt_users = c.fetchall()
		con.close()
		if fbt_data != '':
			fileh = open(OUTPUT+SEP+'fb_messages.html', 'w', encoding='UTF-8')
			fileh.write('<!DOCTYPE html><html><head>\n<title>%s Andriller Report for %s</title>\n<style>body,td,tr {font-family: Vernada, Arial, sans-serif; font-size: 12px;}</style></head>\n<body>\n<a href="REPORT.html">[Back]</a>\n<p align="center"><i># This report was generated using Andriller on %s #</i></p>\n<h3 align="center">[%s] %s</h3>\n<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th nowrap>Sender</th><th nowrap>Image</th><th width="500">Message</th><th nowrap>Recipient(s)</th><th>Time</th></tr>' % (str(rep_title), str(IMEI), str(LOCAL_TIME), str(rep_title), str(IMEI)))
			for fbt_item in fbt_data:
				if fbt_item[0] != None:
					fbt_sender_nm = loads(fbt_item[0]).get('name')
					fbt_sender_id = loads(fbt_item[0]).get('user_key')
				else:
					fbt_sender_nm = ''
					fbt_sender_id = ''
				for fbimgs in fbt_users:
					if fbimgs[0] == fbt_sender_id:
						fbt_img = loads(fbimgs[2])[0].get('url')
				fbt_text = fbt_item[2]
				fbt_time = datetime.utcfromtimestamp(int(str(fbt_item[3])[:10])).strftime('%Y-%m-%d %H:%M:%S UTC')
				fbt_part = []
				for fbtdic in loads(fbt_item[1]):
					fbt_part.append(fbtdic.get('name')+' (ID:'+fbtdic.get('user_key').split(':')[1]+')')
				try:
					fbt_part.remove(fbt_sender_nm+' (ID:'+fbt_sender_id.split(':')[1]+')')
				except:
					pass
				fbt_parti = '<br/>'.join(fbt_part)
				fileh.write('<tr><td nowrap><a href="http://www.facebook.com/profile.php?id=%s">%s</a></td><td><img src="%s"></td><td width="500">%s</td><td nowrap>%s</td><td nowrap>%s</td></tr>\n' % (fbt_sender_id.split(':')[1], fbt_sender_nm, fbt_img, fbt_text, fbt_parti, str(fbt_time)))
			fileh.write(REP_FOOTER)
			fileh.close()
			REPORT.append(['Applications data', '<a href="fb_messages.html">%s (%d)</a>' % (rep_title, len(fbt_data))])
# # # # #

# Decode photos_db # # # # # # # # # # # # # # # # # # # # # # #
def decode_photos_db():
	rep_title = 'Facebook: Viewed Photos'
	con = sq.connect(OUTPUT+'db'+SEP+'photos_db')
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='photos'")
	if c.fetchone() != None:
		c.execute("SELECT _id,owner,src_small,src_big,caption,created,thumbnail FROM photos ORDER BY _id DESC")
		fbp_data = c.fetchall()
		if len(fbp_data) > 0:
			os.mkdir(OUTPUT+'fb_media'); os.mkdir(OUTPUT+'fb_media'+SEP+'Thumbs')
			fileh = open(OUTPUT+'fb_photos2.html', 'w', encoding='UTF-8')
			fileh.write('<!DOCTYPE html><html><head>\n<title>%s Andriller Report for %s</title>\n<style>body,td,tr {font-family: Vernada, Arial, sans-serif; font-size: 12px;}</style></head>\n<body>\n<a href="REPORT.html">[Back]</a>\n<p align="center"><i># This report was generated using Andriller on %s #</i></p>\n<h3 align="center">[%s] %s</h3>\n<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>#</th><th>Picture</th><th>Owner</th><th width="500">Caption</th><th nowrap>Date (uploaded)</th></tr>' % (str(rep_title), str(IMEI), str(LOCAL_TIME), str(rep_title), str(IMEI)))
			for fbp_item in fbp_data:
				fbp_id = fbp_item[0]
				fbp_owner = str(fbp_item[1])
				fbp_thm = fbp_item[2]
				fbp_img = fbp_item[3]
				if fbp_item[4] == None:
					fbp_cap = ''
				else:
					fbp_cap = str(fbp_item[4])
				fbp_date = datetime.utcfromtimestamp(int(str(fbp_item[5])[:10])).strftime('%Y-%m-%d %H:%M:%S UTC')
				if fbp_item[6] != None:
					filewa = open(OUTPUT+'fb_media'+SEP+'Thumbs'+SEP+str(fbp_id)+'.jpg', 'wb')
					filewa.write(fbp_item[6]); filewa.close()					
					fbp_thumb = 'fb_media'+SEP+'Thumbs'+SEP+str(fbp_id)+'.jpg'
				else:
					fbp_thumb = fbp_item[2]
				fileh.write('<tr><td>%s</td><td><a href="%s" target="_blank"><img src="%s"></a></td><td><a href="http://www.facebook.com/profile.php?id=%s" target="_blank">%s</a></td><td width="500">%s</td><td nowrap>%s</td></tr>\n' % (str(fbp_id), str(fbp_img), str(fbp_thm), str(fbp_owner), str(fbp_owner), fbp_cap, fbp_date))
			fileh.write(REP_FOOTER)
			fileh.close()
			REPORT.append(['Applications data', '<a href="fb_photos2.html">%s (%d)</a>' % (rep_title, len(fbp_data))])

# # # # #

# Decode notifications.db # # # # # # # # # # # # # # # # # #
def decode_notificationsdb():
	rep_title = 'Facebook: Notifications'
	con = sq.connect(OUTPUT+SEP+'db'+SEP+'notifications.db')
	c = con.cursor()
	noti_data = c.execute("SELECT gql_payload FROM gql_notifications ORDER BY updated DESC").fetchall()
	con.close()
	fileh = open(OUTPUT+SEP+'fb_notifications.html', 'w', encoding='UTF-8')
	fileh.write('<!DOCTYPE html><html><head>\n<title>%s Andriller Report for %s</title>\n<style>body,td,tr {font-family: Vernada, Arial, sans-serif; font-size: 12px;}</style></head>\n<body>\n<a href="REPORT.html">[Back]</a>\n<p align="center"><i># This report was generated using Andriller on %s #</i></p>\n<h3 align="center">[%s] %s</h3>\n<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th nowrap>Notifying Users</th><th width="200">Notification Title</th><th width="300">Post Text</th><th width="100">Attachments</th><th nowrap>Time/Location</th></tr>\n' % (str(rep_title), str(IMEI), str(LOCAL_TIME), str(rep_title), str(IMEI)))
	for noti_item in noti_data:
		noti_d = loads(noti_item[0].decode('UTF-8'))
		ntf_name = noti_d.get('actors')[0].get('name')
		#ntf_names = '<br/>'.join([x.get('name')+str('(')+x.get('id')+str(')') for x in noti_d.get('actors')])
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
		ntf_time = datetime.utcfromtimestamp(int(str(noti_d.get('creation_time'))[:10])).strftime('%Y-%m-%d %H:%M:%S UTC')
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
	REPORT.append(['Applications data', '<a href="fb_notifications.html">%s (%d)</a>' % (rep_title, len(noti_data))])
# # # # #

# Decode fb.db  # # # # # # # # # # # # # # # # # # # # # # # #
def decode_fbdb():
	rep_title = 'Facebook: Viewed Photos'
	con = sq.connect(OUTPUT+'db'+SEP+'fb.db')
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='photos'")
	if c.fetchone() != None:
		c.execute("SELECT _id,owner,src_small,src_big,caption,created,thumbnail FROM photos ORDER BY _id DESC")
		fbp_data = c.fetchall()
		if len(fbp_data) > 0:
			os.mkdir(OUTPUT+'fb_media'); os.mkdir(OUTPUT+'fb_media'+SEP+'Thumbs')
			fileh = open(OUTPUT+'fb_photos.html', 'w', encoding='UTF-8')
			fileh.write('<!DOCTYPE html><html><head>\n<title>%s Andriller Report for %s</title>\n<style>body,td,tr {font-family: Vernada, Arial, sans-serif; font-size: 12px;}</style></head>\n<body>\n<a href="REPORT.html">[Back]</a>\n<p align="center"><i># This report was generated using Andriller on %s #</i></p>\n<h3 align="center">[%s] %s</h3>\n<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>#</th><th>Picture</th><th>Owner</th><th width="500">Caption</th><th nowrap>Date (uploaded)</th></tr>\n' % (str(rep_title), str(IMEI), str(LOCAL_TIME), str(rep_title), str(IMEI)))
			for fbp_item in fbp_data:
				fbp_id = fbp_item[0]
				fbp_owner = str(fbp_item[1])
				fbp_thm = fbp_item[2]
				fbp_img = fbp_item[3]
				if fbp_item[4] == None:
					fbp_cap = ''
				else:
					fbp_cap = str(fbp_item[4])
				fbp_date = datetime.utcfromtimestamp(int(str(fbp_item[5])[:10])).strftime('%Y-%m-%d %H:%M:%S UTC')
				if fbp_item[6] != None:
					filewa = open(OUTPUT+'fb_media'+SEP+'Thumbs'+SEP+str(fbp_id)+'.jpg', 'wb')
					filewa.write(fbp_item[6]); filewa.close()					
					fbp_thumb = 'fb_media'+SEP+'Thumbs'+SEP+str(fbp_id)+'.jpg'
				else:
					fbp_thumb = fbp_item[2]
				fileh.write('<tr><td>%s</td><td><a href="%s" target="_blank"><img src="%s"></a></td><td><a href="http://www.facebook.com/profile.php?id=%s" target="_blank">%s</a></td><td width="500">%s</td><td nowrap>%s</td></tr>\n' % (str(fbp_id), str(fbp_img), str(fbp_thm), str(fbp_owner), str(fbp_owner), fbp_cap, fbp_date))
			fileh.write(REP_FOOTER)
			fileh.close()
			REPORT.append(['Applications data', '<a href="fb_photos.html">%s (%d)</a>' % (rep_title, len(fbp_data))])

# # # # # 

# Decode wa.db  # # # # # # # # # # # # # # # # # # # # # # # #
def decode_wadb():
	rep_title = 'WhatsApp Contacts'
	con = sq.connect(OUTPUT+'db'+SEP+'wa.db')
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='wa_contacts'")
	if c.fetchone() != None:
		c.execute("select display_name,number,status from wa_contacts where is_whatsapp_user='1'")
		wa_data = c.fetchall()
		con.close()
		fileh = open(OUTPUT+'wa_contacts.html', 'w', encoding='UTF-8')
		fileh.write('<!DOCTYPE html><html><head>\n<title>%s Andriller Report for %s</title>\n<style>body,td,tr {font-family: Vernada, Arial, sans-serif; font-size: 12px;}</style></head>\n<body>\n<a href="REPORT.html">[Back]</a>\n<p align="center"><i># This report was generated using Andriller on %s #</i></p>\n<h3 align="center">[%s] %s</h3>\n<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>Name</th><th>Number</th><th>Status</th></tr>\n' % (str(rep_title), str(IMEI), str(LOCAL_TIME), str(rep_title), str(IMEI)))
		for wa_item in wa_data:
			wa_name = wa_item[0]
			wa_number = wa_item[1]
			wa_status = wa_item[2]
			if wa_status == None:
				wa_status = ''
			fileh.write('<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n' % (wa_name,wa_number,wa_status))
		fileh.write(REP_FOOTER)
		fileh.close()
		REPORT.append(['Applications data', '<a href="wa_contacts.html">%s (%d)</a>' % (rep_title, len(wa_data))])
# # # # # 

# Decode msgstore.db  # # # # # # # # # # # # # # # # # # # # #
def decode_msgstoredb():
	rep_title = 'WhatsApp Messages'
	con = sq.connect(OUTPUT+'db'+SEP+'msgstore.db')
	c = con.cursor()
	c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
	if c.fetchone() != None:
		os.mkdir(OUTPUT+'wa_media'); os.mkdir(OUTPUT+'wa_media'+SEP+'Thumbs')
		c.execute("SELECT _id, key_remote_jid, data, timestamp, key_from_me, media_size, media_mime_type, media_name, raw_data, latitude, longitude FROM messages WHERE NOT status='-1' ORDER BY timestamp DESC")
		wam_data = c.fetchall()
		con.close()
		fileh = open(OUTPUT+'wa_messages.html', 'w', encoding='UTF-8')
		fileh.write('<!DOCTYPE html><html><head>\n<title>%s Andriller Report for %s</title>\n<style>body,td,tr {font-family: Vernada, Arial, sans-serif; font-size: 12px;}</style></head>\n<body>\n<a href="REPORT.html">[Back]</a>\n<p align="center"><i># This report was generated using Andriller on %s #</i></p>\n<h3 align="center">[%s] %s</h3>\n<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>#</th><th>Number</th><th width="500">Message</th><th nowrap>Time</th><th>Type</th></tr>\n' % (str(rep_title), str(IMEI), str(LOCAL_TIME), str(rep_title), str(IMEI)))
		for wam_item in wam_data:
			wam_id = wam_item[0]
			wam_number = wam_item[1].split('@')[0]
			if wam_number[0] != 0:
				wam_number = '+'+wam_number
			wam_text = wam_item[2]		# data
			wam_date = datetime.utcfromtimestamp(int(str(wam_item[3])[:10])).strftime('%Y-%m-%d %H:%M:%S UTC')		# timestamp
			if wam_item[4] == 1:		# key_from_me
				wam_dir = 'Sent'
			else:
				wam_dir = 'Inbox'
			if wam_item[8] != None:			# raw_data
				if wam_item[7] != None:		# media_name
					wam_fname = wam_item[7]
				elif wam_item[6] != None:
					wam_fname = str(wam_item[0])+'.'+wam_item[6].split('/')[1]	# media_mime_type
				else:
					wam_fname = str(wam_item[0])+'.jpg'
				filewa = open(OUTPUT+SEP+'wa_media'+SEP+'Thumbs'+SEP+wam_fname, 'wb')
				filewa.write(wam_item[8]); filewa.close()	# raw_data, writes file
				wam_text = '<img src="'+'wa_media'+SEP+'Thumbs'+SEP+wam_fname+'">'
				if wam_item[6] != None:
					wam_text = 'Type: '+str(wam_item[6])+'<br/>'+wam_text
				if wam_item[7] != None:
					wam_text = 'Filename: '+str(wam_item[7])+'<br/>'+wam_text
				if wam_item[9] != 0 and wam_item[10] != 0:		# latitude, longtitude
					wam_text = '<a href="http://maps.google.com/maps?q='+str(wam_item[9])+','+str(wam_item[10])+'" target="_blank">Map Location: '+str(wam_item[9])+','+str(wam_item[10])+'<br/>'+wam_text+'</a>'
			fileh.write('<tr><td>%s</td><td>%s</td><td width="500">%s</td><td nowrap>%s</td><td>%s</td></tr>\n' % (wam_id, wam_number, wam_text, wam_date, wam_dir))
		fileh.write(REP_FOOTER)
		fileh.close()
		REPORT.append(['Applications data', '<a href="wa_messages.html">%s (%d)</a>' % (rep_title, len(wam_data))])
# # # # # 

# Decode Kik Messenger kikDatabase.db # # # # # # # # # # # # #
def decode_kikDatabasedb():
	rep_title = 'Kik Messages'
	con = sq.connect(OUTPUT+'db'+SEP+'kikDatabase.db')
	c = con.cursor()
	kik_data = c.execute("SELECT messagesTable._id,body,user_name,was_me,timestamp,length,content_id FROM messagesTable JOIN KIKcontactsTable ON (messagesTable.partner_jid=KIKcontactsTable.jid) ORDER BY timestamp DESC").fetchall()
	con.close()
	fileh = open(OUTPUT+'kik_messages.html', 'w', encoding='UTF-8')
	fileh.write('<!DOCTYPE html><html><head>\n<title>%s Andriller Report for %s</title>\n<style>body,td,tr {font-family: Vernada, Arial, sans-serif; font-size: 12px;}</style></head>\n<body>\n<a href="REPORT.html">[Back]</a>\n<p align="center"><i># This report was generated using Andriller on %s #</i></p>\n<h3 align="center">[%s] %s</h3>\n<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>#</th><th>Username</th><th width="300">Message</th><th>Type</th><th nowrap>Time</th></tr>\n' % (str(rep_title), str(IMEI), str(LOCAL_TIME), str(rep_title), str(IMEI)))
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
		kik_time = datetime.utcfromtimestamp(int(str(kik_item[4])[:10])).strftime('%Y-%m-%d %H:%M:%S UTC')
		fileh.write('<tr><td>%s</td><td>%s</td><td width="300">%s</td><td>%s</td><td nowrap>%s</td></tr>\n' % (kik_id, kik_num, kik_msg, kik_typ, kik_time))
	fileh.write(REP_FOOTER)
	fileh.close()
	REPORT.append(['Applications data', '<a href="kik_messages.html">%s (%d)</a>' % (rep_title, len(kik_data))])

# # # # # 

# Decode BBM master.db  # # # # # # # # # # # # # # # # # # # #
def decode_masterdb():
	rep_title = 'Blackberry Messenger'
	con = sq.connect(OUTPUT+'db'+SEP+'master.db')
	c = con.cursor()
	bbm_data = c.execute("SELECT TextMessageId,UserPins.Pin,IsInbound,TextMessages.Timestamp,Content,PictureTransferId,Users.DisplayName,Type FROM textMessages JOIN Participants ON (TextMessages.ParticipantId=Participants.ParticipantId) JOIN UserPins ON (Participants.UserId=UserPins.UserId) JOIN Users ON (Participants.UserId=Users.UserId) ORDER BY TextMessages.Timestamp DESC").fetchall()
	fileh = open(OUTPUT+'bbm_messenger.html', 'w', encoding='UTF-8')
	fileh.write('\
<!DOCTYPE html><html><head>\n<title>%s Andriller Report for %s</title>\n<style>body,td,tr {font-family: Vernada, Arial, sans-serif; font-size: 12px;}</style></head>\n<body>\n<a href="REPORT.html">[Back]</a>\n<p align="center"><i># This report was generated using Andriller on %s #</i></p>\n<h3 align="center">[%s] %s</h3>\n<table border="1" cellpadding="2" cellspacing="0" align="center">\n<tr bgcolor="#72A0C1">\n\
	<th>#</th>\
	<th nowrap>BBM PIN</th>\
	<th>Name</th>\
	<th width="300">Message</th>\
	<th nowrap>Type</th>\
	<th nowrap>Time</th>\
	</tr>\n' % (str(rep_title), str(IMEI), str(LOCAL_TIME), str(rep_title), str(IMEI)))

	for bbm_item in bbm_data:
		bbm_msgid = str(bbm_item[0])
		bbm_msgpin = str(bbm_item[1])
		if bbm_item[2] == 1:
			bbm_msgtype = 'Inbox'
		else:
			bbm_msgtype = 'Sent'
		bbm_msgtime = datetime.utcfromtimestamp(int(str(bbm_item[3])[:10])).strftime('%Y-%m-%d %H:%M:%S UTC')
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
		# Begins writing BBM_MSG to report
		fileh.write('<tr>\
	<td>{0}</td>\
	<td nowrap>{1}</td>\
	<td>{5}</td>\
	<td width="300">{2}{6}{7}</td>\
	<td nowrap>{3}</td>\
	<td nowrap>{4}</td>\
	</tr>\n'.format(\
	bbm_msgid,		#0
	bbm_msgpin,		#1
	bbm_msgtxt,		#2
	bbm_msgtype,	#3
	bbm_msgtime,	#4
	bbm_namepin,	#5
	bbm_msgimg,		#6
	bbm_mtype,		#7
	))
	fileh.write(REP_FOOTER)
	fileh.close()
	REPORT.append(['Applications data', '<a href="bbm_messenger.html">%s (%d)</a>' % (rep_title, len(bbm_data))])
# # # # #

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# DECODING DOWNLOADED DATABASES
#
decoders = [
(decode_gesturekey, 'gesture.key'),
(decode_settingsdb, 'settings.db'),
(decode_contacts2db, 'contacts2.db'),
(decode_calls_contacts2db, 'contacts2.db'),
(decode_logsdb, 'logs.db'),
(decode_mmssmsdb, 'mmssms.db'),
(decode_threads_db2, 'threads_db2'),
(decode_photos_db, 'photos_db'),
(decode_notificationsdb, 'notifications.db'),
(decode_fbdb, 'fb.db'),
(decode_wadb, 'wa.db'),
(decode_msgstoredb, 'msgstore.db'),
(decode_kikDatabasedb, 'kikDatabase.db'),
(decode_masterdb, 'master.db'),
]

# Loop for decoding all DB's
def decode_databases(DLLS):
	for dec in decoders:
		if dec[1] in DLLS:
			try:
				print(' Decoding: ' + dec[1], end='\r')
				dec[0]()
			except:
				pass
	print(' '.join([' ' for x in range(20)]), end='\r')


if DLLS != []:
	print(">>>>>>>>>> Decoding data...")
	decode_databases(DLLS)

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# REPORTING
#
print(">>>>>>>>>> Generating report:")

file_handle = open(OUTPUT+SEP+'REPORT.html', 'w', encoding='UTF-8')

report_t = '<!DOCTYPE html><html><head>\n<title>Andriller Report for %s</title>\n<style>body,td,tr {font-family: Vernada, Arial, sans-serif; font-size: 12px;}</style></head><body>\n<p align="center"><i># This report was generated using Andriller version %s on %s #</i></p><h3 align="center">[Andriller Report] %s %s | %s</h3>\n<table border="1" cellpadding=2 cellspacing="0" align="center">\n<tr bgcolor="#72A0C1"><th>Type</th><th>Data</th></tr>\n' % (str(IMEI), ANDRILLER_VERSION, str(LOCAL_TIME), DEVICE_MANUF, str(DEVICE_MODEL), str(IMEI))

file_handle.write(report_t)

for torep in REPORT:
	file_handle.write('<tr><td>%s:</td><td>' % torep[0])
	if type(torep[1]) is list:
		for tore in torep[1]:
			file_handle.write('%s<br/>' % tore)
		file_handle.write('</td></tr>\n')
	else:
		file_handle.write('%s</td></tr>\n' % torep[1])

file_handle.write(REP_FOOTER)
file_handle.close()

# Print generated report path:
print(' ' + os.getcwd()+SEP+OUTPUT+'REPORT.html')
input(" Completed! Press 'Enter' to exit.")
