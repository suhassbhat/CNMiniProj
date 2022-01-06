def printallpacketinfo(data):
    packettocheck = list()

    for packet in data:
        if 'SYN' in packet['flags'] and len(packet['flags']) == 1:
            packettocheck.append(packet)

        message = {
            'SYN': f"Connection request from {packet['src']} to {packet['dst']}",
            'SYNACK': f"Connection request from {packet['dst']}is accepted and connection request to {packet['dst']} from {packet['src']}'s side is initiated.",
            'PSH': 'Indicates that packet needs to be pushed up to application layer immediately in destination',
            'URG': 'Informs the transport layer of the receiving end that the data is urgent and it should be prioritized',
            'FIN': f"Connection closed from the {packet['src']}'s side",
            'ACK': f"Acknowledges that message till {packet['ack'] - 1} is received, expecting {packet['ack']}"
        }

        if 'SYN' in packet['flags'] and 'ACK' in packet['flags']:
            relevance = message['SYNACK']
        elif 'PSH' in packet['flags'] and 'ACK' in packet['flags']:
            relevance = message['PSH'] + ' and ' + message['ACK'].lower()
        elif 'URG' in packet['flags'] and 'ACK' in packet['flags']:
            relevance = message['URG'] + ' and ' + message['ACK'].lower()
        elif 'ACK' in packet['flags'] and len(packet['flags']) == 1:
            for check in packettocheck:
                if check['src'] == packet['src'] and check['dst'] == packet['dst'] and check['srcport'] == packet['srcport'] and check['dstport'] == packet['dstport']:
                    packettocheck.remove(check)
                    relevance = f"Connection between {packet['src']} and {packet['dst']} has been set up. The connection is ready for data transfer now."
                    break
            else:
                relevance = message[packet['flags'][0]]
        else:
            relevance = message[packet['flags'][0]]

        print(f"Packet {packet['count']}: {packet['flags']}")
        print(f"src: {packet['src']}")
        print(f"dst: {packet['dst']}")
        print(f"ack: {packet['ack']}")
        print(f"seq: {packet['seq']}")
        print(f"Flag relevance: {relevance}")
        print()


def printflaginfo(data, flag):
    filtereddata = list()
    for packet in data:
        if flag in packet['flags']:
            filtereddata.append(packet)
    if len(filtereddata) == 0:
        print('Flag not found in given wireshark output!')
        print()
    else:
        print(
            f'{round(((len(filtereddata)/len(data)) * 100), 2)}% of packets have this flag')
        print()

        count = 0
        for packet in filtereddata:
            count = count + 1
            print(f"Packet {packet['count']}: {packet['flags']}")
            print(f"src: {packet['src']}")
            print(f"dst: {packet['dst']}")
            print(f"ack: {packet['ack']}")
            print(f"seq: {packet['seq']}")
            print()
