import Network
import argparse
from time import sleep
import hashlib


class Packet:
        ## the number of bytes used to store packet length
        seq_num_S_length = 10
        length_S_length = 10
        ## length of md5 checksum in hex
        checksum_length = 32
        
        def __init__(self, seq_num, msg_S):
                self.seq_num = seq_num
                self.msg_S = msg_S
        
        @classmethod
        def from_byte_S(self, byte_S):
                if Packet.corrupt(byte_S):
                        raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
                # extract the fields
                seq_num = int(byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length])
                msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length:]
                return self(seq_num, msg_S)
        
        def get_byte_S(self):
                # convert sequence number of a byte field of seq_num_S_length bytes
                seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
                # convert length to a byte field of length_S_length bytes
                length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(
                        self.length_S_length)
                # compute the checksum
                checksum = hashlib.md5((length_S + seq_num_S + self.msg_S).encode('utf-8'))
                checksum_S = checksum.hexdigest()
                # compile into a string
                return length_S + seq_num_S + checksum_S + self.msg_S
        
        @staticmethod
        def corrupt(byte_S):
                # extract the fields
                length_S = byte_S[0:Packet.length_S_length]
                seq_num_S = byte_S[Packet.length_S_length: Packet.length_S_length + Packet.seq_num_S_length]
                checksum_S = byte_S[
                             Packet.length_S_length + Packet.seq_num_S_length: Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length]
                msg_S = byte_S[Packet.length_S_length + Packet.seq_num_S_length + Packet.checksum_length:]
                
                # compute the checksum locally
                checksum = hashlib.md5(str(length_S + seq_num_S + msg_S).encode('utf-8'))
                computed_checksum_S = checksum.hexdigest()
                # and check if the same
                return checksum_S != computed_checksum_S

        def __str__(self):
                return ("\nPACKET: " + str(self.seq_num) + "\n")


class RDT:
        ## latest sequence number used in a packet
        seq_num = 1
        ## buffer of bytes read from network
        byte_buffer = ''
        
        def __init__(self, role_S, server_S, port):
                self.network = Network.NetworkLayer(role_S, server_S, port)
        
        def disconnect(self):
                self.network.disconnect()

        def mkPkt(self, seqNum, data):
                pkt = Packet(self.seq_num, data)
                self.seq_num = 1 if self.seq_num == 0 else 0
                return pkt

        def corrupt(self, pkt):
                return Packet.corrupt(pkt.get_byte_S())

        def isACK(self, pkt):
                pass

        def isNAK(self, pkt):
                pass

        def deliver_data(self, data):
                #this method passes the received data to the client or server (only once per packet)
                pass

        def extract(self, pkt):
                pass

        def getSeqNum(self, pkt):
                pass

        def udt_send(self, pkt):
                self.network.udt_send(pkt.get_byte_S())
        
        def rdt_1_0_send(self, msg_S):
                p = Packet(self.seq_num, msg_S)
                print(p)
                self.seq_num += 1
                self.network.udt_send(p.get_byte_S())
        
        def rdt_1_0_receive(self):
                ret_S = None
                byte_S = self.network.udt_receive()
                self.byte_buffer += byte_S
                # keep extracting packets - if reordered, could get more than one
                while True:
                        # check if we have received enough bytes
                        if (len(self.byte_buffer) < Packet.length_S_length):
                                return ret_S  # not enough bytes to read packet length
                        # extract length of packet
                        length = int(self.byte_buffer[:Packet.length_S_length])
                        if len(self.byte_buffer) < length:
                                return ret_S  # not enough bytes to read the whole packet
                        # create packet from buffer content and add to return string
                        p = Packet.from_byte_S(self.byte_buffer[0:length])
                        ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                        # remove the packet bytes from the buffer
                        self.byte_buffer = self.byte_buffer[length:]
                # if this was the last packet, will return on the next iteration
        
        def rdt_2_1_send(self, msg_S):
                #if rdt send called
                        #make pkt 0
                        #send pkt 0

                #wait for ACK/NAK 0
                        #if rcv pkt and (pkt corrupt || isNAK)
                        #resend pkt 0

                        #if rcv pkt and pkt !corrupt and pkt is ACK
                        #move on

                #if rdt send called
                        #make pkt 1
                        #send pkt 1

                #wait for ACK/NAK 1
                        #if rcv pkt and (pkt corrupt || isNAK)
                        #resend pkt 1

                        #if rcv pkt and pkt !corrupt and pkt is ACK
                        #move on                    
                pass
        
        def rdt_2_1_receive(self):
                #wait for pkt 0
                        #if pkt !corrupt and seq_num == 0
                        #extract data
                        #deliver data
                        #make pkt with checkSum
                        #send pkt

                        #if pkt corrupt
                        #make a NAK pkt with checkSum
                        #send pkt

                        #if pkt !corrupt and seq_num == 1 (loop on duplicates)
                        #make a NAK pkt with checkSum
                        #send pkt

                #wait for pkt 1
                        #if pkt !corrupt and seq_num == 1
                        #extract data
                        #deliver data
                        #make pkt with checkSum
                        #send pkt

                        #if pkt corrupt
                        #make a NAK pkt with checkSum
                        #send pkt

                        #if pkt !corrupt and seq_num == 0 (loop on duplicates)
                        #make a NAK pkt with checkSum
                        #send pkt
                        
                pass
        
        def rdt_3_0_send(self, msg_S):
                pass
        
        def rdt_3_0_receive(self):
                pass


if __name__ == '__main__':
        parser = argparse.ArgumentParser(description='RDT implementation.')
        parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
        parser.add_argument('server', help='Server.')
        parser.add_argument('port', help='Port.', type=int)
        args = parser.parse_args()
        
        rdt = RDT(args.role, args.server, args.port)
        if args.role == 'client':
                rdt.rdt_1_0_send('MSG_FROM_CLIENT')
                sleep(2)
                print(rdt.rdt_1_0_receive())
                rdt.disconnect()
        
        
        else:
                sleep(1)
                print(rdt.rdt_1_0_receive())
                rdt.rdt_1_0_send('MSG_FROM_SERVER')
                rdt.disconnect()
