import Network
import argparse
import threading
from time import sleep, time
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

        def getSeqNum(self):
                return self.seq_num

        def getMsgS(self):
                return self.msg_S

        def __str__(self):
                return ("PACKET: " + str(self.seq_num))
        
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

        @staticmethod
        def isACK(pkt):
                msg_S = pkt.getMsgS()
                if "ACK:" in msg_S:
                        #print("ACK: " + str(msg_S))
                        return True
                return False

        @staticmethod
        def isNAK(pkt):
                msg_S = pkt.getMsgS()
                if "NAK:" in msg_S:
                        #print("NAK: " + str(msg_S))
                        return True
                return False


class RDT:
        ## latest sequence number used in a packet
        seq_num = 1
        ## buffer of bytes read from network
        byte_buffer = ''
        requestNum = 0
        debugging = False
        
        
        def __init__(self, role_S, server_S, port):
                # use the passed in port and port+1 to set up unidirectional links between
                # RDT send and receive functions
                # cross the ports on the client and server to match net_snd to net_rcv
                if role_S == 'server':
                        self.net_snd = Network.NetworkLayer(role_S, server_S, port)
                        self.net_rcv = Network.NetworkLayer(role_S, server_S, port+1)
                else:
                        self.net_rcv = Network.NetworkLayer(role_S, server_S, port)
                        self.net_snd = Network.NetworkLayer(role_S, server_S, port+1)

        @staticmethod
        def getDebugging():
                return RDT.debugging

        def disconnect(self):
                self.net_snd.disconnect()
                self.net_rcv.disconnect()

        def mkPkt(self, seqNum, data):
                pkt = Packet(self.seq_num, data)
                #self.seq_num = 1 if self.seq_num == 0 else 0
                self.seq_num += 1
                return pkt

        def getByteString(self, pkt):
                return pkt.get_byte_S()

        def getSeqNum(self, pkt):
                return pkt.getSeqNum()

        def udtSend(self, pkt):
                try:
                        self.net_snd.udt_send(pkt.get_byte_S())
                except ConnectionAbortedError as err:
                        self.disconnect()
                except ConnectionResetError as err:
                        pass

        def udtRcv(self):
                return self.net_rcv.udt_receive()

        def sendACK(self, seqNum):
                ack = Packet(seqNum, ("ACK:" + str(seqNum)))
                self.udtSend(ack)
                if(self.debugging == True):
                        print("sendACK success:" + ack.getMsgS())

        def sendNAK(self, seqNum):
                nak = Packet(seqNum, ("NAK:" + str(seqNum)))
                self.udtSend(nak)
                if(self.debugging == True):
                        print("sendNAK success")



        def rdt_2_1_send(self, msg_S):
                # !!! make sure to use net_snd link to udt_send and udt_receive in the RDT send function
                p = Packet(self.seq_num, msg_S)
                
                if(self.debugging == True):
                        print(str(self.requestNum) + ". Send called: ")
                self.requestNum += 1
                
                while True:
                        self.udtSend(p) #send pkt
                        if(self.debugging == True):
                                print("sending: pkt " + str(self.seq_num) + "," + msg_S[0:10] + "...")
                                print("pre-recieve-ack")
                        
                        byte_S = ""
                        acked = False
                        length = None
                        initial = time()
                        elapsed = 0
                        timeout = 8
                        while(acked == False):
                                elapsed = time() - initial

                                if(elapsed > timeout):
                                        initial = time()
                                        print("\n\nsender timeout\n\n")
                                        return
                                        
                                byte_S = self.net_rcv.udt_receive()
                                self.byte_buffer += byte_S
                                if((len(self.byte_buffer) < Packet.length_S_length)):
                                        pass
                                else:
                                        length = int(self.byte_buffer[:Packet.length_S_length])
                                        if(self.debugging == True):
                                                print("ACK length initialized")
                                        if((len(self.byte_buffer) < length)):
                                                pass
                                        else:
                                                acked = True

                        if(self.debugging == True):
                                print("buffer:>" + str(self.byte_buffer[0:length]) + "<")
                        if(Packet.corrupt(self.byte_buffer[0:length]) == False):
                                ack = Packet.from_byte_S(self.byte_buffer[0:length])
                                if(self.debugging == True):
                                        print("ack created")
                                if((self.seq_num == ack.getSeqNum()) == False):
                                        if(self.debugging == True):
                                                print("Bad seq nums")
                                                print("Send ACK-1 to ensure reciept")
                                                
                                        else:
                                                pass
                                        #lastACK = 0 if (self.seq_num == 1) else 1
                                        lastACK = self.seq_num - 1
                                        self.sendACK(lastACK)
                                        
                                elif(Packet.isACK(ack)):
                                        if(self.debugging == True):
                                                print("Recieved ACK:" + str(self.seq_num) +"\n")
                                        #self.seq_num = 1 if self.seq_num == 0 else 0
                                        self.seq_num += 1
                                        self.byte_buffer = self.byte_buffer[length:]
                                        return
                                elif(Packet.isNAK(ack)):
                                        if(self.debugging == True):
                                                print("Recieved NAK")
                                        else:
                                                pass
                        else:
                                if(self.debugging == True):
                                        print("Recieved corrupt ACK")
                                else:
                                        pass
                        if(self.debugging == True):
                                print(">" + self.byte_buffer[0:10] + "<...")
                        self.byte_buffer = self.byte_buffer[length:]
                        if(self.debugging == True):
                                print(">" + self.byte_buffer[0:10] + "<...")
                                print()
                sleep(0.1)

                        
        
        def rdt_2_1_receive(self):
                
                p = None
                ret_S = None

                
                byte_S = self.udtRcv()
                self.byte_buffer += byte_S
                while True:

                        if (len(self.byte_buffer) < Packet.length_S_length):
##                                if(self.debugging == True):
##                                        print("not long enough 1")
                                return ret_S
                        
                        if(self.debugging == True):             
                                print(str(self.requestNum) + ". Recieve called")
                        length = int(self.byte_buffer[:Packet.length_S_length])
                        
                        if len(self.byte_buffer) < length:
                                if(self.debugging == True):
                                        print("not long enough")
                                return ret_S

                        if(Packet.corrupt(self.byte_buffer[0:length])):
                                if(self.debugging == True):
                                        print("Recieved corrupt pkt, ", end='')
                                self.sendNAK(self.seq_num)
                                if(self.debugging == True):
                                        print("Sent NAK: " + str(self.seq_num) + "\n")
                        else:
                                if(self.debugging == True):
                                        print("pre-packet")
                                p = Packet.from_byte_S(self.byte_buffer[0:length])
                                if(Packet.isACK(p) or Packet.isNAK(p)): #
                                        if(self.debugging == True):
                                                print("Packet was ACK/NAK - removed from buffer\n")
                                        else:
                                                pass
                                else:
                                        self.requestNum += 1
                                        self.byte_buffer = self.byte_buffer[length:]
                                        if(self.debugging == True):
                                                print("Recieved good pkt: " + str(p.getSeqNum()) + "," + p.getMsgS()[0:10] + "...")
                                        ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                                        self.sendACK(self.seq_num)
                                        if(self.debugging == True):
                                                print("Sent ACK: " + str(self.seq_num) +"\n")
                                        #self.seq_num = (self.seq_num + 1) if self.seq_num == 0 else 0
                                        self.seq_num += 1
                                        return ret_S

                        self.byte_buffer = self.byte_buffer[length:]



if __name__ == '__main__':
        parser = argparse.ArgumentParser(description='RDT implementation.')
        parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
        parser.add_argument('server', help='Server.')
        parser.add_argument('port', help='Port.', type=int)
        args = parser.parse_args()
        
        rdt = RDT(args.role, args.server, args.port)
        if args.role == 'client':
                rdt.rdt_2_1_send('MSG_FROM_CLIENT')
                sleep(2)
                print("rdt main:" + str(rdt.rdt_2_1_receive()))
                rdt.disconnect()
        
        
        else:
                sleep(1)
                print("rdt main:" + str(rdt.rdt_2_1_receive()))
                rdt.rdt_2_1_send('MSG_FROM_SERVER')
                rdt.disconnect()
                
