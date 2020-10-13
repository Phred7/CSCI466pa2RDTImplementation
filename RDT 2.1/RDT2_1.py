import Network
import argparse
import threading
from time import sleep, time
import hashlib
import os


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
        rcvThread = None
        stop = None
        threadTimeout = 0.1
        interval = 0.001
        requestNum = 0
        startTime = time()
        
        
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

        def disconnect(self):
                try:
                        if self.rcvThread:
                                self.stop = True
                                self.rcvThread.join()
                except RuntimeError:
                        print("cannot join rcvThread")
                
                self.net_snd.disconnect()
                self.net_rcv.disconnect()
                os._exit(1)

        def mkPkt(self, seqNum, data):
                pkt = Packet(self.seq_num, data)
                self.seq_num = 1 if self.seq_num == 0 else 0
                return pkt

        def corrupt(self, pkt): #if returns True pkt is corrupt
                return Packet.corrupt(pkt.get_byte_S())

        def isACK(self, pkt):
                return Packet.isACK(pkt.getMsgS())

        def isNAK(self, pkt):
                return Packet.isNAK(pkt.getMsgS())

        def deliverData(self):
                pass

        def getByteString(self, pkt):
                return pkt.get_byte_S()

        def getSeqNum(self, pkt):
                return pkt.getSeqNum()

        def udtSend(self, pkt):
                self.net_snd.udt_send(pkt.get_byte_S())

        def udtRcv(self):
                return self.net_rcv.udt_receive()

        def sendACK(self, seqNum):
                ack = Packet(seqNum, ("ACK:" + str(seqNum)))
                self.udtSend(ack)
                print("sendACK success:" + ack.getMsgS())
                sleep(0.06)

        def sendNAK(self, seqNum):
                nak = Packet(seqNum, ("NAK:" + str(seqNum)))
                self.udtSend(nak)
                print("sendNAK success")



        def rdt_2_1_send(self, msg_S):
                # !!! make sure to use net_snd link to udt_send and udt_receive in the RDT send function
                
                p = Packet(self.seq_num, msg_S) #make pkt 0
                #print("sending:^" + str(p) + "\n")
                
                print(str(self.requestNum) + ". Send called: ", end='')
                self.requestNum += 1
                while True:
                        print("sending: pkt " + str(self.seq_num) + "," + msg_S[0:10] + "...")
                        self.net_snd.udt_send(p.get_byte_S()) #send pkt 0
                        print("pre-recieve-ack")
                        
                        byte_S = ""
                        acked = False
                        length = None
                        
                        while(acked == False):
                                byte_S = self.net_rcv.udt_receive()
                                self.byte_buffer += byte_S
                                if((len(self.byte_buffer) < Packet.length_S_length)):
                                        pass
                                else:
                                        length = int(self.byte_buffer[:Packet.length_S_length])
                                        print("ACK length initialized")
                                        if((len(self.byte_buffer) < length)):
                                                pass
                                        else:
                                                acked = True
                                sleep(0.1)
                                
                        print("buffer:>" + str(self.byte_buffer[0:length]) + "<")
                        if(Packet.corrupt(self.byte_buffer[0:length]) == False):
                                ack = Packet.from_byte_S(self.byte_buffer[0:length])
                                print("ack created")
                                if((self.seq_num == ack.getSeqNum()) == False):
                                        print("Bad seq nums\n")
                                elif(Packet.isACK(ack)):
                                        print("Recieved ACK:" + str(self.seq_num) +"\n")
                                        self.seq_num = 1 if self.seq_num == 0 else 0
                                        self.byte_buffer = self.byte_buffer[length:]
                                        return
                                elif(Packet.isNAK(ack)):
                                        print("Recieved NAK\n")
                        else:
                                print("Recieved corrupt ACK\n")

                        print(">" + self.byte_buffer[0:10] + "<...")
                        #self.byte_buffer = ''
                        self.byte_buffer = self.byte_buffer[length:]
                        print(">" + self.byte_buffer[0:10] + "<...")
                        print()
                        sleep(0.1)
                        
 
                #self.seq_num = 1 if self.seq_num == 0 else 0 #update seq num
        
        def rdt_2_1_receive(self):
                
                p = None
                ret_S = None

                print(str(self.requestNum) + ". Recieve called")
                self.requestNum += 1
                byte_S = self.net_rcv.udt_receive()
                self.byte_buffer += byte_S
                while True:

                        if (len(self.byte_buffer) < Packet.length_S_length):
                                print("not long enough 1")
                                sleep(0.1)
                                return ret_S  

                        length = int(self.byte_buffer[:Packet.length_S_length])
                        if len(self.byte_buffer) < length:
                                print("not long enough")
                                return ret_S



                        if(Packet.corrupt(self.byte_buffer[0:length])):
                                print("Recieved corrupt pkt, ", end='')
                                self.sendNAK(self.seq_num)
                                print("Sent NAK")
                        else:
                                print("pre-packet")
                                p = Packet.from_byte_S(self.byte_buffer[0:length])
                                self.byte_buffer = self.byte_buffer[length:]
                                if(Packet.isACK(p) or Packet.isNAK(p)):
                                        #self.byte_buffer = self.byte_buffer[length:]
                                        print("Packet was ACK/NAK - removed from buffer")
                                else:
                                       
                                        
                                        print("Recieved good pkt: " + str(p.getSeqNum()) + "," + p.getMsgS()[0:10] + "...")
                                        ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                                        self.sendACK(self.seq_num)
                                        print("Sent ACK: " + str(self.seq_num) +"\n")
                                        self.seq_num = (self.seq_num + 1) if self.seq_num == 0 else 0
                                        #print("\n\nRecieved: " + str(p))
                                        return ret_S

                        self.byte_buffer = self.byte_buffer[length:]
                        #self.byte_buffer = ''
        
        def rdt_3_0_send(self, msg_S):
                pass
        
        def rdt_3_0_receive(self):
                pass

        def rdt_1_0_send(self, msg_S):
                p = Packet(self.seq_num, msg_S)
                self.seq_num += 1
                # !!! make sure to use net_snd link to udt_send and udt_receive in the RDT send function
                self.net_snd.udt_send(p.get_byte_S())         
                print("1.0 send" + str(p))
        
        def rdt_1_0_receive(self):
                #print("1.0\n")
                #this method passes the received data to the client or server (only once per packet)
                ret_S = None
                byte_S = self.net_rcv.udt_receive()
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
                #print(rdt.rdt_1_0_receive())
                print("rdt main:" + str(rdt.rdt_2_1_receive()))
                rdt.disconnect()
        
        
        else:
                sleep(1)
                #print(rdt.rdt_1_0_receive())
                print("rdt main:" + str(rdt.rdt_2_1_receive()))
                rdt.rdt_2_1_send('MSG_FROM_SERVER')
                rdt.disconnect()





##def rdt_2_1_send(self, msg_S):
##                # !!! make sure to use net_snd link to udt_send and udt_receive in the RDT send function
##                
##                p = Packet(self.seq_num, msg_S) #make pkt 0
##                #print("sending:^" + str(p) + "\n")
##                
##                print("Send called: ", end='')
##                while True:
##                        print("sending: pkt " + str(self.seq_num) + "," + msg_S[0:10] + "...")
##                        self.net_snd.udt_send(p.get_byte_S()) #send pkt 0
##                        print("pre-recieve-ack")
##                        
##                        byte_S = ""
##                        acked = False
##                        length = None
##                        while(acked == False):
##                                if((len(self.byte_buffer) < Packet.length_S_length)):
##                                        pass
##                                else:
##                                        length = int(self.byte_buffer[:Packet.length_S_length])
##                                        print("ACK length initialized")
##                                        if((len(self.byte_buffer) < length)):
##                                                pass
##                                        else:
##                                                acked = True
##                                sleep(0.1)
##                                
##                        print("buffer:>" + str(self.byte_buffer[0:length]) + "<")
##                        if(Packet.corrupt(self.byte_buffer[0:length]) == False):
##                                ack = Packet.from_byte_S(self.byte_buffer[0:length])
##                                print("ack created")
##                                if((self.seq_num == ack.getSeqNum()) == False):
##                                        print("Bad seq nums\n")
##                                elif(Packet.isACK(ack)):
##                                        print("Recieved ACK\n")
##                                        #self.seq_num = 1 if self.seq_num == 0 else 0
##                                        return
##                                elif(Packet.isNAK(ack)):
##                                        print("Recieved NAK\n")
##                        else:
##                                print("Recieved corrupt ACK\n")
##
##                        print(">" + self.byte_buffer[0:10] + "<...")
##                        #self.byte_buffer = ''
##                        self.byte_buffer = self.byte_buffer[length:]
##                        print(">" + self.byte_buffer[0:10] + "<...")
##                        sleep(0.1)
##                        
## 
##                self.seq_num = 1 if self.seq_num == 0 else 0 #update seq num
##        
##        def rdt_2_1_receive(self):
##                
##                #msg_S for ACK/NAK
##                #ACK:seq_num
##                #NAK:seq_num
##                p = None
##                ret_S = None
##
##                print("reciece called")
##                
##                while True:
##
##                        if (len(self.byte_buffer) < Packet.length_S_length):
##                                print("not long enough 1")
##                                return ret_S  
##
##                        length = int(self.byte_buffer[:Packet.length_S_length])
##                        if len(self.byte_buffer) < length:
##                                print("not long enough")
##                                return ret_S
##
##
##
##                        if(Packet.corrupt(self.byte_buffer[0:length])):
##                                print("Recieved corrupt pkt, ", end='')
##                                self.sendNAK(self.seq_num)
##                                print("Sent NAK")
##                        else:
##                                print("pre-packet")
##                                p = Packet.from_byte_S(self.byte_buffer[0:length])
##                                if(Packet.isACK(p) or Packet.isNAK(p)):
##                                        #self.byte_buffer = self.byte_buffer[length:]
##                                        print("Packet was ACK/NAK - removed from buffer")
##                                else:
##                                       
##                                        
##                                        print("Recieved good pkt: " + str(p.getSeqNum()) + "," + p.getMsgS()[0:10] + "...")
##                                        ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
##                                        self.sendACK(self.seq_num)
##                                        print("Sent ACK: " + str(self.seq_num) +"\n")
##                                        self.seq_num = (self.seq_num + 1) if self.seq_num == 0 else 0
##                                        #print("\n\nRecieved: " + str(p))
##                                        return ret_S
##
##                        self.byte_buffer = self.byte_buffer[length:]
##                        #self.byte_buffer = ''
##
##
##                #pACK = self.mkPkt(p.seq_num, (str("ACK:" + str(p.seq_num))))
##                #self.udtSend(pACK)
##
##                
##                
##                #wait for pkt 0
##                        #if pkt !corrupt and seq_num == 0
##                        #extract data
##                        #deliver data
##                        #make ACK pkt with checkSum
##                        #send pkt
##
##                        #if pkt corrupt
##                        #make NAK pkt with checkSum
##                        #send pkt
##
##                        #if pkt !corrupt and seq_num == 1 (loop on duplicates)
##                        #make ACK pkt with checkSum
##                        #send pkt
##
##                #wait for pkt 1
##                        #if pkt !corrupt and seq_num == 1
##                        #extract data
##                        #deliver data
##                        #make ACK pkt with checkSum
##                        #send pkt
##
##                        #if pkt corrupt
##                        #make a NAK pkt with checkSum
##                        #send pkt
##
##                        #if pkt !corrupt and seq_num == 0 (loop on duplicates)
##                        #make ACK pkt with checkSum
##                        #send pkt
##
##def recieveHelper(self):
##                seq_num = 1
##                rev_seq_num = None
##                elapsedTime = 0
##                startTime = time()
##                treadTimeoutMod = 400
##
##                #continually runs as rcvThread
##                while(True):
##                        
##                        if(self.threadTimeout*treadTimeoutMod < elapsedTime):
##                                print("\n\n\n\n\nRecieve thread timeout")
##                                #self.sendNAK(self.seq_num)
##                                elapsedTime = 0
##                                startTime = time()
##                                self.disconnect()
##
##                        #feeds buffer
##                        byte_S = self.udtRcv()
##                        self.byte_buffer += byte_S
##                        
##                        if(str(byte_S) == ""):
##                                elapsedTime = time() - startTime
##                        else:
##                                elapsedTime = 0
##
##                        #executes RDT 2.1 recieve FSM?
##
##                        sleep(self.interval)                             
##
##                #pass

