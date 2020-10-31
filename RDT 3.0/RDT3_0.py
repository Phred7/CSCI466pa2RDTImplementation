import Network
import argparse
from time import sleep, time
import hashlib
import threading


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

        def equal(self, other):
                return ((self.msg_S == other.msg_S) and (self.seq_num == other.seq_num))
        
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
        seq_num = 0
        ## buffer of bytes read from network
        byte_buffer = ''
        p = None
        lastP = None
        pACK = None
        rcvThread = None
        sndThread = None
        sndQueue = None
        timerThread = None
        stop = None
        sendSuccess = False
        sendTimeout = .45
        elapsed = 0
        isServer = None
        debugLen = 20
        debugging = True
        
        
        def __init__(self, role_S, server_S, port):
                # use the passed in port and port+1 to set up unidirectional links between
                # RDT send and receive functions
                # cross the ports on the client and server to match net_snd to net_rcv
                if role_S == 'server':
                        self.net_snd = Network.NetworkLayer(role_S, server_S, port)
                        self.net_rcv = Network.NetworkLayer(role_S, server_S, port+1)
                        self.isServer = True
                else:
                        self.net_rcv = Network.NetworkLayer(role_S, server_S, port)
                        self.net_snd = Network.NetworkLayer(role_S, server_S, port+1)
                        self.isServer = False
                        
                self.sndQueue = []
                self.rcvThread = threading.Thread(name='RCV Helper', target=self.rcvHelper)
                self.sndThread = threading.Thread(name='SND Queue', target=self.sndQueueHelper)
                self.timerThread = threading.Thread(name='Timer', target=self.timer)
                self.stop = False
                self.rcvThread.start()
                self.sndThread.start()
                self.timerThread.start()

        @staticmethod
        def getDebugging():
                return RDT.debugging
        
        def disconnect(self):
                self.stop = True
                self.rcvThread.join()
                self.sndThread.join()
                self.timerThread.join()
                
##                if(self.isServer == False):
##                        for x in range(0, 3):
##                                self.sendACK(-1)
                self.net_snd.disconnect()
                self.net_rcv.disconnect()

        def mkPkt(self, seqNum, data): #does not incriment seq_num!
                pkt = Packet(seqNum, data)
                return pkt

##        def sendACK(self, seqNum):
##                ack = Packet(seqNum, ("ACK:" + str(seqNum)))
##                self.net_snd.udt_send(ack.get_byte_S())
##                if(self.debugging == True):
##                        print(str(self.elapsed) + "_ACK Sent:" + ack.getMsgS())
##                return True
##
##        def sendNAK(self, seqNum):
##                nak = Packet(seqNum, ("NAK:" + str(seqNum)))
##                self.net_snd.udt_send(nak.get_byte_S())
##                if(self.debugging == True):
##                        print(str(self.elapsed) + "_NAK Sent:" + nak.getMsgS())



        def sndQueueHelper(self):
                if(self.debugging == True):
                        print(str(time()) + "_snd thread starting")
                while(self.stop != True):
                        if(self.sndQueue):
                                pkt = self.sndQueue.pop(0)
                                self.net_snd.udt_send(pkt.get_byte_S())
                                if(self.debugging == True):
                                        print(str(self.elapsed) + "_pkt sent: " + str(pkt.msg_S[0:self.debugLen]))
                        sleep(0.0001)

        def addQueue(self, pkt):
                self.sndQueue.append(pkt)
                if(self.debugging == True):
                        print(str(self.elapsed) + "_pkt queued: " + str(pkt.msg_S[0:self.debugLen]))


        def timer(self):
                startTime = time()
                self.elapsed = 0
                if(self.debugging == True):
                        print(str(time()) + "_timer thread starting\n\n")
                while(self.stop != True):
                        self.elapsed = round((time() - startTime), 3)
                        sleep(0.0005)

        def rcvHelper(self):
                if(self.debugging == True):
                        print(str(time()) + "_rcv thread starting")
                while(self.stop != True):
                        #self.elapsed = round((time() - startTime), 3)
                        byte_S = self.net_rcv.udt_receive()
                        self.byte_buffer += byte_S

                        if (len(self.byte_buffer) < Packet.length_S_length):
                                continue  

                        length = int(self.byte_buffer[:Packet.length_S_length])
                        if len(self.byte_buffer) < length:
                                continue 

                        if (Packet.corrupt(self.byte_buffer[0:length])):
                                if(length < 100): #means that we're waiting for an ACK so no need to send a response, but need to resend pkt
                                        if(self.debugging == True):
                                                print(str(self.elapsed) + "_recieved corrupt ACK>" + str(self.byte_buffer[0:(self.debugLen*2)]) + "<...")
                                        nak = Packet(self.seq_num, ("NAK:" + str(self.seq_num)))
                                        #self.pACK = nak
                                        self.byte_buffer = self.byte_buffer[length:]
                                        continue
                                else: 
                                        if(self.debugging == True):
                                                print(str(self.elapsed) + "_recieved corrupt pkt>" + str(self.byte_buffer[0:(self.debugLen*2)]) + "<...")
                                        nak = Packet(self.seq_num, ("NAK:" + str(self.seq_num)))
                                        self.addQueue(nak)
                                        if(self.debugging == True):
                                                print(str(self.elapsed) + "_NAK Sent:" + nak.getMsgS())
                                        self.byte_buffer = self.byte_buffer[length:]
                                        continue

                        p = Packet.from_byte_S(self.byte_buffer[0:length])
                        self.byte_buffer = self.byte_buffer[length:]

                        if(self.seq_num == p.seq_num):
                                if(Packet.isACK(p) or Packet.isNAK(p)):
                                        self.pACK = p
                                        if(self.debugging == True):
                                                print(str(self.elapsed) + "_recieved: " + str(p.msg_S))
                                        continue
                                
                                if(self.debugging == True):
                                        print(str(self.elapsed) + "_recieved data: " + str(p.seq_num) + ">" + str(p.msg_S[0:self.debugLen]) + "<...")
                                ack = Packet(p.seq_num, ("ACK:" + str(p.seq_num)))
                                self.addQueue(ack)
                                if(self.debugging == True):
                                        print(str(self.elapsed) + "_ACK Sent:" + ack.getMsgS())
                                self.seq_num = 1 if self.seq_num == 0 else 0
                                self.p = p
                                #self.seq_num = self.seq_num + 1

                        else:
                                if(self.lastP != None):    
                                        if(p.equal(self.lastP)):
                                                ack = Packet(p.seq_num, ("ACK:" + str(p.seq_num)))
                                                if(self.debugging == True):
                                                        print(str(self.elapsed) + "_recieved duplicate data pkt: " + str(p.seq_num) + ">" + str(p.msg_S[0:self.debugLen]) + "<...")
                                                        print(str(self.elapsed) + "_ACK resent:" + ack.getMsgS())
                                                self.addQueue(ack)
                                                continue
                                        
                                if(self.debugging == True):
                                        print(str(self.elapsed) + "_recieved ACK/data with bad seqNum (should be " + str(self.seq_num) + "): " + str(p.seq_num) + ">" + str(p.msg_S[0:self.debugLen]) + "<...")
                                pass

##                        while rcvHelperThread is running
##                                fill the bytebuffer with bytes that this recieves
##                                if the length of the bytebuffer is not long enough to determine packet length go to top of loop
##                                if the length of the bytebuffer is less than the length of this incomming packet go to top of loop
##                                if this packet is corrupt and length of this packet is less than 100 forward a NAK to this sender so that it resend the last packet then go to top of loop
##                                if this packet is corrupt and length of this packet is greater than 100 send a NAK to the source of this packet then go to top of loop
##                                if this packet has the same seqNum as this instance and this packet is an ACK or a NAK forward this packet to this sender then go to top of loop
##                                if this packet has the same seqNum as this instance and this packet is not an ACK or NAK send an ACK to the source of this packet, recieve the packet and incriment this seqNum
##                                if this packet does not have the same seqNum as this instancedo nothing
                                
                                        
                                

                        
        
        def rdt_3_0_send(self, msg_S):
                p = Packet(self.seq_num, msg_S)
                self.sendSuccess = False
                if(self.debugging == True):
                                        print()
                while(self.sendSuccess == False):
                        try:
                                self.addQueue(p)
                        except ConnectionAbortedError as err:
                                print("Connection aborted")
                                self.disconnect()
                                break
                        if(self.debugging == True):
                                print(str(self.elapsed) + "_sending pkt: " + str(self.seq_num) + ">" + str(p.msg_S[0:self.debugLen]) + "<...")
                        startTime = time()
                        elapsed = 0
                        
                        while((self.pACK == None) and (elapsed < self.sendTimeout)):
                                try:
                                        elapsed = (time() - startTime)
                                except KeyboardInterrupt as err:
                                        self.disconnect()
                                        return

                        if(elapsed > self.sendTimeout):
                                if(self.debugging == True):
                                        print(str(self.elapsed) + "_sender timeout")
                                continue

##                        if((self.pACK.seq_num == self.seq_num) == False):
##                                if(self.debugging == True):
##                                        print(str(self.elapsed) + "_sender received bad seqNum")
##                                self.pACK = None
##                                continue
                        
                        if((Packet.isACK(self.pACK))):
                                #self.seq_num += 1
                                self.seq_num = 1 if self.seq_num == 0 else 0
                                self.sendSuccess = True
                                if(self.debugging == True):
                                        print(str(self.elapsed) + "_send success: recieved " + str(self.pACK.msg_S))
                                        print()
                                self.pACK = None
                                elapsed = 0
                                return
                        
                        if((Packet.isNAK(self.pACK))):
                                if(self.debugging == True):
                                        print(str(self.elapsed) + "_send failed: recieved " + str(self.pACK.msg_S))
                                self.pACK = None
                                continue

                        
        
        def rdt_3_0_receive(self):
                ret_S = None
                while(True):
                        if(self.p == None):
                                return ret_S
                        else:
                                ret_S = self.p.msg_S
                                self.lastP = self.p
                                self.p = None
                                return ret_S

                        



if __name__ == '__main__':
        parser = argparse.ArgumentParser(description='RDT implementation.')
        parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
        parser.add_argument('server', help='Server.')
        parser.add_argument('port', help='Port.', type=int)
        args = parser.parse_args()
        
        rdt = RDT(args.role, args.server, args.port)
        if args.role == 'client':
                rdt.rdt_3_0_send('MSG_FROM_CLIENT')
                sleep(2)
                print(rdt.rdt_3_0_receive())
                rdt.disconnect()
        
        
        else:
                sleep(1)
                print(rdt.rdt_3_0_receive())
                rdt.rdt_3_0_send('MSG_FROM_SERVER')
                rdt.disconnect()
