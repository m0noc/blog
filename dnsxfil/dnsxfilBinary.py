#!/usr/bin/python
# coding=utf-8
"""
LICENSE http://www.apache.org/licenses/LICENSE-2.0
"""
import datetime
import sys
import time
import threading
import traceback
import SocketServer
from dnslib import *
import base64

xfilGlobal = {
        'maxLineLen': 64,
        'result': list(),
        'tmp': list(),
        'chars': set("1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM+/")
        }

class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


D = DomainName('example.com')
IP = '127.0.0.1'
TTL = 60 * 5
PORT = 53

soa_record = SOA(
    mname=D.ns1,  # primary name server
    rname=D.andrei,  # email of the domain administrator
    times=(
        201307231,  # serial number
        60 * 60 * 1,  # refresh
        60 * 60 * 3,  # retry
        60 * 60 * 24,  # expire
        60 * 60 * 1,  # minimum
    )
)
ns_records = [NS(D.ns1), NS(D.ns2)]
records = {
    D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
    D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
    D.ns2: [A(IP)],
    D.mail: [A(IP)],
    D.andrei: [CNAME(D)],
}

def processRecord(xfil):
    print "Processing record"
    curLine = 0
    delim = ""

    if 'solved' not in xfil:
        xfil['solved'] = 0

    for line in xfil['tmp']:
        if line[0:6] == "START.":
            delim = line[6:]
            print "  [info] Using deliminiator \"" + delim + "\""
            if len(delim) == 1:
                xfil['chars'] -= set(delim)
        elif line[0:4] == "END.":
            # Finished processing
            if 'lineCount' not in xfil:
                xfil['lineCount'] = curLine
            elif xfil['lineCount'] != curLine:
                print "  [info] line count " + str(curLine) + " does not match last count of " + str(xfil['lineCount'])
            if xfil['solved'] == xfil['lineCount']:
                print "  [info] **** SOLUTION FOUND ****"
                xfil['chars'] = set("")
                b64Str = ""
                for line in xfil['result']:
                    if 'solved' in line:
                        b64Str += line['solved']
                    else:
                        print "  [error] no solution for line"
                if 'filename' in xfil:
                    print "  [info] Writing file " + xfil['filename']
                    f = open(xfil['filename'],"w")
                    f.write(base64.b64decode(b64Str))
                    f.close()
        elif line == "LINE":
            curLine += 1
            if 'lineCount' not in xfil:
                xfil['result'].append({})
        elif line[0:5] == "DATA.":
            # Data to process
            if delim in xfil['result'][curLine-1]:
                print "  [warn] We already have data for deliminator " + delim + ": " + line
            if 'solved' not in xfil['result'][curLine-1]:
                xfil['result'][curLine-1][delim] = []
                for label in line[5:].split("."):
                    if label[0:1] == "D":
                        if label != "D":
                            xfil['result'][curLine-1][delim].append(label[1:])
                    else:
                        print "  [warn] Unexpected item in the bagging area: " + line
                possSol = delim.join(xfil['result'][curLine-1][delim])
                if len(possSol) == xfil['maxLineLen']:
                    print "  [info] Solved line " + str(curLine) + ": " + possSol
                    xfil['result'][curLine-1]['solved'] = possSol
                    xfil['solved'] += 1
                else:
                    dup = ""
                    for i in range(0,len(possSol)-1):
                        if possSol[i] == possSol[i+1]:
                            dup += possSol[i]
                    dupSet = set(dup)
                    goodSet = set(possSol) - dupSet
                    goodSet &= xfil['chars']
                    print "  [info] good choice for line " + str(curLine) + " is: " + repr(goodSet)
                    xfil['result'][curLine-1]['goodSet'] = goodSet
        elif line[0:5] == "LAST.":
            if 'lineCount' not in xfil:
                print "  [error] got a last line record but dont know how many lines"
            else:
                print "  [info] Solved lastline: " + line[5:]
                xfil['result'][curLine-1]['solved'] = line[5:]
                xfil['solved'] += 1

    # Global good set
    knownUnsolved = 0
    goodSet = set(xfil['chars'])
    for line in xfil['result']:
        if ('solved'  not in line) and ('goodSet' in line):
            goodSet &= line['goodSet']
            knownUnsolved += 1

    # print "  [debug] current state: " + repr(xfil)
    print "  [info] Global good set is: " + repr(goodSet)
    print("  [info] Solved " + str(xfil['solved']) + "/" + str(xfil['lineCount']) + " lines with partial info on " +
            str(knownUnsolved) + " lines and no information on " +
            str(xfil['lineCount'] - xfil['solved'] - knownUnsolved) + " lines"
            )
    xfil['tmp'] = []
    return

def dns_response(data):
    request = DNSRecord.parse(data)

    #print request

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q,
            a=RR("m0noc.com", rdata=A("10.66.10.201"))
            )

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]

    if qt == "A":
        pabOut = qn[0:-1]
        xfilGlobal['tmp'].append(pabOut)
        if pabOut[0:4] == "END.":
            processRecord(xfilGlobal)

    return reply.pack()


class BaseRequestHandler(SocketServer.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        #now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        #print "\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
        #                                       self.client_address[1])
        try:
            data = self.get_data()
            #print len(data), data.encode('hex')  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = int(data[:2].encode('hex'), 16)
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = hex(len(data))[2:].zfill(4).decode('hex')
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "usage: " + sys.argv[0] + " saveFile"
        exit(1)
    xfilGlobal['filename'] = sys.argv[1]
    print "Starting nameserver..."

    servers = [
        SocketServer.ThreadingUDPServer(('', PORT), UDPRequestHandler),
        SocketServer.ThreadingTCPServer(('', PORT), TCPRequestHandler),
    ]
    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print "%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name)

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()
