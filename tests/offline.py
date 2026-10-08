#!/usr/bin/env python3
"""Independent known-byte PCAP fixtures test link decoding and TCP/TLS reconstruction."""
import json
import pathlib
import socket
import struct
import subprocess
import sys
import tempfile

binary = pathlib.Path(sys.argv[1]).resolve()

def tcp(source, destination, seq, flags, payload=b''):
    transport = struct.pack('!HHIIBBHHH',source,destination,seq,0,5<<4,flags,65535,0,0)+payload
    addresses = socket.inet_aton('10.0.0.1')+socket.inet_aton('10.0.0.2')
    return struct.pack('!BBHHHBBH',0x45,0,20+len(transport),1,0x4000,64,6,0)+addresses+transport

def record(length): return b'\x17\x03\x03'+struct.pack('!H',length)+b'z'*length

data = record(80)+record(130)
packets = [tcp(12345,443,1000,2),tcp(12345,443,1001,24,data[:2]),
           tcp(12345,443,1041,24,data[40:]),tcp(12345,443,1003,24,data[2:40]),
           tcp(12345,443,1001,24,data)]
passed=[]
with tempfile.TemporaryDirectory(prefix='yjpdding-offline-') as temp:
    temp=pathlib.Path(temp)
    for link in (1,101,113,276):
        def wrap(p):
            if link == 1: return bytes(12)+b'\x08\x00'+p
            if link == 113: return bytes(14)+b'\x08\x00'+p
            if link == 276: return b'\x08\x00'+bytes(18)+p
            return p
        path=temp/f'{link}.pcap'
        content=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,262144,link)
        for index,p in enumerate(packets):
            p=wrap(p);content+=struct.pack('<IIII',1700000000,index*100,len(p),len(p))+p
        path.write_bytes(content)
        out=temp/f'out{link}'
        subprocess.run([str(binary),'analyze',str(path),'--server','10.0.0.2:443','--output',str(out)],check=True,capture_output=True)
        report=json.loads(next(out.glob('*/report.json')).read_text())
        assert report['summary']['packets_matched']==5
        assert report['flows'][0]['up']['tls']['record_lengths']==[80,130]
        assert report['flows'][0]['up']['unique_bytes']==len(data)
        assert report['flows'][0]['up']['duplicate_bytes']==len(data)
        assert report['padding']['scheme'] is None
        passed.append(f'link-{link}-reassembly')
    # Minimal pcapng section + interface + enhanced packet blocks.
    def block(kind,body):
        body+=bytes((-len(body))%4);length=len(body)+12
        return struct.pack('<II',kind,length)+body+struct.pack('<I',length)
    content=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
    content+=block(1,struct.pack('<HHI',101,0,262144))
    for i,p in enumerate(packets):content+=block(6,struct.pack('<IIIII',0,0,i,len(p),len(p))+p)
    p=temp/'fixture.pcapng';p.write_bytes(content)
    subprocess.run([str(binary),'analyze',str(p),'--server','10.0.0.2','--output',str(temp/'ng')],check=True,capture_output=True)
    report=json.loads(next((temp/'ng').glob('*/report.json')).read_text())
    assert report['flows'][0]['up']['tls']['record_lengths']==[80,130]
    passed.append('pcapng')
    for name,content in [('empty',struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,262144,101)),('corrupt',b'not a pcap')]:
        p=temp/(name+'.pcap');p.write_bytes(content)
        completed=subprocess.run([str(binary),'analyze',str(p),'--server','10.0.0.2','--output',str(temp/name)],capture_output=True)
        assert completed.returncode == (2 if name=='empty' else 1)
        passed.append(name)
    for option,value in [('--duration','0'),('--duration','-1'),('--max-mib','0')]:
        completed=subprocess.run([str(binary),'capture','example.com',option,value],capture_output=True)
        assert completed.returncode != 0
        passed.append(option+'='+value)
print(json.dumps({'passed':passed,'count':len(passed)},indent=2))
