#
# Date: 2020-10-02
#
# Author: SN
#
# Script for extracting MSFVENOM alpha encoded shellcode.
#
# Inspired by Flare-On 2020 challenge number 7
# Reference: https://github.com/rapid7/rex-encoder/tree/master/lib/rex/encoder
#

import argparse
import io

#pip install hexdump
import hexdump

def xor(block,base): return 0xFF&(block^base)
def add(block,base): return 0xFF&(block+base)
def hn(x):return 0x0f&(x>>4)
def ln(x):return 0x0f&(x)

ENCODERS={
        b'jAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI':('rex/encoder/alpha2/alpha_mixed',xor),
        b'VTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJI':('rex/encoder/alpha2/alpha_upper',xor),
        b'jXAQADAZABARALAYAIAQAIAQAIAhAAAZ1AIAIAJ11AIAIABABABQI1AIQIAIQI111AIAJQYAZBABABABABkMAGB9u4JB':('rex/encoder/alpha2/unicode_mixed',add),
        b'QATAXAZAPU3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JB':('rex/encoder/alpha2/unicode_upper',add),
}

def decode_alpha2(b,prefix,op):
    lp=len(prefix)
    index = b.find(prefix)+lp
    theend = b.find(b'AA',index+1)
    #print(index,lp,theend)
    if(len(b)<(lp+2)): raise Exception("ERROR: input shellcode is too small")
    if(index<(lp-1)): raise Exception("ERROR: prefix not found in shellcode at expected location")
    if(theend<index):raise Exception("ERROR: shellcode doesn't end with expected TRAILER")
    encoded_part=b[index:theend]
    lep = len(encoded_part)
    if(lep%2!=0):raise Exception("ERROR: encoded shellcode length is not multiple of 2")
    ret = []
    #hexdump.hexdump(encoded_part)
    for i in range(0,lep,2):
        b1 = encoded_part[i]
        b2 = encoded_part[i+1]
        b1_hn=hn(b1)
        b1_ln=ln(b1)
        b2_hn=hn(b2)
        b2_ln=ln(b2)
        final=(0xff&((op(b1_ln,b2_hn)<<4)|b2_ln))
        ret.append(final)
    else:pass
    return bytes(ret)

def decode(fn,args):
    f = open(fn,'rb')
    d = f.read()
    f.close()
    for prefix,value in ENCODERS.items():
        if(prefix in d):
            encoder_name,operator=value
            print("{}: Detected '{}'".format(fn,encoder_name))
            output=decode_alpha2(d,prefix,operator)
            hexdump.hexdump(output)
            if(args.dump):
                fno='{}.{}'.format(fn,args.dump_extension)
                print("Writing decoded shellcode to {}".format(fno))
                f = open(fno,'wb')
                f.write(output)
                f.close()
            else:pass
            break;
        else:pass
    else:pass

    
def main():
    parser = argparse.ArgumentParser("Script for decoding msfvenom alpha encoded shellcode.")
    parser.add_argument("files", metavar="FILE", nargs='+', help="One or more files containing MSVENOM alpha encoded shellcode to decode")
    parser.add_argument("--dump", help="save the decoded shellcode to a file. Default: False",action='store_true',default=False)
    parser.add_argument("--dump-extension", help="The extension to use for the dumped shellcode. Default: msfcure",default='msfcure')
    args = parser.parse_args()

    for fn in args.files:
        decode(fn,args)
    else:pass

if __name__=="__main__":
    main()
