import olefile
import zlib
import re
import sys
import collections
import math

# FileHeader / DocInfo / 005HwpSummaryInformation / PrvText == Strict
# BodyText / BinData / PrvImage / DocOptions / Scripts / XMLTemplate / DocHistory == not Strict

# DocInfo / BodyText / Bindata / DocHistory == compressed data




def function_replace(data):
  # Winexh
  data = re.sub(b'\x68\x57\x69\x6e\x45',b'\x90\x90\x90\x90\x90', data)
  # urlmon.dll
  data = re.sub(b'\x64\x2e\x6e\x6f\x6d\x6c\x72\x75',b'\x90\x90\x90\x90\x90\x90\x90\x90', data)
  # cmd
  data = re.sub(b'\x63\x6d\x64\2e',b'\x90\x90\x90\x90', data)
  
  return data

# PEB(Process Environment Block)
def teb_replace(data): #
  # prevent greb teb for topstack
  data = re.sub(b'\x64\x8b'+b'.'+b'\x18',b'\x90\x90\x90\x90',data)

  return data

# PEB(Process Environment Block)
def peb_replace(data): # PEB + 0x0C = PEB LDR DATA address + 0x14 = in memory module list

  # replace <mov $reg,DWORD PTR fs:0x30> // 64 8b ?? 30
  data = re.sub(b'\x64\x8b'+b'.'+b'\x30',b'\x90\x90\x90\x90',data)

  # replace <mov $reg, fs:[$reg+30h]>// 31 ?? 64 8b ?? 30
  data = re.sub(b'\x31'+b'.'+ b'\x64\x8b.\x30',b'\x90\x90\x90\x90\x90\x90',data)


  return data

# TOPSTACK
def topstack_replace(data):
  # TOPSTACK loop until it's MZ
  data = re.sub(b'\x66\x81\x38\x4d\x5a',b'\x90\x90\x90\x90\x90',data)

  return data

# _LDR_DATA_TABLE_ENTRY
def ldr_replace(data):
  # load / memory / init order // 8b ?? 0c|14|1C
  data = re.sub(b'\x8b.'+ b'\x0c | \x14 | \x1C',b'\x90\x90\x90', data)

  # FullDllName / BaseDllName // 8b 28|30
  #data = re.sub(b'\x8b\x28|\x30',b'\x90\x90',data)

  return data

# SEH(Structured Exception Handler)
def seh_replace(data):
  # xor mov not//  31 ?? 64 8b ?? f7 ??
  data = re.sub(b'\x31.\x64\x8b.\xf7.',b'\x90\x90\x90\x90\x90\x90\x90', data)
  data = re.sub(b'\x90\x57\x56\x52.',b'\x90\x90\x90\x90', data)

  return data

# Heap Spray (ENTROPY)
# under 0.2 has Heap Spray (in my samples)
def entropy(data):
        e = 0
        counter = collections.Counter(data)
        l = len(data)
        for count in counter.values():
            # count is always > 0
            p_x = count / l
            e += - p_x * math.log2(p_x)
        if(e < 0.2):
            if(len(data) > 3000):
                data = data[:3000] + b"\x90" * (len(data) - 3000)
        print(e)
        return data

def bin_data(ole,bin_list):
    print ('[+] BinData Information')
    for content in bin_list:
        print(content)
        bin_text = ole.openstream(content)
        data2 = bin_text.read()
        #compressed data
        if ('BodyText' in content) or ('Scripts' in content) or ('BinData' in content): # or ('DocInfo' in content):
          #decompress data 
          zobj = zlib.decompressobj(-zlib.MAX_WBITS)
          data3 = zobj.decompress(data2)
          #print decompressed data
          #print(data3)
          #edit data
          #cut shell code
          data3 = entropy(data3)
          
          data3 = function_replace(data3)
          data3 = teb_replace(data3)
          data3 = peb_replace(data3)
          data3 = seh_replace(data3)
          data3 = ldr_replace(data3)
          data3 = topstack_replace(data3)

          #re compress data
          data4 = zlib.compress(data3)[2:-4]
          data4 += data2[-8:]

          print(len(data2))
          print(len(data4))

          #put padding if file length is diffrent
          if(len(data2) > len(data4)):
            while(len(data2) != len(data4)):
              data4 += data2[len(data4):]
          elif(len(data2) < len(data4)):
            data4 = data4[0:len(data2)]

          #print(len(data4))
          #move
          ole.write_stream(content,data4)
        #if not compress data
        else:
            
            ole.write_stream(content, data2)



if __name__ == "__main__":
  hwp_file = sys.argv[1]
  print("Detecting shellcode :" + hwp_file)
  hwp_list = []

  ole = olefile.OleFileIO(hwp_file, write_mode=True)
  hwp_list = ole.listdir()

  bin_data(ole,hwp_list)
