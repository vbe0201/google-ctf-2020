# Root Power

> Root is an incredibly powerful account to access. Especially in this National Grid VM.

This challenge is about spotting, decoding and parsing the flag from an ACPI table located in the depths of a
given Linux disk image.

## Introduction

Upon downloading the challenge from the server, you obtain a mysterious file called
`4905c5f476c7e7eac34bd15fbd2e61a6d6c724c8431056f57a61fb0a0a35bf4bbdcae058d9c3fc528ce306e97a42924878c36c4bc2c145548553744e630c6073`.

With the help of the `file` command, it can be identified as a zip archive:

```sh
❯ file 4905c5f476c7e7eac34bd15fbd2e61a6d6c724c8431056f57a61fb0a0a35bf4bbdcae058d9c3fc528ce306e97a42924878c36c4bc2c145548553744e630c6073
4905c5f476c7e7eac34bd15fbd2e61a6d6c724c8431056f57a61fb0a0a35bf4bbdcae058d9c3fc528ce306e97a42924878c36c4bc2c145548553744e630c6073: Zip archive data, at least v2.0 to extract

❯ unzip 4905c5f476c7e7eac34bd15fbd2e61a6d6c724c8431056f57a61fb0a0a35bf4bbdcae058d9c3fc528ce306e97a42924878c36c4bc2c145548553744e630c6073
Archive:  4905c5f476c7e7eac34bd15fbd2e61a6d6c724c8431056f57a61fb0a0a35bf4bbdcae058d9c3fc528ce306e97a42924878c36c4bc2c145548553744e630c6073
 extracting: vm.tar.xz
```

And here we go with another archive called `vm.tar.xz.` that we can extract using `tar -xf vm.tar.xz`.

After that, a new folder called `vm` appears with a `run.sh` script inside of it that loads the other file, `disk.img` into qemu. From looking
at this script, we can figure out that we have an x86 disk image.

## Static Analysis

Before working with the image itself, we can gather some information about it using the `fdisk` command, which reveals that we're dealing with
a Linux system here.

```sh
❯ fdisk -l vm/disk.img
Disk vm/disk.img: 1.5 GiB, 1610612736 bytes, 3145728 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x415c2e94

Device       Boot Start     End Sectors  Size Id Type
vm/disk.img1 *     2048 3145727 3143680  1.5G 83 Linux
```

Once booting that system up in qemu, we'll be prompted with a login screen of an Arch Linux system that prompts us to login as root.

Unfortunately, we don't have the password and can't guess it either. We need to approach this a bit differently. Let's mount the image and inspect
it from the host system. To do this, we essentially have all the necessary information from above `fdisk` usage. The image starts at sector 2048
and has a sector size of 512 bytes each.

```sh
❯ sudo mkdir /mnt/ctf
❯ sudo mount -t auto -o loop,offset=$((2048*512)) vm/disk.img /mnt/ctf
```

Now we have the entire Linux image mounted to the mountpoint `/mnt/ctf` from where all its files are accessible. Let's scan them for something interesting.

## Analyzing the Linux image

The first and probably most obvious step to do is to scan `/mnt/ctf` recursively for a file with our flag, which is a pretty common practice in CTFs:

```sh
❯ sudo find /mnt/ctf -name "*flag*"
/mnt/ctf/usr/include/asm/processor-flags.h
/mnt/ctf/usr/include/lzma/stream_flags.h
/mnt/ctf/usr/include/linux/tty_flags.h
/mnt/ctf/usr/include/linux/kernel-page-flags.h
/mnt/ctf/usr/include/bits/ss_flags.h
/mnt/ctf/usr/include/bits/waitflags.h
...
/mnt/ctf/usr/share/man/man3/RSA_clear_flags.3ssl.gz
/mnt/ctf/usr/share/man/man3/EVP_CIPHER_meth_set_flags.3ssl.gz
/mnt/ctf/usr/share/man/man3/cap_get_flag.3.gz
/mnt/ctf/usr/lib/bash/fdflags
```

Although this landed quite a few hits, none of these files seems to be related to the actual flag in the CTF.

The next thing I tried is to scan for recently modified files. This is generally a really good piece of advice because the most recently edited files are
the files that were modified by Google in this image. This way, we can narrow down where we have to search and what belongs to a vanilla Linux system.

```sh
❯ sudo ls -lt /mnt/ctf
total 72
drwxr-xr-x 34 root root  4096 Jul  2 17:35 etc
drwxr-xr-x  3 root root  4096 Jul  2 17:06 boot
drwxr-x---  3 root root  4096 Jul  2 17:03 root
drwxr-xr-x 12 root root  4096 Jun 18 20:12 var
drwxr-xr-x  8 root root  4096 Jun 18 19:32 usr
drwxr-xr-x  2 root root  4096 Jun 18 19:31 run
lrwxrwxrwx  1 root root     7 Jun 18 19:31 sbin -> usr/bin
drwxr-xr-x  4 root root  4096 Jun 18 19:31 srv
dr-xr-xr-x  2 root root  4096 Jun 18 19:31 sys
drwxr-xr-t  2 root root  4096 Jun 18 19:31 tmp
lrwxrwxrwx  1 root root     7 Jun 18 19:31 lib -> usr/lib
lrwxrwxrwx  1 root root     7 Jun 18 19:31 lib64 -> usr/lib
drwxr-xr-x  2 root root  4096 Jun 18 19:31 mnt
drwxr-xr-x  2 root root  4096 Jun 18 19:31 opt
dr-xr-xr-x  2 root root  4096 Jun 18 19:31 proc
drwxr-xr-x  2 root root  4096 Jun 18 19:31 home
drwxr-xr-x  2 root root  4096 Jun 18 19:31 dev
lrwxrwxrwx  1 root root     7 Jun 18 19:31 bin -> usr/bin
drwx------  2 root root 16384 Jun 18 19:26 lost+found
```

Looking at this, we can see that some files in the first three directories were modified on July 2nd, whereas all the other ones are from June 18th. This means
that the first 3 directories contain what's interesting for us and the exact date to scan for. Let's give it a second shot.

```sh
❯ sudo ls -R -lt /mnt/ctf | grep "Jul  2"
drwxr-xr-x 34 root root  4096 Jul  2 17:35 etc
drwxr-xr-x  3 root root  4096 Jul  2 17:06 boot
drwxr-x---  3 root root  4096 Jul  2 17:03 root
-rw------- 1 root root    379 Jul  2 17:35 shadow
-rw-r--r-- 1 root root    147 Jul  2 17:16 motd
-rw-r--r-- 1 root root     92 Jul  2 17:14 issue
-rw-r--r-- 1 root root  58 Jul  2 17:31 passwd
-rw-r--r-- 1 root root  9399163 Jul  2 17:02 initramfs-linux.img
drwxrwxrwt  2 root root 4096 Jul  2 17:40 tmp
-rw-rw-r--  1 root utmp            104064 Jul  2 17:40 wtmp
-rw-rw-r--  1 root utmp               292 Jul  2 17:37 lastlog
-rw-------  1 root root                64 Jul  2 17:37 tallylog
-rw-rw----  1 root utmp              5760 Jul  2 17:25 btmp
drwxr-sr-x+ 2 root systemd-journal 4096 Jul  2 17:36 945803b84fa14418a278b692b8a0491f
-rw-r-----+ 1 root systemd-journal 8388608 Jul  2 17:40 system.journal
-rw-r-----+ 1 root systemd-journal 8388608 Jul  2 17:36 system@0005a9772cb3906c-d72b29266e01a825.journal~
-rw-r-----+ 1 root systemd-journal 8388608 Jul  2 17:25 system@0005a977037924f9-83222249a728a54f.journal~
-rw-r-----+ 1 root systemd-journal 8388608 Jul  2 17:05 system@0005a976bbe32de9-d33d9be4e7663d4a.journal~
-rw-r-----+ 1 root systemd-journal 8388608 Jul  2 16:12 system@0005a976001f6986-2c4eac47a355dd58.journal~
-rw-r-----+ 1 root systemd-journal 8388608 Jul  2 16:07 system@0005a975ef51106d-c1d860aee42dc081.journal~
-rw------- 1 root root  512 Jul  2 17:40 random-seed
drwxr-xr-x 2 root root 4096 Jul  2 17:25 coredump
-rw-r----- 1 root root 203972 Jul  2 17:25 core.login.0.8dba7463cc1743f9afc1f975403e161c.265.1593703531000000000000.lz4
-rw-r--r-- 1 root root 0 Jul  2 16:06 stamp-shadow.timer
```

Most of the stuff appears uninteresting - except `initramfs-linux.img`! This means that Google played around with the kernel image
directly. Let's see what is going on there by extracting the contents of the image into a separate directory.

```sh
❯ mkdir initramfs && cd initramfs
❯ sudo lsinitcpio -x /mnt/ctf/boot/initramfs-linux.img

❯ lt
 .
└── kernel
   └── firmware
      └── acpi
         └── ssdt.aml
```

Luckily for us, the modified initramfs image only contains a single file that we have to look at, `ssdt.aml`.

## A Primer on ACPI

Before we can actually start looking into the contents of `ssdt.aml`, we first need to understand some terminology and concepts related to
its purpose and how it works.

ACPI (Advanced Configuration and Power Interface) that defines interfaces to software and hardware to enumerate and configure motherboard
devices within an operating system and to manage their power. In Linux, `ssdt.aml` allows for declaring custom devices that override the
global ACPI device tree. Further, these files are implemented in the ASL language which is then compiled into the AML binary format.

Equipped with all this knowledge and a quick search on kernel.org, we can assemble/disassemble AML tables using the `iasl` tool from the
`acpica` package. Let's try that out:

```sh
❯ sudo iasl -d ssdt.aml

Intel ACPI Component Architecture
ASL+ Optimizing Compiler/Disassembler version 20200717
Copyright (c) 2000 - 2020 Intel Corporation

File appears to be binary: found 167 non-ASCII characters, disassembling
Binary file appears to be a valid ACPI table, disassembling
Input file ssdt.aml, Length 0x1FD (509) bytes
ACPI: SSDT 0x0000000000000000 0001FD (v02                 00000000 INTL 20190509)
Pass 1 parse of [SSDT]
Pass 2 parse of [SSDT]
Parsing Deferred Opcodes (Methods/Buffers/Packages/Regions)

Parsing completed
Disassembly completed
ASL Output:    ssdt.dsl - 4182 bytes
```

And it worked! Let's take a look at the resulting output file `ssdt.dsl` which indeed turned into parseable and understandable code.

```asl
/*
 * Intel ACPI Component Architecture
 * AML/ASL+ Disassembler version 20200717 (64-bit version)
 * Copyright (c) 2000 - 2020 Intel Corporation
 * 
 * Disassembling to symbolic ASL+ operators
 *
 * Disassembly of ssdt.aml, Fri Aug 28 20:50:14 2020
 *
 * Original Table Header:
 *     Signature        "SSDT"
 *     Length           0x000001FD (509)
 *     Revision         0x02
 *     Checksum         0xF6
 *     OEM ID           ""
 *     OEM Table ID     ""
 *     OEM Revision     0x00000000 (0)
 *     Compiler ID      "INTL"
 *     Compiler Version 0x20190509 (538510601)
 */
DefinitionBlock ("", "SSDT", 2, "", "", 0x00000000)
{
    Device (CHCK)
    {
        Name (_HID, "CHCK0001")  // _HID: Hardware ID
        Name (_CID, Package (0x02)  // _CID: Compatible ID
        {
            "CHCK0001", 
            "CHCK"
        })
        OperationRegion (KBDD, SystemIO, 0x60, One)
        OperationRegion (KBDC, SystemIO, 0x64, One)
        Field (KBDD, ByteAcc, NoLock, Preserve)
        {
            DTAR,   8
        }

        Field (KBDC, ByteAcc, NoLock, Preserve)
        {
            CSTR,   8
        }

        Name (KBDA, Buffer (0x3E)
        {
            /* 0000 */  0x2A, 0x2E, 0xAE, 0x14, 0x94, 0x21, 0xA1, 0x1A,  // *....!..
            /* 0008 */  0x9A, 0xAA, 0x1E, 0x9E, 0x2E, 0xAE, 0x19, 0x99,  // ........
            /* 0010 */  0x17, 0x97, 0x2A, 0x0C, 0x8C, 0xAA, 0x32, 0xB2,  // ..*...2.
            /* 0018 */  0x1E, 0x9E, 0x2E, 0xAE, 0x23, 0xA3, 0x17, 0x97,  // ....#...
            /* 0020 */  0x31, 0xB1, 0x12, 0x92, 0x2A, 0x0C, 0x8C, 0xAA,  // 1...*...
            /* 0028 */  0x26, 0xA6, 0x1E, 0x9E, 0x31, 0xB1, 0x22, 0xA2,  // &...1.".
            /* 0030 */  0x16, 0x96, 0x1E, 0x9E, 0x22, 0xA2, 0x12, 0x92,  // ...."...
            /* 0038 */  0x2A, 0x1B, 0x9B, 0xAA, 0x1C, 0x9C               // *.....
        })
        Name (KBDB, Buffer (0x3E){})
        Method (WCMD, 0, NotSerialized)
        {
            Local0 = One
            While ((Local0 == One))
            {
                Local0 = CSTR /* \CHCK.CSTR */
                Local0 >>= One
                Local0 &= One
            }
        }

        Method (WDTA, 0, NotSerialized)
        {
            Local0 = Zero
            While ((Local0 == Zero))
            {
                Local0 = CSTR /* \CHCK.CSTR */
                Local0 &= One
            }
        }

        Method (CLRD, 0, NotSerialized)
        {
            Local0 = CSTR /* \CHCK.CSTR */
            Local0 &= One
            While ((Local0 == One))
            {
                Local1 = DTAR /* \CHCK.DTAR */
                Local0 = CSTR /* \CHCK.CSTR */
                Local0 &= One
            }
        }

        Method (DINT, 0, NotSerialized)
        {
            Local0 = 0x44
            WCMD ()
            CSTR = 0x60
            WCMD ()
            DTAR = Local0
        }

        Method (EINT, 0, NotSerialized)
        {
            Local0 = 0x47
            WCMD ()
            CSTR = 0x60
            WCMD ()
            DTAR = Local0
        }

        Method (CHCK, 0, NotSerialized)
        {
            DINT ()
            CLRD ()
            WDTA ()
            Local0 = DTAR /* \CHCK.DTAR */
            If ((Local0 == 0x9C))
            {
                WDTA ()
                Local0 = DTAR /* \CHCK.DTAR */
            }

            Local1 = Zero
            If ((Local0 == 0x36))
            {
                Local0 = 0x2A
            }

            KBDB [Local1] = Local0
            Local1 += One
            While ((Local0 != 0x9C))
            {
                WDTA ()
                Local0 = DTAR /* \CHCK.DTAR */
                If ((Local0 == 0x36))
                {
                    Local0 = 0x2A
                }

                If ((Local0 == 0xB6))
                {
                    Local0 = 0xAA
                }

                If ((Local1 < 0x3E))
                {
                    KBDB [Local1] = Local0
                    Local1 += One
                }
            }

            EINT ()
            If ((KBDA == KBDB))
            {
                Return (One)
            }

            Return (Zero)
        }
    }
}
```

## Parsing the ACPI Table

As I'm following along the code flow with 5 tabs of OSDev Wiki pages open, I noticed that the code converts virtual
keyboard scan codes from a pre-defined table to ASCII characters into virtual key codes first, which are getting
converted to ASCII characters then. Let's try to emulate this in a script and see if this gets us our flag.

As for the scan codes, these are hardware-dependant and the "real" values behind keyboard input: http://www.philipstorr.id.au/pcbook/book3/scancode.htm
Virtual key codes on the other hand are platform-independent and should be collectively used by OSes: https://docs.microsoft.com/en-us/windows/win32/inputdev/virtual-key-codes

ASCII translation is implied by the virtual key code mappings, so all we gotta do in a script is to map all the values accordingly:

```py

```

And ultimately, this computes the flag for us - well, almost.

```sh
❯ ./solve.py
Flag: ctf[acpi-machine-language]
```

As we can see, some of the characters are messed up between uppercase and lowercase key codes, but these are relatively easy to track down.

The real flag is: `CTF{acpi_machine_language}`.
