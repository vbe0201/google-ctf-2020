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

