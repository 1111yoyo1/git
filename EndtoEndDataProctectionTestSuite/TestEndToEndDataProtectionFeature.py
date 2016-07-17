#!/usr/bin/env python
"""
Copyright (C) 2015 Memblaze Technology Co., Ltd.
This software contains confidential information and trade secrets of Memblaze Technology Co., Ltd.
Use, disclosure, or reproduction is prohibited without the prior express written permission of
Memblaze Technology Co., Ltd.

<SCRIPTNAME>
    TestEndToEndDataProtectionFeature.py
</SCRIPTNAME>

<DESCRIPTION>
    The script test end-to-end data protection feature
</DESCRIPTION>

<AUTHOR>
    Youyou Xu
</AUTHOR>

<HISTORY>
Version     Data        Author                  Description
1.0         06/14/2016  youyou xu               Initial script
1.1         07/13/2016  youyou xu               Modify script to adapt to test summary format
</HISTORY>

"""

import random

import TestFramework.TestTarget as TestTarget
import Utilities.Logger as Logger
import Utilities.Buffer as Buffer
import Utilities.Random as Random
import EndToEndDataProtectionLib as EndtoEndLib
import TestFramework.TestSummary as TestSummary


def CaseSendUnaligned(device, logger, options, host, caseno=0):
    errcnt = 0
    verbose = options.verbose
    errcnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=0,
                                          expitype=random.randint(1, 2), expmssetting=None,
                                          explbaf=1, ses=0, verbose=verbose)

    lbaInfoTable = EndtoEndLib.DeviceTable.GetLbaInfoTablebyDevice(device)
    logger.Info(lbaInfoTable.OutputBasic())
    extended = lbaInfoTable.extended

    no = 0
    title = "Send non 4k align write/read and compare the data, expect data match."
    currentSummary = TestSummary.GetSummary(no, title)
    EndtoEndLib.CaseSummary.AddItem(logger, no, title)
    with currentSummary:
        subErrCnt = 0
        metaWAttr = EndtoEndLib.MetaAttr(
            pract=0, checkcrc=0, checkapptag=0,
            checkreftag=0,
            apptag=0, appmask=0, iswrite=True)

        metaRAttr = EndtoEndLib.MetaAttr(
            pract=0, checkcrc=0, checkapptag=0,
            checkreftag=0,
            apptag=0, appmask=0, iswrite=False)

        subErrCnt += EndtoEndLib.CompareWithPi(device, logger, options, firstlba=0, lastlba=16, nlb=1,
                                               buffertype=EndtoEndLib.BufferType.RANDOM, wreftag=None, rreftag=None, wmetaattr=metaWAttr,
                                               rmetaattr=metaRAttr, extended=extended, verbose=verbose)

        currentSummary.IncreaseError(subErrCnt)
        EndtoEndLib.CaseSummary.UpdateItem(0, subErrCnt)
    errcnt += subErrCnt
    return errcnt


def CasePiFormatCheck(device, logger, options, host, caseno=0):
    errcnt = 0
    verbose = options.verbose
    lbaInfoTable = EndtoEndLib.DeviceTable.GetLbaInfoTablebyDevice(device)
    extended = lbaInfoTable.extended
    logger.Info(lbaInfoTable.OutputBasic())

    no = 1.01
    title = "Data protection setting should match supported data protection type"
    currentSummary = TestSummary.GetSummary(no, title)
    EndtoEndLib.CaseSummary.AddItem(logger, no, title)
    with currentSummary:
        subErrCnt = 0
        explbaf = 1
        for exPiType in xrange(1, 4):
            for expPiL in xrange(2):
                Logger.Info("Step 1: Format the drive to Pi Type %d, Pi location %d" % (exPiType, expPiL))
                subErrCnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=expPiL, expitype=exPiType,
                                                         expmssetting=extended, explbaf=explbaf, ses=0,
                                                         verbose=verbose)

                Logger.Info("Step 2: Format the drive to Pi Type 0, Pi location %d" % (expPiL))
                subErrCnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=expPiL, expitype=0,
                                                         expmssetting=extended, explbaf=explbaf, ses=0,
                                                         verbose=verbose)

                Logger.Info("Step 3: Format the drive to Pi Type %d, Pi location %d" % (exPiType, abs(expPiL-1)))
                subErrCnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=abs(expPiL-1),
                                                         expitype=exPiType, expmssetting=extended, explbaf=explbaf,
                                                         ses=0,  verbose=verbose)
                Logger.Info("\n")
        currentSummary.IncreaseError(subErrCnt)
    EndtoEndLib.CaseSummary.UpdateItem(no, subErrCnt)
    errcnt += subErrCnt

    no = 1.04
    title = "Format the drive with different format ID, check if the command could succeed."
    currentSummary = TestSummary.GetSummary(no, title)
    EndtoEndLib.CaseSummary.AddItem(logger, no, title)
    with currentSummary:
        subErrCnt = 0
        for exPiType in xrange(1, 4):
            for explbaf in [0, 2]:
                Logger.Info("Format the drive to Pi Type %d, LBA format %s " % (exPiType, explbaf))

                subErrCnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=None, expitype=exPiType,
                                                         expmssetting=extended, explbaf=explbaf, ses=0,
                                                         verbose=False)
        currentSummary.IncreaseError(subErrCnt)
    EndtoEndLib.CaseSummary.UpdateItem(no, subErrCnt)
    errcnt += subErrCnt

    return errcnt


def CaseSendWriteReadwithPiToPiDisableDrive(device, logger, options, host, caseno=0):

    errcnt = 0
    verbose = options.verbose
    errcnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=0, expitype=0, expmssetting=None,
                                          explbaf=0, ses=0, verbose=verbose)

    lbaInfoTable = EndtoEndLib.DeviceTable.GetLbaInfoTablebyDevice(device)
    maxLba = lbaInfoTable.maxLba
    logger.Info(lbaInfoTable.OutputBasic())

    no = 2.01
    title = "Send write and read command without Pi when Pi is disabled, compare the data \
expect data match"
    currentSummary = TestSummary.GetSummary(no, title)
    EndtoEndLib.CaseSummary.AddItem(logger, no, title)
    with currentSummary:
        subErrCnt = 0
        nlb, firstLba, lastLba = EndtoEndLib.GetLBARange(maxLba)
        subErrCnt += EndtoEndLib.Compare(device, logger, options, firstlba=firstLba, lastlba=lastLba, nlb=nlb,
                                         buffertype=EndtoEndLib.BufferType.RANDOM, verbose=verbose)
        currentSummary.IncreaseError(subErrCnt)
    EndtoEndLib.CaseSummary.UpdateItem(no, subErrCnt)
    errcnt += subErrCnt

    no = 2.02
    title = "Send write read command with Pi when Pi is disabled, expect command get aborted"
    currentSummary = TestSummary.GetSummary(no, title)
    EndtoEndLib.CaseSummary.AddItem(logger, no, title)
    with currentSummary:
        subErrCnt = 0
        slba, nlb = EndtoEndLib.GetNlbSlba(maxLba)
        wBuf = Buffer.Buffer(nlb * (lbaInfoTable.lbaSize+8))
        wBuf.SetUint32(0, slba, isBigEndian=True)
        metaWBuf = None

        metaattr = EndtoEndLib.MetaAttr(
            pract=0, checkcrc=0, checkapptag=0,
            checkreftag=0,
            apptag=0, appmask=0, iswrite=True)
        reftag = EndtoEndLib.GetRefTag(slba)
        if verbose:
            logger.Info("Write command slba=0x%xh/%d, nlb=0x%xh/%d, reference tag 0x%xh/%d" % (
                slba, slba, nlb, nlb, reftag, reftag))
            logger.Info(metaattr.output())

        subErrCnt += EndtoEndLib.ValidateRetValue(logger, None, device.Write, buf=wBuf, slba=slba, nlb=nlb, bufOffset=0,
                                                  metadataBuf=metaWBuf, pract=metaattr.pract,
                                                  checkcrc=metaattr.checkcrc, checkapptag=metaattr.checkapptag, checkreftag=reftag,
                                                  reftag=reftag, apptag=metaattr.apptag, appmask=metaattr.appmask)

        slba, nlb = EndtoEndLib.GetNlbSlba(maxLba)
        rBuf = Buffer.Buffer(nlb*lbaInfoTable.lbaSize)
        rBuf.SetUint32(0, slba, isBigEndian=True)
        metaRBuf = Buffer.Buffer(nlb*8)
        reftag = EndtoEndLib.GetRefTag(slba)
        if verbose:
            metaattr = EndtoEndLib.MetaAttr(
                pract=0, checkcrc=0, checkapptag=0,
                checkreftag=0,
                apptag=0, appmask=0, iswrite=False)
            logger.Info("Read command slba=0x%xh/%d, nlb=0x%xh/%d, reference tag 0x%xh/%d" % (
                slba, slba, nlb, nlb, reftag, reftag))
            logger.Info(metaattr.output())

        subErrCnt += EndtoEndLib.ValidateRetValue(logger, None, device.Read, buf=rBuf, slba=slba, nlb=nlb, bufOffset=0,
                                                  metadataBuf=metaRBuf, pract=metaattr.pract,
                                                  checkcrc=metaattr.checkcrc, checkapptag=metaattr.checkapptag, checkreftag=reftag,
                                                  reftag=reftag, apptag=metaattr.apptag, appmask=metaattr.appmask)
        currentSummary.IncreaseError(subErrCnt)
    EndtoEndLib.CaseSummary.UpdateItem(no, subErrCnt)
    errcnt += subErrCnt

    return errcnt


def ProcessReadWriteTestMatrix(device, logger, options, caseno, no, args):
    lbaInfoTable = EndtoEndLib.DeviceTable.GetLbaInfoTablebyDevice(device)
    maxLba = lbaInfoTable.maxLba
    extended = lbaInfoTable.extended

    subErrCnt = 0
    title = args[0]

    wpract = args[1][0]
    wcheckcrc = args[1][1]
    wcheckapptag = args[1][2]
    wcheckreftag = args[1][3]

    wapptag = args[2][0]
    wappmask = args[2][1]
    wreftag = args[2][2]

    rpract = args[3][0]
    rcheckcrc = args[3][1]
    rcheckapptag = args[3][2]
    rcheckreftag = args[3][3]

    rapptag = args[4][0]
    rappmask = args[4][1]
    rreftag = args[4][2]

    customizedcrc = args[5][0]
    customizedapptag = args[5][1]
    customizedreftag = args[5][2]

    buffertype = args[6]

    verbose = args[7]

    expStatus = args[8]
    no = "%u.%02u" % (caseno, no)

    EndtoEndLib.CaseSummary.AddItem(logger, no, title)
    nlb, firstLba, lastLba = EndtoEndLib.GetLBARange(maxLba)
    metaWAttr = EndtoEndLib.MetaAttr(
        pract=wpract, checkcrc=wcheckcrc, checkapptag=wcheckapptag,
        checkreftag=wcheckreftag,
        apptag=wapptag, appmask=wappmask, iswrite=True)

    metaRAttr = EndtoEndLib.MetaAttr(
        pract=rpract, checkcrc=rcheckcrc, checkapptag=rcheckapptag,
        checkreftag=rcheckreftag,
        apptag=rapptag, appmask=rappmask, iswrite=False)

    currentSummary = TestSummary.GetSummary(no, title)
    with currentSummary:
        subErrCnt += EndtoEndLib.ValidateRetValue(logger, expStatus, EndtoEndLib.CompareWithPi, device, logger, options,
                                                  firstlba=firstLba, lastlba=lastLba, nlb=nlb,
                                                  buffertype=buffertype, wreftag=wreftag, rreftag=rreftag, wmetaattr=metaWAttr,
                                                  rmetaattr=metaRAttr, extended=extended,
                                                  customizedcrc=customizedcrc, customizedapptag=customizedapptag,
                                                  customizedreftag=customizedreftag, verbose=verbose)
        currentSummary.IncreaseError(subErrCnt)
    EndtoEndLib.CaseSummary.UpdateItem(no, subErrCnt)
    return subErrCnt


def CaseWriteReadPositive(device, logger, options, host, expitype=None,
                          expmssetting=None, caseno=0):
    errcnt = 0
    verbose = options.verbose
    # errcnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=None,
    #                                       expitype=expitype, expmssetting=expmssetting, explbaf=1,
    #                                       ses=0, verbose=verbose)
    lbaInfoTable = EndtoEndLib.DeviceTable.GetLbaInfoTablebyDevice(device)
    logger.Info(lbaInfoTable.OutputBasic())

    testMatrix = {
        #title                                                                          #write pract prchk     #apptag reftag   #read pract prchk  #apptag reftag  #customized crc/apptag/refag           #buffer type   #verbose  #status
        1:  ["Host write + correct PI, PRACT = 0, PRCHK=1 (Type %s)" % expitype,        [0, 1, 1, 1],           [0, 0, None],    [0, 1, 1, 1],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        2:  ["Host write + correct PI, PRACT = 0, PRCHK=0 (Type %s)" % expitype,        [0, 0, 0, 0],           [0, 0, None],    [0, 1, 1, 1],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        3:  ["Host write + correct PI, PRACT = 1, PRCHK=0 (Type %s)" % expitype,        [1, 0, 0, 0],           [0, 0, None],    [0, 1, 1, 1],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        4:  ["Host write + correct PI, PRACT = 1, PRCHK=1 (Type %s)" % expitype,        [1, 1, 1, 1],           [0, 0, None],    [0, 1, 1, 1],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        5:  ["Host write + incorrect PI, PRACT = 0, PRCHK=0 (Type %s)" % expitype,      [0, 0, 0, 0],           [0, 0, None],    [0, 0, 0, 0],     [0, 0, None],   [0x1111, None, 0x11111111],             EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        6:  ["Host write + incorrect PI, PRACT = 1, PRCHK=1 (Type %s)" % expitype,      [1, 1, 1, 1],           [0, 0, None],    [0, 1, 1, 1],     [0, 0, None],   [1111, None, 0x11111111],               EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        7:  ["Host write + incorrect PI, PRACT = 1, PRCHK=0 (Type %s)" % expitype,      [1, 0, 0, 0],           [0, 0, None],    [0, 1, 1, 1],     [0, 0, None],   [1111, None, 0x11111111],               EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        8:  ["Host read + correct PI, PRACT = 0, PRCHK=0 (Type %s)" % expitype,         [0, 1, 1, 1],           [0, 0, None],    [0, 0, 0, 0],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        9:  ["Host read + correct PI, PRACT = 0, PRCHK=1 (Type %s)" % expitype,         [0, 1, 1, 1],           [0, 0, None],    [0, 1, 1, 1],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        10: ["Host read + correct PI, PRACT = 1, PRCHK=0 (Type %s)" % expitype,         [0, 1, 1, 1],           [0, 0, None],    [1, 0, 0, 0],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        11: ["Host read + correct PI, PRACT = 1, PRCHK=1 (Type %s)" % expitype,         [0, 1, 1, 1],           [0, 0, None],    [1, 1, 1, 1],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        #12: ["Host read + incorrect PI, PRACT = 0, PRCHK=0 (Type %s)" % expitype,       [0, 1, 1, 1],           [0, 0, None],    [0, 0, 0, 0],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        #13: ["Host read + incorrect PI, PRACT = 1, PRCHK=0 (Type %s)" % expitype,       [0, 1, 1, 1],           [0, 0, None],    [1, 0, 0, 0],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
    }

    for no in sorted(testMatrix.keys(), key=lambda no: no):
        subErrCnt = ProcessReadWriteTestMatrix(device, logger, options, caseno, no, testMatrix[no])
        errcnt += subErrCnt

    return errcnt


def CaseWriteReadNegative(device, logger, options, host, expitype=None,
                          expmssetting=None, caseno=0):
    errcnt = 0
    verbose = options.verbose

    # errcnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=None,
    #                                       expitype=expitype, expmssetting=expmssetting, explbaf=1,
    #                                       ses=0, verbose=verbose)

    lbaInfoTable = EndtoEndLib.DeviceTable.GetLbaInfoTablebyDevice(device)
    logger.Info(lbaInfoTable.OutputBasic())

    testMatrix = {
        #title                                                                                                                         #write pract prchk     #apptag reftag             #read pract prchk  #apptag reftag        #customized crc/apptag/refag           #buffer type   #verbose     #status
        1: ["Host write + incorrect PI, PRACT = 0, PRCHK=1 (Type %s)" % expitype,                                                     [0, 1, 1, 1],           [0, 0, None],              [0, 0, 0, 0],     [0, 0, None],         [0x1111, None, 0x11111111],             EndtoEndLib.BufferType.RANDOM,             verbose,     0x2282],
        2: ["Host write + PI (incorrect guard field), PRACT=0,  PRCHK.bit2 = 1 (Type %s)" % expitype,                                 [0, 1, 0, 0],           [0, 0, None],              [0, 0, 0, 0],     [0, 0, None],         [0x1111, None, None],                   EndtoEndLib.BufferType.RANDOM,             verbose,     0x2282],
        3: ["Host write + PI (incorrect application field), PRACT=0,  PRCHK.bit1 = 1 (Type %s)" % expitype,                           [0, 0, 1, 0],           [0x1110, 0xffff, None],    [0, 0, 0, 0],     [0, 0, None],         [None, 0x1111, None],                   EndtoEndLib.BufferType.RANDOM,             verbose,     0x2283],
        4: ["Host write + PI (incorrect reference field),PRACT=0,  PRCHK.bit0 = 1 (Type %s)" % expitype,                              [0, 0, 0, 1],           [0, 0, None],              [0, 0, 0, 0],     [0, 0, None],         [None, None, 0x11111111],               EndtoEndLib.BufferType.RANDOM,             verbose,     0x2284],
        5: ["Host write + PI (incorrect reference field in command), PRACT=0,  PRCHK.bit0 = 1 (Type %s)" % expitype,                  [0, 0, 0, 1],           [0, 0, 1111],              [0, 0, 0, 0],     [0, 0, None],         [None, None, None],                     EndtoEndLib.BufferType.RANDOM,             verbose,     0x2284],
        6: ["Host read (incorrect reference field in command) + PI, PRACT = 0,  PRCHK.bit0 = 1 (Type %s)" % expitype,                 [0, 0, 0, 0],           [0, 0, None],              [0, 0, 0, 1],     [0, 0, 0x11111111],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,             verbose,     0x2284],
        7: ["Host read (incorrect reference field in command) + PI, PRACT = 1,  PRCHK.bit0 = 1 (Type %s)" % expitype,                 [0, 0, 0, 0],           [0, 0, None],              [1, 0, 0, 1],     [0, 0, 0x11111111],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,             verbose,     0x2284],
    }

    for no in sorted(testMatrix.keys(), key=lambda no: no):
        subErrCnt = ProcessReadWriteTestMatrix(device, logger, options, caseno, no, testMatrix[no])
        errcnt += subErrCnt

    return errcnt


def CaseWriteReadSpecialTag(device, logger, options, host, expitype=None,
                            expmssetting=None, caseno=0):
    errcnt = 0
    verbose = options.verbose
    # errcnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=None,
    #                                       expitype=expitype, expmssetting=expmssetting, explbaf=1,
    #                                       ses=0, verbose=verbose)

    lbaInfoTable = EndtoEndLib.DeviceTable.GetLbaInfoTablebyDevice(device)
    logger.Info(lbaInfoTable.OutputBasic())

    testMatrix = {
        #title                                                                                                                               #write pract prchk     #apptag reftag                        #read pract prchk  #apptag reftag                   #customized crc/apptag/refag           #buffer type   #verbose   #status
        1: ["Application tag set to 0xffffh, Host write + correct Pi, PRACT = 0, PRCHK=1 (Type %s)" % expitype,                             [0, 1, 1, 1],           [0xffff, 0xffff, None],              [0, 0, 0, 0],       [0, 0, None],                   [None, 0xffff, None],                   EndtoEndLib.BufferType.RANDOM,             verbose,     0],
        2: ["Application tag set to 0xffffh, Host write + incorrect guard tag, PRACT = 0, PRCHK=1 (Type %s)" % expitype,                    [0, 1, 1, 1],           [0xffff, 0xffff, None],              [0, 0, 0, 0],       [0, 0, None],                   [0x1111, 0xffff, None],                 EndtoEndLib.BufferType.RANDOM,             verbose,     0],
        3: ["Application tag set to 0xffffh, Host write + incorrect reference tag, PRACT = 0, PRCHK=1 (Type %s)" % expitype,                [0, 1, 1, 1],           [0xffff, 0xffff, None],              [0, 0, 0, 0],       [0, 0, None],                   [None, 0xffff, 0x1111],                 EndtoEndLib.BufferType.RANDOM,             verbose,     0],
        4: ["Application tag set to 0xffffh, Host read + correct Pi, PRACT = 0, PRCHK=1 (Type %s)" % expitype,                              [0, 0, 0, 0],           [0, 0, None],                        [0, 1, 1, 1],       [0xffff, 0xffff, None],         [None, 0xffff, None],                     EndtoEndLib.BufferType.RANDOM,             verbose,     0],
        5: ["Application tag set to 0xffffh, Host read + correct Pi, PRACT = 1, PRCHK=1 (Type %s)" % expitype,                              [0, 0, 0, 0],           [0, 0, None],                        [1, 1, 1, 1],       [0xffff, 0xffff, None],         [None, 0xffff, None],                     EndtoEndLib.BufferType.RANDOM,             verbose,     0],
        6: ["Application tag set to 0xffffh, Host read(incorrect reference field in command), PRACT = 0, PRCHK=1  (Type %s)" % expitype,    [0, 0, 0, 0],           [0, 0, None],                        [0, 1, 1, 1],       [0xffff, 0xffff, 0x11111111],   [None, 0xffff, 0x11111111],                     EndtoEndLib.BufferType.RANDOM,             verbose,     0],
        7: ["Application tag set to 0xffffh, Host read(incorrect reference field in command), PRACT = 1, PRCHK=1  (Type %s)" % expitype,    [0, 0, 0, 0],           [0, 0, None],                        [1, 1, 1, 1],       [0xffff, 0xffff, 0x11111111],   [None, 0xffff, 0x11111111],                     EndtoEndLib.BufferType.RANDOM,             verbose,     0],
    }

    for no in sorted(testMatrix.keys(), key=lambda no: no):
        subErrCnt = ProcessReadWriteTestMatrix(device, logger, options, caseno, no, testMatrix[no])
        errcnt += subErrCnt

    return errcnt


def CaseType3WriteReadPositive(device, logger, options, host, expitype=None,
                               expmssetting=None, caseno=0):
    errcnt = 0
    verbose = options.verbose
    errcnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=None,
                                          expitype=expitype, expmssetting=expmssetting, explbaf=1,
                                          ses=0, verbose=verbose)
    lbaInfoTable = EndtoEndLib.DeviceTable.GetLbaInfoTablebyDevice(device)
    logger.Info(lbaInfoTable.OutputBasic())

    testMatrix = {
        #title                                                                                                                #write pract prchk     #apptag reftag   #read pract prchk  #apptag reftag  #customized crc/apptag/refag           #buffer type   #verbose  #status
        1: ["Host write + correct PI, PRACT = 0,PRCHK=0 (Type %s)" % expitype,                                                [0, 0, 0, 0],           [0, 0, None],    [0, 1, 1, 0],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        2: ["Host write + correct PI, PRACT = 0,PRCHK.bit2&bit1 =1 (Type %s)" % expitype,                                     [0, 1, 1, 0],           [0, 0, None],    [0, 1, 1, 0],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        3: ["Host write + correct PI, PRACT = 1,PRCHK=0 (Type %s)" % expitype,                                                [1, 0, 0, 0],           [0, 0, None],    [0, 1, 1, 0],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        4: ["Host write + correct PI, PRACT = 1,PRCHK.bit2&bit1=1 (Type %s)" % expitype,                                      [1, 1, 1, 0],           [0, 0, None],    [0, 1, 1, 0],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        5: ["Host write + incorrect PI, PRACT = 0,PRCHK=0 (Type %s)" % expitype,                                              [0, 0, 0, 0],           [0, 0, None],    [0, 0, 0, 0],     [0, 0, None],   [0x1111, None, 0x11111111],             EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        6: ["Host write + incorrect PI, PRACT = 1,PRCHK=0 (Type %s)" % expitype,                                              [1, 0, 0, 0],           [0, 0, None],    [0, 1, 1, 1],     [0, 0, None],   [0x1111, None, 0x11111111],             EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        7: ["Host write + incorrect PI(correct reference tag), PRACT = 1, PRCHK.bit2&bit1 =1 (Type %s)" % expitype,           [1, 1, 1, 0],           [0, 0, None],    [0, 1, 1, 1],     [0, 0, None],   [0x1111, None, None],                   EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        8: ["Host write + incorrect PI(incorrect reference tag), PRACT = 1, PRCHK.bit2&bit1 =1 (Type %s)" % expitype,         [0, 1, 1, 0],           [0, 0, None],    [0, 0, 0, 0],     [0, 0, None],   [None, None, 0x11111111],               EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        9: ["Host read + correct PI, PRACT = 0, PRCHK=0 (Type %s)" % expitype,                                                [0, 1, 1, 1],           [0, 0, None],    [0, 0, 0, 0],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        10: ["Host read + correct PI, PRACT = 0, ,PRCHK.bit2&bit1 =1 (Type %s)" % expitype,                                    [0, 1, 1, 1],           [0, 0, None],    [0, 1, 1, 0],     [0, 0, None],   [None, None, None],                    EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        11: ["Host read + correct PI, PRACT = 1, PRCHK=0 (Type %s)" % expitype,                                                [0, 1, 1, 1],           [0, 0, None],    [1, 0, 0, 0],     [0, 0, None],   [None, None, None],                    EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        12: ["Host read + correct PI, PRACT = 1, ,PRCHK.bit2&bit1 =1 (Type %s)" % expitype,                                    [0, 1, 1, 1],           [0, 0, None],    [0, 1, 1, 0],     [0, 0, None],   [None, None, None],                    EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        13: ["Host read  (incorrect reference field in command) + PI, PRACT = 0, PRCHK=0 (Type %s)" % expitype,                [0, 1, 1, 1],           [0, 0, None],    [0, 0, 0, 0],     [0, 0, 0x1111], [None, None, None],                    EndtoEndLib.BufferType.RANDOM,          verbose,   0],
        14: ["Host read  (incorrect reference field in command) + PI, PRACT = 1, PRCHK=0 (Type %s)" % expitype,                [0, 1, 1, 1],           [0, 0, None],    [1, 0, 0, 0],     [0, 0, 0x1111], [None, None, None],                    EndtoEndLib.BufferType.RANDOM,          verbose,   0],
    }

    for no in sorted(testMatrix.keys(), key=lambda no: no):
        subErrCnt = ProcessReadWriteTestMatrix(device, logger, options, caseno, no, testMatrix[no])
        errcnt += subErrCnt

    return errcnt


def CaseType3WriteReadNegative(device, logger, options, host, expitype=None,
                               expmssetting=None, caseno=0):
    errcnt = 0
    verbose = options.verbose
    errcnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=None,
                                          expitype=expitype, expmssetting=expmssetting, explbaf=1,
                                          ses=0, verbose=verbose)

    lbaInfoTable = EndtoEndLib.DeviceTable.GetLbaInfoTablebyDevice(device)
    logger.Info(lbaInfoTable.OutputBasic())

    testMatrix = {
        #title                                                                                                          #write pract prchk     #apptag reftag             #read pract prchk  #apptag reftag  #customized crc/apptag/refag           #buffer type   #verbose   #status
        1: ["Host write + correct PI, PRACT=0, PRCHK.bit0 = 1 (Type %s)" % expitype,                                   [0, 0, 0, 1],           [0, 0, None],              [0, 0, 0, 0],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,     None],
        2: ["Host write + PI (incorrect guard field), PRACT=0, PRCHK.bit2 = 1 (Type %s)" % expitype,                   [0, 1, 0, 0],           [0, 0, None],              [0, 0, 0, 0],     [0, 0, None],   [0x1111, None, None],                   EndtoEndLib.BufferType.RANDOM,          verbose,     0x2282],
        3: ["Host write + PI (incorrect application field), PRACT=0, PRCHK.bit1 = 1 (Type %s)" % expitype,             [0, 0, 1, 0],           [0x1110, 0xffff, None],    [0, 0, 0, 0],     [0, 0, None],   [None, 0x1111, None],                   EndtoEndLib.BufferType.RANDOM,          verbose,     0x2283],
        4: ["Host read + correct PI, PRACT = 0, PRCHK.bit0 = 1 (Type %s)" % expitype,                                  [0, 0, 0, 1],           [0, 0, None],              [0, 0, 0, 1],     [0, 0, None],   [None, None, None],                     EndtoEndLib.BufferType.RANDOM,          verbose,     None],
    }

    for no in sorted(testMatrix.keys(), key=lambda no: no):
        subErrCnt = ProcessReadWriteTestMatrix(device, logger, options, caseno, no, testMatrix[no])
        errcnt += subErrCnt

    return errcnt


def CaseType3WriteReadSpecialTag(device, logger, options, host, expitype=None,
                                 expmssetting=None, caseno=0):
    errcnt = 0
    verbose = options.verbose
    errcnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=None,
                                          expitype=expitype, expmssetting=expmssetting, explbaf=1,
                                          ses=0, verbose=verbose)

    lbaInfoTable = EndtoEndLib.DeviceTable.GetLbaInfoTablebyDevice(device)
    logger.Info(lbaInfoTable.OutputBasic())

    testMatrix = {
        #title                                                                                                                                                                                 #write pract prchk     #apptag reftag                        #read pract prchk  #apptag reftag                   #customized crc/apptag/refag                #buffer type   #verbose   #status
        1: ["Application Tag set to 0xffffh and Reference Tag set to 0xffffffffh, Host write + correct Pi, PRACT = 0,PRCHK.bit2&bit1=1 (Type %s)" % expitype,                                 [0, 1, 1, 0],           [0xffff, 0xffff, None],              [0, 0, 0, 0],       [0, 0, None],                   [None, 0xffff, 0xffffffff],                   EndtoEndLib.BufferType.RANDOM,             verbose,     0],
        2: ["Application Tag set to 0xffffh and Reference Tag set to 0xffffffffh, Host write + incorrect guard tag, PRACT = 0,PRCHK.bit2&bit1=1 (Type %s)" % expitype,                        [0, 1, 1, 0],           [0xffff, 0xffff, None],              [0, 0, 0, 0],       [0, 0, None],                   [0x1111, 0xffff, 0xffffffff],                 EndtoEndLib.BufferType.RANDOM,             verbose,     0],
        3: ["Application Tag set to 0xffffh and Reference Tag set to 0xffffffffh, Host read + correct Pi, PRACT = 0,PRCHK.bit2&bit1=1 (Type %s)" % expitype,                                  [0, 0, 0, 0],           [0, 0, None],                        [0, 1, 1, 0],       [0xffff, 0xffff, 0xffffffff],   [None, None, None],                           EndtoEndLib.BufferType.RANDOM,             verbose,     0],
        4: ["Application Tag set to 0xffffh and Reference Tag set to 0xffffffffh, Host read + correct Pi, PRACT = 1,PRCHK.bit2&bit1=1 (Type %s)" % expitype,                                  [0, 0, 0, 0],           [0, 0, None],                        [1, 1, 1, 0],       [0xffff, 0xffff, 0xffffffff],   [None, None, None],                           EndtoEndLib.BufferType.RANDOM,             verbose,     0],
    }

    for no in sorted(testMatrix.keys(), key=lambda no: no):
        subErrCnt = ProcessReadWriteTestMatrix(device, logger, options, caseno, no, testMatrix[no])
        errcnt += subErrCnt

    return errcnt


class Test (TestTarget.TestCase):
    """
    """
    def OptionList(self):
        """
        Implement this function with optionList needed, and return it out.
        """
        import optparse
        optionList = [
            optparse.Option(
                "--verbose",
                type="int",
                dest="verbose",
                default=1,
                help="Get detailed output from the script 1*. Yes 0.No"),
            optparse.Option(
                "--powercycle",
                type="int",
                dest="powercycle",
                default=1,
                help="Do power cycle after format 1*.Yes 0.No"
                ),
            optparse.Option(
                "--case",
                type="int",
                dest="case",
                default=None,
                help="Select which case to run. Default: All."),

        ]
        return optionList

    def ImportList(self):
        return [Random, Buffer]

    def Setup(self):
        """
        Setup phase
        """
        return True

    def Run(self):
        """
        Run phase
        """
        options = self.options
        device = self.device
        logger = self.logger

        EndtoEndLib.DeviceTable.IntialLbaInfoTablebyDevice(device)

        caseDict = {
            # 0:  ("Unaligned write case under Pi enable",  lambda self, caseNo: CaseSendUnaligned(self.device, self.logger, self.options, self.host, caseno=caseNo)),
            # 1:  ("Namespace and format test",             lambda self, caseNo: CasePiFormatCheck(self.device, self.logger, self.options, self.host, caseno=caseNo)),
            # 2:  ("Data protection disabled test",         lambda self, caseNo: CaseSendWriteReadwithPiToPiDisableDrive(self.device, self.logger, self.options, self.host, caseno=caseNo)),
            3:  ("DIX type 1 write read positive test",   lambda self, caseNo: CaseWriteReadPositive(self.device, self.logger, self.options, self.host, expitype=1, expmssetting=0, caseno=caseNo)),
            4:  ("DIX type 1 write read negative test",   lambda self, caseNo: CaseWriteReadNegative(self.device, self.logger, self.options, self.host, expitype=1, expmssetting=0, caseno=caseNo)),
            5:  ("DIX type 1 write read special tag",     lambda self, caseNo: CaseWriteReadSpecialTag(self.device, self.logger, self.options, self.host, expitype=1, expmssetting=0, caseno=caseNo)),
            # 6:  ("DIX type 2 write read positive test",   lambda self, caseNo: CaseWriteReadPositive(self.device, self.logger, self.options, self.host, expitype=2, expmssetting=0, caseno=caseNo)),
            # 7:  ("DIX type 2 write read negative test",   lambda self, caseNo: CaseWriteReadNegative(self.device, self.logger, self.options, self.host, expitype=2, expmssetting=0, caseno=caseNo)),
            # 8:  ("DIX type 2 write read special tag",     lambda self, caseNo: CaseWriteReadSpecialTag(self.device, self.logger, self.options, self.host, expitype=2, expmssetting=0, caseno=caseNo)),
            # 9:  ("DIX type 3 write read positive test",   lambda self, caseNo: CaseType3WriteReadPositive(self.device, self.logger, self.options, self.host, expitype=3, expmssetting=0, caseno=caseNo)),
            # 10: ("DIX type 3 write read negative test",   lambda self, caseNo: CaseType3WriteReadNegative(self.device, self.logger, self.options, self.host, expitype=3, expmssetting=0, caseno=caseNo)),
            # 11: ("DIX type 3 write read special tag",     lambda self, caseNo: CaseType3WriteReadSpecialTag(self.device, self.logger, self.options, self.host, expitype=3, expmssetting=0, caseno=caseNo)),
            # 12: ("DIF type 1 write read positive test",   lambda self, caseNo: CaseWriteReadPositive(self.device, self.logger, self.options, self.host, expitype=1, expmssetting=1, caseno=caseNo)),
            # 13: ("DIF type 1 write read negative test",   lambda self, caseNo: CaseWriteReadNegative(self.device, self.logger, self.options, self.host, expitype=1, expmssetting=1, caseno=caseNo)),
            # 14: ("DIF type 1 write read special tag",     lambda self, caseNo: CaseWriteReadSpecialTag(self.device, self.logger, self.options, self.host, expitype=1, expmssetting=1, caseno=caseNo)),
            # 15: ("DIF type 2 write read positive test",   lambda self, caseNo: CaseWriteReadPositive(self.device, self.logger, self.options, self.host, expitype=2, expmssetting=1, caseno=caseNo)),
            # 16: ("DIF type 2 write read negative test",   lambda self, caseNo: CaseWriteReadNegative(self.device, self.logger, self.options, self.host, expitype=2, expmssetting=1, caseno=caseNo)),
            # 17: ("DIF type 2 write read special tag",     lambda self, caseNo: CaseWriteReadSpecialTag(self.device, self.logger, self.options, self.host, expitype=2, expmssetting=1, caseno=caseNo)),
            # 18: ("DIF type 3 write read positive test",   lambda self, caseNo: CaseType3WriteReadPositive(self.device, self.logger, self.options, self.host, expitype=3, expmssetting=1, caseno=caseNo)),
            # 19: ("DIF type 3 write read negative test",   lambda self, caseNo: CaseType3WriteReadNegative(self.device, self.logger, self.options, self.host, expitype=3, expmssetting=1, caseno=caseNo)),
            # 20: ("DIF type 3 write read special tag",     lambda self, caseNo: CaseType3WriteReadSpecialTag(self.device, self.logger, self.options, self.host, expitype=3, expmssetting=1, caseno=caseNo)),

        }
        self.SetCases(caseDict)

        runCaseList = sorted(caseDict.keys(), key=lambda no: no) if options.case is None else [options.case]
        caseSummaryDict = self.AddGroupCases(*runCaseList)  # {id: summary}

        for k in runCaseList:
            with caseSummaryDict[k]:
                caseNo = k
                errcnt = caseDict[k][1](self, caseNo)

                caseSummaryDict[k].IncreaseError(errcnt)
                EndtoEndLib.TestSummary.AddItem(caseDict[k][0], errcnt)
                EndtoEndLib.TestSummary.Display(logger)
                EndtoEndLib.CaseSummary.Display(logger)

    def Cleanup(self):
        return True

if __name__ == "__main__":
    # Nothing is needed for main code. But keep the "with .." grammar!
    with Test():
        pass

# end of file
