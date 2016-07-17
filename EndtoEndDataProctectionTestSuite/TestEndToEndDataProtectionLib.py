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
</HISTORY>

"""

import random
import crcmod
import traceback

import Devices.IdentifyData as IdentifyData
import Utilities.Buffer as Buffer
from Utilities.PbdtExceptions import PbdtNvmeCmdError


class BufferType:
    ALL_ZERO = 0
    ALL_ONE = 1
    RANDOM = 2
    INCREMENTAL = 3


class TestSummary(object):
    record = []
    index = 0
    count = 0

    def __init__():
        pass

    @classmethod
    def AddItem(cls, title, errcnt):
        cls.record.append((cls.index, title, errcnt))
        cls.index += 1
        cls.count += 1

    @classmethod
    def ToString(cls):
        itemSpace = 70
        errorCountSpace = 1
        content = "Test Summary".center(itemSpace, "*")
        content += "\n"
        content += "No."+" Item ".ljust(itemSpace) + "Error Count".rjust(errorCountSpace) + "  \n"
        for i in range(cls.count):
            index = cls.record[i][0]
            testitem = cls.record[i][1]
            errcnt = cls.record[i][2]
            content += "%02d. " % (index+1)
            content += testitem.ljust(itemSpace) + "  " + str(errcnt).rjust(errorCountSpace) + " \n"
        return content

    @classmethod
    def Display(cls, logger):
        logger.Info(TestSummary.ToString())


class CaseSummary(object):
    caseRecord = {}
    MaxCaseNum = 500.0

    def __init__():
        pass

    @classmethod
    def AddItem(cls, logger, index, title, errcnt=0):
        header = "Case %s: %s" % (index, title)
        logger.Info(header)
        cls.caseRecord[index] = [title, errcnt]

    @classmethod
    def UpdateItem(cls, index, errcnt):
        cls.caseRecord[index][1] = errcnt

    @classmethod
    def ToString(cls):
        itemSpace = 180
        errorCountSpace = 1
        content = "Case Summary".center(itemSpace, "*")
        content += "\n"
        content += "Case."+" Item ".ljust(itemSpace) + "Error Count".rjust(errorCountSpace) + "  \n"

        for key in sorted(cls.caseRecord.keys(), key=float):
            header = cls.caseRecord[key][0]
            errcnt = cls.caseRecord[key][1]
            content += "%s  " % (key)
            content += header.ljust(itemSpace) + "  " + str(errcnt).rjust(errorCountSpace) + " \n"
        return content

    @classmethod
    def Display(cls, logger):
        logger.Info(CaseSummary.ToString())


def ShowIdentify(device):
    IdentifyData.GetIdentifyNamespaceDataObj(device).Print(level="simple")
    IdentifyData.GetIdentifyNamespaceDataObj(device).Print(level="pi")


def VerifyFormatSetting(device, logger, exppil=None, expitype=None, expmssetting=None, explbaf=0,
                        verbose=False):
    errcnt = 0

    idNsData = IdentifyData.GetIdentifyNamespaceDataObj(device)
    if idNsData.IsPIenabledandTypeofPIenabled != expitype:
        errcnt += 1
        logger.Error("FAIL: Expect Enabled PI Type: %s , actual Enabled PI Type: %s" % (expitype,
                     idNsData.IsPIenabledandTypeofPIenabled))

    if idNsData.transasFirstorLastEightBytesofMeta != exppil:
        errcnt += 1
        logger.Error("FAIL: Expect PI Location: %s , actual PI Location: %s" % (exppil,
                     idNsData.transasFirstorLastEightBytesofMeta))

    if idNsData.metaTransatEndofLBA != expmssetting:
        errcnt += 1
        logger.Error("FAIL: Expect Metadata Setting: %s , actual Metadata Setting: %s" % (expmssetting,
                     idNsData.metaTransatEndofLBA))

    if idNsData.lbaFormatSelected != explbaf:
        errcnt += 1
        logger.Error("FAIL: Expect LBA format: %s , actual LBA format: %s" % (
            explbaf, idNsData.lbaFormatSelected))

    if verbose:
        ShowIdentify(device)

    return errcnt


def FormatNvm(device, logger, options, host, exppil=None, expitype=None, expmssetting=None,
              explbaf=0, ses=0, verbose=False):

    if verbose:
        logger.Info("Send Format command, Pi Location:%d,  Pi Type:%d,  Metadata Setting:%d, "
                    "LBA Format Selected:%d,  security setting:%d" % (
                        exppil, expitype, expmssetting, explbaf, ses))

    try:
        status = device.FormatNvm(ses=ses, pil=exppil, pi=expitype, ms=expmssetting, lbaf=explbaf)
        if status != 0:
            logger.Info("Format command return status : 0x%xh/%d " % (status, status))
    except PbdtNvmeCmdError, e:
        status = e.rawStatus
        if status == 0x010b:   # Firmware Activation Requires Conventional Reset
            logger.Info("Firmware Activation Requires Conventional Reset")
            status = 0
        else:
            logger.Info("Format command return status : 0x%xh/%d " % (status, status))
    except Exception, err:
        logger.Info(err)
        status = 0xffff

    if options.powercycle:
        logger.Info("Going to power cycle")
        host.PowerCycle()

    DeviceTable.IntialLbaInfoTablebyDevice(device)

    return status


def FormatWithCheck(device, logger, options, host, exppil=None, expitype=None, expmssetting=None,
                    explbaf=0, ses=0, verbose=False, needcheck=True):

    errcnt = 0
    if exppil is None:
        # fw bug , alwasy 0
        exppil = random.randint(0, 1)

    if expitype is None:
        expitype = random.randint(1, 3)

    if expmssetting is None:
        # debug
        # we support interleaved meta currently
        expmssetting = 0

    status = FormatNvm(device, logger, options, host, exppil=exppil, expitype=expitype, expmssetting=expmssetting,
                       explbaf=explbaf, ses=ses, verbose=verbose)

    if status != 0:
        errcnt += 1

    if needcheck:
        errcnt += VerifyFormatSetting(device, logger, exppil=exppil, expitype=expitype,
                                      expmssetting=expmssetting, explbaf=explbaf, verbose=verbose)

    return errcnt


def UpdateId(device):
    idNsData = IdentifyData.GetIdentifyNamespaceDataObj(device)
    lbaSize = idNsData.lbaSize
    metaSize = idNsData.metaSize
    maxLba = idNsData.nsUse
    metaTrans = idNsData.metaTrans
    if metaTrans == 0:
        extended = False
    else:
        extended = True
    return maxLba, lbaSize, metaSize, extended


def GetNlbSlba(maxLba):
    nlb = random.randrange(8, 129, 8)
    slba = random.randint(0, maxLba - 1) / nlb * nlb
    return slba, nlb


def GetLBARange(maxLba):
    nlb = random.randrange(8, 129, 8)
    firstLba = random.randint(0, maxLba - 1) / nlb * nlb
    lastLba = firstLba + nlb - 1
    return nlb, firstLba, lastLba


class DeviceTable(object):
    deviceTable = {}     # deviceTable[device] = [lbaInfoTable]

    def __init__():
        pass

    @classmethod
    def SetLbaInfoTable(cls, device, lbainfotable):
        cls.deviceTable[device] = lbainfotable

    @classmethod
    def GetAllDeviceTable(cls):
        return cls.deviceTable

    @classmethod
    def GetLbaInfoTablebyDevice(cls, device):
        return cls.deviceTable[device]

    @classmethod
    def IntialLbaInfoTablebyDevice(cls, device):
        maxLba, lbaSize, metaSize, extended = UpdateId(device)
        if device not in cls.deviceTable.keys():
            lbaInfoTable = LBAInfoTable(maxlba=maxLba, lbasize=lbaSize, metasize=metaSize, extended=extended)
        else:
            lbaInfoTable = cls.deviceTable[device]
            lbaInfoTable.InitialLbaInfoTable(maxlba=maxLba, lbasize=lbaSize, metasize=metaSize, extended=extended)
        DeviceTable.SetLbaInfoTable(device, lbaInfoTable)


class LBAInfoTable(object):
    def __init__(self, maxlba=0, lbasize=512, metasize=8, extended=False):
        self.InitialLbaInfoTable(maxlba, lbasize, metasize, extended)

    def SetLbaInfoTable(self, lba, lbainfo):
        self.lbaInfoTable[lba] = lbainfo

    def InitialLbaInfoTable(self, maxlba, lbasize, metasize, extended):
        self.lbaInfoTable = {}              # LBAInfoTable[lba] = [writebuf, metabuf]
        self.maxLba = maxlba
        self.lbaSize = lbasize
        self.metaSize = metasize
        self.extended = extended

    def OutputBasic(self):
        return "max LBA 0x%xh/%d, LBA size, 0x%xh/%d, Meta size 0x%xh/%d, Meta Setting: %s" % (
            self.maxLba, self.maxLba, self.lbaSize, self.lbaSize, self.metaSize, self.metaSize,
            "extended" if self.extended else "interleaved")


class LBAInfo(object):

    def __init__(self, wBuf, metaWBuf=None):
        self.wBuf = wBuf
        self.metaWBuf = metaWBuf


class MetaAttr(object):

    def __init__(self, pract=0, checkcrc=1, checkapptag=1, checkreftag=1,
                 apptag=0, appmask=0, iswrite=True):
        self.pract = pract
        self.checkcrc = checkcrc
        self.checkapptag = checkapptag
        self.checkreftag = checkreftag
        self.apptag = apptag
        self.appmask = appmask
        self.isWrite = iswrite

    def output(self):
        outputString = ""
        readWriteStr = "Write command" if self.isWrite else "Read command"
        outputString += \
            "%s pract: %d, check crc: %d, check app tag: %d, check ref tag: %d,"\
            "app tag: 0x%xh, app mask: 0x%xh" % (
                readWriteStr, self.pract, self.checkcrc, self.checkapptag, self.checkreftag,
                self.apptag, self.appmask)

        return outputString


def CreateCompareBufferWithPi(logger, slba, nlb, lbainfotable, ismeta=False,
                              extended=True, compare=True, userdataonly=False):

    lbaSize = lbainfotable.lbaSize
    metaSize = lbainfotable.metaSize
    table = lbainfotable.lbaInfoTable

    valueList = []
    for curLBA in xrange(slba, slba+nlb):
        if curLBA in table.keys():
            if ismeta:
                if not extended:
                    valueList.extend(table[curLBA].metaWBuf.GetMultiUint8(0, metaSize))
            else:
                valueList.extend(table[curLBA].wBuf.GetMultiUint8(0, lbaSize))
                if extended and not userdataonly:
                    valueList.extend(table[curLBA].metaWBuf.GetMultiUint8(0, metaSize))
        else:
            if compare:
                raise Exception("LBA 0x%xh/%d hasn't been written, so no info to be compared" % (curLBA, curLBA))
            else:
                pass

    buf = Buffer.FromList(valueList)
    return buf


def CreateWriteBufferWithPi(device, logger, slba=0, nlb=1, buffertype=BufferType.RANDOM, reftag=None, customizedcrc=None,
                            customizedapptag=None, customizedreftag=None, verbose=False):
    # create buffer for each LBA
    lbaInfoTable = DeviceTable.GetLbaInfoTablebyDevice(device)

    newCrc = customizedcrc
    newApptag = customizedapptag
    newReftag = customizedreftag
    for blk in xrange(slba, slba+nlb):
        curLBA = blk

        wBuf = Buffer.Buffer(lbaInfoTable.lbaSize)

        if buffertype == BufferType.ALL_ZERO:
            wBuf.FillZeroes()
        elif buffertype == BufferType.ALL_ONE:
            wBuf.FillOnes()
        elif buffertype == BufferType.RANDOM:
            wBuf.FillRandom()
        elif buffertype == BufferType.INCREMENTAL:
            wBuf.FillIncremental()

        wBuf.SetUint32(0, curLBA, isBigEndian=True)

        if lbaInfoTable.metaSize != 0:
            metaWBuf = Buffer.Buffer(lbaInfoTable.metaSize)
            crc_func = crcmod.predefined.mkCrcFun('crc-16-t10-dif')
            crc = crc_func(wBuf.ToRawString())
            apptag = 0
            if reftag is None:
                initReftag = GetRefTag(curLBA)
            else:
                initReftag = reftag

            if customizedcrc is None:
                metaWBuf.SetUint16(0, crc, isBigEndian=True)
            else:
                metaWBuf.SetUint16(0, newCrc, isBigEndian=True)

            if customizedapptag is None:
                metaWBuf.SetUint16(2, apptag, isBigEndian=True)
            else:
                metaWBuf.SetUint16(2, newApptag, isBigEndian=True)

            if customizedreftag is None:
                metaWBuf.SetUint32(4, initReftag, isBigEndian=True)
            else:
                metaWBuf.SetUint32(4, newReftag, isBigEndian=True)
        else:
            metaWBuf = None

        lbainfo = LBAInfo(wBuf, metaWBuf)
        lbaInfoTable.SetLbaInfoTable(curLBA, lbainfo)


def SendWriteWithPi(
    device, logger, extended=False, slba=0, nlb=1, reftag=None, metaattr=None,
    userdataonly=False, verbose=False
):
    status = 0
    lbaInfoTable = DeviceTable.GetLbaInfoTablebyDevice(device)

    if extended:
        wBuf = CreateCompareBufferWithPi(
            logger, slba, nlb, lbaInfoTable, extended=extended, userdataonly=userdataonly)
        metaWBuf = CreateCompareBufferWithPi(
            logger, slba, nlb, lbaInfoTable, ismeta=True, extended=extended)
    else:
        wBuf = CreateCompareBufferWithPi(
            logger, slba, nlb, lbaInfoTable, extended=extended)
        if userdataonly:
            metaWBuf = None
        else:
            metaWBuf = CreateCompareBufferWithPi(
                logger, slba, nlb, lbaInfoTable, ismeta=True, extended=extended)

    if reftag is None:
        reftag = GetRefTag(slba)

    if verbose:
        logger.Info("Write command slba=0x%xh/%d, nlb=0x%xh/%d, reference tag 0x%xh/%d" % (
            slba, slba, nlb, nlb, reftag, reftag))
        logger.Info(metaattr.output())

    # status = device.Write(
    #     buf=wBuf, slba=slba, nlb=nlb, bufOffset=0, metadataBuf=metaWBuf, pract=metaattr.pract,
    #     checkcrc=metaattr.checkcrc, checkapptag=metaattr.checkapptag, checkreftag=metaattr.checkreftag,
    #     reftag=reftag, apptag=metaattr.apptag, appmask=metaattr.appmask)
    status = 0
    try:
        status = device.Write(
            buf=wBuf, slba=slba, nlb=nlb, bufOffset=0, metadataBuf=metaWBuf, pract=metaattr.pract,
            checkcrc=metaattr.checkcrc, checkapptag=metaattr.checkapptag, checkreftag=metaattr.checkreftag,
            reftag=reftag, apptag=metaattr.apptag, appmask=metaattr.appmask)
        if status != 0:
            logger.Info("Write command return status : 0x%xh/%d " % (status, status))
    except PbdtNvmeCmdError, e:
        status = e.rawStatus
        logger.Info("Write command return status : 0x%xh/%d " % (status, status))
        raise
    except Exception, err:
        logger.Error(err)
        logger.Info(traceback.format_exc())
        status += 1
        raise

    if status != 0:
        logger.Info("Prepare Write Buffer:")
        wBuf.Print(num=(wBuf.size/nlb))
        if not extended:
            logger.Info("Prepare Write Meta Buffer:")
            if metaWBuf is None:
                logger.Info("Meta buffer is None")
            else:
                metaWBuf.Print()
    return status


def SendReadWithPi(
    device, logger, extended=False, slba=0, nlb=1, reftag=None, metaattr=None, needCompare=False,
    userdataonly=False, verbose=False
):
    lbaInfoTable = DeviceTable.GetLbaInfoTablebyDevice(device)

    lbaSize = lbaInfoTable.lbaSize
    metaSize = lbaInfoTable.metaSize

    if extended:
        if userdataonly:
            rBuf = Buffer.Buffer(nlb*lbaSize)
        else:
            rBuf = Buffer.Buffer(nlb*(lbaSize+metaSize))
        metaRBuf = None
    else:
        rBuf = Buffer.Buffer(nlb*lbaSize)
        if userdataonly:
            metaRBuf = None
        else:
            metaRBuf = Buffer.Buffer(nlb*metaSize)

    if reftag is None:
        reftag = GetRefTag(slba)

    if verbose:
        logger.Info("Read command slba=0x%xh/%d, nlb=0x%xh/%d, reference tag 0x%xh/%d" % (
            slba, slba, nlb, nlb, reftag, reftag))
        logger.Info(metaattr.output())

    status = 0
    try:
        status = device.Read(
            buf=rBuf, slba=slba, nlb=nlb, bufOffset=0, metadataBuf=metaRBuf, pract=metaattr.pract,
            checkcrc=metaattr.checkcrc, checkapptag=metaattr.checkapptag, checkreftag=metaattr.checkreftag,
            reftag=reftag, apptag=metaattr.apptag, appmask=metaattr.appmask)
        if status != 0:
            logger.Info("Read command return status : 0x%xh/%d " % (status, status))
    except PbdtNvmeCmdError, e:
        status = e.rawStatus
        logger.Info("Read command return status : 0x%xh/%d " % (status, status))
        raise
    except Exception, err:
        logger.Error(err)
        logger.Info(traceback.format_exc())
        status += 1
        raise

    if needCompare:
        if verbose:
            logger.Info("Comparing read/write buffer ")

        wBuf = CreateCompareBufferWithPi(logger, slba, nlb, lbaInfoTable, ismeta=False,
                                         extended=extended, userdataonly=userdataonly)
        result = wBuf.Compare(rBuf, offset=0, refOffset=0, num=None, errorReport=False)
        if not result:
            status += 1
            if verbose:
                logger.Info("Prepared Write Buffer:")
                wBuf.Print(num=(lbaSize+metaSize))
                logger.Info("Return Read Buffer:")
                rBuf.Print(num=(lbaSize+metaSize))

        if not extended and metaattr.pract != 1:
            if verbose:
                logger.Info("Comparing read/write meta buffer")

            metaWBuf = CreateCompareBufferWithPi(logger, slba, nlb, lbaInfoTable,
                                                 ismeta=True, extended=extended)
            result = metaWBuf.Compare(metaRBuf, offset=0, refOffset=0, num=None, errorReport=False)
            if not result:
                status += 1
                if verbose:
                    logger.Info("Prepared Write Meta Buffer:")
                    metaWBuf.Print()
                    logger.Info("Return Read Meta Buffer:")
                    metaRBuf.Print()

    return status


def GetRefTag(slba):
    reftag = slba & 0xffffffff
    return reftag


def SendWrite(
    device, logger, slba=0, nlb=1, buffertype=BufferType.RANDOM, verbose=False
):
    lbaInfoTable = DeviceTable.GetLbaInfoTablebyDevice(device)

    for blk in xrange(slba, slba+nlb):
        curLBA = blk
        wBuf = Buffer.Buffer(lbaInfoTable.lbaSize)
        if buffertype == BufferType.ALL_ZERO:
            wBuf.FillZeroes()
        elif buffertype == BufferType.ALL_ONE:
            wBuf.FillOnes()
        elif buffertype == BufferType.RANDOM:
            wBuf.FillRandom()
        elif buffertype == BufferType.INCREMENTAL:
            wBuf.FillIncremental()

        wBuf.SetUint32(0, curLBA, isBigEndian=True)

        metaWBuf = None

        lbainfo = LBAInfo(wBuf, metaWBuf)
        lbaInfoTable.SetLbaInfoTable(curLBA, lbainfo)

    lbaSize = lbaInfoTable.lbaSize
    table = lbaInfoTable.lbaInfoTable

    valueList = []
    for curLBA in xrange(slba, slba+nlb):
        valueList.extend(table[curLBA].wBuf.GetMultiUint8(0, lbaSize))

    wBuf = Buffer.FromList(valueList)

    status = 0
    if verbose:
        logger.Info("Write command slba=0x%xh/%d, nlb=0x%xh/%d, " % (slba, slba, nlb, nlb))

    try:
        status = device.Write(
            buf=wBuf, slba=slba, nlb=nlb, bufOffset=0)
        if status != 0:
            logger.Info("Write command return status : 0x%xh/%d " % (status, status))
    except PbdtNvmeCmdError, e:
        status = e.rawStatus
        logger.Info("Write command return status : 0x%xh/%d " % (status, status))
        raise
    except Exception, err:
        logger.Error(err)
        logger.Info(traceback.format_exc())
        status += 1
        raise

    if status != 0:
        logger.Info("Prepare Write Buffer:")
        wBuf.Print(num=lbaSize)
    return status


def SendRead(
    device, logger, slba=0, nlb=1, needcompare=False, verbose=False
):
    lbaInfoTable = DeviceTable.GetLbaInfoTablebyDevice(device)
    table = lbaInfoTable.lbaInfoTable

    lbaSize = lbaInfoTable.lbaSize

    rBuf = Buffer.Buffer(nlb*lbaSize)

    if verbose:
        logger.Info("Read command slba=0x%xh/%d, nlb=0x%xh/%d" % (slba, slba, nlb, nlb))

    status = 0
    try:
        status = device.Read(
            buf=rBuf, slba=slba, nlb=nlb, bufOffset=0)
        if status != 0:
            logger.Info("Read command return status : 0x%xh/%d " % (status, status))
    except PbdtNvmeCmdError, e:
        status = e.rawStatus
        logger.Info("Read command return status : 0x%xh/%d " % (status, status))
        raise
    except Exception, err:
        logger.Error(err)
        logger.Info(traceback.format_exc())
        status += 1
        raise

    if needcompare:
        logger.Info("Comparing read/write buffer")

        valueList = []
        for curLBA in xrange(slba, slba+nlb):
            if curLBA in table.keys():
                valueList.extend(table[curLBA].wBuf.GetMultiUint8(0, lbaSize))
            else:
                raise Exception("LBA 0x%xh/%d hasn't been written,"
                                "so no info to be compared" % (curLBA, curLBA))
        wBuf = Buffer.FromList(valueList)

        result = wBuf.Compare(rBuf, offset=0, refOffset=0, num=None, errorReport=False)
        if not result:
            status += 1
            if verbose:
                logger.Info("Prepared Write Buffer:")
                wBuf.Print(num=lbaSize)
                logger.Info("Return Read Buffer:")
                rBuf.Print(num=lbaSize)
    return status


def Write(
    device, logger, options, firstlba=0, lastlba=1, nlb=1,
    buffertype=BufferType.RANDOM, verbose=False
):
    errcnt = 0

    remain = 1 if (lastlba - firstlba + 1) % nlb else 0
    count = (lastlba - firstlba + 1)/nlb + remain

    for cnt in xrange(count):

        slba = firstlba

        nlb = nlb if lastlba - slba + 1 >= nlb else (lastlba - slba + 1)

        errcnt += SendWrite(device, logger, slba=slba, nlb=nlb,
                            buffertype=buffertype, verbose=verbose)

        firstlba += nlb - 1

    return errcnt


def Read(
    device, logger, options, firstlba=0, lastlba=1, nlb=1,
    needcompare=False, verbose=False
):
    errcnt = 0

    remain = 1 if (lastlba - firstlba + 1) % nlb else 0
    count = (lastlba - firstlba + 1)/nlb + remain

    for cnt in xrange(count):

        slba = firstlba

        nlb = nlb if lastlba - slba + 1 >= nlb else (lastlba - slba + 1)

        errcnt += SendRead(device, logger, slba=slba, nlb=nlb,
                           needcompare=needcompare, verbose=verbose)

        firstlba += nlb - 1
    return errcnt


def Compare(device, logger, options, firstlba=0, lastlba=0, nlb=8, buffertype=BufferType.RANDOM, verbose=True):
    errcnt = 0

    logger.Info("Write from LBA address 0x%xh/%d to 0x%xh/%d, nlb=0x%xh/%d" % (
        firstlba, firstlba, lastlba, lastlba, nlb, nlb))

    errcnt += Write(device, logger, options, firstlba=firstlba, lastlba=lastlba, nlb=nlb,
                    buffertype=buffertype, verbose=verbose)

    logger.Info("Read from LBA address 0x%xh/%d to 0x%xh/%d, nlb=0x%xh/%d" % (firstlba,
                firstlba, lastlba, lastlba, nlb, nlb))
    errcnt += Read(device, logger, options, firstlba=firstlba, lastlba=lastlba, nlb=nlb,
                   needcompare=True, verbose=verbose)

    return errcnt


def WriteWithPi(
    device, logger, options, firstlba=0, lastlba=1, nlb=1,
    buffertype=BufferType.RANDOM, reftag=None, wmetaattr=None, extended=False,
    userdataonly=False, customizedcrc=None, customizedapptag=None, customizedreftag=None, verbose=False
):
    errcnt = 0

    remain = 1 if (lastlba - firstlba + 1) % nlb else 0
    count = (lastlba - firstlba + 1)/nlb + remain

    for cnt in xrange(count):
        slba = firstlba

        nlb = nlb if lastlba - slba + 1 >= nlb else (lastlba - slba + 1)

        CreateWriteBufferWithPi(
            device, logger, slba=slba, nlb=nlb, buffertype=buffertype,
            reftag=reftag, customizedcrc=customizedcrc, customizedapptag=customizedapptag,
            customizedreftag=customizedreftag, verbose=verbose)

        errcnt += SendWriteWithPi(
            device, logger, extended=extended, slba=slba, nlb=nlb, reftag=reftag,
            metaattr=wmetaattr, userdataonly=userdataonly, verbose=verbose)

        if wmetaattr.pract == 1:  # because it could send incorrect PI when PRACT 1, need to send correct PI to LBA table to compare
            lbaInfoTable = DeviceTable.GetLbaInfoTablebyDevice(device)

            for blk in xrange(slba, slba+nlb):
                curLBA = blk
                wBuf = lbaInfoTable.lbaInfoTable[curLBA].wBuf
                metaWBuf = Buffer.Buffer(lbaInfoTable.metaSize)
                crc_func = crcmod.predefined.mkCrcFun('crc-16-t10-dif')
                crc = crc_func(wBuf.ToRawString())
                metaWBuf.SetUint16(0, crc, isBigEndian=True)
                metaWBuf.SetUint16(2, 0, isBigEndian=True)
                metaWBuf.SetUint32(4, GetRefTag(curLBA), isBigEndian=True)
                lbainfo = LBAInfo(wBuf, metaWBuf)
                lbaInfoTable.SetLbaInfoTable(curLBA, lbainfo)

        firstlba += nlb - 1
    return errcnt


def ReadWithPi(
    device, logger, options, firstlba=0, lastlba=1, nlb=1,
    reftag=None, rmetaattr=None, extended=False, needCompare=False,
    userdataonly=False, verbose=False
):
    errcnt = 0

    remain = 1 if (lastlba - firstlba + 1) % nlb else 0
    count = (lastlba - firstlba + 1) / nlb + remain

    for cnt in xrange(count):

        slba = firstlba

        nlb = nlb if lastlba - slba + 1 >= nlb else (lastlba - slba + 1)

        errcnt += SendReadWithPi(
            device, logger, extended=extended, slba=slba, nlb=nlb, reftag=reftag,
            metaattr=rmetaattr, needCompare=needCompare, userdataonly=userdataonly,
            verbose=verbose)
        firstlba += nlb - 1
    return errcnt


def CompareWithPi(
    device, logger, options, firstlba=0, lastlba=0, nlb=8, buffertype=BufferType.RANDOM,
    wreftag=None, rreftag=None, wmetaattr=None, rmetaattr=None, extended=False,
    userdataonly=False, customizedcrc=None, customizedapptag=None, customizedreftag=None,
    verbose=True
):
    errcnt = 0
    status = 0

    logger.Info("Write from LBA address 0x%xh/%d to 0x%xh/%d, nlb=0x%xh/%d" % (
        firstlba, firstlba, lastlba, lastlba, nlb, nlb))

    try:
        errcnt += WriteWithPi(device, logger, options, firstlba=firstlba, lastlba=lastlba, nlb=nlb,
                              buffertype=buffertype, reftag=wreftag, wmetaattr=wmetaattr,
                              extended=extended, userdataonly=userdataonly, customizedcrc=customizedcrc,
                              customizedapptag=customizedapptag, customizedreftag=customizedreftag,
                              verbose=verbose)

        logger.Info("Read from LBA address 0x%xh/%d to 0x%xh/%d, nlb=0x%xh/%d" % (
            firstlba, firstlba, lastlba, lastlba, nlb, nlb))
        errcnt += ReadWithPi(device, logger, options, firstlba=firstlba, lastlba=lastlba,
                             nlb=nlb, reftag=rreftag, rmetaattr=rmetaattr,
                             extended=extended,  userdataonly=userdataonly, needCompare=True,
                             verbose=verbose)
    except PbdtNvmeCmdError, e:
        status = e.rawStatus
        logger.Info("Caught error, command return status : 0x%xh/%d " % (status, status))
        logger.Info(e.msg)
        return status
    except Exception, err:
        status += 1
        logger.Error(err)
        logger.Info(traceback.format_exc())
        return status

    return errcnt


def ValidateRetValue(logger, expstatus, func, *args, **kwargs):
    '''
    None: Command has error, but error code unknown
    '''
    errcnt = 0

    try:
        status = func(*args, **kwargs)
        if status == expstatus:
            if expstatus is not None:
                logger.Info("PASS: Command return status 0x%xh/%d" % (expstatus, expstatus))
            else:
                logger.Info("PASS: Command return no error")
        else:
            errcnt += 1
            if expstatus is None:
                logger.Error("FAIL: Command return status 0x%xh/%d, expect command return error" % (
                    status, status))
            else:
                logger.Error("FAIL: Command return status 0x%xh/%d, expect command return 0x%xh/%d" % (
                    status, status, expstatus, expstatus))
    except PbdtNvmeCmdError, e:
        if e.rawStatus == -22:
            errcnt += 1
            logger.Error("FAIL: Return system error by driver, not by fw")

        elif e.rawStatus == 0x010b:   # Firmware Activation Requires Conventional Reset
            errcnt += 1
            logger.Error("FAIL: Return status need Firmware Activation Requires Conventional Reset")

        elif e.rawStatus == expstatus:
            logger.Info("PASS: command return 0x%xh/%d, which is expected" % (expstatus, expstatus))
        else:
            errcnt += 1
            if expstatus is None:
                logger.Error("FAIL: command return error 0x%xh/%d, expect command return no error" % (
                    e.rawStatus, e.rawStatus))
            else:
                logger.Error("FAIL: command return 0x%xh/%d, expect command return 0x%xh/%d" % (
                    e.rawStatus, e.rawStatus, expstatus, expstatus))
        logger.Info(e.msg)

    return errcnt
