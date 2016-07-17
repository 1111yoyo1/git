#!/usr/bin/env python
"""
Copyright (C) 2015 Memblaze Technology Co., Ltd.
This software contains confidential information and trade secrets of Memblaze Technology Co., Ltd.
Use, disclosure, or reproduction is prohibited without the prior express written permission of
Memblaze Technology Co., Ltd.

<SCRIPTNAME>
</SCRIPTNAME>

<DESCRIPTION>

</DESCRIPTION>

<AUTHOR>
    Youyou Xu
</AUTHOR>

<HISTORY>
Version     Data        Author                  Description
1.0         04/20/2016  jing.xu@memblaze.com    initial script
</HISTORY>

"""

import random
import math
import os
import time
import collections
import zlib
import array

import Devices.Vu as Vu
import TestFramework.TestTarget as TestTarget
import IoExerciser.IoExerciser as IoExerciser
import Devices.IdentifyData as IdentifyData
import Utilities.Logger as Logger
import Utilities.Buffer as Buffer
import Utilities.crcmod as crcmod
import Utilities.Random as Random

Logger.LogModule(level=Logger.DEBUG)

# need to add case that insert identify between write and read

def compareBuff(logger, buffer_1, buffer_2):
    errcnt = 0

    result = True
    if buffer_1.size != buffer_2.size:
        logger.Error("Buffer size not match, one is %d and the other is %d" % (buffer_1.size, buffer_2.size))
        result = False
    if result:
        for byte in range(0, buffer_1.size):
            value_buffer1 = buffer_1.GetUint8(byte)
            value_buffer2 = buffer_2.GetUint8(byte)
            if value_buffer1 != value_buffer2:
                # debug
                logger.Error("Data[Byte]: %3d, Expected: %4d/0x%2x, Actual: %4d/0x%2x. Check **FAIL**." % (byte, value_buffer1, value_buffer1, value_buffer2, value_buffer2))
                result = False

    errcnt = 0 if result else 1
    return errcnt


def ShowIdentify(device):
    IdentifyData.GetIdentifyNamespaceDataObj(device).Print(level="simple")
    IdentifyData.GetIdentifyNamespaceDataObj(device).Print(level="pi")


def Format(device, ses=0, pil=0, pi=0, ms=0, lbaf=0):
    device.FormatNvm(ses=ses, pil=pil, pi=pi, ms=ms, lbaf=lbaf)
    ShowIdentify(device)
    #need to compare identify data after format\


def FormatWithCheck(device, logger, expPiL=0, expPiType=0, expMsSetting=0, expLbaf=0, ses=0, verbose=False):
    errcnt = 0

    logger.Info("Send Format command, Pi Location:%d  Pi Type:%d  Metadata Setting:%d   LBA FormatSelected:%d  security setting:%d" % (expPiL, expPiType, expMsSetting, expLbaf, ses))
    status = device.FormatNvm(ses=ses, pil=expPiL, pi=expPiType, ms=expMsSetting, lbaf=expLbaf)

    if status != 0:
        errcnt += 1
        logger.Error("Format command return status : %s " % (status))

    idNsData = IdentifyData.GetIdentifyNamespaceDataObj(device)
    if idNsData.IsPIenabledandTypeofPIenabled != expPiType:
        errcnt += 1
        logger.Error("Expect Enabled PI Type: %s , actual Enabled PI Type: %s" % (expPiType, idNsData.IsPIenabledandTypeofPIenabled))

    if idNsData.transasFirstorLastEightBytesofMeta != expPiL:
        errcnt += 1
        logger.Error("Expect PI Location: %s , actual Enabled PI Location: %s" % (expPiL, idNsData.transasFirstorLastEightBytesofMeta))

    if idNsData.metaTransatEndofLBA != expMsSetting:
        errcnt += 1
        logger.Error("Expect Metadata Setting: %s , actual Metadata Setting: %s" % (expMsSetting, idNsData.metaTransatEndofLBA))

    if idNsData.lbaFormatSelected != expLbaf:
        errcnt += 1
        logger.Error("Expect LBA format: %s , actual LBA format: %s" % (expLbaf, idNsData.lbaFormatSelected))

    if verbose:
        ShowIdentify(device)

    return errcnt


def TestPiSettingMatchExp(device, logger, verbose=False):
    errcnt = 0

    idNsData = IdentifyData.GetIdentifyNamespaceDataObj(device)
    expMsSetting = idNsData.metaTrans
    expPiL = idNsData.transasFirstorLastEightBytesofMeta
    lbaSize = idNsData.lbaSize

    errcnt += FormatWithCheck(device, logger, expPiL=expPiL, expPiType=0, expMsSetting=expMsSetting, expLbaf=1, ses=0, verbose=verbose)
    errcnt += FormatWithCheck(device, logger, expPiL=expPiL, expPiType=1, expMsSetting=expMsSetting, expLbaf=1, ses=0, verbose=verbose)
    errcnt += FormatWithCheck(device, logger, expPiL=expPiL, expPiType=2, expMsSetting=expMsSetting, expLbaf=1, ses=0, verbose=verbose)
    errcnt += FormatWithCheck(device, logger, expPiL=expPiL, expPiType=3, expMsSetting=expMsSetting, expLbaf=1, ses=0, verbose=verbose)

    return errcnt


def CreateReadBuffer(nlb=1, usemptr=True, lbaSize=512, metaSize=8):
    if not usemptr:
        blockSize = lbaSize+metaSize
    else:
        blockSize = lbaSize
    bufSize = blockSize*nlb

    rbuf = Buffer.Buffer(bufSize)
    rbuf.FillZeroes()
    return rbuf


def CreateReadMetaBuffer(nlb=1, usemptr=True, metaSize=8):
    if not usemptr:
        metaRBuf = None
    else:
        metaRBuf = Buffer.Buffer(metaSize*nlb)
        metaRBuf.FillZeroes()

    return metaRBuf


def CreateWriteBufferWithPi(logger, slba=0, nlb=1, usemptr=True, buffertype=0, lbaSize=512, metaSize=8, verbose=False):
    if not usemptr:
        blockSize = lbaSize+metaSize
    else:
        blockSize = lbaSize
    if verbose:
        logger.Info("***********Prepared Write Buffer**********")
        logger.Info("Each Buffer Size :%d   nlb: %d " % (blockSize, nlb))

    bufSize = blockSize*nlb
    buf = Buffer.Buffer(bufSize)

    if buffertype == 0:
        buf.FillZeroes()
    elif buffertype == 1:
        buf.FillOnes()
    elif buffertype == 2:
        buf.FillRandom()
    elif buffertype == 3:
        if usemptr:
            buf.FillIncremental()
        else:
            for blk in xrange(nlb):
                valueRange = range(0, 256)
                valueLen = len(valueRange)
                for i in range(lbaSize):
                    buf.SetUint8(blk*lbaSize + blk*metaSize + i, valueRange[i % valueLen])

    if not usemptr:
        for blk in xrange(nlb):
            blkBuff = buf.GetMultiUint8(blk*blockSize, lbaSize)
            crc_func = crcmod.predefined.mkCrcFun('crc-16-t10-dif')
            crc = crc_func(blkBuff.tostring())
            apptag = 0
            reftag = (slba+blk) & 0x0f
            buf.SetUint16(lbaSize*(blk+1)+metaSize*blk + 0, crc, isBigEndian=True)
            buf.SetUint16(lbaSize*(blk+1)+metaSize*blk + 2, apptag, isBigEndian=True)
            buf.SetUint32(lbaSize*(blk+1)+metaSize*blk + 4, reftag, isBigEndian=True)

    if verbose:
        buf.Print(num=bufSize)
        logger.Info("*********************")

    # if not usemptr:
    #     buf = Buffer.Buffer((lbaSize+metaSize)*nlb)

    #     if IsWriteBuffer:
    #         # buf.FillOnes()

    #         # buf.FillIncremental()
    #         # for incremental
    #         for blk in xrange(nlb):
    #             valueRange = range(0, 256)
    #             valueLen = len(valueRange)
    #             for i in range(lbaSize):
    #                 buf.SetUint8(blk*lbaSize + blk*metaSize + i, valueRange[i % valueLen])
    #             blkBuff = buf.GetMultiUint8(blk*(lbaSize+metaSize), lbaSize)
    #             crc_func = crcmod.predefined.mkCrcFun('crc-16-t10-dif')
    #             crc = crc_func(blkBuff.tostring())
    #             apptag = 0
    #             reftag = (slba+blk) & 0x0f
    #             buf.SetUint16(lbaSize*(blk+1)+metaSize*blk + 0, crc, isBigEndian=True)
    #             buf.SetUint16(lbaSize*(blk+1)+metaSize*blk + 2, apptag, isBigEndian=True)
    #             buf.SetUint32(lbaSize*(blk+1)+metaSize*blk + 4, reftag, isBigEndian=True)

    #         # # create buffer first, then insert crc
    #         # buf.FillRandom()
    #         # for blk in xrange(nlb):
    #         #     blkBuff = buf.GetMultiUint8(blk*(lbaSize+metaSize), lbaSize)
    #         #     crc_func = crcmod.predefined.mkCrcFun('crc-16-t10-dif')
    #         #     crc = crc_func(blkBuff.tostring())
    #         #     apptag = 0
    #         #     reftag = (slba+blk) & 0x0f
    #         #     buf.SetUint16(lbaSize*(blk+1)+metaSize*blk + 0, crc, isBigEndian=True)
    #         #     buf.SetUint16(lbaSize*(blk+1)+metaSize*blk + 2, apptag, isBigEndian=True)
    #         #     buf.SetUint32(lbaSize*(blk+1)+metaSize*blk + 4, reftag, isBigEndian=True)

    #     else:
    #         buf.FillZeroes()
    # else:
    #     size = (lbaSize)*nlb
    #     buf = Buffer.Buffer(size)
    #     if IsWriteBuffer:
    #         buf.FillRandom()
    #         #buf.FillIncremental()
    #     else:
    #         buf.FillZeroes()

    return buf


def CreateWriteMetaBufferWithPi(logger, buf, slba=0, nlb=1, usemptr=None, lbaSize=512, metaSize=8, verbose=False):
    size = metaSize*nlb
    if not usemptr:
        metabuf = None
    else:
        metabuf = Buffer.Buffer(size)
        for blk in xrange(nlb):
            blkBuff = buf.GetMultiUint8(blk*lbaSize, lbaSize)
            crc_func = crcmod.predefined.mkCrcFun('crc-16-t10-dif')
            crc = crc_func(blkBuff.tostring())
            apptag = 0
            reftag = (slba+blk) & 0x0f
            metabuf.SetUint16(metaSize*blk + 0, crc, isBigEndian=True)
            metabuf.SetUint16(metaSize*blk + 2, apptag, isBigEndian=True)
            metabuf.SetUint32(metaSize*blk + 4, reftag, isBigEndian=True)
            # if verbose:
            #     logger.Info("Metadata buffer: CRC tag 0x%xh, app tag 0x%dh, ref tag 0x%xh" % (crc, apptag, reftag))

    if verbose and metabuf is not None:
        logger.Info("*****Prepared Write Metadata Buffer********")
        logger.Info("Buffer Size: %d" % (size))
        if usemptr:
            metabuf.Print(num=size)
        logger.Info("*********************")

    return metabuf


def SendWriteWithPi(device, logger, wbuf, metaBuf, slba=0, nlb=1, pract=1, checkcrc=0, checkapptag=0, checkreftag=0, reftag=None, apptag=0, appmask=0, verbose=False):
    errcnt = 0

    if reftag is None:
        initRefTag = slba & 0x0f
    else:
        initRefTag = reftag

    logger.Info("Send Write command, slba: %d/0x%xh, nlb: %d/0x%xh, pract: %d/0%xh, checkcrc:  %d/0%xh, check app tag:  %d/0%xh, check ref tag: %d/0%xh, init ref tag : %d/0%xh" % (slba, slba, nlb, nlb, pract, pract, checkcrc, checkcrc, checkapptag, checkapptag, checkreftag, checkreftag, initRefTag, initRefTag))
    status = device.Write(buf=wbuf, slba=slba, nlb=nlb, bufOffset=0, metadataBuf=metaBuf, pract=pract, checkcrc=checkcrc, checkapptag=checkapptag, checkreftag=checkreftag, reftag=initRefTag, apptag=apptag, appmask=appmask, lr=0)

    if status != 0:
        errcnt += 1
        logger.Error("Write command return status 0x%xh/%d" % (errcnt, errcnt))

    return errcnt


def SendReadWithPi(device, logger, rbuf, metaBuf, slba=0, nlb=1, pract=0, checkcrc=0, checkapptag=0, checkreftag=0, reftag=None, apptag=0, appmask=0, verbose=False):
    errcnt = 0

    if reftag is None:
        extRefTag = slba & 0x0f
    else:
        extRefTag = reftag

    logger.Info("Send Read command, slba: %d/0x%xh, nlb: %d/0x%xh, pract: %d/0%xh, checkcrc:  %d/0%xh, checkapptag:  %d/0%xh, checkreftag: %d/0%xh, expect ref tag : %d/0%xh" % (slba, slba, nlb, nlb, pract, pract, checkcrc, checkcrc, checkapptag, checkapptag, checkreftag, checkreftag, extRefTag, extRefTag))
    status = device.Read(buf=rbuf, slba=slba, nlb=nlb, bufOffset=0, metadataBuf=metaBuf, pract=pract, checkcrc=checkcrc, checkapptag=checkapptag, checkreftag=checkreftag, reftag=extRefTag, apptag=apptag, appmask=appmask, lr=0)
    if status != 0:
        errcnt += 1
        logger.Error("Read command return status 0x%xh/%d" % (errcnt, errcnt))

    return errcnt


def SendWriteReadCompareWithPi(device, logger, options, buffertype=0, slba=0, nlb=1, writepract=0, readpract=0, checkcrc=0, checkapptag=0, checkreftag=0, reftag=None, apptag=0, appmask=0, verbose=False):
    errcnt = 0

    sleeptime = 0
    time.sleep(sleeptime)

    if options.usemtpr is None:
        idNsData = IdentifyData.GetIdentifyNamespaceDataObj(device)
        if idNsData.metaTrans == 1:
            usemptr = False
        else:
            usemptr = True
    else:
        usemptr = True if options.usemptr == 1 else False

    idNsData = IdentifyData.GetIdentifyNamespaceDataObj(device)
    lbaSize = idNsData.lbaSize if options.lbaSize is None else options.lbaSize
    metaSize = 8

    wbuf = CreateWriteBufferWithPi(logger, slba=slba, nlb=nlb,  usemptr=usemptr, buffertype=buffertype, lbaSize=lbaSize, metaSize=metaSize, verbose=verbose)
    metaWBuf = CreateWriteMetaBufferWithPi(logger, wbuf, slba=slba, nlb=nlb, usemptr=usemptr, lbaSize=lbaSize,  metaSize=metaSize, verbose=verbose)
    errcnt += SendWriteWithPi(device, logger, wbuf, metaWBuf, slba=slba, nlb=nlb, pract=writepract, checkcrc=checkcrc, checkapptag=checkapptag, checkreftag=checkreftag, reftag=reftag, apptag=apptag, appmask=appmask, verbose=verbose)

    time.sleep(sleeptime)

    rbuf = CreateReadBuffer(nlb=nlb, usemptr=usemptr, lbaSize=lbaSize, metaSize=metaSize)
    metaRBuf = CreateReadMetaBuffer(nlb=nlb, usemptr=usemptr, metaSize=metaSize)
    errcnt += SendReadWithPi(device, logger, rbuf, metaRBuf, slba=slba, nlb=nlb, pract=readpract, checkcrc=checkcrc, checkapptag=checkapptag, checkreftag=checkreftag, reftag=reftag, apptag=apptag, appmask=appmask, verbose=verbose)

    errcnt += compareBuff(logger, wbuf, rbuf)
    logger.Info("Results of comparing write/read Buffer:  error count %d" % errcnt)

    if usemptr:
        errcnt += compareBuff(logger, metaWBuf, metaRBuf)
        logger.Info("Results of comparing metadata Buffer: error count %d" % errcnt)

    if verbose:
        logger.Info("Results of read Buffer")
        rbuf.Print()
        if usemptr:
            logger.Info("Results of metadata Buffer")
            metaRBuf.Print()
    # if errcnt != 0: # debug
    #         raise Exception( "Error count %d" % errcnt)

    return errcnt


def Tuning(device, host, logger):
    pass
    # power cycle
    # host.PowerCycle()

    # format check identify
    # FormatWithCheck(device, logger, expPiL=0, expPiType=0, expMsSetting=0, expLbaf=0, verbose=False)

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
                "--lbasize",
                type="int",
                dest="lbaSize",
                default=None,
                help="Choose LBA Size to test,  default is based on Identify data, you can input \
                supported value (512, 4096) you want"),
            optparse.Option(
                "--usemtpr",
                type="int",
                dest="usemtpr",
                default=None,
                help="Choose to use mtpr you want, default is based on Identify data, you can input \
                supported value (0,1) you want"),
            optparse.Option(
                "-m", "--debug",
                type="int",
                dest="debugMode",
                default=0,
                help="default is 0, not in debug mode"),
        ]
        return optionList

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
        debugMode = options.debugMode
        device = self.device
        host = self.host
        logger = self.logger

        seed = Random.SetRandomSeed(seed=None)
        Logger.Info("Random Seed %s" % seed)

        errcnt = 0
        verbose = True

        # use mptr
        # slba 4k align, nlb 4k align
        # for slba in xrange(0, 100):
        #     errcnt += SendWriteReadCompareWithPi(device, logger, usemptr=True, slba=slba, nlb=8, writepract=0, readpract=0, checkcrc=0, checkapptag=0, checkreftag=0, reftag=None, apptag=0, appmask=0, verbose=True)

        # not use mptr
        # slba 4k align, nlb 4k align
        # for slba in xrange(0, 100):
        #     errcnt += SendWriteReadCompareWithPi(device, logger, usemptr=False, slba=slba, nlb=8, writepract=0, readpract=0, checkcrc=0, checkapptag=0, checkreftag=0, reftag=None, apptag=0, appmask=0, verbose=True)

        for slba in xrange(0, 1):
            errcnt += SendWriteReadCompareWithPi(device, logger, options, buffertype=3, slba=slba*8, nlb=8, writepract=0, readpract=0, checkcrc=0, checkapptag=0, checkreftag=0, reftag=None, apptag=0, appmask=0, verbose=True)


        print errcnt
        return errcnt

    def Cleanup(self):
        return True

if __name__ == "__main__":
    # Nothing is needed for main code. But keep the "with .." grammar!
    with Test():
        pass

# end of file
