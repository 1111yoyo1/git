#!/usr/bin/env python
"""
Copyright (C) 2015 Memblaze Technology Co., Ltd.
This software contains confidential information and trade secrets of Memblaze Technology Co., Ltd.
Use, disclosure, or reproduction is prohibited without the prior express written permission of
Memblaze Technology Co., Ltd.

<SCRIPTNAME>
   TestEndToEndDataProtectionPerformance.py
</SCRIPTNAME>

<DESCRIPTION>
    The script test end-to-end data protection performance
</DESCRIPTION>

<AUTHOR>
    Youyou Xu
</AUTHOR>

<HISTORY>
Version     Data        Author                  Description
1.0         06/23/2016  youyou xu               Initial script
1.1         07/13/2016  youyou xu               Modify script to adapt to test summary format
</HISTORY>

"""

import random

import TestFramework.TestTarget as TestTarget
import Utilities.Buffer as Buffer
import IoExerciser.IoExerciser as IoExerciser
import Utilities.Random as Random
import EndToEndDataProtectionLib as EndtoEndLib
import TestFramework.TestSummary as TestSummary


class IOType:
    SEQ_WRITE = 1
    SEQ_READ = 2
    RAN_WRITE = 3
    RAN_READ = 4
    MIX_RAN_WRITE = 5


def GetLBARange(maxLba, startLBA=None, step=None):
    if step is None:
        step = (maxLba/10) >> 3 << 3

    if startLBA is None:
        startLBA = random.randint(0, maxLba - 1) / 8 * 8

    endLBA = startLBA + step if startLBA + step < maxLba else maxLba
    return startLBA, endLBA


def ProcessReadWriteTestMatrix(device, logger, options, caseno, no, args):
    lbaInfoTable = EndtoEndLib.DeviceTable.GetLbaInfoTablebyDevice(device)
    maxLba = lbaInfoTable.maxLba
    extended = lbaInfoTable.extended

    title = args[0]
    pract = args[1][0]
    iotype = args[1][1]

    subErrCnt = 0
    no = "%u.%02u" % (caseno, no)
    if extended:
        raise Exception("Extended Metadata is currently not supported")

    ioEx = IoExerciser.GetIoExerciserObj(device, engine="native")
    currentSummary = TestSummary.GetSummary(no, title)
    EndtoEndLib.CaseSummary.AddItem(logger, no, title)
    with currentSummary:

        startLBA, endLBA = GetLBARange(maxLba)

        if iotype == IOType.SEQ_WRITE:
            logger.Info("Exucute sequential write")
            subErrCnt += EndtoEndLib.ValidateRetValue(logger, None, ioEx.SeqWriteLoop, loop=1,
                                                      ioSizeInBytes=131072, minLba=startLBA, maxLba=endLBA,
                                                      dataPattern=None, qDepth=256, wrapUpTime=1,
                                                      checkcrc=1, checkapptag=1, checkreftag=1,
                                                      pract=pract)
        elif iotype == IOType.SEQ_READ:
            logger.Info("Exucute sequential read")
            logger.Info("Precondition with sequential write")
            subErrCnt += EndtoEndLib.ValidateRetValue(logger, None, ioEx.SeqWriteLoop, loop=1,
                                                      ioSizeInBytes=131072, minLba=startLBA, maxLba=endLBA,
                                                      dataPattern=None, qDepth=256, wrapUpTime=1,
                                                      checkcrc=1, checkapptag=1, checkreftag=1,
                                                      pract=pract)
            logger.Info("Doing sequential read")
            subErrCnt += EndtoEndLib.ValidateRetValue(logger, None, ioEx.SeqReadLoop, loop=1,
                                                      ioSizeInBytes=131072, maxIoSizeInBytes=None,
                                                      minLba=startLBA, maxLba=endLBA, dataPattern=None,
                                                      qDepth=256, wrapUpTime=1,
                                                      checkcrc=1, checkapptag=1, checkreftag=1,
                                                      pract=pract)
        elif iotype == IOType.RAN_WRITE:
            logger.Info("Exucute random write")
            subErrCnt += EndtoEndLib.ValidateRetValue(logger, None, ioEx.RandWriteTime, timeInSec=60,
                                                      ioSizeInBytes=4096, maxIoSizeInBytes=None,
                                                      minLba=startLBA, maxLba=endLBA,
                                                      dataPattern=None, qDepth=256, wrapUpTime=1,
                                                      checkcrc=1, checkapptag=1, checkreftag=1,
                                                      pract=pract)
        elif iotype == IOType.RAN_READ:
            logger.Info("Exucute random read")
            logger.Info("Precondition with sequential write")
            subErrCnt += EndtoEndLib.ValidateRetValue(logger, None, ioEx.SeqWriteLoop, loop=1,
                                                      ioSizeInBytes=131072, minLba=startLBA, maxLba=endLBA,
                                                      dataPattern=None, qDepth=256, wrapUpTime=1,
                                                      checkcrc=1, checkapptag=1, checkreftag=1, pract=pract)
            logger.Info("Doing random read")
            subErrCnt += EndtoEndLib.ValidateRetValue(logger, None, ioEx.RandReadTime,
                                                      timeInSec=60, ioSizeInBytes=4096, maxIoSizeInBytes=None,
                                                      minLba=startLBA, maxLba=endLBA, dataPattern=None,
                                                      qDepth=256, wrapUpTime=1, checkcrc=1, checkapptag=1, checkreftag=1,
                                                      pract=pract)
        elif iotype == IOType.MIX_RAN_WRITE:
            logger.Info("Exucute mix random write read")
            logger.Info("Precondition with sequential write")
            subErrCnt += EndtoEndLib.ValidateRetValue(logger, None, ioEx.SeqWriteLoop, loop=1,
                                                      ioSizeInBytes=131072, minLba=startLBA, maxLba=endLBA,
                                                      dataPattern=None, qDepth=256, wrapUpTime=1,
                                                      checkcrc=1, checkapptag=1, checkreftag=1,
                                                      pract=pract)
            logger.Info("Doing mix random write read")
            subErrCnt += EndtoEndLib.ValidateRetValue(logger, None, ioEx.RandIoTime, timeInSec=60,
                                                      readPercentage=50,
                                                      ioSizeInBytes=None, maxIoSizeInBytes=None,
                                                      minLba=startLBA, maxLba=endLBA,
                                                      dataPattern=None, qDepth=256, wrapUpTime=1,
                                                      checkcrc=1, checkapptag=1, checkreftag=1,
                                                      pract=pract)
        currentSummary.IncreaseError(subErrCnt)
    EndtoEndLib.CaseSummary.UpdateItem(no, subErrCnt)
    return subErrCnt


def CasePiWriteReadTest(device, logger, options, host, expitype, caseno):
    errcnt = 0
    verbose = options.verbose

    errcnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=None,
                                          expitype=expitype, expmssetting=None,
                                          explbaf=1, ses=0, verbose=verbose)

    lbaInfoTable = EndtoEndLib.DeviceTable.GetLbaInfoTablebyDevice(device)
    logger.Info(lbaInfoTable.OutputBasic())
    testMatrix = {                                                              # iotype
        1:  ["Sequential write, PRACT 0 (Type %s)" % expitype,               [0, IOType.SEQ_WRITE    ], ],
        2:  ["Sequential read, PRACT 0 (Type %s)" % expitype,                [0, IOType.SEQ_READ     ], ],
        3:  ["Sequential write, PRACT 1 (Type %s)" % expitype,               [1, IOType.SEQ_WRITE    ], ],
        4:  ["Sequential read, PRACT 1 (Type %s)" % expitype,                [1, IOType.SEQ_READ     ], ],
        5:  ["Random write, PRACT 0 (Type %s)" % expitype,                   [0, IOType.RAN_WRITE    ], ],
        6:  ["Random read, PRACT 0 (Type %s)" % expitype,                    [0, IOType.RAN_READ     ], ],
        7:  ["Random write, PRACT 1 (Type %s)" % expitype,                   [1, IOType.RAN_WRITE    ], ],
        8:  ["Random read, PRACT 1 (Type %s)" % expitype,                    [1, IOType.RAN_READ     ], ],
        9:  ["Mix write/read, PRACT 0 (Type %s)" % expitype,                 [0, IOType.MIX_RAN_WRITE], ],
        10: ["Mix write/read, PRACT 1 (Type %s)" % expitype,                 [1, IOType.MIX_RAN_WRITE], ],
        }

    for no in sorted(testMatrix.keys(), key=lambda no: no):
        subErrCnt = ProcessReadWriteTestMatrix(device, logger, options, caseno, no, testMatrix[no])
        errcnt += subErrCnt

    return errcnt


def SeqWrite(device, logger, startLBA, endLBA):
    errcnt = 0
    logger.Info("Doing sequential write")
    ioEx = IoExerciser.GetIoExerciserObj(device, engine="native")
    errcnt += EndtoEndLib.ValidateRetValue(logger, None, ioEx.SeqWriteLoop, loop=1,
                                           ioSizeInBytes=131072, minLba=startLBA, maxLba=endLBA,
                                           dataPattern=None, qDepth=256, wrapUpTime=1,
                                           checkcrc=1, checkapptag=1, checkreftag=1)
    return errcnt


def SeqRead(device, logger, startLBA, endLBA):
    errcnt = 0
    logger.Info("Doing sequential read")
    ioEx = IoExerciser.GetIoExerciserObj(device, engine="native")
    errcnt += EndtoEndLib.ValidateRetValue(logger, None, ioEx.SeqReadLoop, loop=1,
                                           ioSizeInBytes=131072, maxIoSizeInBytes=None,
                                           minLba=startLBA, maxLba=endLBA, dataPattern=None,
                                           qDepth=256, wrapUpTime=1, checkcrc=1, checkapptag=1, checkreftag=1)
    return errcnt


def CasePiWriteReadPowerCycleTest(device, logger, options, host, expitype, caseno):
    errcnt = 0
    verbose = options.verbose

    errcnt += EndtoEndLib.FormatWithCheck(device, logger, options, host, exppil=None,
                                          expitype=expitype, expmssetting=None,
                                          explbaf=1, ses=0, verbose=verbose)

    lbaInfoTable = EndtoEndLib.DeviceTable.GetLbaInfoTablebyDevice(device)
    logger.Info(lbaInfoTable.OutputBasic())
    maxLba = lbaInfoTable.maxLba

    no = "%u.%02u" % (caseno, 2)
    title = "UnSafe Power cycle test"
    currentSummary = TestSummary.GetSummary(no, title)
    with currentSummary:
        subErrCnt = 0
        EndtoEndLib.CaseSummary.AddItem(logger, no, title)
        startLBA, endLBA = GetLBARange(maxLba)

        logger.Info("Doing sequential write")
        subErrCnt += SeqWrite(device, logger, startLBA, endLBA)

        if options.powercycle == 1:
            logger.Info("Doing power cycle")
            host.PowerCycle()

        logger.Info("Doing sequential read")
        subErrCnt += SeqRead(device, logger, startLBA, endLBA)

        currentSummary.IncreaseError(subErrCnt)
    EndtoEndLib.CaseSummary.UpdateItem(no, subErrCnt)
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
            21: ("DIX Type 1 stress test", lambda self, caseno: CasePiWriteReadTest(self.device, self.logger, self.options, self.host, expitype=1, caseno=caseno)),
            22: ("DIX Type 2 stress test", lambda self, caseno: CasePiWriteReadTest(self.device, self.logger, self.options, self.host, expitype=2, caseno=caseno)),
            23: ("DIX Type 3 stress test", lambda self, caseno: CasePiWriteReadTest(self.device, self.logger, self.options, self.host, expitype=3, caseno=caseno)),
            24: ("DIX Type 1 power cycle test", lambda self, caseno: CasePiWriteReadPowerCycleTest(self.device, self.logger, self.options, self.host, expitype=1, caseno=caseno)),
            25: ("DIX Type 2 power cycle test", lambda self, caseno: CasePiWriteReadPowerCycleTest(self.device, self.logger, self.options, self.host, expitype=2, caseno=caseno)),
            26: ("DIX Type 3 power cycle test", lambda self, caseno: CasePiWriteReadPowerCycleTest(self.device, self.logger, self.options, self.host, expitype=2, caseno=caseno)),
        }
        self.SetCases(caseDict)

        runCaseList = sorted(caseDict.keys()) if options.case is None else [options.case]
        caseSummaryDict = self.AddGroupCases(*runCaseList)  # {id: summary}

        for caseno in runCaseList:
            with caseSummaryDict[caseno]:
                errcnt = caseDict[caseno][1](self, caseno)
                caseSummaryDict[caseno].IncreaseError(errcnt)
                EndtoEndLib.TestSummary.AddItem(caseDict[caseno][0], errcnt)
                EndtoEndLib.TestSummary.Display(logger)
                EndtoEndLib.CaseSummary.Display(logger)

    def Cleanup(self):
        return True

if __name__ == "__main__":
    # Nothing is needed for main code. But keep the "with .." grammar!
    with Test():
        pass

# end of file
