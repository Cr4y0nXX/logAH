#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
# @Author  : yyxzz
# @Software: PyCharm
# @Time    : 2020/9/5 10:18

import configparser

class Conf:
    __conf = configparser.ConfigParser()
    __conf.read("./conf/default.conf")
    # [global]
    loadLogIntervalTime = __conf.getint("global", "loadLogIntervalTime")
    # [filePath]
    webLogFile = __conf.get("filePath", "webLogFile")
    logPath = __conf.get("filePath", "logPath")
    filterIPFile = __conf.get("filePath", "filterIPFile")
    # [accessTimes]
    accessTimes_status = __conf.getboolean("accessTimes", "status")
    accessTimes_countIP = __conf.getint("accessTimes", "countIP")
    accessTimes_accessInterval = __conf.getint("accessTimes", "accessInterval")
    accessTimes_ratio = __conf.getfloat("accessTimes", "ratio")
    # [badRequest]
    badRequest_status = __conf.getboolean("badRequest", "status")
    badRequest_countIP = __conf.getint("badRequest", "countIP")
    badRequest_codeList = list(__conf.get("badRequest", "codeList").split())
    badRequest_ratio = __conf.getfloat("badRequest", "ratio")
    # [maliciousDataList]
    maliciousData_status = __conf.getboolean("maliciousData", "status")
    maliciousData_sign = __conf.get("maliciousData", "sign")
    maliciousData_word = __conf.get("maliciousData", "word")
    maliciousData_strs = __conf.get("maliciousData", "strs")
    maliciousData_maliciousDataCountIP = __conf.getint("maliciousData", "maliciousDataCountIP")
    # maliciousData_ratio = __conf.getfloat("maliciousData", "ratio")