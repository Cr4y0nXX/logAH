#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
# @Author  : yyxzz
# @Software: PyCharm
# @Time    : 2020/9/4 20:36

import os
import time
from hashlib import md5
from datetime import datetime
try:
    from loadConfig import Conf
except:
    print("[" + "\033[91m" + "ERROR" + "\033[0m" + "]" + " Some error in config file, Please check and run again letter.")
    os._exit(0)

# 原始数据：74.120.14.51 - - [09/Sep/2020:13:48:14 +0800] "GET / HTTP/1.1" 301 248
# 有用信息：['193.112.78.4', '09/Sep/2020:11:36:01', '/elrekt.php', '404']
# 加载服务器日志，截取有用信息
def loadLog(path):
    ipInfoList = []
    with open(path, "r") as f:
        for line in f.readlines():
            try:
                headInfo = (line.split("\"-\"")[0]).replace("- -", "")
                # headInfo = headInfo
                ip = headInfo.split()[0]
                time = (headInfo.split()[1]).replace("[", "")
                url = headInfo.split()[4]
                code = headInfo.split()[6]
                ipInfoList.append([ip, time, url, code])
            except:
                pass
    return ipInfoList

# 通过访问次数过滤，以countIP为阀值，accessInterval为访问间隔
def accessTimes(ipInfoList, countIP, accessInterval, ratio):
    resultList = [] # 符合过滤条件的最终ip集合
    ipTimeInfoList = [] # 所有符合countIP的ip及其所有访问时间
    indexStart = 0
    while indexStart < len(ipInfoList) - 2:
        ipAccessInfo = [ipInfoList[indexStart][0]]
        for i in range(indexStart, len(ipInfoList) - 1):
            if ipInfoList[i][0] == ipInfoList[i + 1][0]:
                time = datetime.strptime(ipInfoList[i][1].split("2020:")[1], "%H:%M:%S")
                ipAccessInfo.append(time)
            else:
                indexStart = int(i) + 1
                break
        if len(ipAccessInfo) >= countIP:
            ipTimeInfoList.append(ipAccessInfo)
    # 得到ip-timeInterval的列表
    for ipTimeInfo in ipTimeInfoList:
        count = 0
        for i in range(1, len(ipTimeInfo) - 1):
            if (ipTimeInfo[i + 1] - ipTimeInfo[i]).seconds <= accessInterval:
                count += 1
        if count >= (countIP * ratio):
            resultList.append(ipTimeInfo[0])
    return resultList

# 恶意数据，以恶意数据集为特征值
def maliciousData(ipInfoList, maliciousDataCountIP, sign, word, strs):
    resultList = []
    ipReqDataInfoList = []
    maliciousDataList = list(map(lambda x: x[1:-1], list(sign.split(","))))
    maliciousDataList += list(map(lambda x: x[1:-1], list(word.split(","))))
    maliciousDataList += list(map(lambda x: x[1:-1], list(strs.split(","))))
    indexStart = 0
    while indexStart < len(ipInfoList) - 2:
        ipReqDataInfo = [ipInfoList[indexStart][0]]
        count = 0
        for i in range(indexStart, len(ipInfoList) - 1):
            if ipInfoList[i][0] == ipInfoList[i + 1][0]:
                for word in maliciousDataList:
                    if word in ipInfoList[i][2]:
                        count += 1
            else:
                ipReqDataInfo.append(count)
                indexStart = int(i) + 1
                break
        ipReqDataInfoList.append(ipReqDataInfo)
    # 得到ip-maliciousDataTimes的列表
    for ipReqDataInfo in ipReqDataInfoList:
        if ipReqDataInfo[1] >= maliciousDataCountIP:
            resultList.append(ipReqDataInfo[0])
    return resultList
    
# 错误请求，以状态码为特征值,countIP为阀值
def badRequest(ipInfoList, countIP, codeList, ratio):
    resultList = []
    ipResCodeInfoList = []
    indexStart = 0
    while indexStart < len(ipInfoList) - 2:
        ipResCodeInfo = [ipInfoList[indexStart][0]]
        for i in range(indexStart, len(ipInfoList) - 1):
            if ipInfoList[i][0] == ipInfoList[i + 1][0]:
                code = ipInfoList[i][3]
                ipResCodeInfo.append(code)
            else:
                indexStart = int(i) + 1
                break
        if len(ipResCodeInfo) >= countIP:
            ipResCodeInfoList.append(ipResCodeInfo)
    # 得到ip-code的列表
    print(ipResCodeInfoList)
    for ipResCodeInfo in ipResCodeInfoList:
        count = 0
        for i in range(1, len(ipResCodeInfo) - 1):
            if ipResCodeInfo[i] in codeList:
                count += 1
        if count >= (len(ipResCodeInfo) * ratio):
            resultList.append(ipResCodeInfo[0])
    return resultList

# 对文件内容做MD5签名
def sign(filter_ip_file):
    data = ""
    path = "/".join(list(filter_ip_file.split("/"))[0:-1])
    if not os.path.isdir(path):
        os.mkdir(path)
    if not os.path.isfile(filter_ip_file):
        print(filter_ip_file)
        open(filter_ip_file, "a").close()
    with open(filter_ip_file, "r") as f:
        for line in f.readlines():
            data += line.strip()
        hash = md5(data.encode('utf-8')).hexdigest()
    return hash

# 验证文件签名
def verifySign(filter_ip_file, hashSign):
    hash = sign(filter_ip_file)
    if hashSign == hash:
        return True
    return False

# 根据分析结果进行Ban IP，以及创建日志
def filter(ipFilterList, filter_ip_file, logFilePath):
    filteredIPList = [] # 已经封禁的IP
    willFilterIP = [] # 将要封禁的IP（传进来的IP列表与已封禁IP的差集）
    if not os.path.isfile(filter_ip_file):
        open(filter_ip_file, "a").close()
    with open(filter_ip_file, "r") as f:
        filteredIPIter = f.readlines()
        for ip in filteredIPIter:
            filteredIPList.append(ip.split()[0])
    for ip in ipFilterList:
        if ip not in filteredIPList:
            willFilterIP.append(ip)
    # ban ip文件
    with open(filter_ip_file, "a") as f:
        for ip in willFilterIP:
            cmd = "iptables -I INPUT -p tcp --dport 80 -s " + ip + " -j DROP"
            os.system(cmd)
            f.write("%-20s\t%s\n" %(ip, time.strftime('%Y-%m-%d/%H:%M:%S', time.localtime(time.time()))))
    # 写入日志文件
    date = datetime.now()
    fileName = str(date).split()[0] + ".log"
    if not os.path.isdir(logFilePath):
        os.mkdir(logFilePath)
    with open(logFilePath + fileName, "a") as f:
        for ip in willFilterIP:
            f.write("%-20s\t%s\n" %(ip, time.strftime('%Y-%m-%d/%H:%M:%S', time.localtime(time.time()))))

# 运行所有操作
def run():
    ipFilterList = []
    ipInfoList = loadLog(conf.webLogFile)
    ipInfoList.sort(key=lambda x: x[0], reverse=True)
    if conf.accessTimes_status:
        ipFilterList += accessTimes(ipInfoList, conf.accessTimes_countIP, conf.accessTimes_accessInterval, conf.accessTimes_ratio)
    if conf.badRequest_status:
        ipFilterList += badRequest(ipInfoList, conf.badRequest_countIP, conf.badRequest_codeList, conf.badRequest_ratio)
    if conf.maliciousData_status:
        ipFilterList += maliciousData(ipInfoList, conf.maliciousData_maliciousDataCountIP, conf.maliciousData_sign, conf.maliciousData_word, conf.maliciousData_strs)
    ipFilterList = list(set(ipFilterList))
    print(ipFilterList)
    filter(ipFilterList, conf.filterIPFile, conf.logPath)

if __name__ == "__main__":
    ipFilterList = []
    conf = Conf()
    hashSign = sign(conf.filterIPFile)
    now = datetime.now()
    while True:
        if (datetime.now() - now).seconds == conf.loadLogIntervalTime:
            if not verifySign(conf.filterIPFile, hashSign):
                print( "[" + "\033[91m" + "ERROR" + "\033[0m" + "]" + " Failed to verify hash sign.")
                os._exit(0)
            run()
            hashSign = sign(conf.filterIPFile)
            now = datetime.now()
            print(hashSign)
