import os
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.ticker import (MultipleLocator, FormatStrFormatter, AutoMinorLocator)
import matplotlib.dates as mdates
import numpy as np
import datetime


path = "DAta\\"

totalPktSum = 0 #Total amount of packets
totalPktLens = {} #The total summary of packet lengths
dataSum = 0 #Total amount of data passed

pktPerSecond = {} #How many packets passed per second
dataPerSecond = {} #Bytes per second
biggest = 0

def main():
    response = ""
    dataFolder = os.scandir(path)
    for file in dataFolder:
        response += (file.name + ": \n")
        ret = scanFile(file.name)
        response += ret + "\n" + "#"*15 + "\n"
    medianVal = calcTotalMed()
    response += medianVal
    result = open("results.txt", "w", encoding = "utf-16")
    result.write(response)
    printPerSecond()
    result.close()
    PlotPacketsPerMinute()
    #PlotDataPerMinute()
    findBiggest()
    print("Done!")

def printPerSecond():
    resultString = ""
    for timestamp in pktPerSecond:
        resultString += timestamp + "|" + str(pktPerSecond[timestamp]) + "|" + str(dataPerSecond[timestamp]) + "\n"
    
    output = open("perSecond.txt", "w", encoding= "utf-16")
    output.write(resultString)
    output.close()

def findBiggest():
    compactPacket = minimizeData(pktPerSecond)
    compactData = minimizeData(dataPerSecond)
    mostPackets = 0
    mostData = 0

    for entry in compactPacket:
        if (compactPacket[entry] > mostPackets):
            mostPackets = compactPacket[entry]
    for entry in compactData:
        if (compactData[entry] > mostData):
            mostData = compactData[entry]
    
    print("Most data/min: " + str(mostData))
    print("Most pckt/min: " + str(mostPackets))


def PlotDataPerMinute():
    compactDict = minimizeData(dataPerSecond)
    hoursInData = []
    timestamps = []
    figure, ax = plt.subplots()
    for time in compactDict:
        val = mdates.date2num(time)
        timestamps.append(val)
        compactDict[time] = compactDict[time]/1000
    #timeList = mdates.date2num(timestamps)
    valueList = compactDict.values()
    hours = mdates.HourLocator()
    ax.plot(timestamps, valueList, "-b")
    ax.set(xlabel="Time", ylabel="", title="KiloBytes per minute")
    fmt_hms = mdates.DateFormatter('%H:%M')
    ax.xaxis.set_major_locator(hours)
    ax.xaxis.set_major_formatter(fmt_hms)
    ax.yaxis.get_major_formatter().set_useOffset(False)
    ax.grid()
    plt.show()

def PlotPacketsPerMinute():
    compactDict = minimizeData(pktPerSecond)
    hoursInData = []
    timestamps = []
    figure, ax = plt.subplots()
    for time in compactDict:
        val = mdates.date2num(time)
        timestamps.append(val)
    #timeList = mdates.date2num(timestamps)
    valueList = compactDict.values()
    hours = mdates.HourLocator()
    ax.plot(timestamps, valueList, "-b")
    ax.set(xlabel="Time", ylabel="Packets", title="Packets per minute")
    fmt_hms = mdates.DateFormatter('%H:%M')
    ax.xaxis.set_major_locator(hours)
    ax.xaxis.set_major_formatter(fmt_hms)
    ax.grid()
    plt.show()
def minimizeData(secondList):
    returnDict = {}
    current = -1
    currentTimestamp = np.datetime64.min
    for entry in secondList:
        if(entry == ""):
            continue
        parts = entry.split(":")
        if(int(parts[1]) > current): #Next minute
            current = int(parts[1])
            textTime = ""
            currentTimestamp = np.datetime64("2021-02-22T"+parts[0] + ":" + parts[1] + ":" + parts[2])
            
            returnDict[currentTimestamp] = secondList[entry]

        elif (int(parts[1]) == current): #Same minute
            returnDict.update({currentTimestamp:returnDict[currentTimestamp] + secondList[entry]})
        else: #Rolling over to next hour
            current = 0
            currentTimestamp = np.datetime64("2021-02-22T"+parts[0] + ":" + parts[1] + ":" + parts[2])
            returnDict[currentTimestamp]  = secondList[entry]

    return returnDict







def calcTotalMed():
    median = 0
    average = dataSum/totalPktSum

    half = int(totalPktSum/2) #Calculate Average
    currentSum = 0
    sortedTotalPktLens = sorted(totalPktLens) #Sort to make reading easier
    for size in sortedTotalPktLens:
        val = totalPktLens[size]
        currentSum += val
        if(currentSum >= half): #Find the value that covers the middle point.
            median = size
            break
    retVal = "Total average: " + str(average) + "\n"
    retVal += "Total median size: " + str(median) + "\n"
    return retVal

# Example packet data from snort
#
#02/22-10:50:24.346567 109.74.11.185:3389 -> 185.193.88.64:52324
#TCP TTL:128 TOS:0x0 ID:30078 IpLen:20 DgmLen:320 DF
#***AP*** Seq: 0x6E791CA0  Ack: 0xB6BDAEF6  Win: 0xF7AC  TcpLen: 20
#=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# 
# DgmLen is full datagram length in bytes
#         

def scanFile(fileName):
    with open(path+fileName, "r", encoding = "utf-16") as file:
        global totalPktLens
        retVal = ""
        once = True
        totalLen = 0
        pktLengths = {}
        count = 0
        
        text = file.read()
        packets = text.split("=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+")
        for entry in packets:
            dataLen = 0
            packetTime = ""

            rows = entry.rsplit()
            for row in rows:
                options = row.split(" ")
                for opt in options:
                    parts = opt.split(":")
                    if(len(parts) == 2):
                        if(parts[0] == "DgmLen"):
                            count +=1
                            text = parts[1].rstrip()
                            value = int(text)
                            dataLen = value
                            totalLen = totalLen+value
                            if value in pktLengths:
                                pktLengths.update({value: pktLengths[value] + 1})
                            else:
                                pktLengths[value] = 1
                            if value in totalPktLens:
                                totalPktLens.update({value:totalPktLens[value] + 1})
                            else:
                                totalPktLens[value] = 1
                    if(len(parts) == 3):
                        global pktPerSecond
                        second = parts[2].split(".")[0]
                        minute = parts[1]
                        hour = parts[0].split("-")[1]

                        fullTime  = str(hour) + ":" + str(minute) + ":" + str(second)
                        packetTime = fullTime

                        if fullTime in pktPerSecond:
                            pktPerSecond.update({fullTime:pktPerSecond[fullTime] + 1})
                        else:
                            pktPerSecond[fullTime] = 1

            global dataPerSecond
            if packetTime in dataPerSecond:
                dataPerSecond.update({packetTime:dataPerSecond[fullTime] + dataLen})
            else:
                dataPerSecond[packetTime] = dataLen

                        

        
        retVal += "Total data passed: " + str(totalLen)
        retVal += "\nAverage packet size: " + str(totalLen/len(packets)) + "\n\nPacket sizes passed:\n"
        sortedLengths = sorted(pktLengths)
        for length in sortedLengths:
            retVal+= str(length) + ":" + str(pktLengths[length]) + "\n"
        global dataSum
        dataSum += totalLen
        global totalPktSum
        totalPktSum += count
        return retVal



    


if __name__ == "__main__":
    main()