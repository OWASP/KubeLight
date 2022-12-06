def container_path(dataDict, mapList):
    for k in mapList:
        if k in dataDict.keys():
            dataDict = dataDict[k]
        else:
            return []
    return dataDict
