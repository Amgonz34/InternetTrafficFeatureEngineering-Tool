import pandas as pd
import numpy as np



#input is a data frame and a string value of the IP address of the system that is being attacked 
def FeatureExtraction(df_input, HomeIP):
    #time delta. 
    T = 1
    feature_calculated = ['srcport','dstport','Inbound','Land','Oneway','OnewayRatio','AverageLengthIPFlow','RatioofInOut',
                          'Ratiotcp','Ratioudp','Ratioicmp',
                          'Urg','LandCount',
                          'Srccnt','Dstcnt','Syncnt','Fincnt','Ackcnt','Pshcnt','Rstcnt']
     #adds feature_calculated to the inputed data frame 
    df_feature_calculated = pd.DataFrame(columns=feature_calculated)
    frames = [df_input, df_feature_calculated]
    df = pd.concat(frames, axis=1)
    
    # functions used to calculate ratios over time interval T 
    def Set_Ratiotcp(df_T):
        occurrences = np.count_nonzero(df_T["ip.proto"] == 6)
        ratio = occurrences/df_T.shape[0]
        return ratio

    def Set_Ratioudp(df_T):
        occurrences = np.count_nonzero(df_T["ip.proto"] == 17)
        ratio = occurrences/df_T.shape[0]
        return ratio

    def Set_Ratioicmp(df_T):
        occurrences = np.count_nonzero(df_T["ip.proto"] == 1)
        ratio = occurrences/df_T.shape[0]
        return ratio

    def Set_RatioofInOut(df_T):
        occurrences = np.count_nonzero(df_T["Inbound"] == 1)
        ratio = occurrences/df_T.shape[0]
        return ratio

    def Set_OnewayRatio(df_T):
        occurrences = np.count_nonzero(df_T["Oneway"] == 1)
        ratio = occurrences/df_T.shape[0]
        return ratio

    #calculates average length of an IP flow over time interval T 
    def Set_AverageLengthIPFlow(df_T):
        temp = df_T.groupby(['ip.src','ip.dst','ip.proto','srcport','dstport']).size().reset_index()
        if temp.shape[0] == 0:
            return df_T.shape[0]
        else:
            return df_T.shape[0] / temp.shape[0]
    
    
    #sets value for destination and source port that can be used by other functions
    # if no port or a protocol is used that doesn’t access ports with 
    # TCP or UDP protocols is used then sets value to NaN


    def Set_srcport(row):
        srcp = 0
        if not pd.isnull(row["tcp.srcport"]):
            srcp = row["tcp.srcport"]
        elif not pd.isnull(row["udp.srcport"]):
            srcp = row["udp.srcport"]
        else:
            srcp = float("NaN")
        return srcp


    def Set_dstport(row):
        dstp = 0
        if not pd.isnull(row["tcp.dstport"]):    #np.isnan( or pd.isnull(
            dstp = row["tcp.dstport"]
        elif not pd.isnull(row["udp.dstport"]):
            dstp = row["udp.dstport"]
        else:
            dstp = float("NaN")
        return dstp

    #sets value to 1 if it is a land conection
    def Set_Land(row):
        if row["ip.src"] == row["ip.dst"]:
            return 1
        else:
            return 0
    
    #sets value to 1 if the connection is inbound 
    def Set_Inbound(row):
        if row["ip.dst"] == HomeIP:
            return 1
        else:
            return 0

    #Sets flag count over time interval T 

    def Set_Urg(df_T):
        occurrences = np.count_nonzero(df_T["tcp.flags.urg"] == 1)
        return occurrences

    def Set_Syncnt(df_T):
        occurrences = np.count_nonzero(df_T["tcp.flags.syn"] == 1)
        return occurrences

    def Set_Fincnt(df_T):
        occurrences = np.count_nonzero(df_T["tcp.flags.fin"] == 1)
        return occurrences

    def Set_Ackcnt(df_T):
        occurrences = np.count_nonzero(df_T["tcp.flags.ack"] == 1)
        return occurrences

    def Set_Pshcnt(df_T):
        occurrences = np.count_nonzero(df_T["tcp.flags.push"] == 1)
        return occurrences

    def Set_Rstcnt(df_T):
        occurrences = np.count_nonzero(df_T["tcp.flags.reset"] == 1)
        return occurrences

    def Set_LandCount(df_T):
        occurrences = np.count_nonzero(df_T["Land"] == 1)
        return occurrences
    #One way ratio

    
    #determines if a packet is a one-way connection
    def Set_Oneway(row, df_T):
        if row["ip.proto"] == 6: #tcp
            if row["tcp.flags"] == "0x00000010":
                for index, rows in df_T.iterrows():
                    if rows["dstport"] == row["srcport"] and rows["srcport"] == row["dstport"] and rows["ip.src"] == row["ip.dst"] and rows["ip.dst"] == row["ip.src"] and rows["ip.dst"]:
                        if rows["tcp.flags"] == "0x00000010" or  rows["tcp.flags"] == "0x00000018":
                            return 0
                        if rows["tcp.flags"] == "0x00000012":
                            for index, rows in df.iterrows():
                                if rows["dstport"] == row["srcport"] and rows["srcport"] == row["dstport"] and rows["ip.src"] == row["ip.dst"] and rows["ip.dst"] == row["ip.src"] and rows["ip.dst"] and rows["tcp.flags"] == "0x00000002":
                                    return 0
                return 1
            else:
                return 1
        elif row["ip.proto"] == 1: #ICMP
            for index, rows in df_T.iterrows():
                flagcheck = checkFlags(row["icmp.type"],rows["icmp.type"])
                if rows["dstport"] == row["srcport"] and rows["srcport"] == row["dstport"] and rows["ip.src"] == row["ip.dst"] and rows["ip.dst"] == row["ip.src"] and flagcheck:
                    return 0
            return 1   

        elif row["ip.proto"] == 17: #UDP
            for index, rows in df_T.iterrows():
                if rows["dstport"] == row["srcport"] and rows["srcport"] == row["dstport"] and rows["ip.src"] == row["ip.dst"] and rows["ip.dst"] == row["ip.src"]:
                    return 0
            return 1 

        else:
            return 0
   
    #used by Set_Oneway to determin if ICMP flags are related and used if a two way conection. 
    def checkFlags(reply, request):
        if reply == 0 and request == 8:
            return True
        elif reply == 14 and request == 13:
            return True
        elif reply == 16 and request == 15:
            return True
        elif reply == 18 and request == 17:
            return True
        else:
            return False
    
    #calculates values for new features  
    for index, row in df.iterrows():  
       
        #finds the subset of packets in within time T of the current row's packet arrival time
        timeMax= df.loc[index, "frame.time_epoch"]
        timeMin = timeMax - T
        mask = (df['frame.time_epoch'] <= timeMax) & (df['frame.time_epoch'] >= timeMin)
        df_T = df.loc[mask]


        #sets each new value
        df.loc[index, "srcport"] = Set_srcport(row)
        df.loc[index, "dstport"] = Set_dstport(row)
        df.loc[index, "Land"] = Set_Land(row)
        df.loc[index, "Inbound"] = Set_Inbound(row)
        df.loc[index, "Urg"] = Set_Urg(df_T)
        df.loc[index, "Syncnt"] = Set_Syncnt(df_T)
        df.loc[index, "Fincnt"] = Set_Fincnt(df_T)
        df.loc[index, "Ackcnt"] = Set_Ackcnt(df_T)
        df.loc[index, "Pshcnt"] = Set_Pshcnt(df_T)
        df.loc[index, "Rstcnt"] = Set_Rstcnt(df_T)
        df.loc[index, "Ratiotcp"] = Set_Ratiotcp(df_T)
        df.loc[index, "Ratioudp"] = Set_Ratioudp(df_T)
        df.loc[index, "Ratioicmp"] = Set_Ratioicmp(df_T)
        df.loc[index, "LandCount"] = Set_LandCount(df_T)
        df.loc[index, "RatioofInOut"] = Set_RatioofInOut(df_T)
        df.loc[index, "AverageLengthIPFlow"] = Set_AverageLengthIPFlow(df_T)
        df.loc[index, "Oneway"] = Set_Oneway(row, df_T)
        df.loc[index, "OnewayRatio"] = Set_OnewayRatio(df_T)
        
    
    return df  

file = pd.read_csv("benignHome2.csv")
file.info()

'''
fields needed to be pulled from tshark to be able to execute the script
tshark -r packet1.pcap -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e ip.proto -e ip.len -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e icmp.type -e tcp.flags -e tcp.flags.urg -e tcp.flags.fin -e tcp.flags.ack -e tcp.flags.syn -e tcp.flags.push -e tcp.flags.reset -E header=y -E separator=, -E quote=d > test.csv

'''
 #replace csv
HomeIP = '' #replace IP
df1 = FeatureExtraction(file, HomeIP)

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)
print(df1.head())


#set outputfile below
file = "set path"
df1.to_csv(file, index = False, header=True)
