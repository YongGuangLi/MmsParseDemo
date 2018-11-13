/*
 * PacketParse.h
 *
 *  Created on: Aug 2, 2018
 *      Author: root
 */

#ifndef PACKETPARSE_H_
#define PACKETPARSE_H_

#include "RtdbMessage.pb.h"
#include "Log4Cplus.h"
#include "RedisHelper.h"
#include "MysqlHelper.h"
#include "SemaphoreQueue.h"
#include "ConfigIni.h"
#include "DataSetModel.h"

#include <mms_value.h>
#include <mms_client_internal.h>
#include <mms_common_internal.h>
#include <iso_session.h>
#include <iso_presentation.h>

#include <boost/lexical_cast.hpp>
#include <boost/thread/thread.hpp>
#include "boost/thread/mutex.hpp"
#include <boost/function.hpp>

#include "pcap.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <stdio.h>
#include <iostream>
#include <vector>
#include <map>
#
using namespace std;

#define MACLENGTH 14
#define IPLENGTH 20

typedef enum {
	ServiceNOTHING,
	confirmedServiceRequestRead,
	confirmedServiceRequestWrite,                  //遥控选择服务被映射到MMS中的write服务
	confirmedServiceResponseRead,
	confirmedServiceResponseWrite,
	unconfirmedServiceListOfVariable,              //当遥控操作失败，服务器还会利用report服务上送否定响应的具体细节，报告由变量列表ListOfVariable和访问结果AccessResults组成
	unconfirmedServiceVariableList                 //当遥控操作成功，受控对象状态发生变化，服务器端会触发一个report服务，向客户端报告受控对象最新的状态,报告由有名变量列表VariableList和访问结果AccessResults组成
}ServiceType;                                      //开关量，保护动作事件，报警等遥信类数据一般通过缓存报告服务上送；    遥测类数据一般通过无缓存报告服务上送(一般没有时标，品质)

typedef struct
{
	struct ip* iphdr;
	struct tcphdr* tcphdr;
	string srcIp;
	string dstIp;
	uint32_t invokeId;
	ServiceType serviceType;
	vector<string> vecDomainName;        //域名   变量列表ListofVariable由一个或多个变量组成，客户端能够在一次write服务中访问多个变量，但是程序中默认一次只write一个变量
	vector<string> vecItemName;          //项目名  域名，项目名组合起来就是代表受控对象的变量名
	MmsValue*  mmsValue;
	string ctrlValue;                    //遥控值，以断路器遥控为例，true代表合闸，false分闸
	int responseResult;                  //遥控Response结果         默认一次只write一个变量
	uint64_t packetTimeStamp;            //报文时标
	string pcapFile;                     //报文文件名
}stMmsContent;

typedef struct
{
	string srcIp;
	string dstIp;
	uint64_t packetTimeStamp;            //报文时标
	string pcapFile;                     //报文文件名
	int timeCnt;
}stTcpContent;

typedef struct
{
	u_char segmentData[8192];
	u_int32_t length;
}stSegmentContent;

class PacketParse {
public:
	PacketParse(string datasetFilePath);
	virtual ~PacketParse();

	void dissectPacket(string pcapfile, struct pcap_pkthdr *pkthdr, u_char *packet);

	int dissectEthernet(struct pcap_pkthdr *pkthdr, u_char *packet, int offset);

	int dissectIpHeader(struct pcap_pkthdr *pkthdr, u_char *packet, int offset, stMmsContent *mmsContent);

	int dissectTcpHeader(struct pcap_pkthdr *pkthdr, u_char *packet, int offset, stMmsContent *mmsContent);
	//返回应用数据长度
	int dissectTPKT(u_char *packet, int offset);

	int dissectCOTP(u_char *packet, int offset);

	int dissectSession(u_char *packet, int datalen, int offset);

	int dissectPresentation(u_char *packet, int datalen, int offset);

	int dissectMmsContent(u_char *packet, int datalen, int offset, stMmsContent *mmsContent);

	void SetConfirmedRequestPduResult(MmsPdu_t* mmsPdu, stMmsContent *mmsContent);

	void SetConfirmedResponsePduResult(MmsPdu_t* mmsPdu, stMmsContent *mmsContent);

	void SetUnConfirmedPduResult(MmsPdu_t* mmsPdu, stMmsContent *mmsContent);

public:
	//分析MMS报文内容
	void analysisMmsContent(stMmsContent mmsContent);
	//获取遥控请求时标
	char* getMmsValueUtcTime(MmsValue* mmsValue, char* buffer, int bufferSize);
	//分析遥控请求
	void analysisServiceRequestWrite(stMmsContent mmsContent);
	//分析遥控回复
	void analysisServiceResponseWrite(stMmsContent mmsContent);
	//获取控制值
	char* getControlValue(MmsValue* mmsValue, char* buffer, int bufferSize);
	//通过redis发布遥控信息
	int publishRemoteControl(stMmsContent mmsContent, string ctrlObject, char* utcTime, string ctrlValue, int ctrlCmdType, int ctrlResult);

	//分析有名变量列表
	void analysisVaribleList(stMmsContent mmsContent);



	//获取实时点值类型
	PointValueType getPointValueType(MmsValue*  mmsValue);

	//通过redis发布实时点值
	int publishPointValue(stMmsContent mmsContent, string fcda, char* timeOfEntry, string redisAddr, MmsValue*  fcdaMmsValue);

	//从mms的数据拷贝tcp数据
	void copyTcpContentFromMmsContent(stMmsContent mmsContent);
	//设备是否离
	bool isOnlineDevice(string iedIp);
	//删除离线设备
	void eraseOnlineDevice(string iedIp);
	//通过redis发布连接状态
	int publishLinkStatus(stTcpContent tcpContent, string redisAddr, string linkStatus);
public:
	//因为遥控请求和遥控回复的InvokeId相同，通过InvokeId获取遥控请求对象
	stMmsContent getMmsContentByInvokeId(uint32_t);

	void start();                                      //开启线程

	void stop();

	void run();                                        //处理解析完成的报文内容

	void subscribe();                                  //订阅redis，循环获取数据

	void sendHeartBeat();                              //发送心跳

	void judgeLinkStatus();                       	//判断装置连接状态
private:
	map<uint32_t, stMmsContent> mapInvokeIdMmsContent;       //保存遥控请求数据

	RedisHelper *redisHelper;
	RedisHelper *heatRedisHelper;                 //发送心跳 redis

	SemaphoreQueue<stMmsContent> queMmsContent;

	boost::mutex lock;
	map<string, stTcpContent> mapTcpContent;                //key:设备ip value:tcp报文内容
	list<string> listOnlineDevice;                          //所有在线设备的ip

	bool isRunning;

	DataSetModel dataSetModel;

	map<u_int32_t, u_int32_t> mapReassembledTcpLength;       //tcp多包发送时，总数据长度 (每个包的ACK相同，值在第一个包的TPKT中） key:ack  value:数据长度
	map<u_int32_t, stSegmentContent*> mapSegmentData;
};

#endif /* PACKETPARSE_H_ */
