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
}ServiceType;                                      //开关量，保护动作事件，报警等遥信类数据一般通过缓存报告服务上送；    遥测类数据一般通过无缓存报告服务上送

typedef struct
{
	struct ip* iphdr;
	struct tcphdr* tcphdr;
	string srcIp;
	string dstIp;
	uint32_t invokeId;
	ServiceType serviceType;
	vector<string> vecDomainName;
	vector<string> vecItemName;
	MmsValue*  mmsValue;
	vector<int> vecResponseResult;
	uint64_t packetTimeStamp;

}stMmsContent;


class PacketParse {
public:
	PacketParse();
	virtual ~PacketParse();

	void dissectPacket(struct pcap_pkthdr *pkthdr, u_char *packet);

	int dissectEthernet(struct pcap_pkthdr *pkthdr, u_char *packet, int offset);

	int dissectIpHeader(struct pcap_pkthdr *pkthdr, u_char *packet, int offset, stMmsContent *mmsContent);

	int dissectTcpHeader(struct pcap_pkthdr *pkthdr, u_char *packet, int offset, stMmsContent *mmsContent);

	int dissectTPKT(struct pcap_pkthdr *pkthdr, u_char *packet, int offset);        //返回应用数据长度

	int dissectCOTP(struct pcap_pkthdr *pkthdr, u_char *packet, int offset);

	int dissectSession(struct pcap_pkthdr *pkthdr, u_char *packet, int datalen, int offset);

	int dissectPresentation(struct pcap_pkthdr *pkthdr, u_char *packet, int datalen, int offset);

	int dissectMmsContent(struct pcap_pkthdr *pkthdr, u_char *packet, int datalen, int offset, stMmsContent *mmsContent);

	void SetConfirmedRequestPduResult(MmsPdu_t* mmsPdu, stMmsContent *mmsContent);

	void SetConfirmedResponsePduResult(MmsPdu_t* mmsPdu, stMmsContent *mmsContent);

	void SetUnConfirmedPduResult(MmsPdu_t* mmsPdu, stMmsContent *mmsContent);

public:
	void analysisMmsContent(stMmsContent mmsContent);                                //分析MMS报文内容

	void analysisServiceRequestWrite(stMmsContent mmsContent);                       //分析遥控请求

	void analysisServiceResponseWrite(stMmsContent mmsContent);                      //分析遥控回复

	void analysisVaribleList(stMmsContent mmsContent);                               //分析有名变量列表

	PointValueType getPointValueType(MmsValue*  mmsValue);

	char* getMmsValueUtcTime(MmsValue*  mmsValue, char* buffer, int bufferSize);

	int publishPointValue(string fcda, MmsValue*  fcdaMmsValue);

	void judgeRemoteControl(stMmsContent mmsContent);

public:
	stMmsContent getMmsContentByInvokeId(uint32_t);

	void run();                                        //处理解析完成的报文内容

	void subscribe();                                  //订阅redis，循环获取数据

	void sendHeartBeat();                              //发送心跳

	void start();                                      //开启线程

	void stop();

private:
	map<uint32_t, stMmsContent> mapInvokeIdMmsContent;       //保存遥控请求数据

	RedisHelper* redisHelper;
	RedisHelper *heatRedisHelper;                 //发送心跳 redis

	MysqlHelper mysqlHelper;

	SemaphoreQueue<stMmsContent> queMmsContent;

	bool isRunning;

	DataSetModel dataSetModel;
};

#endif /* PACKETPARSE_H_ */
