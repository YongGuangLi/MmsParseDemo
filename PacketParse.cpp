/*
 * PacketParse.cpp
 *
 *  Created on: Aug 2, 2018
 *      Author: root
 */

#include "PacketParse.h"

PacketParse::PacketParse(string datasetFilePath) {
	isRunning = true;
	queMmsContent.set_size(100000);

	start();

	if(dataSetModel.load(datasetFilePath))
	{
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Load datasetfile Success:" + datasetFilePath);
	}
	else
	{
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_WARN, "Load datasetfile Failure:" + datasetFilePath);
	}
}

PacketParse::~PacketParse() {
	// TODO Auto-generated destructor stub
}

void PacketParse::dissectPacket(string pcapfile, struct pcap_pkthdr *pkthdr, u_char *packet)
{
	stMmsContent mmsContent;
	mmsContent.mmsValue = 0;      //需要赋值为空，否则第二次定义值不会为空
	mmsContent.invokeId = 0;
	mmsContent.serviceType = ServiceNOTHING;
	mmsContent.iphdr = 0;
	mmsContent.tcphdr = 0;
	mmsContent.packetTimeStamp = pkthdr->ts.tv_sec * 1000 + pkthdr->ts.tv_usec;
	mmsContent.pcapFile = pcapfile;

	int offset = 0;
	int type = dissectEthernet(pkthdr, packet, offset);
	offset += MACLENGTH;
	if(type != ETHERTYPE_IP)
	{
		return;
	}

	dissectIpHeader(pkthdr, packet, offset, &mmsContent);
	offset += IPLENGTH;

	dissectTcpHeader(pkthdr, packet, offset,  &mmsContent);
	offset += mmsContent.tcphdr->doff * 4;  // tcp头长度 tcphdr->doff * 4
	if(pkthdr->len <= offset)               //报文数据太短，不是mms
	{
		return;
	}

	//如果存在此ACK，表示这个ACK是多包发送，并且不是第一个包,并判断是否是最后一个包，如果不是最后一个包，退出，直到接收整个包
	int segmentDataLength = pkthdr->len - 14 - 20 - mmsContent.tcphdr->doff * 4;
	int tpkt_len = ntohs(*(uint16_t*)(packet + offset + 2));

	//printf("Ack = %ld segmentDataLength = %d\n", mmsContent.tcphdr->ack_seq, segmentDataLength);
	//如果数据长度大于报文实际长度，表示这是分段组包, 一般数据长度等于报文长度减去Mac头，IP头，TCP头  第一个包以0x0300开头    tpkt_len协议数据段长度    segmentDataLength当前报文数据段长度
	if(tpkt_len != 8196 &&  tpkt_len > segmentDataLength && packet[offset] == 0x03 && packet[offset + 1] == 0x00)
	{
		//printf("Ack = %u tpkt_len = %d\n", mmsContent.tcphdr->ack_seq, tpkt_len);
		mapReassembledTcpLength.insert(make_pair(mmsContent.tcphdr->ack_seq, tpkt_len));

		stSegmentContent * segmentContent = new stSegmentContent();
		memcpy(segmentContent->segmentData, packet + offset, segmentDataLength);
		segmentContent->length = segmentDataLength;

		map<u_int32_t, stSegmentContent*>::iterator itSegmentContent= mapSegmentData.find(mmsContent.tcphdr->ack_seq);
		if(itSegmentContent != mapSegmentData.end())
			mapSegmentData.erase(itSegmentContent);

		mapSegmentData.insert(make_pair(mmsContent.tcphdr->ack_seq, segmentContent));
		return;
	}

	map<u_int32_t, u_int32_t>::iterator it = mapReassembledTcpLength.find(mmsContent.tcphdr->ack_seq);
	if(it != mapReassembledTcpLength.end())
	{
		map<u_int32_t, stSegmentContent*>::iterator itSegmentContent= mapSegmentData.find(mmsContent.tcphdr->ack_seq);
		if(itSegmentContent == mapSegmentData.end())
			return;

		stSegmentContent * segmentContent = itSegmentContent->second;
		memcpy(segmentContent->segmentData + segmentContent->length, packet + offset, segmentDataLength);
		segmentContent->length += segmentDataLength;

		if(it->second != segmentContent->length)                      //不是最后一个包
			return;

		mapReassembledTcpLength.erase(it);

		memcpy(packet, segmentContent->segmentData, segmentContent->length);
		offset = 0;

		delete segmentContent;
		segmentContent = NULL;
		mapSegmentData.erase(itSegmentContent);
	}

	int datalen = dissectTPKT(packet, offset);                      //TPKT占4个字节
	offset += 4;
	datalen -= 4;

	int cotpOffset = dissectCOTP(packet, offset);                   //COTP占3个字节
	offset += cotpOffset;
	datalen -= cotpOffset;

	int sessionOffset = dissectSession(packet, datalen, offset);
	offset += sessionOffset;
	datalen -= sessionOffset;
	if(sessionOffset == -1)         //Session Analysis Abnormal
	{
		//printf("sessionOffset = %d\n",sessionOffset);
		return;
	}

	int presentationOffset = dissectPresentation(packet, datalen, offset);    //修改了源代码的返回值
	offset += presentationOffset;
	datalen -= presentationOffset;

	dissectMmsContent(packet, datalen, offset, &mmsContent);
	queMmsContent.push_back(mmsContent);

	copyTcpContentFromMmsContent(mmsContent);
}


int PacketParse::dissectEthernet(struct pcap_pkthdr *pkthdr, u_char *packet, int offset)
{
	struct ether_header *ethdr = (struct ether_header*)(packet);
	int type = ntohs(ethdr->ether_type);
	return type;
}

int PacketParse::dissectIpHeader(struct pcap_pkthdr *pkthdr, u_char *packet, int offset, stMmsContent *mmsContent)
{
	struct ip* iphdr = (struct ip*)(packet + offset);
	mmsContent->iphdr = iphdr;
	mmsContent->srcIp = inet_ntoa(iphdr->ip_src);
	mmsContent->dstIp = inet_ntoa(iphdr->ip_dst);
	return 0;
}

int PacketParse::dissectTcpHeader(struct pcap_pkthdr *pkthdr, u_char *packet, int offset, stMmsContent *mmsContent)
{
	struct tcphdr* tcphdr = (struct tcphdr*)(packet + offset);
	mmsContent->tcphdr = tcphdr;
	return 0;
}

int PacketParse::dissectTPKT(u_char *packet, int offset)
{
	int tpkt_version = *(uint8_t*)(packet + offset);

	int tpkt_reserved = *(uint8_t*)(packet + offset + 1);

	int tpkt_len = ntohs(*(uint16_t*)(packet + offset + 2));

	return tpkt_len;
}

int PacketParse::dissectCOTP(u_char *packet, int offset)
{
	return 3;
}

int PacketParse::dissectSession(u_char *packet, int datalen, int offset)
{
	IsoSession session;
	ByteBuffer message;
	message.buffer = packet + offset;
	message.maxSize = datalen;
	message.size = datalen;

	IsoSessionIndication isoSessionIndication = IsoSession_parseMessage(&session, &message);

	int sessionOffset = -1;
	switch(isoSessionIndication)
	{
	case SESSION_DATA:
		sessionOffset = 4;
		break;
	default:
		break;
	}
	return sessionOffset;
}

int PacketParse::dissectPresentation(u_char *packet, int datalen, int offset)
{
	IsoPresentation self;
	ByteBuffer readBuffer;
	readBuffer.buffer = packet + offset;
	readBuffer.size = datalen;
	readBuffer.maxSize = datalen;

	int presentationOffset = IsoPresentation_parseUserData(&self, &readBuffer);
	return presentationOffset;
}

int PacketParse::dissectMmsContent(u_char *packet, int datalen, int offset, stMmsContent *mmsContent)
{
	MmsPdu_t* mmsPdu = 0; /* allow asn1c to allocate structure */

	asn_dec_rval_t rval = ber_decode(NULL, &asn_DEF_MmsPdu, (void**) &mmsPdu, packet + offset, datalen);

	if (rval.code == RC_OK)
	{
		switch(mmsPdu->present)
		{
		case MmsPdu_PR_confirmedRequestPdu:
			SetConfirmedRequestPduResult(mmsPdu, mmsContent);
			break;
		case MmsPdu_PR_confirmedResponsePdu:
			SetConfirmedResponsePduResult(mmsPdu, mmsContent);
			break;
		case MmsPdu_PR_unconfirmedPDU:
			SetUnConfirmedPduResult(mmsPdu, mmsContent);
			break;
		 default:
		    break;
		}
	}

    asn_DEF_MmsPdu.free_struct(&asn_DEF_MmsPdu, mmsPdu, 0);

	return 0;
}

//带确认请求
void PacketParse::SetConfirmedRequestPduResult(MmsPdu_t* mmsPdu, stMmsContent *mmsContent)
{
	mmsContent->invokeId = mmsClient_getInvokeId(&mmsPdu->choice.confirmedResponsePdu);  //#include "mms_client_internal.h" 加了extern "C" 否则会找不到定义
	//SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, "invokeID:" + boost::lexical_cast<string>(mmsContent->invokeId));

	if (ConfirmedServiceRequest_PR_read == mmsPdu->choice.confirmedRequestPdu.confirmedServiceRequest.present)  //read     只解析报文，后续没有处理
	{
		mmsContent->serviceType = confirmedServiceRequestRead;

		ReadRequest_t request = mmsPdu->choice.confirmedRequestPdu.confirmedServiceRequest.choice.read;
		if(VariableAccessSpecification_PR_listOfVariable == request.variableAccessSpecification.present)
		{
			VariableAccessSpecification__listOfVariable listOfVariable = request.variableAccessSpecification.choice.listOfVariable;

			for(int i = 0; i < listOfVariable.list.count; ++i)
			{
				if(VariableSpecification_PR_name == listOfVariable.list.array[i]->variableSpecification.present)
				{
					if(ObjectName_PR_domainspecific == listOfVariable.list.array[i]->variableSpecification.choice.name.present)
					{
						ObjectName__domainspecific objDomainSpc = listOfVariable.list.array[i]->variableSpecification.choice.name.choice.domainspecific;
						mmsContent->vecDomainName.push_back((char*)objDomainSpc.domainId.buf);
						mmsContent->vecItemName.push_back((char*)objDomainSpc.itemId.buf);
					}
				}
			}
		}
	}
	else if(ConfirmedServiceRequest_PR_write == mmsPdu->choice.confirmedRequestPdu.confirmedServiceRequest.present)    //遥控请求
	{
		mmsContent->serviceType = confirmedServiceRequestWrite;

		WriteRequest_t writeRequest = mmsPdu->choice.confirmedRequestPdu.confirmedServiceRequest.choice.write;
		VariableAccessSpecification__listOfVariable listOfVariable = writeRequest.variableAccessSpecification.choice.listOfVariable;
		if(listOfVariable.list.count >= 1)                                                        //遥控一次只改一个值
		{
			if(VariableSpecification_PR_name == listOfVariable.list.array[0]->variableSpecification.present)
			{
				if(ObjectName_PR_domainspecific == listOfVariable.list.array[0]->variableSpecification.choice.name.present)
				{
					ObjectName__domainspecific objDomainSpc = listOfVariable.list.array[0]->variableSpecification.choice.name.choice.domainspecific;
					mmsContent->vecDomainName.push_back((char*)objDomainSpc.domainId.buf);
					mmsContent->vecItemName.push_back((char*)objDomainSpc.itemId.buf);
				}
			}
		}

		if(writeRequest.listOfData.list.count >= 1)
		{
			MmsValue* value = mmsMsg_parseDataElement(writeRequest.listOfData.list.array[0]);
			mmsContent->mmsValue = value;                 //遥控请求详细数据
		}
	}
};

//带确认回复
void PacketParse::SetConfirmedResponsePduResult(MmsPdu_t* mmsPdu, stMmsContent *mmsContent)
{
	mmsContent->invokeId = mmsClient_getInvokeId(&mmsPdu->choice.confirmedResponsePdu);
	//SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, "invokeID:" + boost::lexical_cast<string>(mmsContent->invokeId));

	if (ConfirmedServiceResponse_PR_read == mmsPdu->choice.confirmedResponsePdu.confirmedServiceResponse.present)          	//read  只解析报文，后续没有处理
	{
		mmsContent->serviceType = confirmedServiceResponseRead;

		ReadResponse_t readResponse = mmsPdu->choice.confirmedResponsePdu.confirmedServiceResponse.choice.read;
		int elementCount = readResponse.listOfAccessResult.list.count;
		MmsValue* value = mmsClient_parseListOfAccessResults(readResponse.listOfAccessResult.list.array, elementCount, true);
		mmsContent->mmsValue = value;
	}
	else if(ConfirmedServiceResponse_PR_write == mmsPdu->choice.confirmedResponsePdu.confirmedServiceResponse.present)     //遥控回复是枚举类型    成功或者失败
	{
		mmsContent->serviceType = confirmedServiceResponseWrite;

		WriteResponse_t writeResponse = mmsPdu->choice.confirmedResponsePdu.confirmedServiceResponse.choice.write;
		if(writeResponse.list.count >= 1)
		{
			mmsContent->responseResult = writeResponse.list.array[0]->present;
		}
	}
}


void PacketParse::SetUnConfirmedPduResult(MmsPdu_t* mmsPdu, stMmsContent *mmsContent)
{
	InformationReport_t report = mmsPdu->choice.unconfirmedPDU.unconfirmedService.choice.informationReport;        //mms报告服务(Report)服务属于非确认服务，用于定时上传所采集的电压，电流值(遥测量)

	if (VariableAccessSpecification_PR_listOfVariable == report.variableAccessSpecification.present)               //需要确认此种情况是否需要处理
	{
		mmsContent->serviceType = unconfirmedServiceListOfVariable;

		VariableAccessSpecification__listOfVariable listOfVariable = report.variableAccessSpecification.choice.listOfVariable;

		for(int i = 0; i < listOfVariable.list.count; ++i)
		{
			if(VariableSpecification_PR_name == listOfVariable.list.array[i]->variableSpecification.present)
			{
				if(ObjectName_PR_vmdspecific == listOfVariable.list.array[i]->variableSpecification.choice.name.present)
				{
					mmsContent->vecDomainName.push_back((char*)listOfVariable.list.array[i]->variableSpecification.choice.name.choice.vmdspecific.buf);
					mmsContent->vecItemName.push_back("");
				}
				else if(ObjectName_PR_domainspecific == listOfVariable.list.array[i]->variableSpecification.choice.name.present)
				{
					ObjectName__domainspecific objDomainSpc = listOfVariable.list.array[i]->variableSpecification.choice.name.choice.domainspecific;

					mmsContent->vecDomainName.push_back((char*)objDomainSpc.domainId.buf);
					mmsContent->vecItemName.push_back((char*)objDomainSpc.itemId.buf);
				}
			}
		}

		int elementCount = report.listOfAccessResult.list.count;
		MmsValue* value = mmsClient_parseListOfAccessResults(report.listOfAccessResult.list.array, elementCount, true);
		mmsContent->mmsValue = value;
	}
	else if (VariableAccessSpecification_PR_variableListName == report.variableAccessSpecification.present)
	{
		mmsContent->serviceType = unconfirmedServiceVariableList;
		if (ObjectName_PR_vmdspecific == report.variableAccessSpecification.choice.variableListName.present)
		{
			int elementCount = report.listOfAccessResult.list.count;

			MmsValue* value = mmsClient_parseListOfAccessResults(report.listOfAccessResult.list.array, elementCount, true);
			mmsContent->mmsValue = value;
		}
	}
}

void PacketParse::analysisMmsContent(stMmsContent mmsContent)
{
	switch(mmsContent.serviceType)
	{
	case confirmedServiceRequestRead:
	{
		break;
	}
	case confirmedServiceRequestWrite:                                                               //遥控请求
	{
		analysisServiceRequestWrite(mmsContent);
		break;
	}
	case confirmedServiceResponseRead:
	{
		break;
	}
	case confirmedServiceResponseWrite:                                                               //遥控回复
	{
		analysisServiceResponseWrite(mmsContent);
		break;
	}
	case unconfirmedServiceListOfVariable:
	{
		break;
	}
	case unconfirmedServiceVariableList:
	{
		analysisVaribleList(mmsContent);
		break;
	}
	default:
		break;
	}

	MmsValue_deleteIfNotNull(mmsContent.mmsValue);
}


char* PacketParse::getMmsValueUtcTime(MmsValue*  mmsValue, char* buffer, int bufferSize)
{
	int elementCount = MmsValue_getArraySize(mmsValue);
	for(int i = 0; i < elementCount; ++i)
	{
		MmsValue*  value = MmsValue_getElement(mmsValue, i);

		if(MMS_UTC_TIME == MmsValue_getType(value))
		{
			MmsValue_printToBuffer(value, buffer, bufferSize);
		}
	}
	return buffer;
}


//分析遥控Request
void PacketParse::analysisServiceRequestWrite(stMmsContent mmsContent)
{
	mapInvokeIdMmsContent.insert(make_pair(mmsContent.invokeId, mmsContent));
	string ctrlObject = mmsContent.vecDomainName.at(0) + "/" + mmsContent.vecItemName.at(0);     //一般一次只遥控一个点

	if(ctrlObject.find("SBOw") == string::npos && ctrlObject.find("Oper") == string::npos)       //只判断遥控选择和遥控执行的Request
		return;

	//遥控请求带时标
	char utcTime[64] = {0};
	getMmsValueUtcTime(mmsContent.mmsValue, utcTime, 64);

	int ctrlCmdType = ctrlObject.find("SBOw") != string::npos ? 0 : 1;    //报文类型 0:选择  1:执行

	char ctrlValue[64] = {0};
	getControlValue(mmsContent.mmsValue, ctrlValue, 64);

	int ctrlResult = 0;  //Request没有控制结果，以0表示Requset

	publishRemoteControl(mmsContent, ctrlObject,  utcTime, ctrlValue, ctrlCmdType, ctrlResult);
}

//分析遥控Respnse
void PacketParse::analysisServiceResponseWrite(stMmsContent mmsContent)
{
	stMmsContent requestMmmsContent = getMmsContentByInvokeId(mmsContent.invokeId);              //通过invokeId获取之前request的详细数据，因为Respnse只有结果，遥控点名在Request报文中

	if(requestMmmsContent.vecDomainName.size() < 1 || requestMmmsContent.vecItemName.size() < 1)
	{
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO,"invokeId:" + boost::lexical_cast<string>(mmsContent.invokeId) + " not Request");
		return;
	}

	string ctrlObject = requestMmmsContent.vecDomainName.at(0) + "/" + requestMmmsContent.vecItemName.at(0);  //一般一次只遥控一个点
	if(ctrlObject.find("$SBOw") == string::npos && ctrlObject.find("$Oper") == string::npos)                    //只判断遥控选择和遥控执行的Response
		return;

	//遥控回复没带时标，控制时间采用报文时标
	char utcTime[64] = {0};                                                                      //时间格式 yyyy-MM-dd hh:mm:ss.zzz
	Conversions_msTimeToGeneralizedTime(mmsContent.packetTimeStamp, (uint8_t*)utcTime);          //#include "conversions.h" 加了extern "C" 否则会找不到定义

	int ctrlCmdType = ctrlObject.find("SBOw") != string::npos ? 0 : 1;    //报文类型 0:选择  1:执行

	char ctrlValue[64] = {0};        //回复没有遥控值

	int ctrlResult = WriteResponse__Member_PR_success == mmsContent.responseResult ? 1 : 2;       //Reponse遥控执行结果 1:成功  2:失败   0:Request

	publishRemoteControl(mmsContent, ctrlObject, utcTime, ctrlValue, ctrlCmdType, ctrlResult);
}

char* PacketParse::getControlValue(MmsValue* mmsValue, char* buffer, int bufferSize)
{
	int elementCount = MmsValue_getArraySize(mmsValue);
	if(elementCount >= 1)
	{
		MmsValue*  value = MmsValue_getElement(mmsValue, 0);             //控制值在最前面

		//if(MMS_BOOLEAN == MmsValue_getType(value))
		//{
			MmsValue_printToBuffer(value, buffer, bufferSize);
		//}
	}
	return buffer;
}

int PacketParse::publishRemoteControl(stMmsContent mmsContent, string ctrlObject, char* utcTime, string ctrlValue, int ctrlCmdType, int ctrlResult)
{
	if(ctrlResult == 0)
	{
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO,"Request  invokeId:" + boost::lexical_cast<string>(mmsContent.invokeId) +
																		  " ctrlObject:" + ctrlObject + " utcTime:" + utcTime + " ctrlValue:" + ctrlValue);
	}
	else
	{
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO,"Response invokeId:" + boost::lexical_cast<string>(mmsContent.invokeId) +
																		  " ctrlResult" + boost::lexical_cast<string>(ctrlResult));
	}

	RtdbMessage rtdbMessage;
	rtdbMessage.set_messagetype(TYPE_REALPOINT);

	RealPointValue* realPointValue = rtdbMessage.mutable_realpointvalue();
	realPointValue->set_channelname(SingletonConfig->getChannelName());
	realPointValue->set_pointvalue(ctrlValue);
	realPointValue->set_pointaddr(SingletonConfig->getPubAddrByFcda(ctrlObject));
	realPointValue->set_valuetype(VTYPE_BOOL);
	realPointValue->set_channeltype(2);                                       //通道类型，1-采集  2-网分
	realPointValue->set_timevalue(utcTime);
	realPointValue->set_sourip(mmsContent.srcIp);
	realPointValue->set_destip(mmsContent.dstIp);
	realPointValue->set_protocoltype("IEC61850");
	realPointValue->set_ctrlcmdtype(CtrlCmdType(ctrlCmdType));                            //0
	realPointValue->set_executeresult(CmdExecuteResult(ctrlResult));
	realPointValue->add_pcapfilename(mmsContent.pcapFile);

	string dataBuf;
	rtdbMessage.SerializeToString(&dataBuf);

	return redisHelper->publish(REDIS_CHANNEL_CONFIG, dataBuf, string("6014_") + SingletonConfig->getPubAddrByFcda(ctrlObject) + "_2");
}

void PacketParse::analysisVaribleList(stMmsContent mmsContent)
{
	MmsValue* optFlds = MmsValue_getElement(mmsContent.mmsValue, 1);        //报告选项域在访问结果中的下标为1         详情在IEC611850入门第215页

	int mmsValueIndex = 2;
	/* check for sequence-number */
	if (MmsValue_getBitStringBit(optFlds, 1) == true) {
		mmsValueIndex++;
	}

	/* check for report-timestamp */
	if (MmsValue_getBitStringBit(optFlds, 2) == true) {
		mmsValueIndex++;
	}

	char datasetname[64] = {0};
	/* check for data set name */
	if (MmsValue_getBitStringBit(optFlds, 4) == true) {                                        //选项域中各个比特位的含义，详情在IEC611850入门第217页
		MmsValue* mmsValue = MmsValue_getElement(mmsContent.mmsValue, mmsValueIndex);
		MmsValue_printToBuffer(mmsValue, datasetname, 64);
		mmsValueIndex++;
	}

	/* check for bufOvfl */
	if (MmsValue_getBitStringBit(optFlds, 6) == true) {
		mmsValueIndex++;
	}

	/* check for entryId */
	if (MmsValue_getBitStringBit(optFlds, 7) == true) {
		mmsValueIndex++;
	}

	/* check for confRev */
	if (MmsValue_getBitStringBit(optFlds, 8) == true) {
		mmsValueIndex++;
	}

	/* check for segmentation fields */
	if (MmsValue_getBitStringBit(optFlds, 9) == true)
		mmsValueIndex += 2;                         											 //存在SubSeqNum和MoreSegmentFollow 2个值

	MmsValue* inclusionBitstring = MmsValue_getElement(mmsContent.mmsValue, mmsValueIndex);     //获取包含位串
	int inclusionBitSize = MmsValue_getBitStringSize(inclusionBitstring);                       //inclusionBitSize等于数据集中数据的个数

	/* parse data-references*/
	if (MmsValue_getBitStringBit(optFlds, 5) == true)
	{
		for(int i = 0; i < inclusionBitSize; ++i)
		{
			if(MmsValue_getBitStringBit(inclusionBitstring, i))                                      //值为1表示在数据集中的位置
			{
				mmsValueIndex++;
			}
		}
	}

	vector<string> vecFcd = dataSetModel.getFcdByDataset(datasetname);
	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, string("DataSet:") + datasetname + " Size:" + boost::lexical_cast<string>(vecFcd.size()) + " inclusionBitSize:" + boost::lexical_cast<string>(inclusionBitSize));

	if(vecFcd.size() != inclusionBitSize)
	{
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_ERROR, " Size not equal to inclusionBitSize");
		return;
	}
	for(int i = 0; i < inclusionBitSize; ++i)
	{
		if(MmsValue_getBitStringBit(inclusionBitstring, i))
		{
			mmsValueIndex++;
			MmsValue* fcdaMmsValue = MmsValue_getElement(mmsContent.mmsValue, mmsValueIndex);             //通过数据集中功能约束数据的下标获取当前值

			string fcd = vecFcd.at(i);
			vector<string> vecFcda = dataSetModel.getFcdaByFcd(fcd);                               //通过FCD获取FCD中的每个数据引用
			string fcda = vecFcda.at(0);
			string redisAddr = SingletonConfig->getPubAddrByFcda(fcda);
			if(redisAddr.empty())
			{
				SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_ERROR, fcda + " not redisAddr");
				continue;
			}

			publishPointValue(mmsContent, fcda, redisAddr, fcdaMmsValue);                                  //通过redis发布实时点值
		}
	}
}

PointValueType PacketParse::getPointValueType(MmsValue*  mmsValue)
{
	MmsType fcdaType = MmsValue_getType(mmsValue);

	PointValueType ctype = VTYPE_RESERVE;
	switch(fcdaType)
	{
	case MMS_BOOLEAN:
		ctype = VTYPE_BOOL;
		break;
	case MMS_INTEGER:
	case MMS_UNSIGNED:
		ctype = VTYPE_INT32;
		break;
	case MMS_FLOAT:
		ctype = VTYPE_FLOAT;
		break;
	case MMS_OCTET_STRING:
	case MMS_VISIBLE_STRING:
	case MMS_STRING:
	case MMS_UTC_TIME:
		ctype = VTYPE_STRING;
		break;
	}
	return ctype;
}


int PacketParse::publishPointValue(stMmsContent mmsContent, string fcda, string redisAddr, MmsValue* fcdaMmsValue)
{

	char value[64] = {0};
	char quality[64] = {0};
	char timestamp[64] = {0};
	MmsValue* valueMmsValue = NULL ;
	MmsValue* qualityMmsValue = NULL;
	MmsValue* timestampMmsValue = NULL;

	MmsType fcdaType = MmsValue_getType(fcdaMmsValue);
	switch(fcdaType)
	{
	case MMS_ARRAY:
	case MMS_STRUCTURE:
		valueMmsValue = MmsValue_getElement(fcdaMmsValue, 0);
		while( MmsValue_getType(valueMmsValue) == MMS_ARRAY || MmsValue_getType(valueMmsValue) == MMS_STRUCTURE)
			valueMmsValue = MmsValue_getElement(valueMmsValue, 0);
		MmsValue_printToBuffer(valueMmsValue, value, 64);

		qualityMmsValue = MmsValue_getElement(fcdaMmsValue, 1);
		if(qualityMmsValue != NULL)
			MmsValue_printToBuffer(qualityMmsValue, quality, 64);

		timestampMmsValue = MmsValue_getElement(fcdaMmsValue, 2);
		if(timestampMmsValue != NULL)
			MmsValue_printToBuffer(timestampMmsValue, timestamp, 64);
		break;
	default:
		valueMmsValue = fcdaMmsValue;
		Conversions_msTimeToGeneralizedTime(mmsContent.packetTimeStamp, (uint8_t*)timestamp);   //时间格式 yyyy-MM-dd hh:mm:ss.zzz
		break;
	}

	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_INFO, fcda + " type:" + MmsValue_getTypeString(valueMmsValue) + string("  value:") + value + " timestamp:" + timestamp);

	PointValueType ctype = getPointValueType(valueMmsValue);

	RtdbMessage rtdbMessage;
	rtdbMessage.set_messagetype(TYPE_REALPOINT);

	RealPointValue* realPointValue = rtdbMessage.mutable_realpointvalue();
	realPointValue->set_channelname(SingletonConfig->getChannelName());
	realPointValue->set_pointvalue(value);
	realPointValue->set_pointaddr(redisAddr);
	realPointValue->set_valuetype(ctype);
	realPointValue->set_channeltype(2);                                       //通道类型，1-采集  2-网分
	realPointValue->set_timevalue(timestamp);                                        //实时点时标
	realPointValue->set_sourip(mmsContent.srcIp);
	realPointValue->set_destip(mmsContent.dstIp);
	realPointValue->set_protocoltype("IEC61850");
	realPointValue->add_pcapfilename(mmsContent.pcapFile);

	string dataBuf;
	rtdbMessage.SerializeToString(&dataBuf);

	return redisHelper->publish(REDIS_CHANNEL_CONFIG, dataBuf, string("6014_") + redisAddr + "_2");
}


void PacketParse::copyTcpContentFromMmsContent(stMmsContent mmsContent)
{
	lock.lock();
	stTcpContent tcpContent;
	tcpContent.srcIp = mmsContent.srcIp;
	tcpContent.dstIp = mmsContent.dstIp;
	tcpContent.packetTimeStamp = mmsContent.packetTimeStamp;
	tcpContent.pcapFile = mmsContent.pcapFile;
	tcpContent.timeCnt = 0;
	if(mapTcpContent.find(mmsContent.srcIp) != mapTcpContent.end())
		mapTcpContent.erase(mmsContent.srcIp);

	mapTcpContent.insert(make_pair(tcpContent.srcIp, tcpContent));
	lock.unlock();
}

bool PacketParse::isOnlineDevice(string iedIp)
{
	bool result = false;
	list<string>::iterator itOnlineDevice = listOnlineDevice.begin();
	for(; itOnlineDevice != listOnlineDevice.end(); ++itOnlineDevice)
	{
		if(iedIp == *itOnlineDevice)
		{
			result = true;
			break;
		}
	}
	return result;
}

void PacketParse::eraseOnlineDevice(string iedIp)
{
	list<string>::iterator itOnlineDevice = listOnlineDevice.begin();
	for(; itOnlineDevice != listOnlineDevice.end(); ++itOnlineDevice)
	{
		if(iedIp == *itOnlineDevice)
		{
			listOnlineDevice.erase(itOnlineDevice);
			break;
		}
	}
}

int PacketParse::publishLinkStatus(stTcpContent tcpContent, string redisAddr, string linkStatus)
{
	char utcTime[64] = {0};                                                                      //时间格式 yyyy-MM-dd hh:mm:ss.zzz
	Conversions_msTimeToGeneralizedTime(tcpContent.packetTimeStamp, (uint8_t*)utcTime);          //#include "conversions.h" 加了extern "C" 否则会找不到定义

	RtdbMessage rtdbMessage;
	rtdbMessage.set_messagetype(TYPE_REALPOINT);

	RealPointValue* realPointValue = rtdbMessage.mutable_realpointvalue();
	realPointValue->set_channelname(SingletonConfig->getChannelName());
	realPointValue->set_pointvalue(linkStatus);                               //连接状态   1:断链   0:重连
	realPointValue->set_pointaddr(redisAddr);
	realPointValue->set_valuetype(VTYPE_BOOL);
	realPointValue->set_channeltype(2);                                       //通道类型，1-采集  2-网分
	realPointValue->set_timevalue(utcTime);                                   //报文时标
	realPointValue->set_sourip(tcpContent.srcIp);
	realPointValue->set_destip(tcpContent.dstIp);
	realPointValue->add_pcapfilename(tcpContent.pcapFile);

	string dataBuf;
	rtdbMessage.SerializeToString(&dataBuf);

	return redisHelper->publish(REDIS_CHANNEL_CONFIG, dataBuf, string("6014_")  + redisAddr + "_" + linkStatus);
}


stMmsContent PacketParse::getMmsContentByInvokeId(uint32_t invokeId)
{
	stMmsContent mmsContent;
	map<uint32_t, stMmsContent>::iterator it = mapInvokeIdMmsContent.find(invokeId);
	if(it != mapInvokeIdMmsContent.end())
	{
		mmsContent = it->second;
	}
	return mmsContent;
}


void PacketParse::start()
{
	boost::function0< void> subscribeFun =  boost::bind(&PacketParse::subscribe,this);
	boost::thread redisThread(subscribeFun);
	redisThread.detach();

	boost::function0< void> sendHeartBeatFun =  boost::bind(&PacketParse::sendHeartBeat,this);
	boost::thread sendHeartBeatThread(sendHeartBeatFun);
	sendHeartBeatThread.detach();

	boost::function0< void> runFun =  boost::bind(&PacketParse::run,this);
	boost::thread runThread(runFun);
	runThread.detach();

	boost::function0< void> judgeFun =  boost::bind(&PacketParse::judgeLinkStatus,this);
	boost::thread judgeThread(judgeFun);
	judgeThread.detach();
}

void PacketParse::stop()
{
	isRunning = false;
}


void PacketParse::run()
{
	while(isRunning)
	{
		stMmsContent mmsContent;
		if(queMmsContent.pop_front(mmsContent, 100))
		{
			analysisMmsContent(mmsContent);
		}
	}
}

void PacketParse::subscribe()
{
	//默认取消自动重连，因为自动重连，需要重新订阅,但是无法获知何时重连成功
	redisHelper = new RedisHelper(SingletonConfig->getRedisIp() + ":" + boost::lexical_cast<string>(SingletonConfig->getRedisPort()));
	while(isRunning)
	{
		if(!redisHelper->check_connect())
		{
			if(redisHelper->open())
			{
				SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Redis Connect Success:" + SingletonConfig->getRedisIp());
				if(redisHelper->subscribe(SingletonConfig->getChannelName()) >= 1)
				{
					SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Redis Subscribe Success:" + SingletonConfig->getChannelName());
				}
			}
			else
			{
				SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_WARN, "Redis Connect Failure:" + SingletonConfig->getRedisIp());
				sleep(1);
				continue;
			}
		}

		string message;
		if(redisHelper->getMessage(message))
		{
			RtdbMessage rtdbMessage;
			if(rtdbMessage.ParseFromString(message))
			{
				//RemoteControl remoteControl = rtdbMessage.remotecontrol();
				//LOG_DEBUG(remoteControl.protocolname());

				switch(rtdbMessage.messagetype())
				{
				case TYPE_REALPOINT:
				{
					RealPointValue realPointValue = rtdbMessage.realpointvalue();
					SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, realPointValue.pointaddr() + " " + realPointValue.pointvalue());
					break;
				}
				case TYPE_HEARTBEATMESSAGE:
				{
					HeartBeatMessage heartBeatMessage = rtdbMessage.heartbeatmessage();
					SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "heartTime:" + boost::lexical_cast<string>(heartBeatMessage.time()));
					break;
				}
				case TYPE_LOGREQUEST:
				{
					LogRequest logRequest = rtdbMessage.logrequest();
					SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "channel:" + logRequest.channelname() + " command:" + boost::lexical_cast<string>(logRequest.command()));
					if(logRequest.channelname().compare(SingletonConfig->getChannelName()) == 0)
					{
						SingletonLog4cplus->setLogRequestFlag(logRequest.command());
					}
					break;
				}
				default:
					break;
				}
			}
			else
			{
				SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_WARN, "ParseFromString Failure");
			}
		}
	}
}

void PacketParse::sendHeartBeat()         //发送心跳
{
	heatRedisHelper = new RedisHelper(SingletonConfig->getRedisIp() + ":" + boost::lexical_cast<string>(SingletonConfig->getRedisPort()), true);  //设置自动重连
	heatRedisHelper->open();
	while(isRunning)
	{
		sleep(10);
		RtdbMessage rtdbMessage;
		rtdbMessage.set_messagetype(TYPE_HEARTBEATMESSAGE);

		HeartBeatMessage* heartBeatMessage = rtdbMessage.mutable_heartbeatmessage();
		heartBeatMessage->set_time(time(NULL));
		heartBeatMessage->set_channelname(SingletonConfig->getChannelName());

		string message;
		rtdbMessage.SerializeToString(&message);

		heatRedisHelper->publish(REDIS_CHANNEL_PROCTRL, message);
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Write Heart Beat");
	}
}

void PacketParse::judgeLinkStatus()
{
	while(isRunning)
	{
		lock.lock();
		map<string, stTcpContent>::iterator itTcpContent = mapTcpContent.begin();
		for(; itTcpContent != mapTcpContent.end(); ++itTcpContent)
		{
			stTcpContent tcpContent = itTcpContent->second;
			string iedName = SingletonConfig->getIedName(tcpContent.srcIp);
			string iedIp = tcpContent.srcIp;
			if(iedName.empty())
			{
				iedName = SingletonConfig->getIedName(tcpContent.dstIp);
				iedIp = tcpContent.dstIp;
			}
			//SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, tcpContent.srcIp + " " + boost::lexical_cast<string>(itTcpContent->second.timeCnt));

			//设备之前是否在线
			bool srcIpResult = isOnlineDevice(tcpContent.srcIp);

			if(tcpContent.timeCnt == 0 && srcIpResult == false)
			{
				listOnlineDevice.push_back(tcpContent.srcIp);
				bool dstResult = isOnlineDevice(tcpContent.dstIp);
				if(dstResult == false)           //源ip,目的ip之前都离线，才判断在线
				{
					string redisAddr = SingletonConfig->getLinkStatusRedisAddr(iedName, iedIp);
					publishLinkStatus(tcpContent, redisAddr, "0");
					SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, iedName + " is connect!");
				}
			}
			else if(tcpContent.timeCnt >= SingletonConfig->getHeartBeatTime() && srcIpResult == true)  //如果已经离线，不再继续告警
			{
				eraseOnlineDevice(tcpContent.srcIp);
				bool dstResult = isOnlineDevice(tcpContent.dstIp);
				if(dstResult == false)           //源ip,目的ip都没有报文才判断离线
				{
					string redisAddr = SingletonConfig->getLinkStatusRedisAddr(iedName, iedIp);
					publishLinkStatus(tcpContent, redisAddr, "1");
					SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, iedName + " is disconnect!");
				}
			}

			itTcpContent->second.timeCnt++;
		}
		lock.unlock();
		sleep(1);
	}
}



