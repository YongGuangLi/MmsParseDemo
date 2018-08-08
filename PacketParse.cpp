/*
 * PacketParse.cpp
 *
 *  Created on: Aug 2, 2018
 *      Author: root
 */

#include "PacketParse.h"

PacketParse::PacketParse() {
	isRunning = true;
	if(redisHelper.open("192.168.239.140:6379"))
	{
		LOG_DEBUG("Redis Connect Success");
	}
	queMmsContent.set_size(100000);

	dataSetModel.load("/home/wgj/MmsParseDemo/dataset.txt");

	start();
	LOG_DEBUG("Start Dissect Packet");
}

PacketParse::~PacketParse() {
	// TODO Auto-generated destructor stub
}

void PacketParse::dissectPacket(struct pcap_pkthdr *pkthdr, u_char *packet)
{
	stMmsContent mmsContent;
	mmsContent.mmsValue = 0;      //需要赋值为空，否则第二次定义值不会为空
	mmsContent.invokeId = 0;
	mmsContent.serviceType = ServiceNOTHING;
	mmsContent.iphdr = 0;
	mmsContent.tcphdr = 0;

	int offset = 0;
	int type = dissectEthernet(pkthdr, packet, offset);
	offset += MACLENGTH;
	if(type != 0x0800)
	{
		return;
	}

	dissectIpHeader(pkthdr, packet, offset, &mmsContent);
	offset += IPLENGTH;

	dissectTcpHeader(pkthdr, packet, offset,  &mmsContent);
	offset += mmsContent.tcphdr->doff * 4;

	if(pkthdr->len <= offset)         //不是报文数据太短，不是mms
	{
		return;
	}

	int datalen = dissectTPKT(pkthdr, packet, offset);
	offset += 4;
	datalen -= 4;

	int cotpOffset = dissectCOTP(pkthdr, packet, offset);
	offset += cotpOffset;
	datalen -= cotpOffset;

	int sessionOffset = dissectSession(pkthdr, packet, datalen, offset);
	offset += sessionOffset;
	datalen -= sessionOffset;
	if(sessionOffset == -1)         //Session Analysis Abnormal
	{
		return;
	}

	int presentationOffset = dissectPresentation(pkthdr, packet, datalen, offset);    //修改了源代码的返回值
	offset += presentationOffset;
	datalen -= presentationOffset;

	dissectMmsContent(pkthdr, packet, datalen, offset, &mmsContent);

	queMmsContent.push_back(mmsContent);
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
	return 0;
}

int PacketParse::dissectTcpHeader(struct pcap_pkthdr *pkthdr, u_char *packet, int offset, stMmsContent *mmsContent)
{
	struct tcphdr* tcphdr = (struct tcphdr*)(packet + offset);
	mmsContent->tcphdr = tcphdr;
	return 0;
}

int PacketParse::dissectTPKT(struct pcap_pkthdr *pkthdr, u_char *packet, int offset)
{
	int tpkt_version = *(uint8_t*)(packet + offset);

	int tpkt_reserved = *(uint8_t*)(packet + offset + 1);

	int tpkt_len = ntohs(*(uint16_t*)(packet + offset + 2));

	return tpkt_len;
}

int PacketParse::dissectCOTP(struct pcap_pkthdr *pkthdr, u_char *packet, int offset)
{
	return 3;
}

int PacketParse::dissectSession(struct pcap_pkthdr *pkthdr, u_char *packet, int datalen, int offset)
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

int PacketParse::dissectPresentation(struct pcap_pkthdr *pkthdr, u_char *packet, int datalen, int offset)
{
	IsoPresentation self;
	ByteBuffer readBuffer;
	readBuffer.buffer = packet + offset;
	readBuffer.size = datalen;
	readBuffer.maxSize = datalen;

	int presentationOffset = IsoPresentation_parseUserData(&self, &readBuffer);
	return presentationOffset;
}

int PacketParse::dissectMmsContent(struct pcap_pkthdr *pkthdr, u_char *packet, int datalen, int offset, stMmsContent *mmsContent)
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

void PacketParse::SetConfirmedRequestPduResult(MmsPdu_t* mmsPdu, stMmsContent *mmsContent)
{
	uint32_t invokeId = mmsClient_getInvokeId(&mmsPdu->choice.confirmedResponsePdu);  //#include "mms_client_internal.h" 加了extern "C" 否则会找不到定义
	mmsContent->invokeId = invokeId;

	if (ConfirmedServiceRequest_PR_read == mmsPdu->choice.confirmedRequestPdu.confirmedServiceRequest.present)  //read
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
	else if(ConfirmedServiceRequest_PR_write == mmsPdu->choice.confirmedRequestPdu.confirmedServiceRequest.present)  //write
	{
		mmsContent->serviceType = confirmedServiceRequestWrite;

		WriteRequest_t writeRequest = mmsPdu->choice.confirmedRequestPdu.confirmedServiceRequest.choice.write;
		VariableAccessSpecification__listOfVariable listOfVariable = writeRequest.variableAccessSpecification.choice.listOfVariable;

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

		MmsValue* value = mmsMsg_parseDataElement(writeRequest.listOfData.list.array[0]);
		mmsContent->mmsValue = value;
	}
}

void PacketParse::SetConfirmedResponsePduResult(MmsPdu_t* mmsPdu, stMmsContent *mmsContent)
{
	uint32_t invokeId = mmsClient_getInvokeId(&mmsPdu->choice.confirmedResponsePdu);
	mmsContent->invokeId = invokeId;

	if (ConfirmedServiceResponse_PR_read == mmsPdu->choice.confirmedResponsePdu.confirmedServiceResponse.present)          	//read
	{
		mmsContent->serviceType = confirmedServiceResponseRead;

		ReadResponse_t readResponse = mmsPdu->choice.confirmedResponsePdu.confirmedServiceResponse.choice.read;
		int elementCount = readResponse.listOfAccessResult.list.count;
		MmsValue* value = mmsClient_parseListOfAccessResults(readResponse.listOfAccessResult.list.array, elementCount, true);
		mmsContent->mmsValue = value;
	}
	else if(ConfirmedServiceResponse_PR_write == mmsPdu->choice.confirmedResponsePdu.confirmedServiceResponse.present)  	//write
	{
		mmsContent->serviceType = confirmedServiceResponseWrite;

		WriteResponse_t writeResponse = mmsPdu->choice.confirmedResponsePdu.confirmedServiceResponse.choice.write;
		for(int i = 0; i < writeResponse.list.count; ++i)
		{
			mmsContent->vecResponseResult.push_back(writeResponse.list.array[i]->present);
		}
	}
}


void PacketParse::SetUnConfirmedPduResult(MmsPdu_t* mmsPdu, stMmsContent *mmsContent)
{
	InformationReport_t report = mmsPdu->choice.unconfirmedPDU.unconfirmedService.choice.informationReport;      //mms报告服务(Report)服务属于非确认服务，用于定时上传所采集的电压，电流值(遥测量)

	if (VariableAccessSpecification_PR_listOfVariable == report.variableAccessSpecification.present)              //需要确认此种情况是否需要处理
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
	//LOG_DEBUG("invokeID:" + boost::lexical_cast<string>(mmsContent.invokeId));

	switch(mmsContent.serviceType)
	{
	case confirmedServiceRequestRead:
	{
		break;
	}
	case confirmedServiceRequestWrite:                             //遥控选择服务被映射到MMS中的write服务
	{
		mapInvokeIdMmsContent.insert(make_pair(mmsContent.invokeId, mmsContent));

		break;
	}
	case confirmedServiceResponseRead:
	{
		break;
	}
	case confirmedServiceResponseWrite:                             //write的response是枚举类型    成功或者失败
	{
		stMmsContent requestMmmsContent = getMmsContentByInvokeId(mmsContent.invokeId);

		for(int i = 0; i <  requestMmmsContent.vecDomainName.size(); ++i)
		{
			string pointName = requestMmmsContent.vecDomainName.at(i) + "/" + requestMmmsContent.vecItemName.at(i);

			if(WriteResponse__Member_PR_success == mmsContent.vecResponseResult[i])
			{
				//LOG_DEBUG("WriteResponse__Member_PR_success");
			}
			else if(WriteResponse__Member_PR_failure == mmsContent.vecResponseResult[i])
			{
				//LOG_DEBUG("WriteResponse__Member_PR_failure");
			}
		}

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


void PacketParse::analysisVaribleList(stMmsContent mmsContent)
{
	MmsValue* optFlds = MmsValue_getElement(mmsContent.mmsValue, 1);        //报告选项域在访问结果中的下标为1

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
	if (MmsValue_getBitStringBit(optFlds, 4) == true) {
		MmsValue* mmsValue = MmsValue_getElement(mmsContent.mmsValue, mmsValueIndex);
		MmsValue_printToBuffer(mmsValue, datasetname, 64);
		//LOG_DEBUG(string("data-set-name:") + datasetname);
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
		mmsValueIndex += 2;                          //存在SubSeqNum和MoreSegmentFollow 2个值

	MmsValue* inclusionBitstring = MmsValue_getElement(mmsContent.mmsValue, mmsValueIndex);     //获取包含位串
	int inclusionBitSize = MmsValue_getBitStringSize(inclusionBitstring);

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
	for(int i = 0; i < inclusionBitSize; ++i)
	{
		if(MmsValue_getBitStringBit(inclusionBitstring, i))
		{
			mmsValueIndex++;
			MmsValue* value = MmsValue_getElement(mmsContent.mmsValue, mmsValueIndex);

			string fcd = vecFcd.at(i);
			vector<string> vecFcda = dataSetModel.getFcdaByFcd(fcd);
			for(int j = 0; j < vecFcda.size(); ++j)
			{
				string fcda = vecFcda.at(j);
				MmsValue* fcdaMmsValue = MmsValue_getElement(value, j);
				publishPointValue(fcda, fcdaMmsValue);
			}

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

int PacketParse::publishPointValue(string fcda, MmsValue*  fcdaMmsValue)
{
	MmsType fcdaType = MmsValue_getType(fcdaMmsValue);
	switch(fcdaType)
	{
	case MMS_ARRAY:
	case MMS_STRUCTURE:
		fcdaMmsValue = MmsValue_getElement(fcdaMmsValue,0);
		break;
	default:
		break;
	}

	char strFcdaMmsValue[64] = {0};
	MmsValue_printToBuffer(fcdaMmsValue, strFcdaMmsValue, 64);
	LOG_DEBUG(fcda + " type:" + MmsValue_getTypeString(fcdaMmsValue) + string("  value:") + strFcdaMmsValue);

	PointValueType ctype = getPointValueType(fcdaMmsValue);

	RtdbMessage rtdbMessage;
	rtdbMessage.set_messagetype(TYPE_REALPOINT);
	RealPointValue* realPointValue = rtdbMessage.mutable_realpointvalue();
	realPointValue->set_channelname("MmsParse");
	realPointValue->set_pointvalue(strFcdaMmsValue);
	realPointValue->set_pointaddr(fcda);
	realPointValue->set_valuetype(ctype);
	realPointValue->set_channeltype(2);  //通道类型，1-采集  2-网分

	string dataBuf;
	rtdbMessage.SerializeToString(&dataBuf);
	return redisHelper.publish(CHANNEL, dataBuf);
}

void PacketParse::judgeRemoteControl(stMmsContent mmsContent)
{
	for(int i = 0; i < mmsContent.vecItemName.size(); ++i)
	{
		string itemName = mmsContent.vecItemName.at(i);
		if(itemName.find("SBOw") == string::npos && itemName.find("Oper") == string::npos)
			continue;

		string pointName = mmsContent.vecDomainName.at(i) + "/" + itemName;
	}
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
	redisHelper.subscribe(CHANNEL);
	while(isRunning)
	{
		string message;
		if(redisHelper.getMessage(message))
		{
			RtdbMessage rtdbMessage;
			if(rtdbMessage.ParseFromString(message))
			{
				//RemoteControl remoteControl = rtdbMessage.remotecontrol();
				//LOG_DEBUG(remoteControl.protocolname());
				RealPointValue realPointValue = rtdbMessage.realpointvalue();
				LOG_DEBUG(realPointValue.pointaddr() + " " + realPointValue.pointvalue());
			}
			else
			{
				LOG_DEBUG("ParseFromString Failure");
			}
		}
	}
}

void PacketParse::start()
{
	boost::function0< void> runFun =  boost::bind(&PacketParse::run,this);
	boost::thread runThread(runFun);

	boost::function0< void> subscribeFun =  boost::bind(&PacketParse::subscribe,this);
	boost::thread redisThread(subscribeFun);
}

void PacketParse::stop()
{
	isRunning = false;
}


//RtdbMessage rtdbMessage;
//	rtdbMessage.set_messagetype(TYPE_REMOTECONTROL);
//	RemoteControl* remoteControl = rtdbMessage.mutable_remotecontrol();
//	remoteControl->set_protocolname("iec61850");
//	remoteControl->set_timestamp("");
//	remoteControl->set_srcip(inet_ntoa(mmsContent.iphdr->ip_src));
//	remoteControl->set_srcdevice("");
//	remoteControl->set_dstip(inet_ntoa(mmsContent.iphdr->ip_dst));
//	remoteControl->set_dstdevice("");
//	remoteControl->set_pointname("");
//	remoteControl->set_pointdesc("");
//	remoteControl->set_result(0);    //iec61850遥控执行结果  0 失败   1 成功
//	remoteControl->set_sbo(0);      //选择报文还是执行报文 1 选择  0执行
//
//	string dataBuf;
//	rtdbMessage.SerializeToString(&dataBuf);
//	redisHelper.publish(CHANNEL, dataBuf);

//		stMmsContent requestMmmsContent = getMmsContentByInvokeId(mmsContent.invokeId);
//		for(int i = 0; i <  requestMmmsContent.vecDomainName.size(); ++i)
//		{
//			string pointName = requestMmmsContent.vecDomainName.at(i) + "/" + requestMmmsContent.vecItemName.at(i);
//			LOG_DEBUG(pointName);
//			MmsValue* mmsValue = MmsValue_getElement(mmsContent.mmsValue, i);
//			char strMmsValue[64] = {0};
//			MmsValue_printToBuffer(mmsValue, strMmsValue, 64);
//			LOG_DEBUG(strMmsValue);
//		}

//vector<string> vecObjectName;
//for(int i = 0; i < mmsContent->vecDomainName.size(); ++i)
//{
//	string domainName = mmsContent->vecDomainName[i];
//	string itemName = mmsContent->vecItemName[i];
//	vecObjectName.push_back(domainName + "/" + itemName);
//}
//mapInvokeIdObjectName.insert(make_pair(mmsContent->invokeId, vecObjectName));



//map<uint32_t, vector<string> >::iterator it = mapInvokeIdObjectName.find(mmsContent->invokeId);
//if(it != mapInvokeIdObjectName.end())
//{
//	vector<string> vecObjectName = it->second;
//	for(int i = 0; i < vecObjectName.size(); ++i)
//	{
//		string objectName = vecObjectName[i];
//		LOG_DEBUG(objectName);
//
//		MmsValue* mmsValue = MmsValue_getElement(mmsContent->mmsValue, i);
//		char strMmsValue[64] = {0};
//		MmsValue_printToBuffer(mmsValue, strMmsValue, 64);
//		LOG_DEBUG(strMmsValue);
//	}
//}


//map<uint32_t, vector<string> >::iterator it = mapInvokeIdObjectName.find(mmsContent->invokeId);
//if(it != mapInvokeIdObjectName.end())
//{
//	vector<string> vecObjectName = it->second;
//	for(int i = 0; i < vecObjectName.size(); ++i)
//	{
//		string objectName = vecObjectName[i];
//		LOG_DEBUG("objectName:" + objectName);
//
//		if(WriteResponse__Member_PR_success == mmsContent->vecResponseResult[i])
//		{
//			LOG_DEBUG("WriteResponse__Member_PR_success");
//		}
//		else if(WriteResponse__Member_PR_failure == mmsContent->vecResponseResult[i])
//		{
//			LOG_DEBUG("WriteResponse__Member_PR_failure");
//		}
//	}
//}


//		cout<<inet_ntoa(mmsContent.iphdr->ip_dst)<<endl;
//		cout<<inet_ntoa(mmsContent.iphdr->ip_src)<<endl;
//		cout<<ntohs(mmsContent.tcphdr->source)<<endl;
//		cout<<ntohs(mmsContent.tcphdr->dest)<<endl;


//char src_mac[18] = {0};
//char dst_mac[18] = {0};
//sprintf(dst_mac,"%02x:%02x:%02x:%02x:%02x:%02x", ethdr->ether_dhost[0], ethdr->ether_dhost[1],ethdr->ether_dhost[2],ethdr->ether_dhost[3],ethdr->ether_dhost[4],ethdr->ether_dhost[5]);
//sprintf(src_mac,"%02x:%02x:%02x:%02x:%02x:%02x", ethdr->ether_shost[0], ethdr->ether_shost[1],ethdr->ether_shost[2],ethdr->ether_shost[3],ethdr->ether_shost[4],ethdr->ether_shost[5]);

