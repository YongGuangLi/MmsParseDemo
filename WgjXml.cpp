#include "WgjXml.h"


WgjXml::WgjXml()
{

}

WgjXml::~WgjXml()
{
}

bool WgjXml::LoadXml(const char * name)
{
	if (m_doc.LoadFile(name)) {
		//m_doc.Print();
		m_bOpenStatus = true;
	}
	else {
		cout << "can not parse xml" << endl;
		m_bOpenStatus = false;
		return false;
	}
	return true;
}

map<string, string >WgjXml::Get_Point61850(string channel)
{

	Get_61850(channel);

	return m_Point61850;
}

vector<string> WgjXml::GetTransmitChannel()
{
	m_TransmitChannel.clear();
	if (!m_bOpenStatus) return m_TransmitChannel;
	TiXmlElement* Element = m_doc.RootElement();

	Element = Element->FirstChildElement();
	while (Element != NULL)
	{
		if (strcmp(Element->Value(), "forwardservice") == 0)
		{
			Element = Element->FirstChildElement();
			while (Element != NULL)
			{
				if (strcmp(Element->Value(), "channel") == 0)
				{
					m_TransmitChannel.push_back(Element->Attribute("name"));
				}
				if (Element != NULL)Element = Element->NextSiblingElement();
			}
		}
		if (Element != NULL)Element = Element->NextSiblingElement();
	}

	return m_TransmitChannel;
}

IEC61850_STRUCT::Map_IedInfo WgjXml::Get_61850(string channel)
{
	m_mapIedInfo.clear();
	this->m_Point61850.clear();
	m_channel = channel;
	TiXmlElement* rootElement = m_doc.RootElement();
	//TiXmlElement *FirstNode = rootElement->FirstChildElement();
	parse_61850(rootElement);
	return m_mapIedInfo;
}

void WgjXml::GetRedisConnectionConfig(string & ip, int & port)
{
	if (!m_bOpenStatus) return;
	TiXmlElement* Element = m_doc.RootElement();

	Element = Element->FirstChildElement();
	while (Element != NULL)
	{
		if (strcmp(Element->Value(), "project") == 0)
		{
			ip = Element->Attribute("RedisIp");
			string 	strPort = Element->Attribute("RedisPort");
			if (strPort == "" || strPort.empty())
				port = 0;
			else
				port = atoi(strPort.c_str());
			break;
		}
		if (Element != NULL)Element = Element->NextSiblingElement();
	}

	return;
}

bool WgjXml::GetCollectionRedisInfo(string channel, REDIS_INFO & redis_info)
{
	m_mapIedInfo.clear();
	m_channel = channel;
	find_RedisInfo("collection", redis_info);

	//TiXmlElement *FirstNode = rootElement->FirstChildElement();
	//parse_61850(rootElement);
	return true;
}

NetworkPcap::Map_NetworkPcap WgjXml::GetPcapConfigInfo(string strChannel)
{
	m_pcapConfig.clear();
	m_channel = strChannel;
	getPcapConfigInfo();
	return m_pcapConfig;
}

ProcessManag::Map_Channel WgjXml::GetAllChannelName()
{
	m_MapChannelAll.clear();
	TiXmlElement* rootElement = m_doc.RootElement();
	get_AllChannel(rootElement);
	return m_MapChannelAll;
};
NetworkParse::Map_ParseConfig  WgjXml::GetParseConfigInfo(string strchannel)
{
	m_parseConfig.clear();
	m_channel = strchannel;
	getParseConfigInfo("");
	return m_parseConfig;
}
IEC61850Server::Map_IECServer WgjXml::GetIEC61850ServerPoint(string strchannel,string & cidName)
{
	m_iec61850Server.clear();
	m_cidname = "";
	m_channel = strchannel;
	
	TiXmlElement* rootElement = m_doc.RootElement();
	getIEC61850ServerPoint(rootElement);
	cidName = m_cidname;
	return m_iec61850Server;
}


bool WgjXml::InitIEC103Xml(string channel)
{
	this->m_map103Config.clear();
	this->m_map103Point.clear();
	this->m_lmapPoint.clear();

	this->m_channel = channel;
	TiXmlElement* rootElement = m_doc.RootElement();
	return parse_Iec103(rootElement);
}
IEC103::Map_IEC103Config  WgjXml::GetIEC103Param()
{
	return m_map103Config;
}
IEC103::Map_IEC103Point  WgjXml::GetIEC103Point()
{
	return this->m_map103Point;
}
IEC104WF::IpMap104 WgjXml::GetIEC104WFPoint(string channel)
{
	m_mapIP104.clear();
	m_map104Point.clear();
	m_l_tempPoint.clear();
	this->m_tempIedName.clear();
	TiXmlElement* rootElement = m_doc.RootElement();
	m_channel = channel;
	parse_Iec104(rootElement);
	return m_mapIP104;
}
map<string ,string> WgjXml::GetIEC104WFParam(string channel)
{
	m_iec104Config.clear();
	TiXmlElement* rootElement = m_doc.RootElement();
	m_channel = channel;
	parse_Iec104Param(rootElement);
	return m_iec104Config;
}
list<string> WgjXml::Get61850IP(string networkType)
{
	m_listIP.clear();
	
	this->m_NetworkType = networkType;
	TiXmlElement* rootElement = m_doc.RootElement();
	parse_61850IP(rootElement);

	return m_listIP;
}


/*************************************************************************************/
//内部解析采集点的61850
bool WgjXml::parse_61850(TiXmlElement*  Element)
{
	if (!m_bOpenStatus) return false;
	Element = Element->FirstChildElement();
	while (Element!=NULL)
	{
		if (strcmp(Element->Value(), "collection")==0   )
		{
			//cout << Element->Value() << endl;
			parse_61850(Element);
		}
		if (strcmp(Element->Value(), "channel") == 0 &&
			strcmp(Element->Attribute("name"), m_channel.c_str()) == 0 &&
			strcmp(Element->Attribute("program_name"), "IEC61850") == 0)
		{
			m_iedStruct.channel = Element->Attribute("name");
			//cout << Element->Attribute("name") << endl;
			parse_61850(Element);
		}
		if (strcmp(Element->Value(), "ied") == 0)
		{
			m_iedStruct.iedName = Element->Attribute("name");
			m_iedStruct.inst = atoi(Element->Attribute("inst"));
			//cout << Element->Attribute("name") << endl;
			m_mapIedInfo[m_iedStruct.iedName] = m_iedStruct;
			parse_61850(Element);
		}
		if (strcmp(Element->Value(), "master_network") == 0)    //master_network
		{
			m_mapIedInfo[m_iedStruct.iedName].ip_A = Element->Attribute("ipaddress");
			m_mapIedInfo[m_iedStruct.iedName].port = atoi(Element->Attribute("port"));
			//cout << "主网ip:" << Element->Attribute("ipaddress") << endl;
		}
		if (strcmp(Element->Value(), "standby_network") == 0)//master_network
		{
			m_mapIedInfo[m_iedStruct.iedName].ip_B = Element->Attribute("ipaddress");
			//m_mapIedInfo[m_iedStruct.iedName].port = atoi(Element->Attribute("port"));
			//cout << "备网ip :" << Element->Attribute("ipaddress") << endl;
		}
		if (strcmp(Element->Value(), "protocol") == 0)//参数列表
		{
			parse_61850(Element);
		}
		if (strcmp(Element->Value(), "parameter") == 0)
		{
			//cout << Element->Attribute("name")<<" \t" << Element->Attribute("value") << endl;
			if (strcmp(Element->Attribute("name"), "period_time") == 0)
			{
				m_mapIedInfo[m_iedStruct.iedName].period_time = atoi(Element->Attribute("value"));
			}

			if (strcmp(Element->Attribute("name"), "datachange") == 0)
			{
				m_mapIedInfo[m_iedStruct.iedName].bdatachange = atoi(Element->Attribute("value"));
			}

			if (strcmp(Element->Attribute("name"), "period") == 0)
			{
				m_mapIedInfo[m_iedStruct.iedName].bperiod = atoi(Element->Attribute("value"));
			}
		}
		if (strcmp(Element->Value(), "dots") == 0)
		{
			parse_61850(Element);
		}
		if (strcmp(Element->Value(), "dot") == 0)
		{
			//cout <<"点名称=>" <<Element->Attribute("name") << endl;
			m_Point61850[Element->Attribute("address")] = Element->Attribute("redisAddress");
			m_mapIedInfo[m_iedStruct.iedName].mapPoint[Element->Attribute("address")] = Element->Attribute("redisAddress");
		}
		Element = Element->NextSiblingElement();
	}
	return true;
}
//内部解析采集点的104
bool WgjXml::parse_Iec104(TiXmlElement*  Element)
{
	if (!m_bOpenStatus) return false;
	Element = Element->FirstChildElement();
	while (Element != NULL)
	{
		if (strcmp(Element->Value(), "collection") == 0)
		{
			parse_Iec104(Element);
		}
		if (strcmp(Element->Value(), "channel") == 0  &&
			strcmp(Element->Attribute("program_name"), "IEC60870_5_104") == 0)
		{
			//cout << Element->Attribute("name") << endl;
			parse_Iec104(Element);
		}
		if (strcmp(Element->Value(), "ied") == 0)
		{
			//m_mapIec104[Element->Attribute("name")] = m_104Ied;
			//m_tempIedName = Element->Attribute("name");
			parse_Iec104(Element);
		}
		if (strcmp(Element->Value(), "master_network") == 0)    //master_network
		{
			this->m_l_tempA = Element->Attribute("ipaddress");
			//m_mapIec104[m_tempIedName].A_Port = atoi(Element->Attribute("port"));
			//cout << "主网ip:" << Element->Attribute("ipaddress") << endl;
		}
		if (strcmp(Element->Value(), "standby_network") == 0)//master_network
		{
			this->m_l_tempB = Element->Attribute("ipaddress");
			//m_mapIec104[m_tempIedName].ip_B = Element->Attribute("ipaddress");
			//m_mapIec104[m_tempIedName].B_Port = atoi(Element->Attribute("port"));
			//cout << "备网ip :" << Element->Attribute("ipaddress") << endl;
		}
		if (strcmp(Element->Value(), "protocol") == 0)//参数列表
		{
			//增加参数列表
			//configParam 
			parse_Iec104(Element);
		}
		if (strcmp(Element->Value(), "parameter") == 0)
		{
			cout << Element->Attribute("name") << " \t" << Element->Attribute("value") << endl;
		
			//m_iec104Config[Element->Attribute("name")] = Element->Attribute("value");
			//m_mapIec104[m_tempIedName].configParam = m_iec104Config;			
		}
		if (strcmp(Element->Value(), "dots") == 0)
		{
			parse_Iec104(Element);
		}
		if (strcmp(Element->Value(), "dot") == 0)
		{
			//cout <<"点名称=>" <<Element->Attribute("name") << endl;
			m_l104Point.coe = stringToNum<float>( Element->Attribute("rate"));
			m_l104Point.off_set = stringToNum<float>( Element->Attribute("offset"));
			m_l104Point.redisAddr = (Element->Attribute("redisAddress"));

			int nIndex = stringToNum<int>(Element->Attribute("address"));
			int terminal = stringToNum<int>(Element->Attribute("terminal"));

			m_l_tempPoint[nIndex] = m_l104Point;
			m_map104Point[terminal] = m_l_tempPoint;

			m_mapIP104[m_l_tempA] = m_map104Point;
			if (m_l_tempB.empty() != true || m_l_tempB !="")
				m_mapIP104[m_l_tempB] = m_map104Point;
		}
		Element = Element->NextSiblingElement();
	}
	return true;
}
//内部解析采集点的104
bool WgjXml::parse_Iec104Param(TiXmlElement*  Element)
{
	if (!m_bOpenStatus) return false;
	Element = Element->FirstChildElement();
	while (Element != NULL)
	{
		if (strcmp(Element->Value(), "collection") == 0)
		{
			parse_Iec104Param(Element);
		}
		if (strcmp(Element->Value(), "channel") == 0 &&
			strcmp(this->m_channel.c_str(), "name") == 0 &&
			strcmp(Element->Attribute("program_name"), "104ParsetestPcap") == 0)
		{
			//cout << Element->Attribute("name") << endl;
			this->m_iec104Config["NetWorkType"] = Element->Attribute("NetWorkType");
			this->m_iec104Config["network_name"] = Element->Attribute("network_name");
			parse_Iec104Param(Element);
		}
		if (strcmp(Element->Value(), "ied") == 0)
		{
			//this->m_iec104Config["src_mac"] = Element->Attribute("src_mac");
			//this->m_iec104Config["dst_mac"] = Element->Attribute("dst_mac");
			parse_Iec104Param(Element);
		}
		if (strcmp(Element->Value(), "pcapfile") == 0)    //master_network
		{
			this->m_iec104Config["src_file_path"] = Element->Attribute("src_file_path");
			this->m_iec104Config["dst_file_path"] = Element->Attribute("dst_file_path");

			//m_mapIec104[m_tempIedName].A_Port = atoi(Element->Attribute("port"));
			//cout << "主网ip:" << Element->Attribute("ipaddress") << endl;
		}
		if (strcmp(Element->Value(), "protocol") == 0)//master_network
		{
			parse_Iec104Param(Element);
		}
		if (strcmp(Element->Value(), "parameter") == 0)//参数列表
		{
			//增加参数列表
			//configParam 
			m_iec104Config[Element->Attribute("name")] = Element->Attribute("value");
			//parse_Iec104Param(Element);
		}
		
		Element = Element->NextSiblingElement();
	}
	return true;
}


//内部解析采集点的103
bool WgjXml::parse_Iec103(TiXmlElement*  Element)
{
	if (!m_bOpenStatus) return false;
	Element = Element->FirstChildElement();
	while (Element != NULL)
	{
		if (strcmp(Element->Value(), "collection") == 0)
		{
			parse_Iec103(Element);
		}
		if (strcmp(Element->Value(), "channel") == 0 &&
			strcmp(Element->Attribute("name"), m_channel.c_str()) == 0 )
		{
			m_lstConfigParam.type = Element->Attribute("communication_mode");
			parse_Iec103(Element);
		}
		if (strcmp(Element->Value(), "ied") == 0)
		{
			//m_mapIec104[Element->Attribute("name")] = m_104Ied;
			//m_tempIedName = Element->Attribute("name");
			m_lIedName = Element->Attribute("name");
			parse_Iec103(Element);
		}
		if (strcmp(Element->Value(), "master_network") == 0)    //master_network
		{
			m_lstConfigParam.A_Port = atoi(Element->Attribute("port"));
			m_lstConfigParam.ip_A = Element->Attribute("ipaddress");
			//cout << "主网ip:" << Element->Attribute("ipaddress") << endl;
		}
		if (strcmp(Element->Value(), "standby_network") == 0)//master_network
		{
			m_lstConfigParam.B_Port = atoi(Element->Attribute("port"));
			m_lstConfigParam.ip_B = Element->Attribute("ipaddress");
			this->m_map103Config[m_lIedName] = m_lstConfigParam;
		}
		if (strcmp(Element->Value(), "protocol") == 0)//参数列表
		{
			//增加参数列表
			//configParam 
			parse_Iec103(Element);
		}
		if (strcmp(Element->Value(), "parameter") == 0)
		{
			//cout << Element->Attribute("name") << " \t" << Element->Attribute("value") << endl;

			//m_iec104Config[Element->Attribute("name")] = Element->Attribute("value");
			//m_mapIec104[m_tempIedName].configParam = m_iec104Config;
		}
		if (strcmp(Element->Value(), "dots") == 0)
		{
			parse_Iec103(Element);
		}
		if (strcmp(Element->Value(), "dot") == 0)
		{
			//cout <<"点名称=>" <<Element->Attribute("name") << endl;
			m_lmapPoint[Element->Attribute("address")] = Element->Attribute("redisAddress");
			m_map103Point[m_lIedName] = m_lmapPoint;
		}
		Element = Element->NextSiblingElement();
	}
	return true;
}

bool WgjXml::find_RedisInfo(string strNode,REDIS_INFO & redis_info)
{
	if (!m_bOpenStatus) return false;
	TiXmlElement* Element = m_doc.RootElement();

	Element = Element->FirstChildElement();
	while (Element != NULL)
	{
		if (strcmp(Element->Value(), strNode.c_str()) == 0)
		{
			Element = Element->FirstChildElement();
			while (Element != NULL)
			{
				if (strcmp(Element->Value(), "channel") == 0 &&
					(strcmp(Element->Attribute("name"), m_channel.c_str()) == 0))
				{
					Element = Element->FirstChildElement();
					while (Element != NULL)
					{
						if (strcmp(Element->Value(), "rtdb") == 0)
						{
							redis_info.ip = Element->Attribute("ipaddress");
							redis_info.port = atoi(Element->Attribute("port"));
							redis_info.channel = Element->Attribute("sub_channel");
							return true;
						}
						Element = Element->NextSiblingElement();
					}

				}
				Element = Element->NextSiblingElement();
			}
		}
		Element = Element->NextSiblingElement();
	}
	return true;
}
//内部解析获取所有通道
void WgjXml::get_AllChannel(TiXmlElement*  Element)
{
	if (!m_bOpenStatus) return  ;
	Element = Element->FirstChildElement();
	while (Element != NULL)
	{

		if (strcmp(Element->Value(), "channel")==0)
		{
			m_MapChannelAll[Element->Attribute("name")] = Element->Attribute("program_name");
			
			//return;
		}
		else
		{
			if (!Element->NoChildren())
				get_AllChannel(Element);
		}
		Element = Element->NextSiblingElement();
	}
}
//内部解析网分的参数
void WgjXml::getParseConfigInfo(string parseType)
{
	m_parseConfig.clear();
	if (!m_bOpenStatus) return  ;
	TiXmlElement* Element = m_doc.RootElement();

	Element = Element->FirstChildElement();
	while (Element != NULL)
	{
		if (strcmp(Element->Value(), "networkanalysis") == 0)
		{
			Element = Element->FirstChildElement();
			while (Element != NULL)
			{
				if (strcmp(Element->Value(), "channel") == 0 &&
					(strcmp(Element->Attribute("name"), m_channel.c_str()) == 0))
				{
					m_parseConfig["NetWorkType"] = Element->Attribute("NetWorkType");
					m_parseConfig["NetworkName"] = Element->Attribute("network_name");
					Element = Element->FirstChildElement();
					while (Element != NULL)
					{
						//cout << Element->Value() << endl;
						if (strcmp(Element->Value(), "ied") == 0)
						{
							Element = Element->FirstChildElement();
							while (Element != NULL)
							{
								if (strcmp(Element->Value(), "protocol") == 0)
								{
									Element = Element->FirstChildElement();
									while (Element != NULL)
									{
										if (strcmp(Element->Value(), "parameter") == 0)
										{
											m_parseConfig[Element->Attribute("name")] = Element->Attribute("value");
										}
										if (Element != NULL)	Element = Element->NextSiblingElement();
									}
								}
								if (Element != NULL){
									if (strcmp(Element->Value(), "pcapfile") == 0)
									{
										m_parseConfig["src_file_path"] = Element->Attribute("src_file_path");
										m_parseConfig["dst_file_path"] = Element->Attribute("dst_file_path");
									}
								}
								if (Element != NULL) Element = Element->NextSiblingElement();
							}

						}
						if (Element != NULL)Element = Element->NextSiblingElement();
					}
				}
				if (Element!=NULL)Element = Element->NextSiblingElement();
			}
		}
		if (Element != NULL)Element = Element->NextSiblingElement();
	}
	
	return;
}
map<string,string> WgjXml::GetDataStorageConfig(string channel)
{
	m_mapStorageConfig.clear();

	if (!m_bOpenStatus) return m_mapStorageConfig;
	TiXmlElement* Element = m_doc.RootElement();

	Element = Element->FirstChildElement();
	while (Element != NULL)
	{
		if (strcmp(Element->Value(),"data_storageServer") == 0)
		{
			Element = Element->FirstChildElement();
			while (Element != NULL)
			{
				if (strcmp(Element->Value(), "channel") == 0 &&
					(strcmp(Element->Attribute("name"), channel.c_str()) == 0))
				{
					Element = Element->FirstChildElement();
					while (Element != NULL)
					{
						if (strcmp(Element->Value(), "parameter") == 0)
						{
							m_mapStorageConfig[Element->Attribute("name")] = Element->Attribute("value");
						}
						if (Element != NULL)	Element = Element->NextSiblingElement();
					}
				}
				if (Element != NULL)	Element = Element->NextSiblingElement();
			}
		}
		if (Element != NULL)	Element = Element->NextSiblingElement();
	}
	return m_mapStorageConfig;
}
//内部解析抓包的参数
void WgjXml::getPcapConfigInfo()
{
	if (!m_bOpenStatus) return;
	TiXmlElement* Element = m_doc.RootElement();

	Element = Element->FirstChildElement();
	while (Element != NULL)
	{
		if (strcmp(Element->Value(), "sniffer") == 0)
		{
			Element = Element->FirstChildElement();
			while (Element != NULL)
			{
				if (strcmp(Element->Value(), "channel") == 0 &&
					(strcmp(Element->Attribute("name"), m_channel.c_str()) == 0))
				{
					//m_parseConfig["NetWorkType"] = Element->Attribute("NetWorkType");
					m_pcapConfig["network_name"] = Element->Attribute("network_name");
					m_pcapConfig["NetWorkType"] = Element->Attribute("NetWorkType");
					Element = Element->FirstChildElement();
					while (Element != NULL)
					{
						//cout << Element->Value() << endl;
						if (strcmp(Element->Value(), "ied") == 0)
						{
							Element = Element->FirstChildElement();
							while (Element != NULL)
							{
								if (strcmp(Element->Value(), "protocol") == 0)
								{
									Element = Element->FirstChildElement();
									while (Element != NULL)
									{
										if (strcmp(Element->Value(), "parameter") == 0)
										{
											m_pcapConfig[Element->Attribute("name")] = Element->Attribute("value");
										}
										if (Element != NULL)	Element = Element->NextSiblingElement();
									}
								}
								if (Element != NULL) Element = Element->NextSiblingElement();
							}
						}
						if (Element != NULL)Element = Element->NextSiblingElement();
					}
				}
				if (Element != NULL)Element = Element->NextSiblingElement();
			}
		}
		if (Element != NULL)Element = Element->NextSiblingElement();
	}

	return;
}
//内部解析IECServer 61850服务点表
void WgjXml::getIEC61850ServerPoint(TiXmlElement*  Element)
{
	if (!m_bOpenStatus) return  ;
	Element = Element->FirstChildElement();
	while (Element != NULL)
	{
		//转发节点
		if (strcmp(Element->Value(), "forwardservice") == 0)
		{
			getIEC61850ServerPoint(Element);
		}
		//找到对应的通道
		if (strcmp(Element->Value(), "channel") == 0 &&
			strcmp(Element->Attribute("name"), m_channel.c_str()) == 0 &&
			strcmp(Element->Attribute("program_name"), "IEC61850_Server") == 0)
		{
			getIEC61850ServerPoint(Element);
		}
		if (strcmp(Element->Value(), "protocol") == 0)//参数列表
		{
			getIEC61850ServerPoint(Element);
		}
		if (strcmp(Element->Value(), "parameter") == 0)
		{
			cout << Element->Attribute("name") << " \t" << Element->Attribute("value") << endl;
			if (strcmp(Element->Attribute("name"), "cidname") == 0)
			{
				this->m_cidname = Element->Attribute("value");
			}
			break;
		}
		if (strcmp(Element->Value(), "dots") == 0)
		{
			getIEC61850ServerPoint(Element);
		}
		if (strcmp(Element->Value(), "dot") == 0)
		{
			//cout <<"点名称=>" <<Element->Attribute("name") << endl;
			m_iec61850Server[Element->Attribute("cjRedis")] = Element->Attribute("pubaddr");
			//m_Point61850[Element->Attribute("address")] = Element->Attribute("redisAddress");
			//m_mapIedInfo[m_iedStruct.iedName].mapPoint[Element->Attribute("address")] = Element->Attribute("redisAddress");
		}
		Element = Element->NextSiblingElement();
	}
	return  ;
}
//内部解析采集点的61850
bool WgjXml::parse_61850IP(TiXmlElement*  Element)
{
	if (!m_bOpenStatus) return false;
	Element = Element->FirstChildElement();
	while (Element != NULL)
	{
		if (strcmp(Element->Value(), "collection") == 0)
		{
			parse_61850IP(Element);
		}
		if (strcmp(Element->Value(), "channel") == 0 &&
			strcmp(Element->Attribute("program_name"), "IEC61850") == 0)
		{
			parse_61850IP(Element);
		}
		if (strcmp(Element->Value(), "ied") == 0)
		{
			parse_61850IP(Element);
		}
		if (strcmp(Element->Value(), "master_network") == 0)    //master_network
		{
			if (m_NetworkType.compare("ANetwork") == 0)
			{
				m_listIP.push_back(Element->Attribute("ipaddress"));
			}
		}
		if (strcmp(Element->Value(), "standby_network") == 0)//master_network
		{
			if (m_NetworkType.compare("BNetwork") == 0)
			{
				m_listIP.push_back(Element->Attribute("ipaddress"));
			}
		}
		
		Element = Element->NextSiblingElement();
	}
	return true;
}
