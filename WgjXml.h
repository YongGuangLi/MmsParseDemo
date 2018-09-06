#pragma once
#include "constStruct.h"
#include "tinyxml.h"
#include "tinystr.h"
#include <iostream>
#include <vector>
#include <sstream>     
using namespace std;
class WgjXml
{
public:
	WgjXml();
	~WgjXml();
public:
	template <class Type>
	Type stringToNum(const string& str)
	{
		istringstream iss(str);
		Type num;
		iss >> num;
		return num;
	}

	bool LoadXml(const char * name);
	/*
	*功能    =》 获取所有的通道名称
	*所属模块=》进程管理
	*参数    =》返回MAP，第一个string通道名称,第二个string程序名称,
	*/
	ProcessManag::Map_Channel GetAllChannelName();   //通道名称，与采集服务

	/*
	*所属模块=》61850直采
	*获取61850采集点，参数：通道的名称
	*返回结果：Map_IedInfo,ied所有信息
	*/
	IEC61850_STRUCT::Map_IedInfo Get_61850(string channel);

	/*
	*所属模块 =》通用，网分可加载，直采可加载，实时数据显示可加载
	*功能：根据通道，返回对应的61850采集点
	*/
	map<string, string > Get_Point61850(string channel);
	/*
	*功能    =》获取对应通道的redis配置信息
	*所属模块=》61850直采
	*参数    =》第一个传递名称，第二参数redis传递结构
	*/
	bool GetCollectionRedisInfo(string channel, REDIS_INFO & redis_info);

	/*
	*函数名称=》GetMMSParseConfigInfo
	*功能    =》返回网分的配置参数
	*所属模块=》网分模块中的MMS
	*参数    =》通道名称
	*/
	NetworkParse::Map_ParseConfig GetParseConfigInfo(string strchannel);

	/*
	* 所属模块 =》抓包程序
	* 功能     =》获取抓包的参数
	* 参数     =》传递通道名称
	*/
	NetworkPcap::Map_NetworkPcap GetPcapConfigInfo(string strchannel);
	/*
	* 所属模块 =》抓包程序
	* 功能     =》获取61850A,B网的ip
	* 参数     =》传递网络类型
	*/
	list<string> Get61850IP(string networkType);

	/*
	*所属模块 =》IEC61850Server（61850转发）
	*功能     =》获取IEC61850Server的点表
	*参数     =》传递通道名称
	*/
	IEC61850Server::Map_IECServer GetIEC61850ServerPoint(string strchannel, string & cidName);
	/*
	*获取转发服务的通道名称
	*/
	vector<string> GetTransmitChannel();
	/*
	*获取redisip,redisport
	*/
	void GetRedisConnectionConfig(string & ip,int & port);
	/*
	*获取iec104直采的配置参数，以及点表
	* 目前，只支持单个设备的
	*/
	IEC104WF::IpMap104 GetIEC104WFPoint(string channel);
	map<string ,string> GetIEC104WFParam(string channel);

	/*
	*所属模块 =》IEC103（IEC103直采程序）
	*功能=》初始化103解析配置数据
	*参数=》传递通道名称
	*/
	bool InitIEC103Xml(string channel);
	/*
	*所属模块 =》IEC103（IEC103直采程序)
	*功能     =》获取103配置的连接参数
	*参数     =》无
	*/
	IEC103::Map_IEC103Config GetIEC103Param();
	/*
	*所属模块 =》IEC103（IEC103直采程序)
	*功能     =》获取103的点表
	*参数     =》无
	*/
	IEC103::Map_IEC103Point GetIEC103Point();
	/*
	*所属模块 =》数据存储程序
	*功能     =》获取配置参数
	*参数     =》道通名称
	*/
	map<string, string> GetDataStorageConfig(string channel);
private:
	bool parse_61850(TiXmlElement* rootElement);
	bool parse_Iec104(TiXmlElement*  Element);
	bool parse_Iec103(TiXmlElement*  Element);
	bool find_RedisInfo(string strNode, REDIS_INFO & redis_info);
	void get_AllChannel(TiXmlElement* rootElement);
	void getParseConfigInfo(string parseType);
	void getPcapConfigInfo();
	void getIEC61850ServerPoint(TiXmlElement*  Element);
	bool parse_61850IP(TiXmlElement*  Element);
	bool parse_Iec104Param(TiXmlElement*  Element);
private:
	TiXmlDocument				   m_doc;
	IEC61850_STRUCT::Map_IedInfo   m_mapIedInfo;    //61850信息
	bool						   m_bOpenStatus;
	IEC61850_STRUCT::IED_61850     m_iedStruct;
	string						   m_channel;

	ProcessManag::Map_Channel	   m_MapChannelAll;
	NetworkParse::Map_ParseConfig  m_parseConfig;
	NetworkPcap::Map_NetworkPcap   m_pcapConfig;
	map<string, string>            m_Point61850;	

	list<string >                  m_listIP;
	string						   m_NetworkType;
	

	IEC61850Server::Map_IECServer  m_iec61850Server; //保存IEC61850Server转发数据点表
	string						   m_cidname;
	vector<string>				   m_TransmitChannel;

	IEC104WF::IpMap104             m_mapIP104;
	IEC104WF::Map104		       m_map104Point;
	std::map<int, IEC104WF::stPointTable>    m_l_tempPoint;
	IEC104WF::stPointTable         m_l104Point;
	string						   m_l_tempA;
	string						   m_l_tempB;

	

	map<string, string>            m_iec104Config;
	//map<string, string>			   m_iec104Point;
	string						   m_tempIedName;

	IEC103::Map_IEC103Config	   m_map103Config;
	IEC103::Map_IEC103Point		   m_map103Point;
	IEC103::stConfigParam		   m_lstConfigParam;
	string						   m_lNetworkType;
	string						   m_lIedName;
	map<string, string>			   m_lmapPoint;
	//103

	map<string,string>   m_mapStorageConfig;

};
