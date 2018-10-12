/*
 * ConfigIni.h
 *
 *  Created on: Jul 25, 2018
 *      Author: root
 */

#ifndef CONFIGINI_H_
#define CONFIGINI_H_

#include "WgjXml.h"

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/lexical_cast.hpp>

using namespace boost::property_tree;

#include <string>
#include <iostream>

using namespace std;

#define SingletonConfig ConfigIni::getInstance()

class ConfigIni {
public:
	static ConfigIni* getInstance();

	bool initConfig(string);

	bool loadConfiguration(string);

	string getPubAddrByFcda(string);     //通过点名获取发布点

	string getIedName(string);

	string getLinkStatusRedisAddr(string iedName, string iedIp);
public:
	void setChannelName(string);
	string getChannelName() const;

	string getRedisIp() const;
	int getRedisPort() const;

	string getMysqlIp() const;
	int getMysqlPort() const;
	string getMysqlDbName() const;
	string getMysqlUser() const;
	string getMysqlPassWd() const;

	string getNetCardType() const;

	string getSrcPacpFilePath() const;

	string getDstPacpFilePath() const;

	string getDatasetFilePath() const;

	int getPacketCnt() const;

	int getHeartBeatTime() const;
private:
	ConfigIni();
	virtual ~ConfigIni();

	static ConfigIni* configIni;
	map<string,string> mapFcdaToPubAddr;       //key:点名   value:发布点名

	string channelName;                        //运行参数传入的通道名

	string redisIp;
	int redisPort;

	string mysqlIp;
	int mysqlPort;
	string dbName;
	string user;
	string passwd;

	string netCardType;                       //网卡类型，A网:01  B网:02   用于报文文件解析完成，移动命名

	int packetCnt;                            //报文文件最大报文数量

	int heartBeatTime;                        //心跳时间，用于断链判断

	string srcPacpFilePath;                   //报文存储路径

	string dstPacpFilePath;                   //报文移动路径

	string datasetFilePath;                   //点表文件路径

	IEC61850_STRUCT::Map_IedInfo mapIedInfo;
	map<string, string> mapIedName;           //key:设备ip  value:设备名
};

#endif /* CONFIGINI_H_ */
