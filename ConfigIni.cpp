/*
 * ConfigIni.cpp
 *
 *  Created on: Jul 25, 2018
 *      Author: root
 */

#include "ConfigIni.h"


ConfigIni* ConfigIni::configIni = NULL;

ConfigIni* ConfigIni::getInstance()
{
	if(configIni == NULL)
	{
		configIni = new ConfigIni();
	}
	return configIni;
}
ConfigIni::ConfigIni() {
}

ConfigIni::~ConfigIni() {
}

bool ConfigIni::initConfig(string filename)
{
	ptree properties;
	ini_parser::read_ini(filename, properties);
	basic_ptree<string, string> lvbtItems = properties.get_child("MYSQL");
	try{
		mysqlIp = lvbtItems.get<string>("ip");
		mysqlPort = lvbtItems.get<int>("port");
		dbName = lvbtItems.get<string>("dbName");
		user = lvbtItems.get<string>("user");
		passwd = lvbtItems.get<string>("passwd");
	}
	catch (std::exception& e) {
		cerr << e.what() << endl;
	}

	return true;
}

bool ConfigIni::loadConfiguration(string filename)
{
	WgjXml wgjXML;
	if(!wgjXML.LoadXml(filename.c_str()))
	{
		return false;
	}

	ProcessManag::Map_Channel mapChannel = wgjXML.GetAllChannelName();                    //获取所有通道名
	ProcessManag::Map_Channel::iterator itChannel = mapChannel.begin();
	for( ; itChannel != mapChannel.end(); itChannel++)
	{
		if(itChannel->second.compare("IEC61850") == 0)                                    //通过直采IEC61850获取点表对应的发布点
		{
			mapFcdaToPubAddr =  wgjXML.Get_Point61850(itChannel->first);
		}
	}

	wgjXML.GetRedisConnectionConfig(redisIp,redisPort);                               //获取redis信息

	NetworkParse::Map_ParseConfig mapParseConfig = wgjXML.GetParseConfigInfo(channelName);
	NetworkParse::Map_ParseConfig::iterator it = mapParseConfig.begin();
	for( ; it != mapParseConfig.end(); it++)
	{
		if(it->first.compare("src_file_path") == 0)
		{
			srcPacpFilePath = it->second;
		}else if(it->first.compare("dst_file_path") == 0)
		{
			dstPacpFilePath = it->second;
		}else if(it->first.compare("dataset_da_point_file") == 0)
		{
			datasetFilePath = it->second;
		}else if(it->first.compare("mms_count") == 0)
		{
			packetCnt = boost::lexical_cast<int>(it->second);
		}else if(it->first.compare("heart_beat_time") == 0)
		{
			heartBeatTime = boost::lexical_cast<int>(it->second);
		}else if(it->first.compare("NetWorkType") == 0)
		{
			netCardType = it->second.compare("ANetwork") == 0 ? "_01_" : "_02_";
		}
	}

	return true;
}


string ConfigIni::getPubAddrByFcda(string fcda)     //通过点名获取发布点
{
	string pubAddr;
	map<string,string>::iterator it = mapFcdaToPubAddr.find(fcda);
	if(it != mapFcdaToPubAddr.end())
	{
		pubAddr = it->second;
	}
	return pubAddr;
}

bool ConfigIni::initDeviceDescTxt(string path)
{
	ifstream infile(path.c_str());
	if (!infile) {
		return false;
	}
	string line, key, value;
	while (getline(infile, line)) {
		size_t pos = line.find(':');
		mapDeviceDesc.insert( make_pair(line.substr(0, pos), line.substr(pos + 1)));
	}
	return true;
}

bool ConfigIni::initPointDescTxt(string path)
{
	ifstream infile(path.c_str());
	if (!infile) {
		return false;
	}
	string line, key, value;
	while (getline(infile, line)) {
		size_t pos = line.find(':');
		mapPointDesc.insert(make_pair(line.substr(0, pos), line.substr(pos + 1)));
	}
	return true;
}


string ConfigIni::getDeviceDesc(string deviceip)
{
	string iedDesc;
	map<string, string>::iterator it = mapDeviceDesc.find(deviceip);
	if(it != mapDeviceDesc.end())
	{
		iedDesc = it->second;
	}

	return iedDesc;
}

string ConfigIni::getPointDesc(string pointname)
{
	string pointdesc;
	map<string, string>::iterator it = mapPointDesc.find(pointname);
	if(it != mapPointDesc.end())
	{
		pointdesc = it->second;
	}

	return pointdesc;
}

void ConfigIni::setChannelName(string channel)
{
	channelName = channel;
}

string ConfigIni::getChannelName() const
{
	return channelName;
}

string ConfigIni::getRedisIp() const
{
	return redisIp;
}

int ConfigIni::getRedisPort() const
{
	return redisPort;
}

string ConfigIni::getMysqlIp() const
{
	return mysqlIp;
}
int ConfigIni::getMysqlPort() const
{
	return mysqlPort;
}
string ConfigIni::getMysqlDbName() const
{
	return dbName;
}
string ConfigIni::getMysqlUser() const
{
	return user;
}
string ConfigIni::getMysqlPassWd() const
{
	return passwd;
}

string ConfigIni::getNetCardType() const
{
	return netCardType;
}

string ConfigIni::getSrcPacpFilePath() const
{
	return srcPacpFilePath;
}

string ConfigIni::getDstPacpFilePath() const
{
	return dstPacpFilePath;
}

string ConfigIni::getDatasetFilePath() const
{
	return datasetFilePath;
}
int ConfigIni::getPacketCnt() const
{
	return packetCnt;
}


//list all key/value under setting session
//	for (basic_ptree<string, string>::iterator lvitem=lvbtItems.begin();lvitem!=lvbtItems.end();lvitem++)
//	{
//		cout << (*lvitem).first.data() << "=" << (*lvitem).second.data() << endl;
//	}

//	//change key values
//	lvptProperties.put<string>("setting.key2", "new value");
//	lvptProperties.put<int>("setting.key1", ++lvnInt);
//	//update ini file
//	ini_parser::write_ini("d:\\temp\\win.ini", lvptProperties);
