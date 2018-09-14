


#include <iostream>
#include "PcapDirManager.h"
#include "ReadPcapFile.h"
#include "ConfigIni.h"
#include "PacketParse.h"

#include <boost/date_time/posix_time/posix_time.hpp>

#include <unistd.h>
#include <signal.h>

using namespace std;


bool g_isRunning = true;

void signal_handler(int sign_no)
{
	if(sign_no == SIGINT)
	{
		g_isRunning = false;
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "get SIGINT");
	}
	else if(sign_no == SIGTERM)
	{
		g_isRunning = false;
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "get SIGTERM");
	}
}

void initConfigDetail()
{
	if(SingletonConfig->loadConfiguration("/home/GM2000/Configuration.xml"))
	{
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Load Configuration.xml Success");
	}
}

int main(int argc,char **argv)
{
	signal(SIGTERM, signal_handler);  // kill -15 终止
	signal(SIGINT, signal_handler);   // kill -2 （同 Ctrl + C）

	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "-----------------start--------------------");
	SingletonConfig->setChannelName("N1");

    //初始化所有配置数据
	initConfigDetail();

	struct pcap_pkthdr *pkthdr = NULL;
	u_char *packet = NULL;
	ReadPcapFile readPcapFile;
	PacketParse packetParse;
	PcapDirManager pcapDirManager(SingletonConfig->getSrcPacpFilePath());

	while(g_isRunning)
	{
		boost::filesystem::path filePath = pcapDirManager.getFisrtFile();
		string fileName = filePath.string();

		if(fileName.empty())
		{
			SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, SingletonConfig->getSrcPacpFilePath() + " is Empty");
			sleep(1);
			continue;
		}

		if(readPcapFile.openPcapFile(fileName))
		{
			SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Open " + fileName + " Success");
			int packetCnt = 0;
			while(g_isRunning)
			{
				int result = readPcapFile.pcapNextEx(&pkthdr, (const u_char **)&packet );
				if(result == 1)             	//返回数据成功
				{
					packetCnt++;
					//printf("packetCnt = %d\n",packetCnt);
					packetParse.dissectPacket(filePath.filename().string(), pkthdr, packet);     //分析报文内容
				}
				else if(result == -2)          //文件最后一个报文
				{
					if(pcapDirManager.getFileNum() <= 1 && packetCnt < SingletonConfig->getPacketCnt())  //文件报文个数还没大最大值,而且没有新文件，继续读取
					{
						sleep(1);
						continue;
					}

					readPcapFile.closePcapFile();
					pcapDirManager.renamePcapFile(fileName, SingletonConfig->getDstPacpFilePath() + "/" + filePath.filename().string());
					break;
				}
			}
		}
		else
		{
			SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_WARN, "Open " + fileName + " Failure");
		}
	}

	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "-----------------end--------------------");
	return 0;
}


//if(SingletonConfig->initConfig("/home/GM2000/config.ini"))
//{
//	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Load config.ini Success");
//}

//if(SingletonConfig->initDeviceDescTxt("/home/GM2000/devicedesc.txt"))
//{
//	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Load devicedesc.txt Success");
//}
//
//if(SingletonConfig->initPointDescTxt("/home/GM2000/pointdesc.txt"))
//{
//	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Load pointdesc.txt Success");
//}


