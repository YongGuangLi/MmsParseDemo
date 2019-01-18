


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

int main(int argc,char **argv)
{
	signal(SIGTERM, signal_handler);  // kill -15 终止
	signal(SIGINT, signal_handler);   // kill -2 （同 Ctrl + C）

	if(argc >= 2)
		SingletonConfig->setChannelName(argv[1]);

	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "-----------------start--------------------");


    //初始化所有配置数据
	if(SingletonConfig->loadConfiguration("/home/GM2000/Configuration.xml"))
	{
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Load Configuration.xml Success");
	}

	struct pcap_pkthdr *pkthdr = NULL;
	u_char *packet = NULL;
	ReadPcapFile readPcapFile;
	PacketParse packetParse("/home/GM2000/" + SingletonConfig->getDatasetFilePath());
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

		if(readPcapFile.openPcapFile(fileName) == false)
		{
			SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_WARN, "Open " + fileName + " Failure");
			if(pcapDirManager.getFileNum() > 1)
			{
				pcapDirManager.renamePcapFile(fileName, SingletonConfig->getDstPacpFilePath() + "/" + filePath.filename().string());
			}
			else
				sleep(1);

			continue;
		}

		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "Open " + fileName + " Success");
		int packetCnt = 0;
		while(g_isRunning)
		{
			int result = readPcapFile.pcapNextEx(&pkthdr, (const u_char **)&packet );
			if(result == 1)             	//返回数据成功
			{
				packetCnt++;
				//SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "packetCnt:" + boost::lexical_cast<string>(packetCnt));
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

	SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_DEBUG, "-----------------end--------------------");
	return 0;
}



