


#include <iostream>
#include "PcapDirManager.h"
#include "ReadPcapFile.h"
#include "ConfigIni.h"
#include "PacketParse.h"
#include "RedisHelper.h"

#include <unistd.h>
#include <signal.h>

using namespace std;

#define PCAPNUM 10000

bool g_isRunning = true;

void signal_handler(int sign_no)
{
	if(sign_no == SIGINT)
	{
		g_isRunning = false;
		LOG_DEBUG("get SIGINT");
	}
	else if(sign_no == SIGTERM)
	{
		g_isRunning = false;
		LOG_DEBUG("get SIGTERM");
	}
}

int main(int argc,char **argv)
{
	signal(SIGTERM, signal_handler);  // kill -15 终止
	signal(SIGINT, signal_handler);   // kill -2 （同 Ctrl + C）

	LOG_DEBUG("-----------------start--------------------");
	string dir = "/home/test";
	struct pcap_pkthdr *pkthdr = NULL;
	u_char *packet = NULL;
	ReadPcapFile readPcapFile;
	PacketParse packetParse;
	PcapDirManager pcapDirManager(dir);

	while(g_isRunning)
	{
		string fileName = pcapDirManager.getFisrtFile();
		if(fileName.empty())
		{
			LOG_DEBUG(dir + " is Empty");
			sleep(1);
			continue;
		}

		if(readPcapFile.openPcapFile(fileName))
		{
			LOG_DEBUG(fileName + " Open Success");
			int packetCnt = 0;
			while(g_isRunning)
			{
				int result = readPcapFile.pcapNextEx(&pkthdr, (const u_char **)&packet );

				if(result == 1)             	//返回数据成功
				{
					packetCnt++;
					packetParse.dissectPacket(pkthdr, packet);     //分析报文内容
				}else if(result == -2){          //文件最后一个报文
					if(pcapDirManager.getFileNum() <= 1 && packetCnt < PCAPNUM) //文件报文个数还没大最大值,而且没有新文件，继续读取
					{
						sleep(1);
					}else{
						break;                                                  //文件报文个数还没大最大值,但是有新文件，读取新文件
					}
				}else{

				}
			}
			readPcapFile.renamePcapFile(fileName, fileName + "bak");
		}else{
			LOG_DEBUG(fileName + " Open Failure");
		}
	}

	LOG_DEBUG("-----------------end--------------------");
	return 0;
}


