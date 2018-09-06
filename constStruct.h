#ifndef CONST_STRUCT
#define CONST_STRUCT
#include <string>
#include <map>
#include <list>
using namespace std;
//g++ tinystr.cpp tinyxml.cpp  tinyxmlerror.cpp  tinyxmlparser.cpp   WgjXml.cpp -c
// ar -r libwjgxml.a tinystr.o tinyxml.o WgjXml.o  tinyxmlerror.o tinyxmlparser.o 


struct REDIS_INFO
{
	string ip;
	string channel;
	int port;
};
typedef map<string, string > MAP_CHANNEL_REDIS;
namespace  IEC61850_STRUCT
{ 
	struct IED_61850
	{
		string    ip_A;        //A网ip
		string    ip_B;        //B网IP
		string	  channel;	   //通道名称
		string    iedName;     //设备名称

		int		  port;        //端口号;
		int       inst;        //实例号;
		bool      bperiod;     //周期上送;
		bool      bdatachange; //数据改变
		int		  period_time; //周期时间

		string    redisip;
		int       redisPort;
		string    redisChannel;

		map<string,string>  mapPoint;
	};

	typedef map<string, IED_61850> Map_IedInfo;   //key  iedName, value:  信息
	
	//struct IEC61850_INFO
	//{
	//	Map_IedInfo map;
	//};
}

namespace  ProcessManag
{
	typedef map<string, string > Map_Channel; //通道名称,对应的程序名字
}

namespace NetworkParse
{
	typedef map<string,string > Map_ParseConfig; //通道名称,对应的程序名字
}
namespace NetworkPcap
{
	typedef map<string, string > Map_NetworkPcap; 
}
namespace IEC61850Server
{

	typedef map<string, string> Map_IECServer;      //1、采集点的redis地址，2、发布的redis地址
}
namespace IEC104WF
{
	struct  stPointTable
	{
		string   redisAddr; //redis地址
		float    off_set;   //可能是偏移量
		float    coe;		//可能是倍率
	};
	//struct stIED_IEC104
	//{
	//	string    ip_A;						//A网ip
	//	string    ip_B;						//B网IP

	//	int		  A_Port;					//端口号;
	//	int		  B_Port;					//端口号;

	//	map<string, string> configParam;	//配置参数，1是名称，2是值
	//	map<string, string> pointTable;  //点表
	//};
	typedef std::map<int, std::map<int, stPointTable> >Map104;
	typedef std::map<string, Map104> IpMap104;
	///typedef map<string, stIED_IEC104> Map_IEC104;   //  iedName, value:  信息

}

namespace IEC103
{
	struct stConfigParam
	{
		string    ip_A;						//A网ip
		string    ip_B;						//B网IP

		int		  A_Port;					//端口号;
		int		  B_Port;					//端口号;

		string    type;                 //类型,tcp,udp
	};
	typedef map<string, stConfigParam> Map_IEC103Config;		//  1/iedName，2/连接参数信息
	typedef map<string, map<string, string > > Map_IEC103Point;  //	1/iedName, 2/点表信息
}
#endif
