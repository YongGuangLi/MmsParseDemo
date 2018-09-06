/*
 * Log4cplusHelp.h
 *
 *  Created on: Jul 1, 2018
 *      Author: root
 */

#ifndef LOG4CPLUS_H_
#define LOG4CPLUS_H_

#include <log4cplus/configurator.h>
#include <log4cplus/logger.h>
#include <log4cplus/loggingmacros.h>      //需要在redis庫之前引用
using namespace log4cplus;

#include "RedisHelper.h"

#include "ConfigIni.h"
#include "RtdbMessage.pb.h"


#include <string>
using namespace std;

#define SingletonLog4cplus Log4Cplus::getInstance()

namespace Log4cplus{
	//类型{0全部, 1普通日志，2报文日志 ,3变位信息, 4授权信息}
	enum LogType
	{
		LOG_NORMAL = 1,
		LOG_DATAFRAME = 2,
		LOG_DATACHANGE = 3,
		LOG_AUTHORIZE = 4,
	};


	//等级 1信息[INFO], 2调试信息[DEBUG]，3错误信息[ERROR]，4告警信息[WARN]}
	enum LogLevel
	{
		LOG_INFO = 1,
		LOG_DEBUG = 2,
		LOG_ERROR = 3,
		LOG_WARN = 4,
	};
}

class Log4Cplus {
public:
	static Log4Cplus *getInstance();
    Logger getLogger() const;

    void setLogRequestFlag(int);

    void log(Log4cplus::LogType, Log4cplus::LogLevel, string);

private:
	static Log4Cplus * log4cplus_;
	Log4Cplus();
	virtual ~Log4Cplus();

	Logger logger_;
	int logRequestFlag_;           //日志开关  0:关闭  1:开启
	log4cplus::ConfigureAndWatchThread *configureThread;
	RedisHelper *redisHelper;
};


#endif /* LOG4CPLUSHELP_H_ */
