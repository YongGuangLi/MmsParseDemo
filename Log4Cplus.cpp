/*
 * Log4cplusHelp.cpp
 *
 *  Created on: Jul 1, 2018
 *      Author: root
 */

#include "Log4Cplus.h"

Log4Cplus * Log4Cplus::log4cplus_ = NULL;

Log4Cplus *Log4Cplus::getInstance()
{
	if(log4cplus_ == NULL)
	{
		log4cplus_ = new Log4Cplus();
	}
	return log4cplus_;
}
Log4Cplus::Log4Cplus()
{
	log4cplus::initialize();
	logger_ = log4cplus::Logger::getInstance("Mms");
	configureThread = new log4cplus::ConfigureAndWatchThread(LOG4CPLUS_TEXT("/home/GM2000/log4cplus.properties"), 1000);
	logRequestFlag_ = 0;

	redisHelper = new RedisHelper(SingletonConfig->getRedisIp() + ":" + boost::lexical_cast<string>(SingletonConfig->getRedisPort()), true);  //设置自动重连
	redisHelper->open();
}

Log4Cplus::~Log4Cplus()
{
	log4cplus::Logger::shutdown();
	delete redisHelper;
}

Logger Log4Cplus::getLogger() const
{
    return logger_;
}

void Log4Cplus::setLogRequestFlag(int flag)
{
	logRequestFlag_ = flag;
}

//同事定义的日志等级         1信息[INFO]       2调试信息[DEBUG]，3错误信息[ERROR]    4告警信息[WARN]
//log4cplus定义的日志等级   1调试信息[DEBUG]   2信息[INFO],     3告警信息[WARN]     4错误信息[ERROR]
void Log4Cplus::log(Log4cplus::LogType type, Log4cplus::LogLevel level, string msg)
{
	switch(level)
	{
	case Log4cplus::LOG_INFO:
		LOG4CPLUS_DEBUG(logger_ ,msg);
		break;
	case Log4cplus::LOG_DEBUG:
		LOG4CPLUS_INFO(logger_ ,msg);
		break;
	case Log4cplus::LOG_ERROR:
		LOG4CPLUS_WARN(logger_ ,msg);
		break;
	case Log4cplus::LOG_WARN:
		LOG4CPLUS_ERROR(logger_ ,msg);
		break;
	default:
		break;
	}

	if(logRequestFlag_ == 1)
	{
		RtdbMessage rtdbMessage;
		rtdbMessage.set_messagetype(TYPE_LOGRESPONSE);

		RealLogResponse* realLogResponse = rtdbMessage.mutable_reallogresponse();
		realLogResponse->set_logdetail(msg);
		realLogResponse->set_type(type);
		realLogResponse->set_channelname(SingletonConfig->getChannelName());
		realLogResponse->set_level(level);
		realLogResponse->set_logtime(time(NULL));

		string message;
		rtdbMessage.SerializeToString(&message);

		redisHelper->publish(REDIS_CHANNEL_CONFIG, message);
	}
}

