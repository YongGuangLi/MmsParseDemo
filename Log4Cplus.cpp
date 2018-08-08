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
	log4cplus::PropertyConfigurator::doConfigure(LOG4CPLUS_TEXT("/home/wgj/MmsParseDemo/MmsParse/log4cplus.properties"));
	logger_ = log4cplus::Logger::getInstance("Log");
}

Log4Cplus::~Log4Cplus()
{
	log4cplus::Logger::shutdown();
}

Logger Log4Cplus::getLogger() const
{
    return logger_;
}


