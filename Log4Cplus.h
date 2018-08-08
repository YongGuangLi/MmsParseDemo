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
#include <log4cplus/loggingmacros.h>
using namespace log4cplus;

#define Log4cplusSingleton Log4Cplus::getInstance()

class Log4Cplus {
public:
	static Log4Cplus *getInstance();
	virtual ~Log4Cplus();
    Logger getLogger() const;

private:
	static Log4Cplus * log4cplus_;
	Log4Cplus();
	Logger logger_;
};


#endif /* LOG4CPLUSHELP_H_ */
