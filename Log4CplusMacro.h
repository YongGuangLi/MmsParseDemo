/*
 * Log4CplusMacro.h
 *
 *  Created on: Jul 2, 2018
 *      Author: root
 */

#ifndef LOG4CPLUSMACRO_H_
#define LOG4CPLUSMACRO_H_

#include "Log4Cplus.h"


#define LOG_DEBUG(msg) LOG4CPLUS_DEBUG(Log4cplusSingleton->getLogger() ,msg)

#endif /* LOG4CPLUSMACRO_H_ */
