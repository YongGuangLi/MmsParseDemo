/*
 * MysqlHelper.h
 *
 *  Created on: Aug 9, 2018
 *      Author: root
 */

#ifndef MYSQLHELPER_H_
#define MYSQLHELPER_H_

#include "ConfigIni.h"
#include "Log4Cplus.h"
#include <mysql.h>

class MysqlHelper {
public:
	MysqlHelper();
	virtual ~MysqlHelper();

	bool connect(string ip, int port, string dbname, string user, string passwd);

	bool execSql(string);
private:
	 MYSQL* mysql;
};

#endif /* MYSQLHELPER_H_ */
