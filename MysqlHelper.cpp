/*
 * MysqlHelper.cpp
 *
 *  Created on: Aug 9, 2018
 *      Author: root
 */

#include "MysqlHelper.h"

MysqlHelper::MysqlHelper() {
	mysql = NULL;
}

MysqlHelper::~MysqlHelper() {
    if(mysql != NULL)
    {
        mysql_close(mysql);
        mysql_library_end();
    }
}


bool MysqlHelper::connect(string ip, int port, string dbname, string user, string passwd)
{
	mysql = mysql_init(NULL);

	if (mysql_real_connect(mysql, ip.c_str(), user.c_str(), passwd.c_str(), dbname.c_str(), port, NULL, 0) == NULL)
	{
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_WARN, string("Connect Failure:") + mysql_error(mysql));
		return false;
	}

	mysql_set_character_set(mysql,"utf8");
	return true;
}

bool MysqlHelper::execSql(string sql)
{
	if(mysql_query(mysql, sql.c_str()))
	{
		SingletonLog4cplus->log(Log4cplus::LOG_NORMAL, Log4cplus::LOG_WARN, string("Query Failure:") + mysql_error(mysql));
		return false;
	}
	return true;
}
