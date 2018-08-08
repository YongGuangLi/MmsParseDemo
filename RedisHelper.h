/*
 * RedisHelper.h
 *
 *  Created on: Aug 6, 2018
 *      Author: root
 */

#ifndef REDISHELPER_H_
#define REDISHELPER_H_

#include "Log4CplusMacro.h"    //需要放到最前面，可能是引用庫的顺序

#include "acl_cpp/lib_acl.hpp"       //需要把-lpthread 链接在libacl庫之后
#include "lib_acl.h"

#include <string>

using namespace std;

#define CHANNEL "MmsParse"

class RedisHelper {
public:
	RedisHelper();
	virtual ~RedisHelper();
	bool open(string addr, bool sentinel = false, int conn_timeout = 60, int rw_timeout = 30);
	bool set(string key, string value);
	int publish(string channel, string message);              //返回订阅者数量， -1出错
	int publish(string channel, char* message, int length);   //返回订阅者数量， -1出错
	int subscribe(string channel);                            //the number of channels subscribed by the current client
	bool getMessage(string& message, string channel = "");

private:
	acl::redis_client *client_pub_;
	acl::redis_client *client_sub_;
	acl::redis_pubsub redis_pub_;
	acl::redis_pubsub redis_sub_;
};

#endif /* REDISHELPER_H_ */
