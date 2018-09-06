/*
 * RedisHelper.h
 *
 *  Created on: Aug 6, 2018
 *      Author: root
 */

#ifndef REDISHELPER_H_
#define REDISHELPER_H_

#include "acl_cpp/lib_acl.hpp"
#include <string>

using namespace std;

#define REDIS_CHANNEL_ALARM "alarmdata"
#define REDIS_CHANNEL_NETCONTROLANA "NetControlAna"
#define REDIS_CHANNEL_CONFIG "config"

class RedisHelper {
public:
    RedisHelper(string addr, bool retry = false, bool sentinel = false, int conn_timeout = 60, int rw_timeout = 30);
	virtual ~RedisHelper();
    bool open();
    bool check_connect();
	bool set(string key, string value);
	int publish(string channel, string message, string key = "");              //返回订阅者数量， -1出错
	int publish(string channel, char* message, int length, string key = "");   //返回订阅者数量， -1出错
    int subscribe(string channel);                                            //the number of channels subscribed by the current client
    bool getMessage(string& message, string channel = "");
private:
	acl::redis_client *client_pub_;
	acl::redis_client *client_sub_;
	acl::redis_pubsub redis_pub_;
	acl::redis_pubsub redis_sub_;

    string addr_;
    bool retry_;
    bool sentinel_;
    int conn_timeout_;
    int rw_timeout_;
};

#endif /* REDISHELPER_H_ */
