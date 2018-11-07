/*
 * RedisHelper.h
 *
 *  Created on: Aug 6, 2018
 *      Author: root
 */

#ifndef REDISHELPER_H_
#define REDISHELPER_H_

#include "acl_cpp/redis/redis.hpp"
#include "acl_cpp/redis/redis_client.hpp"
#include "acl_cpp/redis/redis_pubsub.hpp"
#include "acl_cpp/redis/redis_connection.hpp"

#include <iostream>
#include <string>
using namespace std;

#define REDIS_CHANNEL_ALARM "alarmdata"
#define REDIS_CHANNEL_NETCONTROLANA "NetControlAna"
#define REDIS_CHANNEL_CONFIG "config"
#define REDIS_CHANNEL_PROCTRL "proCtrl"
#define REDIS_CHANNEL_ALARMCALC "AlarmCalc"

class RedisHelper {
public:
    RedisHelper(string addr, bool retry = false, bool sentinel = false, int conn_timeout = 60, int rw_timeout = 30);
	virtual ~RedisHelper();

    bool open();

    bool check_connect();

	bool set(string key, string value);

    //返回订阅者数量， -1出错
    int publish(string channel, string message, string key = "");

    //返回订阅者数量， -1出错
    int publish(string channel, char* message, int length, string key = "");

    //返回最后一个channel参数订阅者数量， -1出错，   最后1个参数需要传入NULL,用于判断结束
    int subscribe(string channel, ...);

    int unsubscribe(string channel);

    //调用此函数,必须已有channel被订阅，  获取指定channel的消息，不传则获取所有已订阅的消息
    bool getMessage(string& message, string channel = "");
private:
    acl::redis_client *client_con_;
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
