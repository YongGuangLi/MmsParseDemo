/*
 * RedisHelper.cpp
 *
 *  Created on: Aug 6, 2018
 *      Author: root
 */

#include "RedisHelper.h"

RedisHelper::RedisHelper() {
	client_pub_ = NULL;
	client_sub_ = NULL;
	acl::acl_cpp_init();
}

RedisHelper::~RedisHelper() {
	if(client_pub_ != NULL)
	{
		client_pub_->close();
		delete client_pub_;
	}
	if(client_sub_ != NULL)
	{
		client_sub_->close();
		delete client_sub_;
	}
}

bool RedisHelper::open(string addr, bool sentinel, int conn_timeout, int rw_timeout)
{
	client_pub_ = new  acl::redis_client(addr.c_str(), conn_timeout, rw_timeout);
	client_sub_ = new  acl::redis_client(addr.c_str(), conn_timeout, rw_timeout);
	bool result = client_pub_->eof();
	result = client_sub_->eof();
	if(result == true)
	{
		redis_pub_.set_client(client_pub_);
		redis_sub_.set_client(client_sub_);
	}
	return result;
}

bool RedisHelper::set(string key, string value)
{
	acl::redis redis(client_pub_);
	bool result = redis.set(key.c_str(), value.c_str());
	if(!result)
	{
		const acl::redis_result* res = redis.get_result();
		printf("error: %s\r\n",res ? res->get_error() : "unknown error");
	}

	return result;
}

int RedisHelper::publish(string channel, string message)
{
	redis_pub_.clear();
	int result = redis_pub_.publish(channel.c_str(), message.c_str(), message.length());
	return result;
}

int RedisHelper::publish(string channel, char* message, int length)
{
	redis_pub_.clear();
	int result = redis_pub_.publish(channel.c_str(), message, length);
	return result;
}

int RedisHelper::subscribe(string channel)
{
	redis_sub_.clear();
	int result = redis_sub_.subscribe(channel.c_str(), NULL);
	if(result <= 0)
	{
		printf("subscribe %s error(%s), ret: %d\r\n",channel.c_str(),redis_sub_.result_error(), result);
	}
	return result;
}

bool RedisHelper::getMessage(string& message, string channel)
{
	acl::string acl_channel;
	acl::string acl_msg;

	redis_sub_.clear();
	bool result = redis_sub_.get_message(acl_channel, acl_msg);
	if(result == true && channel.empty())
	{
		message = acl_msg.c_str();
		//printf("get one message: %s, channel: %s\r\n",acl_msg.c_str(), acl_channel.c_str());
	}
	else if( result == true && strcmp(channel.c_str(), acl_channel.c_str()) == 0)
	{
		message = acl_msg.c_str();
	}
	return result;
}
